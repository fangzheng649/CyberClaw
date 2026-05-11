"""Device isolation service for CyberClaw.

Supports multiple isolation methods:
  - iptables: Linux/WSL firewall rules (default, no hardware needed)
  - ssh_switch: SSH to managed switch (Huawei/Cisco/H3C via netmiko)
  - record_only: Log-only fallback when neither is available

Method is controlled by ISOLATION_METHOD env var.
"""
import asyncio
import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"

_SHUTDOWN_CMDS = {
    "huawei": [
        "system-view", "interface {port}", "shutdown", "return",
    ],
    "cisco_ios": [
        "configure terminal", "interface {port}", "shutdown", "end",
    ],
    "hp_comware": [
        "system-view", "interface {port}", "shutdown", "return",
    ],
}

_UNSHUTDOWN_CMDS = {
    "huawei": [
        "system-view", "interface {port}", "undo shutdown", "return",
    ],
    "cisco_ios": [
        "configure terminal", "interface {port}", "no shutdown", "end",
    ],
    "hp_comware": [
        "system-view", "interface {port}", "undo shutdown", "return",
    ],
}

# Track active iptables rules for cleanup
_iptables_rules: dict[str, str] = {}


def _get_method() -> str:
    return os.getenv("ISOLATION_METHOD", "iptables").lower()


def _load_device_ports() -> dict:
    """Load device-to-switch-port mapping from topology config."""
    try:
        with open(_TOPOLOGY_PATH, encoding="utf-8") as f:
            config = json.load(f)
        gateway_ip = next(
            (d["ip"] for d in config["devices"] if d["type"] == "gateway"),
            os.getenv("SWITCH_IP", "10.0.0.1"),
        )
        ports = {}
        for d in config["devices"]:
            sp = d.get("switch_port")
            if sp:
                ports[d["ip"]] = {
                    "switch": gateway_ip if sp != "local" else d["ip"],
                    "port": sp,
                    "name": d["name"],
                }
        return ports
    except Exception as e:
        logger.error(f"Failed to load topology: {e}")
        return {}


def _resolve_device(device_ip: str) -> dict | None:
    info = _load_device_ports().get(device_ip)
    if info:
        return {"switch": info["switch"], "port": info["port"], "name": info["name"]}
    return None


class IsolationService:

    async def isolate(self, device_ip: str, method: str = "auto") -> dict:
        """Isolate a device from the network.

        Args:
            device_ip: Target device IP.
            method: "auto" (use env config), "iptables", "ssh_switch", "record_only"

        Returns:
            Result dict with status and details.
        """
        if method == "auto":
            method = _get_method()

        info = _resolve_device(device_ip)
        result = {
            "device_ip": device_ip,
            "device_name": info["name"] if info else "unknown",
            "method": method,
            "timestamp": datetime.now().isoformat(),
        }

        if method == "iptables":
            r = await self._isolate_iptables(device_ip)
            result.update(r)
        elif method == "ssh_switch":
            if not info:
                result["status"] = "error"
                result["message"] = f"Device {device_ip} not found in port mapping"
                return result
            r = await self._isolate_ssh(info["switch"], info["port"])
            result.update(r)
            result["switch"] = info["switch"]
            result["port"] = info["port"]
        else:
            result["status"] = "recorded"
            result["message"] = f"Isolation recorded for {device_ip} (no active method)"

        return result

    async def restore(self, device_ip: str, method: str = "auto") -> dict:
        """Restore a previously isolated device."""
        if method == "auto":
            method = _get_method()

        info = _resolve_device(device_ip)
        result = {
            "device_ip": device_ip,
            "device_name": info["name"] if info else "unknown",
            "method": method,
            "timestamp": datetime.now().isoformat(),
        }

        if method == "iptables":
            r = await self._restore_iptables(device_ip)
            result.update(r)
        elif method == "ssh_switch":
            if not info:
                result["status"] = "error"
                result["message"] = f"Device {device_ip} not found"
                return result
            r = await self._restore_ssh(info["switch"], info["port"])
            result.update(r)
            result["switch"] = info["switch"]
            result["port"] = info["port"]
        else:
            result["status"] = "recorded"
            result["message"] = f"Restore recorded for {device_ip}"

        return result

    async def get_status(self, device_ip: str) -> dict:
        """Check isolation status of a device."""
        method = _get_method()

        if method == "iptables":
            blocked = device_ip in _iptables_rules
            return {
                "device_ip": device_ip,
                "method": method,
                "is_isolated": blocked,
                "rule": _iptables_rules.get(device_ip),
            }

        return {
            "device_ip": device_ip,
            "method": method,
            "is_isolated": False,
        }

    # ── iptables implementation ────────────────────────────────────

    async def _isolate_iptables(self, device_ip: str) -> dict:
        """Block all traffic to/from device_ip via iptables DROP rules."""
        try:
            # Try WSL first (Windows), then direct Linux
            for cmd_prefix in [["wsl", "-e"], []]:
                drop_in = cmd_prefix + [
                    "iptables", "-C", "FORWARD", "-s", device_ip, "-j", "DROP",
                ]
                check = await self._run_cmd(drop_in)
                if check.get("code") == 0:
                    return {"status": "already_isolated", "message": f"{device_ip} already blocked"}

                # Add DROP rules (both directions)
                for direction in ["-s", "-d"]:
                    r = await self._run_cmd(
                        cmd_prefix + [
                            "iptables", "-I", "FORWARD", direction, device_ip, "-j", "DROP",
                        ]
                    )
                    if r.get("code") != 0:
                        # Try without FORWARD chain (may not exist)
                        r2 = await self._run_cmd(
                            cmd_prefix + [
                                "iptables", "-I", "OUTPUT", direction, device_ip, "-j", "DROP",
                            ]
                        )
                        if r2.get("code") != 0:
                            return {
                                "status": "error",
                                "message": f"iptables rule failed: {r.get('stderr', r2.get('stderr', 'unknown'))}",
                            }

                _iptables_rules[device_ip] = f"FORWARD DROP {device_ip}"
                return {"status": "isolated", "message": f"iptables DROP rules added for {device_ip}"}

        except FileNotFoundError:
            return {
                "status": "unavailable",
                "message": "iptables/wsl not available on this system",
            }

    async def _restore_iptables(self, device_ip: str) -> dict:
        """Remove iptables DROP rules for device_ip."""
        if device_ip not in _iptables_rules:
            return {"status": "not_isolated", "message": f"No rules found for {device_ip}"}

        try:
            for cmd_prefix in [["wsl", "-e"], []]:
                for direction in ["-s", "-d"]:
                    await self._run_cmd(
                        cmd_prefix + [
                            "iptables", "-D", "FORWARD", direction, device_ip, "-j", "DROP",
                        ]
                    )
                    await self._run_cmd(
                        cmd_prefix + [
                            "iptables", "-D", "OUTPUT", direction, device_ip, "-j", "DROP",
                        ]
                    )

            del _iptables_rules[device_ip]
            return {"status": "restored", "message": f"iptables rules removed for {device_ip}"}

        except FileNotFoundError:
            return {"status": "error", "message": "iptables/wsl not available"}

    # ── SSH switch implementation ───────────────────────────────────

    async def _isolate_ssh(self, switch_ip: str, port: str) -> dict:
        """Shutdown a switch port via SSH (netmiko)."""
        switch_type = os.getenv("SWITCH_TYPE", "huawei").lower()
        cmds = _SHUTDOWN_CMDS.get(switch_type, _SHUTDOWN_CMDS["huawei"])
        cmds = [c.replace("{port}", port) for c in cmds]

        return await self._ssh_exec(switch_ip, cmds, "shutdown")

    async def _restore_ssh(self, switch_ip: str, port: str) -> dict:
        """Re-enable a switch port via SSH (netmiko)."""
        switch_type = os.getenv("SWITCH_TYPE", "huawei").lower()
        cmds = _UNSHUTDOWN_CMDS.get(switch_type, _UNSHUTDOWN_CMDS["huawei"])
        cmds = [c.replace("{port}", port) for c in cmds]

        return await self._ssh_exec(switch_ip, cmds, "undo shutdown")

    async def _ssh_exec(self, switch_ip: str, commands: list[str],
                        operation: str) -> dict:
        """Execute commands on a switch via netmiko SSH."""
        try:
            from netmiko import ConnectHandler
        except ImportError:
            return {
                "status": "unavailable",
                "message": "netmiko not installed — install with: pip install netmiko",
            }

        switch_type = os.getenv("SWITCH_TYPE", "huawei").lower()
        device_type_map = {
            "huawei": "huawei",
            "cisco_ios": "cisco_ios",
            "hp_comware": "hp_comware",
        }
        device_type = device_type_map.get(switch_type, "huawei")

        try:
            conn = ConnectHandler(
                device_type=device_type,
                host=switch_ip,
                username=os.getenv("SWITCH_SSH_USER", "admin"),
                password=os.getenv("SWITCH_SSH_PASS", ""),
                timeout=10,
            )
            output = conn.send_config_set(commands)
            conn.disconnect()

            return {
                "status": "executed",
                "switch": switch_ip,
                "port": commands[1] if len(commands) > 1 else "",
                "operation": operation,
                "output": output[:500],
            }
        except Exception as e:
            return {
                "status": "error",
                "switch": switch_ip,
                "message": str(e),
            }

    # ── helpers ─────────────────────────────────────────────────────

    async def _run_cmd(self, cmd: list[str]) -> dict:
        """Run a subprocess command asynchronously."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            return {
                "code": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="replace").strip(),
                "stderr": stderr.decode("utf-8", errors="replace").strip(),
            }
        except (FileNotFoundError, asyncio.TimeoutError) as e:
            return {"code": -1, "stderr": str(e)}


_service: Optional["IsolationService"] = None


def get_isolation_service() -> IsolationService:
    global _service
    if _service is None:
        _service = IsolationService()
    return _service
