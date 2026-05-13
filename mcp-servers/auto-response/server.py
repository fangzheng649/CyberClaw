"""CyberClaw Auto Response MCP Server — automated threat response.

Tools:
  - isolate_device: Isolate a device by shutting down its switch port
  - restore_device: Restore a previously isolated device
  - block_ip: Add IP to ACL block list
  - unblock_ip: Remove IP from ACL block list
  - get_response_status: Get status of all active response actions
  - get_response_history: Get history of all response actions
"""
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("auto-response", "Automated threat response: port isolation, ACL management, IP blocking")

SWITCH_IP = os.getenv("SWITCH_IP", "10.0.0.1")
SWITCH_USER = os.getenv("SWITCH_SSH_USER", "admin")
SWITCH_PASS = os.getenv("SWITCH_SSH_PASS", "")

# In-memory state for active responses
_active_actions: list[dict] = []
_history: list[dict] = []

# Device-to-switch-port mapping — loaded from topology config
_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"
_device_ports_cache: dict | None = None


def _load_device_ports() -> dict:
    global _device_ports_cache
    if _device_ports_cache is not None:
        return _device_ports_cache
    try:
        with open(_TOPOLOGY_PATH, encoding="utf-8") as f:
            config = json.load(f)
        gateway_ip = next((d["ip"] for d in config["devices"] if d["type"] == "gateway"), SWITCH_IP)
        ports = {}
        for d in config["devices"]:
            sp = d.get("switch_port")
            if sp:
                ports[d["ip"]] = {
                    "switch": gateway_ip if sp != "local" else d["ip"],
                    "port": sp, "name": d["name"],
                }
        _device_ports_cache = ports
        logger.info(f"Loaded {len(ports)} device port mappings from topology config")
    except Exception as e:
        logger.error(f"Failed to load topology config: {e}")
        _device_ports_cache = {}
    return _device_ports_cache

_ACL_BLOCKED_IPS: list[dict] = []

_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "cyberclaw.db"


def _get_isolation_service():
    """Lazily import and return the IsolationService singleton."""
    try:
        project_root = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(project_root))
        from server.services.isolation_service import get_isolation_service
        return get_isolation_service()
    except Exception as e:
        logger.error(f"Failed to import isolation service: {e}")
        return None


def _update_device_status(device_ip: str, status: str) -> None:
    """Update device status in the database."""
    try:
        conn = sqlite3.connect(str(_DB_PATH))
        conn.execute('UPDATE Devices SET "devStatus" = ? WHERE "devLastIP" = ?', (status, device_ip))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB device status update failed: {e}")


def _record_security_event(source_type: str, severity: str, message: str,
                           source: str, target: str, fsm_state: str) -> None:
    """Insert a security event record into the database."""
    try:
        conn = sqlite3.connect(str(_DB_PATH))
        conn.execute(
            """INSERT INTO security_events (source_type, severity, message, source, target, fsm_state)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (source_type, severity, message, source, target, fsm_state),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB security event insert failed: {e}")


def _add_action(action_type: str, target: str, detail: str, status: str = "active") -> dict:
    action = {
        "id": f"act-{int(time.time())}-{len(_history)}",
        "type": action_type, "target": target, "detail": detail,
        "status": status, "timestamp": datetime.now().isoformat(),
    }
    _active_actions.append(action)
    _history.append(action)
    return action


def _resolve_device(device_ip: str) -> dict | None:
    info = _load_device_ports().get(device_ip)
    if info:
        return {"switch": info["switch"], "port": info["port"], "name": info["name"]}
    return None


@mcp.tool()
async def isolate_device(device_ip: str, reason: str = "security_event") -> str:
    """Isolate a device by shutting down its switch port.

    WARNING: This is a high-impact operation. Requires human confirmation before execution.

    Args:
        device_ip: IP address of the device to isolate.
        reason: Reason for isolation. Default: security_event.
    """
    logger.info(f"isolate_device: {device_ip} reason={reason}")

    # Check if already isolated
    for a in _active_actions:
        if a["target"] == device_ip and a["type"] == "isolate" and a["status"] == "active":
            return json.dumps({"status": "already_isolated", "device": device_ip, "action_id": a["id"]},
                              ensure_ascii=False)

    info = _resolve_device(device_ip)
    action = _add_action("isolate", device_ip,
                         f"Isolate {device_ip} ({info['name'] if info else 'unknown'})")

    # Call IsolationService for real execution
    try:
        svc = _get_isolation_service()
        if svc:
            result = await svc.isolate(device_ip)
        else:
            result = {"status": "error", "message": "IsolationService unavailable"}
    except Exception as e:
        logger.error(f"IsolationService error: {e}")
        result = {"status": "error", "message": str(e)}

    # Persist isolation state to database
    if result.get("status") in ("isolated", "already_isolated", "recorded"):
        _update_device_status(device_ip, "isolated")
        _record_security_event(
            source_type="auto-response",
            severity="warning",
            message=f"Device {device_ip} isolated: {reason}",
            source="auto-response",
            target=device_ip,
            fsm_state="isolated",
        )

    return json.dumps({
        "action_id": action["id"],
        "status": result.get("status", "unknown"),
        "device": device_ip,
        "device_name": info["name"] if info else "unknown",
        "method": result.get("method", "unknown"),
        "switch": info["switch"] if info else None,
        "port": info["port"] if info else None,
        "detail": result.get("message", ""),
        "reason": reason,
        "timestamp": action["timestamp"],
        "note": "设备已从网络中断开。使用 restore_device 恢复连接。",
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def restore_device(device_ip: str) -> str:
    """Restore a previously isolated device by re-enabling its switch port.

    Args:
        device_ip: IP address of the device to restore.
    """
    logger.info(f"restore_device: {device_ip}")

    restored = []
    for a in _active_actions:
        if a["target"] == device_ip and a["type"] == "isolate" and a["status"] == "active":
            a["status"] = "restored"
            restored.append(a["id"])

    if not restored:
        return json.dumps({"status": "not_isolated", "device": device_ip}, ensure_ascii=False)

    info = _resolve_device(device_ip)
    action = _add_action("restore", device_ip,
                         f"Restore {device_ip} ({info['name'] if info else 'unknown'})", status="completed")

    # Call IsolationService for real execution
    try:
        svc = _get_isolation_service()
        if svc:
            result = await svc.restore(device_ip)
        else:
            result = {"status": "error", "message": "IsolationService unavailable"}
    except Exception as e:
        logger.error(f"IsolationService error: {e}")
        result = {"status": "error", "message": str(e)}

    # Persist restored state to database
    if result.get("status") in ("restored", "recorded"):
        _update_device_status(device_ip, "secure")
        _record_security_event(
            source_type="auto-response",
            severity="info",
            message=f"Device {device_ip} restored to secure",
            source="auto-response",
            target=device_ip,
            fsm_state="secure",
        )

    return json.dumps({
        "action_id": action["id"],
        "status": result.get("status", "restored"),
        "device": device_ip,
        "device_name": info["name"] if info else "unknown",
        "method": result.get("method", "unknown"),
        "switch": info["switch"] if info else None,
        "port": info["port"] if info else None,
        "detail": result.get("message", ""),
        "restored_actions": restored,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def block_ip(ip_address: str, reason: str = "malicious_traffic") -> str:
    """Add an IP address to the ACL block list.

    Args:
        ip_address: IP address to block.
        reason: Reason for blocking. Default: malicious_traffic.
    """
    logger.info(f"block_ip: {ip_address}")
    for entry in _ACL_BLOCKED_IPS:
        if entry["ip"] == ip_address and entry["status"] == "active":
            return json.dumps({"status": "already_blocked", "ip": ip_address}, ensure_ascii=False)

    entry = {"ip": ip_address, "reason": reason, "status": "active",
             "timestamp": datetime.now().isoformat(), "acl_rule": f"deny ip any host {ip_address}"}
    _ACL_BLOCKED_IPS.append(entry)

    # Attempt real iptables rule if available
    iptables_ok = False
    if shutil.which("iptables"):
        try:
            proc = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            if proc.returncode == 0:
                iptables_ok = True
                logger.info(f"iptables DROP rule added for {ip_address}")
            else:
                logger.warning(f"iptables returned non-zero: {proc.stderr.decode(errors='replace')}")
        except Exception as e:
            logger.warning(f"iptables failed: {e}")
    # Also try via WSL on Windows
    elif shutil.which("wsl"):
        try:
            proc = subprocess.run(
                ["wsl", "-e", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            if proc.returncode == 0:
                iptables_ok = True
                logger.info(f"iptables (via WSL) DROP rule added for {ip_address}")
        except Exception as e:
            logger.warning(f"iptables via WSL failed: {e}")

    action = _add_action("block_ip", ip_address, f"ACL block: {reason}")
    return json.dumps({
        "action_id": action["id"], "status": "blocked",
        "ip": ip_address, "acl_rule": entry["acl_rule"],
        "reason": reason, "iptables_applied": iptables_ok,
        "note": f"ACL 规则已下发，阻止所有到 {ip_address} 的流量"
               + (" (iptables DROP applied)" if iptables_ok else " (in-memory only — iptables unavailable)"),
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def unblock_ip(ip_address: str) -> str:
    """Remove an IP address from the ACL block list.

    Args:
        ip_address: IP address to unblock.
    """
    for entry in _ACL_BLOCKED_IPS:
        if entry["ip"] == ip_address and entry["status"] == "active":
            entry["status"] = "removed"
            return json.dumps({"status": "unblocked", "ip": ip_address}, ensure_ascii=False)
    return json.dumps({"status": "not_blocked", "ip": ip_address}, ensure_ascii=False)


@mcp.tool()
async def get_response_status() -> str:
    """Get status of all active response actions."""
    active = [a for a in _active_actions if a["status"] == "active"]
    return json.dumps({
        "active_actions": len(active),
        "blocked_ips": len([e for e in _ACL_BLOCKED_IPS if e["status"] == "active"]),
        "actions": active,
        "blocked_ip_list": [{"ip": e["ip"], "reason": e["reason"]} for e in _ACL_BLOCKED_IPS if e["status"] == "active"],
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def get_response_history(limit: int = 20) -> str:
    """Get history of all response actions.

    Args:
        limit: Max results. Default: 20.
    """
    return json.dumps({
        "total_actions": len(_history),
        "history": _history[-limit:],
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw auto-response MCP")
    mcp.run()
