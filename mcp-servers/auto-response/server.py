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
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from server.services.isolation_service import get_isolation_service
        svc = get_isolation_service()
        result = await svc.isolate(device_ip)
    except Exception as e:
        logger.error(f"IsolationService error: {e}")
        result = {"status": "error", "message": str(e)}

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
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from server.services.isolation_service import get_isolation_service
        svc = get_isolation_service()
        result = await svc.restore(device_ip)
    except Exception as e:
        logger.error(f"IsolationService error: {e}")
        result = {"status": "error", "message": str(e)}

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
    action = _add_action("block_ip", ip_address, f"ACL block: {reason}")
    return json.dumps({
        "action_id": action["id"], "status": "blocked",
        "ip": ip_address, "acl_rule": entry["acl_rule"],
        "reason": reason, "note": f"ACL 规则已下发，阻止所有到 {ip_address} 的流量",
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
