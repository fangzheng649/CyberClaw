import asyncio
import json
import logging
import uuid
from datetime import datetime

from .topology_service import get_device_by_ip, get_device_id_by_ip

logger = logging.getLogger(__name__)

_broadcast_fn = None


def set_broadcast(fn):
    global _broadcast_fn
    _broadcast_fn = fn


async def _broadcast(data: dict):
    if _broadcast_fn:
        await _broadcast_fn(data)


def _parse_json_result(result: dict) -> dict | None:
    raw = result.get("result")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
    return None


# ── Tool execution with WebSocket broadcast ────────────────────

async def run_tool_and_broadcast(
    server: str,
    tool: str,
    args: dict,
    target_device_id: str | None = None,
):
    task_id = f"task-{uuid.uuid4().hex[:8]}"
    tool_label = f"{server}/{tool}"

    await _broadcast({
        "type": "tool_started",
        "tool": tool_label,
        "task_id": task_id,
        "target_device": target_device_id,
        "message": f"Starting {tool_label}…",
        "timestamp": datetime.now().isoformat(),
    })

    try:
        from .mcp_tool_service import call_tool
        result = await call_tool(server, tool, **args)
        parsed = _parse_json_result(result)
        if not parsed:
            parsed = result

        await _dispatch_result(server, tool, parsed, target_device_id)

    except Exception as e:
        logger.error(f"Tool {tool_label} failed: {e}")
        await _broadcast({
            "type": "tool_error",
            "tool": tool_label,
            "task_id": task_id,
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
        })

    await _broadcast({
        "type": "tool_complete",
        "tool": tool_label,
        "task_id": task_id,
        "timestamp": datetime.now().isoformat(),
    })


# ── Result dispatch by tool type ───────────────────────────────

async def _dispatch_result(
    server: str, tool: str, data: dict, target_device_id: str | None,
):
    handler = _DISPATCH.get(f"{server}/{tool}")
    if handler:
        await handler(data, target_device_id)
    else:
        await _broadcast({
            "type": "tool_result",
            "tool": f"{server}/{tool}",
            "data": data,
            "timestamp": datetime.now().isoformat(),
        })


async def _handle_network_scan(data: dict, _target: str | None):
    hosts = data.get("hosts", [])
    devices = []
    for h in hosts:
        ip = h.get("ip", "")
        dev_id = get_device_id_by_ip(ip)
        if not dev_id:
            continue
        devices.append({
            "device_id": dev_id,
            "ip": ip,
            "ports": h.get("open_ports", []),
            "vendor": h.get("vendor", ""),
            "os": h.get("os", []),
        })

    await _broadcast({
        "type": "scan_result",
        "scan_type": "network_scan",
        "devices": devices,
        "total_hosts": data.get("hosts_found", len(hosts)),
        "timestamp": datetime.now().isoformat(),
    })

    if devices:
        for d in devices:
            vendor = d.get("vendor", "")
            if vendor:
                asyncio.create_task(run_tool_and_broadcast(
                    "cve-intel", "check_device_vulns",
                    {"vendor": vendor},
                    target_device_id=d["device_id"],
                ))
                break


async def _handle_iot_fingerprint(data: dict, _target: str | None):
    devices = []
    for d in data.get("devices", []):
        ip = d.get("ip", "")
        dev_id = get_device_id_by_ip(ip)
        if not dev_id:
            continue
        devices.append({
            "device_id": dev_id,
            "ip": ip,
            "vendor": d.get("vendor", ""),
            "device_type": d.get("type", ""),
            "model": d.get("model", ""),
            "confidence": d.get("confidence", 0),
            "open_ports": d.get("open_ports", []),
        })

    await _broadcast({
        "type": "scan_result",
        "scan_type": "iot_fingerprint",
        "devices": devices,
        "total_hosts": data.get("iot_devices_found", len(devices)),
        "timestamp": datetime.now().isoformat(),
    })


async def _handle_vuln_scan(data: dict, _target: str | None):
    for f in data.get("findings", []):
        ip = f.get("host", "")
        dev_id = get_device_id_by_ip(ip)
        await _broadcast({
            "type": "vuln_result",
            "device_id": dev_id,
            "ip": ip,
            "vulnerabilities": f.get("vulnerabilities", []),
            "timestamp": datetime.now().isoformat(),
        })


async def _handle_credential_check(data: dict, _target: str | None):
    devices = []
    for r in data.get("results", []):
        ip = r.get("ip", "")
        dev_id = get_device_id_by_ip(ip)
        if not dev_id:
            continue
        devices.append({
            "device_id": dev_id,
            "ip": ip,
            "vulnerable": r.get("vulnerable", False),
            "credentials_tried": r.get("credentials_tried", []),
        })

    await _broadcast({
        "type": "scan_result",
        "scan_type": "credential_check",
        "devices": devices,
        "vulnerable_count": data.get("vulnerable_devices", 0),
        "timestamp": datetime.now().isoformat(),
    })


async def _handle_check_device_vulns(data: dict, target_device_id: str | None):
    cves = []
    for c in data.get("cves", []):
        cves.append({
            "cve_id": c.get("cve_id", ""),
            "cvss": c.get("cvss_v3", 0),
            "severity": c.get("severity", ""),
            "description": c.get("description", ""),
        })

    await _broadcast({
        "type": "cve_result",
        "device_id": target_device_id,
        "vendor": data.get("vendor", ""),
        "total_cves": data.get("total_cves", len(cves)),
        "critical": data.get("critical", 0),
        "high": data.get("high", 0),
        "cves": cves,
        "timestamp": datetime.now().isoformat(),
    })


async def _handle_baseline(data: dict, _target: str | None):
    devices = []
    for d in data.get("devices", []):
        ip = d.get("ip", "")
        dev_id = get_device_id_by_ip(ip)
        if not dev_id:
            continue
        devices.append({
            "device_id": dev_id,
            "ip": ip,
            "device": d.get("device", ""),
            "score": d.get("score", 0),
            "pass": d.get("pass", 0),
            "fail": d.get("fail", 0),
            "critical_failures": d.get("critical_failures", 0),
            "failed_rules": d.get("failed_rules", []),
        })

    summary = data.get("summary", {})
    await _broadcast({
        "type": "baseline_result",
        "profile": data.get("profile", ""),
        "overall_score": data.get("overall_score", 0),
        "summary": summary,
        "devices": devices,
        "timestamp": datetime.now().isoformat(),
    })


async def _handle_isolate(data: dict, target_device_id: str | None):
    dev_id = target_device_id
    if not dev_id:
        ip = data.get("device", "")
        dev_id = get_device_id_by_ip(ip)

    import subprocess
    container_name = ""
    if dev_id:
        from .topology_service import get_device
        dev = get_device(dev_id)
        if dev:
            container_name = dev.name

    if container_name:
        try:
            subprocess.run(
                ["wsl", "-d", "Ubuntu-20.04", "-e", "docker", "stop", container_name],
                capture_output=True, text=True, timeout=15,
            )
            logger.info(f"Docker container {container_name} stopped")
        except Exception as e:
            logger.warning(f"Docker stop failed: {e}")

    await _broadcast({
        "type": "device_isolated",
        "target": dev_id,
        "severity": "info",
        "message": f"Device {dev_id} isolated",
        "details": data,
        "timestamp": datetime.now().isoformat(),
    })


async def _handle_restore(data: dict, target_device_id: str | None):
    dev_id = target_device_id
    if not dev_id:
        ip = data.get("device", "")
        dev_id = get_device_id_by_ip(ip)

    container_name = ""
    if dev_id:
        from .topology_service import get_device
        dev = get_device(dev_id)
        if dev:
            container_name = dev.name

    if container_name:
        import subprocess
        try:
            subprocess.run(
                ["wsl", "-d", "Ubuntu-20.04", "-e", "docker", "start", container_name],
                capture_output=True, text=True, timeout=15,
            )
            logger.info(f"Docker container {container_name} started")
        except Exception as e:
            logger.warning(f"Docker start failed: {e}")

    await _broadcast({
        "type": "device_restored",
        "target": dev_id,
        "message": f"Device {dev_id} restored",
        "timestamp": datetime.now().isoformat(),
    })


_DISPATCH = {
    "nmap-scan/network_scan": _handle_network_scan,
    "nmap-scan/host_discovery": _handle_network_scan,
    "nmap-scan/service_detection": _handle_network_scan,
    "nmap-scan/vuln_scan": _handle_vuln_scan,
    "nmap-scan/iot_fingerprint": _handle_iot_fingerprint,
    "nmap-scan/default_credential_check": _handle_credential_check,
    "cve-intel/check_device_vulns": _handle_check_device_vulns,
    "security-baseline/check_baseline": _handle_baseline,
    "auto-response/isolate_device": _handle_isolate,
    "auto-response/restore_device": _handle_restore,
}
