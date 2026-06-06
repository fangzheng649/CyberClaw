import asyncio
import json
import uuid

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..services.topology_service import get_device, get_device_by_ip
from ..services.tool_broadcast_service import run_tool_and_broadcast
from ..services.isolation_service import get_isolation_service

router = APIRouter(prefix="/api/tools", tags=["tools"])


def _task_id() -> str:
    return f"task-{uuid.uuid4().hex[:8]}"


@router.post("/scan")
async def trigger_scan(body: dict):
    target = body.get("target", "10.0.0.0/24")
    scan_type = body.get("scan_type", "network")

    tool_map = {
        "network": ("nmap-scan", "network_scan", {"target": target}),
        "service": ("nmap-scan", "service_detection", {"target": target}),
        "vuln": ("nmap-scan", "vuln_scan", {"target": target}),
        "iot": ("nmap-scan", "iot_fingerprint", {"target": target}),
        "credential": ("nmap-scan", "default_credential_check", {"target": target}),
    }
    server, tool, args = tool_map.get(scan_type, tool_map["network"])

    dev_id = None
    if "/24" not in target:
        from ..services.topology_service import get_device_id_by_ip
        dev_id = get_device_id_by_ip(target)

    tid = _task_id()
    asyncio.create_task(run_tool_and_broadcast(server, tool, args, dev_id))
    return {"task_id": tid, "status": "started"}


@router.post("/cve-check")
async def trigger_cve_check(body: dict):
    vendor = body.get("vendor", "")
    model = body.get("model", "")
    device_id = body.get("device_id")

    args = {"vendor": vendor}
    if model:
        args["model"] = model

    tid = _task_id()
    asyncio.create_task(run_tool_and_broadcast(
        "cve-intel", "check_device_vulns", args, device_id,
    ))
    return {"task_id": tid, "status": "started"}


@router.post("/baseline")
async def trigger_baseline(body: dict):
    profile = body.get("profile", "iot-default")
    target = body.get("target", "")

    args = {"profile": profile}
    if target and target != "all":
        args["target"] = target

    tid = _task_id()
    asyncio.create_task(run_tool_and_broadcast(
        "security-baseline", "check_baseline", args, None,
    ))
    return {"task_id": tid, "status": "started"}


@router.post("/isolate")
async def trigger_isolate(body: dict):
    import logging
    logger = logging.getLogger(__name__)

    device_id = body.get("device_id", "")
    device_ip = body.get("device_ip", "")

    if not device_id and device_ip:
        from ..services.topology_service import get_device_id_by_ip
        device_id = get_device_id_by_ip(device_ip)

    if not device_id:
        return JSONResponse({"error": "device not found", "device_ip": device_ip}, status_code=404)

    dev = get_device(device_id)
    container = dev.name if dev else ""
    target_ip = device_ip or (dev.ip if dev else "")

    if not target_ip:
        return JSONResponse({"error": "cannot determine device IP"}, status_code=400)

    # Collect isolation result from either MCP or direct service
    isolation_result = {}

    # Try MCP tool first
    try:
        from ..services.mcp_tool_service import call_tool
        result = await call_tool(
            "auto-response", "isolate_device",
            device_ip=target_ip, reason="security_event",
        )
        isolation_result = result
    except Exception as e:
        logger.warning(f"MCP isolate failed: {e}")

    # Fallback to direct IsolationService if MCP didn't isolate
    status = isolation_result.get("status", "") if isinstance(isolation_result, dict) else ""
    if status not in ("isolated", "already_isolated", "recorded"):
        try:
            iso_svc = get_isolation_service()
            iso_result = await iso_svc.isolate(target_ip)
            isolation_result.update(iso_result)
        except Exception as e:
            logger.warning(f"Direct isolate failed: {e}")
            isolation_result.setdefault("status", "error")
            isolation_result.setdefault("detail", str(e))

    # ── Docker container stop (most reliable method in lab env) ───
    docker_stopped = False
    if container:
        import subprocess
        for wsl_flag in [["wsl", "-d", "Ubuntu-20.04", "-e"], []]:
            try:
                r = subprocess.run(
                    wsl_flag + ["docker", "stop", container],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0:
                    docker_stopped = True
                    isolation_result["docker"] = "stopped"
                    isolation_result.setdefault("status", "isolated")
                    logger.info(f"Docker container {container} stopped")
                    break
            except Exception as e:
                logger.debug(f"Docker stop via {'wsl' if wsl_flag else 'direct'} failed: {e}")
    if not docker_stopped and container:
        isolation_result.setdefault("status", isolation_result.get("status", "recorded"))
        isolation_result.setdefault("detail", "Docker stop failed, status recorded only")

    # Update device status and record security event via nx_bridge
    if dev and dev.mac:
        try:
            from ..services.nx_bridge import get_bridge
            bridge = get_bridge()
            await bridge.update_device_status(dev.mac, "isolated")
            await bridge.record_security_event(
                source_type="isolation",
                severity="high",
                message=f"Device {device_id} isolated",
                target=device_id,
                target_mac=dev.mac,
                fsm_state="isolated",
            )
        except Exception as e:
            logger.warning(f"DB update failed: {e}")

    # ── Broadcast device_isolated directly (do NOT re-call MCP) ──
    # Previously used run_tool_and_broadcast which called MCP again —
    # that second call would fail since device is already isolated,
    # and the error path never sends device_isolated, so HUD got no feedback.
    from datetime import datetime
    from ..services.tool_broadcast_service import _broadcast
    await _broadcast({
        "type": "device_isolated",
        "target": device_id,
        "source": "cyberagent",
        "severity": "high",
        "message": f"Device {device_id} ({target_ip}) isolated",
        "timestamp": datetime.now().isoformat(),
    })

    tid = _task_id()
    return {
        "task_id": tid,
        "status": "isolated",
        "device": device_id,
        "ip": target_ip,
        "container": container,
        "isolation": isolation_result,
    }


# ── Collector endpoints ──────────────────────────────────────────


@router.post("/collector/start")
async def start_collector(body: dict = None):
    from ..services.collector_service import get_receiver
    recv = get_receiver()
    port = (body or {}).get("port", 8514)
    recv.port = port
    await recv.start()
    return recv.get_stats()


@router.post("/collector/stop")
async def stop_collector():
    from ..services.collector_service import get_receiver
    recv = get_receiver()
    await recv.stop()
    return recv.get_stats()


@router.get("/collector/events")
async def get_collector_events(limit: int = 50, severity: str = ""):
    from ..services.collector_service import get_receiver
    recv = get_receiver()
    return {
        "stats": recv.get_stats(),
        "events": recv.get_events(limit=limit, severity=severity),
    }


@router.get("/collector/status")
async def get_collector_status():
    from ..services.collector_service import get_receiver
    return get_receiver().get_stats()


@router.post("/restore")
async def trigger_restore(body: dict):
    import logging
    logger = logging.getLogger(__name__)

    device_id = body.get("device_id", "")
    device_ip = body.get("device_ip", "")

    if not device_id and device_ip:
        from ..services.topology_service import get_device_id_by_ip
        device_id = get_device_id_by_ip(device_ip)

    if not device_id:
        return JSONResponse({"error": "device not found"}, status_code=404)

    dev = get_device(device_id)
    target_ip = device_ip or (dev.ip if dev else "")

    if not target_ip:
        return JSONResponse({"error": "cannot determine device IP"}, status_code=400)

    restore_result = {}

    # Try MCP tool first
    try:
        from ..services.mcp_tool_service import call_tool
        result = await call_tool(
            "auto-response", "restore_device",
            device_ip=target_ip,
        )
        restore_result = result
    except Exception as e:
        logger.warning(f"MCP restore failed: {e}")

    # Fallback to direct service
    status = restore_result.get("status", "") if isinstance(restore_result, dict) else ""
    if status not in ("restored", "not_isolated", "recorded"):
        try:
            iso_svc = get_isolation_service()
            iso_result = await iso_svc.restore(target_ip)
            restore_result.update(iso_result)
        except Exception as e:
            logger.warning(f"Direct restore failed: {e}")
            restore_result.setdefault("status", "error")
            restore_result.setdefault("detail", str(e))

    # ── Docker container start (restore in lab env) ───────────────
    container = dev.name if dev else ""
    docker_started = False
    if container:
        import subprocess
        for wsl_flag in [["wsl", "-d", "Ubuntu-20.04", "-e"], []]:
            try:
                r = subprocess.run(
                    wsl_flag + ["docker", "start", container],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0:
                    docker_started = True
                    restore_result["docker"] = "started"
                    restore_result.setdefault("status", "restored")
                    logger.info(f"Docker container {container} started")
                    break
            except Exception as e:
                logger.debug(f"Docker start via {'wsl' if wsl_flag else 'direct'} failed: {e}")

    # Update device status and record security event via nx_bridge
    if dev and dev.mac:
        try:
            from ..services.nx_bridge import get_bridge
            bridge = get_bridge()
            await bridge.update_device_status(dev.mac, "secure")
            await bridge.record_security_event(
                source_type="isolation",
                severity="info",
                message=f"Device {device_id} restored",
                target=device_id,
                target_mac=dev.mac,
                fsm_state="secure",
            )
        except Exception as e:
            logger.warning(f"DB update failed: {e}")
            pass

    # ── Broadcast threat_resolved directly ──
    from datetime import datetime
    from ..services.tool_broadcast_service import _broadcast
    await _broadcast({
        "type": "threat_resolved",
        "target": device_id,
        "source": "cyberagent",
        "severity": "info",
        "message": f"Device {device_id} ({target_ip}) restored to secure",
        "timestamp": datetime.now().isoformat(),
    })

    tid = _task_id()
    return {"task_id": tid, "status": "restored"}


# ── SNMP endpoints ───────────────────────────────────────────────


@router.post("/snmp/start")
async def start_snmp_trap(body: dict = None):
    from ..services.snmp_service import get_snmp_service
    svc = get_snmp_service()
    port = (body or {}).get("port", 1162)
    svc.trap_port = port
    return await svc.start_trap_receiver()


@router.post("/snmp/stop")
async def stop_snmp_trap():
    from ..services.snmp_service import get_snmp_service
    return await get_snmp_service().stop_trap_receiver()


@router.get("/snmp/traps")
async def get_snmp_traps(limit: int = 50):
    from ..services.snmp_service import get_snmp_service
    svc = get_snmp_service()
    return {"status": svc.get_status(), "traps": svc.get_traps(limit=limit)}


@router.post("/snmp/query")
async def snmp_query_device(body: dict):
    from ..services.snmp_service import get_snmp_service
    ip = body.get("ip", "")
    if not ip:
        return {"error": "ip is required"}
    community = body.get("community", "public")
    version = body.get("version", "2c")
    return await get_snmp_service().get_device_info(ip, community, version)


@router.get("/snmp/status")
async def get_snmp_status():
    from ..services.snmp_service import get_snmp_service
    return get_snmp_service().get_status()


@router.post("/snmp/discover-topology")
async def discover_topology(body: dict = {}):
    """Discover network topology via SNMP (ARP + bridge table walk)."""
    switch_ip = body.get("switch_ip", "")
    community = body.get("community", "public")
    version = body.get("version", "2c")
    port = body.get("port", 161)
    if not switch_ip:
        return {"status": "error", "message": "switch_ip required"}
    from ..services.snmp_service import get_snmp_service
    return await get_snmp_service().discover_topology(switch_ip, community, version, port)


# ── MQTT endpoints ───────────────────────────────────────────────


@router.post("/mqtt/connect")
async def mqtt_connect(body: dict):
    from ..services.mqtt_service import get_mqtt_service
    broker = body.get("broker", "")
    if not broker:
        return {"error": "broker is required"}
    port = body.get("port", 1883)
    username = body.get("username")
    password = body.get("password")
    result = await get_mqtt_service().connect(broker, port, username, password)
    if result.get("status") == "connected":
        topics = body.get("topics", ["#"])
        await get_mqtt_service().subscribe(topics)
        result["subscribed_topics"] = topics
    return result


@router.post("/mqtt/disconnect")
async def mqtt_disconnect():
    from ..services.mqtt_service import get_mqtt_service
    return await get_mqtt_service().disconnect()


@router.get("/mqtt/messages")
async def get_mqtt_messages(limit: int = 50, topic: str = ""):
    from ..services.mqtt_service import get_mqtt_service
    svc = get_mqtt_service()
    return {
        "status": svc.get_status(),
        "messages": svc.get_messages(limit=limit, topic=topic),
        "anomalies": svc.detect_anomalies(),
    }


@router.get("/mqtt/status")
async def get_mqtt_status():
    from ..services.mqtt_service import get_mqtt_service
    return get_mqtt_service().get_status()


# ── Scan Scheduler ───────────────────────────────────────────────


@router.post("/scan-schedule/start")
async def start_scan_schedule(body: dict = None):
    from ..services.scan_service import get_scan_service
    svc = get_scan_service()
    subnet = (body or {}).get("subnet", "192.168.1.0/24")
    interval = (body or {}).get("interval", 300)
    return await svc.start(subnet=subnet, interval=interval)


@router.post("/scan-schedule/stop")
async def stop_scan_schedule():
    from ..services.scan_service import get_scan_service
    return await get_scan_service().stop()


@router.get("/scan-schedule/status")
async def get_scan_schedule_status():
    from ..services.scan_service import get_scan_service
    return get_scan_service().get_status()


# ── Suricata IDS ────────────────────────────────────────────────

@router.post("/suricata/start")
async def start_suricata(body: dict = {}):
    from ..services.suricata_service import get_suricata_service
    svc = get_suricata_service()
    eve_path = body.get("eve_path", "")
    if eve_path:
        from pathlib import Path
        svc.eve_json_path = Path(eve_path)
    return await svc.start()


@router.post("/suricata/stop")
async def stop_suricata():
    from ..services.suricata_service import get_suricata_service
    return await get_suricata_service().stop()


@router.get("/suricata/alerts")
async def get_suricata_alerts(severity: str = "", limit: int = 100):
    from ..services.suricata_service import get_suricata_service
    svc = get_suricata_service()
    return {
        "alerts": svc.get_events(limit=limit, severity=severity),
        "stats": svc.get_stats(),
    }


@router.get("/suricata/stats")
async def get_suricata_stats():
    from ..services.suricata_service import get_suricata_service
    return get_suricata_service().get_stats()
