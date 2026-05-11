import asyncio
import json
import uuid

from fastapi import APIRouter

from ..services.topology_service import get_device, get_device_by_ip
from ..services.tool_broadcast_service import run_tool_and_broadcast

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
    device_id = body.get("device_id", "")
    device_ip = body.get("device_ip", "")

    if not device_id and device_ip:
        from ..services.topology_service import get_device_id_by_ip
        device_id = get_device_id_by_ip(device_ip)

    if not device_id:
        return {"error": "device not found"}, 404

    dev = get_device(device_id)
    container = dev.name if dev else ""

    tid = _task_id()
    asyncio.create_task(run_tool_and_broadcast(
        "auto-response", "isolate_device",
        {"device_ip": device_ip or (dev.ip if dev else ""), "reason": "security_event"},
        device_id,
    ))
    return {"task_id": tid, "status": "started", "container": container}


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
    device_id = body.get("device_id", "")
    device_ip = body.get("device_ip", "")

    if not device_id and device_ip:
        from ..services.topology_service import get_device_id_by_ip
        device_id = get_device_id_by_ip(device_ip)

    if not device_id:
        return {"error": "device not found"}, 404

    dev = get_device(device_id)

    tid = _task_id()
    asyncio.create_task(run_tool_and_broadcast(
        "auto-response", "restore_device",
        {"device_ip": device_ip or (dev.ip if dev else "")},
        device_id,
    ))
    return {"task_id": tid, "status": "started"}


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
