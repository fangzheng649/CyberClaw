"""REST API endpoints for network device discovery."""
import logging

from fastapi import APIRouter

from ..services.discovery_service import get_discovery_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.post("/scan")
async def trigger_scan(body: dict | None = None):
    """Trigger network device discovery.

    Body: { "subnet": "10.0.0.0/24", "methods": ["nmap", "arp"] }
    """
    body = body or {}
    subnet = body.get("subnet", "10.0.0.0/24")
    methods = body.get("methods", ["nmap", "arp"])

    svc = get_discovery_service()
    result = await svc.scan_network(subnet, methods)
    return result.model_dump()


@router.get("/status")
async def get_status():
    """Get last discovery result (cached for 5 minutes)."""
    svc = get_discovery_service()
    result = svc.get_last_result()
    if result:
        return result.model_dump()
    return {"status": "no_scan", "message": "No recent scan. POST /api/discovery/scan to start."}


@router.post("/register")
async def register_device(body: dict):
    """Manually register a device into topology config."""
    from ..services.topology_service import load_topology_config, _config_to_topology
    import json

    required = ["id", "name", "type", "ip"]
    for field in required:
        if field not in body:
            return {"error": f"Missing required field: {field}"}

    config = load_topology_config()
    for d in config["devices"]:
        if d["id"] == body["id"] or d["ip"] == body["ip"]:
            return {"error": f"Device with id={body['id']} or ip={body['ip']} already exists"}

    new_device = {
        "id": body["id"],
        "name": body["name"],
        "type": body["type"],
        "ip": body["ip"],
        "mac": body.get("mac", ""),
        "vendor": body.get("vendor"),
        "model": body.get("model"),
        "pos": body.get("pos"),
        "role": body.get("role", "target"),
        "switch_port": body.get("switch_port"),
        "expected_ports": body.get("expected_ports", []),
        "os_guess": body.get("os_guess"),
        "protocols": body.get("protocols", []),
        "discovery_method": "manual",
    }

    config["devices"].append(new_device)

    import pathlib
    config_path = pathlib.Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # Clear topology cache so next get_topology() reloads
    from ..services import topology_service
    topology_service._config_cache = None

    return {"status": "registered", "device": new_device}
