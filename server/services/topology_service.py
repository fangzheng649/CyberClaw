import json
import logging
from pathlib import Path

from ..models.schemas import DeviceResponse, LinkResponse, TopologyResponse

logger = logging.getLogger(__name__)

# ── Load topology from JSON config ──────────────────────────────
_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"
_config_cache: dict | None = None


def load_topology_config() -> dict:
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    try:
        with open(_CONFIG_PATH, encoding="utf-8") as f:
            _config_cache = json.load(f)
        logger.info(f"Loaded topology config: {len(_config_cache['devices'])} devices, {len(_config_cache['links'])} links")
    except FileNotFoundError:
        logger.error(f"Topology config not found: {_CONFIG_PATH}")
        _config_cache = {"network": {}, "devices": [], "links": []}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid topology config: {e}")
        _config_cache = {"network": {}, "devices": [], "links": []}
    return _config_cache


def _config_device_db() -> dict[str, dict]:
    """Build name→metadata lookup from config (replaces DEVICE_DB)."""
    config = load_topology_config()
    return {d["name"]: d for d in config["devices"]}


def _config_to_topology() -> TopologyResponse:
    """Convert JSON config to TopologyResponse (fallback mode)."""
    config = load_topology_config()
    devices = []
    for d in config["devices"]:
        devices.append(DeviceResponse(
            id=d["id"], name=d["name"], type=d["type"],
            ip=d["ip"], mac=d.get("mac", ""), status="secure",
            pos=d.get("pos"), vendor=d.get("vendor"), model=d.get("model"),
            firmware_version=d.get("firmware_version"),
            serial_number=d.get("serial_number"),
            discovery_method=d.get("discovery_method", "config"),
            protocols=d.get("protocols"),
        ))
    links = [LinkResponse(from_=l["from"], to=l["to"]) for l in config["links"]]
    return TopologyResponse(devices=devices, links=links)


# ── Docker live data ───────────────────────────────────────────
_docker_client = None
_docker_available: bool | None = None


def _get_docker_client():
    global _docker_client, _docker_available
    if _docker_available is not None:
        return _docker_client if _docker_available else None
    try:
        import docker
        _docker_client = docker.from_env()
        _docker_client.ping()
        _docker_available = True
        logger.info("Docker connected — live topology mode")
    except Exception as e:
        logger.info(f"Docker SDK not available ({e})")
        _docker_available = False
    return _docker_client if _docker_available else None


def _get_live_topology_subprocess() -> TopologyResponse | None:
    try:
        import subprocess, json as _json
        result = subprocess.run(
            ["wsl", "-d", "Ubuntu-20.04", "-e", "docker", "ps",
             "--format", "{{.Names}}|{{.Status}}|{{.Networks}}",
             "--filter", "network=iot-lab"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None

        ip_result = subprocess.run(
            ["wsl", "-d", "Ubuntu-20.04", "-e", "docker", "network", "inspect",
             "iot-lab", "-f", "{{json .Containers}}"],
            capture_output=True, text=True, timeout=10,
        )
        ip_map = {}
        if ip_result.returncode == 0 and ip_result.stdout.strip():
            try:
                containers_json = _json.loads(ip_result.stdout.strip())
                for cid, info in containers_json.items():
                    name = info.get("Name", "").lstrip("/")
                    ip_full = info.get("IPv4Address", "")
                    if name and ip_full:
                        ip_map[name] = ip_full.split("/")[0]
            except (_json.JSONDecodeError, Exception):
                pass

        devices = []
        links = []
        hub_id = "switch-core"

        devices.append(DeviceResponse(
            id=hub_id, name="Switch-Core", type="switch",
            ip="10.0.0.0", mac="00:1A:2B:3C:4D:10",
            status="secure", pos=[0, 0, 0],
            vendor="Docker", model="Bridge Network",
        ))

        device_db = _config_device_db()
        for line in result.stdout.strip().split("\n"):
            parts = line.strip().split("|")
            if len(parts) < 2:
                continue
            name = parts[0]
            status_str = parts[1].lower()

            meta = device_db.get(name, {})
            ip = ip_map.get(name, "N/A")
            dev_id = name.lower().replace("-", "_")

            devices.append(DeviceResponse(
                id=dev_id, name=name, type=meta.get("type", "unknown"),
                ip=ip, mac="",
                status="secure" if "up" in status_str else "vulnerable",
                pos=meta.get("pos"),
                vendor=meta.get("vendor"),
                model=meta.get("model"),
            ))
            links.append(LinkResponse(from_=hub_id, to=dev_id))

        if len(devices) <= 1:
            return None
        return TopologyResponse(devices=devices, links=links)
    except Exception as e:
        logger.debug(f"Subprocess Docker query failed: {e}")
        return None


def _status_to_security(container_status: str) -> str:
    if container_status == "running":
        return "secure"
    elif container_status == "exited":
        return "vulnerable"
    return "scanning"


def _get_live_topology() -> TopologyResponse | None:
    client = _get_docker_client()
    if not client:
        return None

    devices = []
    links = []
    hub_id = "switch-core"

    devices.append(DeviceResponse(
        id=hub_id, name="Switch-Core", type="switch",
        ip="10.0.0.0", mac="00:1A:2B:3C:4D:10",
        status="secure", pos=[0, 0, 0],
        vendor="Docker", model="Bridge Network",
    ))

    try:
        network = client.networks.get("iot-lab")
        containers = network.attrs.get("Containers", {})
    except Exception:
        containers = {}

    if not containers:
        for c in client.containers.list(all=True):
            nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
            if "iot-lab" in nets:
                containers[c.id[:12]] = {
                    "Name": f"/{c.name}",
                    "IPv4Address": nets["iot-lab"].get("IPAddress", ""),
                }

    device_db = _config_device_db()
    for cid, info in containers.items():
        name = info.get("Name", "").lstrip("/")
        ip_full = info.get("IPv4Address", "")
        ip = ip_full.split("/")[0] if "/" in ip_full else ip_full

        meta = device_db.get(name, {})

        try:
            container = client.containers.get(cid)
            status_str = container.status
        except Exception:
            status_str = "unknown"

        dev_id = name.lower().replace("-", "_")
        devices.append(DeviceResponse(
            id=dev_id, name=name, type=meta.get("type", "unknown"),
            ip=ip or "N/A", mac="",
            status=_status_to_security(status_str),
            pos=meta.get("pos"),
            vendor=meta.get("vendor"),
            model=meta.get("model"),
        ))
        links.append(LinkResponse(from_=hub_id, to=dev_id))

    if len(devices) <= 1:
        return None

    return TopologyResponse(devices=devices, links=links)


def _db_to_topology() -> TopologyResponse | None:
    """从数据库读取设备列表构建拓扑（优先路径）"""
    try:
        from ..services.nx_bridge import get_bridge
        bridge = get_bridge()
        # 同步调用 — topology_service 是同步模块
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return None  # 在 async 上下文中不能阻塞，跳过
        except RuntimeError:
            pass
        db_devices = bridge._sync_get_all_devices()
        if not db_devices:
            return None

        import json as _json
        devices = []
        links = []

        # First pass: build device list and MAC→dev_id lookup
        mac_to_id: dict[str, str] = {}
        for d in db_devices:
            if isinstance(d, dict):
                mac = d.get("devMac", "")
                name = d.get("devName", "") or mac
                dev_id = name.lower().replace("-", "_").replace(" ", "_") if name else mac.replace(":", "")
                status = d.get("devStatus", "secure")
                pos_raw = d.get("devPos", "")
                pos = None
                if pos_raw:
                    try:
                        pos = _json.loads(pos_raw) if isinstance(pos_raw, str) else pos_raw
                    except (_json.JSONDecodeError, TypeError):
                        pos = None

                devices.append(DeviceResponse(
                    id=dev_id,
                    name=name or d.get("devLastIP", ""),
                    type=d.get("devType", "unknown"),
                    ip=d.get("devLastIP", ""),
                    mac=mac,
                    status=status,
                    pos=pos,
                    vendor=d.get("devVendor", ""),
                    model=d.get("devModel", ""),
                    firmware_version=d.get("devFirmwareVersion", ""),
                    serial_number=d.get("devSerialNumber", ""),
                    discovery_method=d.get("devDiscoveryMethod", "scan"),
                    protocols=_json.loads(d.get("devProtocols", "[]")) if d.get("devProtocols") else None,
                ))
                if mac:
                    mac_to_id[mac.lower()] = dev_id

        # Second pass: build links from devParentMAC
        for d in db_devices:
            if isinstance(d, dict):
                parent_mac = (d.get("devParentMAC") or "").strip()
                if not parent_mac:
                    continue  # orphan node — no link
                parent_id = mac_to_id.get(parent_mac.lower())
                mac = d.get("devMac", "")
                name = d.get("devName", "") or mac
                dev_id = name.lower().replace("-", "_").replace(" ", "_") if name else mac.replace(":", "")
                if parent_id and parent_id != dev_id:
                    links.append(LinkResponse(from_=parent_id, to=dev_id))

        return TopologyResponse(devices=devices, links=links)
    except Exception as e:
        logger.debug(f"DB topology query failed: {e}")
        return None


def get_topology() -> TopologyResponse:
    # 1. 优先从数据库读取（持久化数据）
    db_topo = _db_to_topology()
    if db_topo:
        return db_topo
    # 2. 尝试 Docker SDK
    live = _get_live_topology()
    if live:
        return live
    # 3. 尝试 WSL subprocess
    live = _get_live_topology_subprocess()
    if live:
        return live
    # 4. 最终降级到 JSON 配置
    return _config_to_topology()


def get_device(device_id: str) -> DeviceResponse | None:
    topo = get_topology()
    return next((d for d in topo.devices if d.id == device_id), None)


def get_device_by_ip(ip: str) -> DeviceResponse | None:
    topo = get_topology()
    return next((d for d in topo.devices if d.ip == ip), None)


def get_device_id_by_ip(ip: str) -> str | None:
    dev = get_device_by_ip(ip)
    return dev.id if dev else None
