import json
import logging
from pathlib import Path

from ..models.schemas import DeviceResponse, LinkResponse, TopologyResponse

logger = logging.getLogger(__name__)

# ── Load topology from JSON config ──────────────────────────────
_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"
_MOCK_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "mock_topology.json"
_config_cache: dict | None = None
_mock_mode: bool | None = None  # None=unknown, True=mock, False=real


def set_mock_mode(enabled: bool):
    """Switch between mock and real topology. Clears cache to force reload."""
    global _mock_mode, _config_cache
    if _mock_mode != enabled:
        _mock_mode = enabled
        _config_cache = None
        mode_str = "MOCK (demo)" if enabled else "REAL (live devices)"
        logger.info(f"Topology mode switched → {mode_str}")


def is_mock_mode() -> bool:
    """Check if system is currently in mock mode."""
    return _mock_mode is True


def load_topology_config() -> dict:
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    # Pick the right config file based on mode
    path = _MOCK_PATH if _mock_mode else _CONFIG_PATH
    label = "mock" if _mock_mode else "real"
    try:
        with open(path, encoding="utf-8") as f:
            _config_cache = json.load(f)
        logger.info(f"Loaded {label} topology: {len(_config_cache['devices'])} devices, {len(_config_cache['links'])} links")
    except FileNotFoundError:
        logger.error(f"Topology config not found: {path}")
        _config_cache = {"network": {}, "devices": [], "links": []}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid topology config: {e}")
        _config_cache = {"network": {}, "devices": [], "links": []}
    return _config_cache


def _load_mock_topology() -> TopologyResponse | None:
    """Load mock demo topology when no real devices are online."""
    try:
        with open(_MOCK_PATH, encoding="utf-8") as f:
            config = json.load(f)
        devices = []
        for d in config.get("devices", []):
            devices.append(DeviceResponse(
                id=d.get("id", ""),
                name=d.get("name", ""),
                type=d.get("type", "unknown"),
                ip=d.get("ip", ""),
                mac=d.get("mac", ""),
                status="secure",
                online=True,
                pos=d.get("pos"),
                vendor=d.get("vendor"),
                model=d.get("model"),
                discovery_method="mock",
                protocols=d.get("protocols"),
            ))
        links = []
        for l in config.get("links", []):
            links.append(LinkResponse(from_=l.get("from", ""), to=l.get("to", "")))
        logger.info(f"Loaded mock topology: {len(devices)} demo devices")
        return TopologyResponse(devices=devices, links=links)
    except FileNotFoundError:
        logger.debug("mock_topology.json not found — skipping mock fallback")
        return None
    except Exception as e:
        logger.debug(f"Mock topology load failed: {e}")
        return None
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
                    online=bool(d.get("devPresentLastScan", 1)),
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


async def async_get_topology() -> TopologyResponse:
    """Async-safe version of get_topology() for use in FastAPI endpoints.

    The sync get_topology() skips DB in async contexts (running event loop),
    causing all device statuses to show as 'secure'. This version uses
    await bridge.get_all_devices() to query DB without blocking the loop.

    Strategy: DB devices (authoritative status) + config links (topology structure).
    The DB may lack devParentMAC for most devices, so we merge config links
    to preserve the tree hierarchy while using DB's real-time device statuses.
    """
    # 1. DB — via async bridge (the primary path)
    try:
        from ..services.nx_bridge import get_bridge
        import json as _json, re
        bridge = get_bridge()
        db_devices_raw = await bridge.get_all_devices()
        if db_devices_raw:
            # Filter out phantom "New Device" entries where devMac is a config ID
            # (e.g. mac="switch-core") instead of a real MAC address.
            _MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', re.IGNORECASE)
            db_devices = [
                d for d in db_devices_raw
                if isinstance(d, dict) and _MAC_RE.match(d.get("devMac", ""))
            ]

            devices = []
            mac_to_id: dict[str, str] = {}
            db_ip_to_id: dict[str, str] = {}
            for d in db_devices:
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
                    online=bool(d.get("devPresentLastScan", 1)),
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
                ip = d.get("devLastIP", "")
                if ip:
                    db_ip_to_id[ip] = dev_id

            # Build links: merge config links + DB devParentMAC links
            seen_links: set[tuple[str, str]] = set()
            links = []

            # Map config IDs -> DB device IDs via IP matching
            # Config uses short IDs (e.g. "switch-core"), DB derives from devName
            config_devs = load_topology_config().get("devices", [])
            cfg_id_to_db_id: dict[str, str] = {}
            for cd in config_devs:
                cfg_id = cd.get("id", "")
                cfg_ip = cd.get("ip", "")
                if cfg_ip in db_ip_to_id:
                    cfg_id_to_db_id[cfg_id] = db_ip_to_id[cfg_ip]

            # Priority 1: config links (authoritative topology structure)
            config = load_topology_config()
            for l in config.get("links", []):
                from_cfg = l.get("from", "")
                to_cfg = l.get("to", "")
                from_id = cfg_id_to_db_id.get(from_cfg, from_cfg)
                to_id = cfg_id_to_db_id.get(to_cfg, to_cfg)
                if from_id and to_id:
                    key = (from_id, to_id)
                    if key not in seen_links:
                        seen_links.add(key)
                        links.append(LinkResponse(from_=from_id, to=to_id))

            # Priority 2: DB devParentMAC links (for dynamically discovered devices)
            for d in db_devices:
                if isinstance(d, dict):
                    parent_mac = (d.get("devParentMAC") or "").strip()
                    if not parent_mac:
                        continue
                    parent_id = mac_to_id.get(parent_mac.lower())
                    _mac = d.get("devMac", "")
                    _name = d.get("devName", "") or _mac
                    _dev_id = _name.lower().replace("-", "_").replace(" ", "_") if _name else _mac.replace(":", "")
                    if parent_id and parent_id != _dev_id:
                        key = (parent_id, _dev_id)
                        if key not in seen_links:
                            seen_links.add(key)
                            links.append(LinkResponse(from_=parent_id, to=_dev_id))

            # Check: if all REAL (non-mock) devices are offline, return mock demo topology instead
            any_online = any(d.get("devPresentLastScan", 0) for d in db_devices
                             if isinstance(d, dict) and d.get("devDiscoveryMethod") != "mock")
            if not any_online and len(db_devices) > 0:
                mock_topo = _load_mock_topology()
                if mock_topo:
                    return mock_topo

            return TopologyResponse(devices=devices, links=links)
    except Exception as e:
        logger.debug(f"async_get_topology DB path failed: {e}")

    # 2. Docker SDK (sync — fast local call or returns None)
    live = _get_live_topology()
    if live:
        return live

    # 3. WSL subprocess
    live = _get_live_topology_subprocess()
    if live:
        return live

    # 4. JSON config fallback
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


def get_mac_by_device_id(device_id: str) -> str | None:
    """通过 topology device_id 查找真实 MAC 地址"""
    dev = get_device(device_id)
    return dev.mac if dev and dev.mac else None
