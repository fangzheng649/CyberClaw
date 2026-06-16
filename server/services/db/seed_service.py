"""Seed service — 导入 topology config 到数据库"""
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def seed_from_config(force: bool = False):
    """将 topology config 的设备导入数据库（默认仅在空库时执行）

    自动读取当前模式的配置：mock 模式读 mock_topology.json，real 模式读 topology.json。
    force=True 时跳过空库检查，upsert 配置设备（用于 mock→real 切换时补回真实拓扑，
    不删除既有 mock 数据）。
    """
    from server.services.nx_bridge import get_bridge
    from server.services.topology_service import is_mock_mode

    bridge = get_bridge()

    # 检查数据库是否已有设备
    existing = await bridge.get_all_devices()
    if existing and not force:
        logger.info(f"Database already has {len(existing)} devices, skipping seed")
        return

    # 根据当前模式选择配置文件
    mock_mode = is_mock_mode()
    config_dir = Path(__file__).resolve().parent.parent.parent.parent / "config"
    config_path = config_dir / ("mock_topology.json" if mock_mode else "topology.json")

    if not config_path.exists():
        logger.warning(f"{config_path.name} not found, skipping seed")
        return

    config = json.loads(config_path.read_text(encoding="utf-8"))
    devices = config.get("devices", [])

    seeded_devs = []
    for dev in devices:
        mac = dev.get("mac", "").lower()
        if not mac:
            continue
        data = {
            "devMac": mac,
            "devName": dev.get("name", ""),
            "devType": dev.get("type", "unknown"),
            "devVendor": dev.get("vendor", ""),
            "devModel": dev.get("model", ""),
            "devLastIP": dev.get("ip", ""),
            "devStatus": "secure",
            "devIcon": dev.get("type", ""),
            "devGroup": dev.get("role", ""),
            "devNotes": dev.get("notes", ""),
            "devPos": json.dumps(dev.get("pos", [])),
            "devOpenPorts": json.dumps(dev.get("expected_ports", [])),
            "devProtocols": json.dumps(dev.get("protocols", [])),
            "devOsGuess": dev.get("os_guess", ""),
            "devSwitchPort": dev.get("switch_port", ""),
            "devRole": dev.get("role", "target"),
            "devDiscoveryMethod": "mock" if mock_mode else "config",
            "devPresentLastScan": 0 if not mock_mode else 1,
            "devIsNew": 0,
            "devIsArchived": 0,
            "devFirmwareVersion": dev.get("firmware_version", ""),
            "devSerialNumber": dev.get("serial_number", ""),
        }
        await bridge.upsert_device(mac, data, source="CONFIG")
        seeded_devs.append({
            "mac": mac,
            "name": dev.get("name", ""),
            "ip": dev.get("ip", ""),
            "type": dev.get("type", "unknown"),
            "vendor": dev.get("vendor", ""),
            "model": dev.get("model", ""),
            "pos": dev.get("pos", []),
        })

    logger.info(f"Seeded {len(seeded_devs)}/{len(devices)} devices from {config_path.name}"
                f" ({'mock' if mock_mode else 'real'} mode)")
    return seeded_devs
