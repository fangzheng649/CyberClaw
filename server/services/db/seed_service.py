"""Seed service — 导入 topology.json 到数据库"""
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


async def seed_from_config():
    """将 config/topology.json 的设备导入数据库（仅在空库时执行）"""
    from server.services.nx_bridge import get_bridge

    bridge = get_bridge()

    # 检查数据库是否已有设备
    existing = await bridge.get_all_devices()
    if existing:
        logger.info(f"Database already has {len(existing)} devices, skipping seed")
        return

    config_path = Path("config/topology.json")
    if not config_path.exists():
        logger.warning("config/topology.json not found, skipping seed")
        return

    config = json.loads(config_path.read_text(encoding="utf-8"))
    devices = config.get("devices", [])

    for dev in devices:
        data = {
            "devMac": dev.get("mac", "").lower(),
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
            "devDiscoveryMethod": "config",
            "devPresentLastScan": 1,
            "devIsNew": 0,
            "devIsArchived": 0,
            "devFirmwareVersion": dev.get("firmware_version", ""),
            "devSerialNumber": dev.get("serial_number", ""),
        }
        if data["devMac"]:
            await bridge.upsert_device(dev["mac"], data, source="CONFIG")

    logger.info(f"Seeded {len(devices)} devices from topology.json")
