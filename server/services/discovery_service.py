"""Network device discovery service for CyberClaw.

Supports multiple discovery methods:
  - nmap ping sweep (requires nmap binary)
  - scapy ARP scan (requires scapy library)
  - Static config fallback

Reference: NetAlertX device_heuristics.py (multi-layer device identification)
Reference: lan-control registry.py (MAC prefix + hostname pattern matching)
"""
import asyncio
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path

from ..models.discovery_models import DiscoveredDevice, DiscoveryResult

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config"
_VENDOR_OUI_PATH = _CONFIG_PATH / "vendor_oui.json"
_TOPOLOGY_PATH = _CONFIG_PATH / "topology.json"

_vendor_cache: dict | None = None
_hostname_patterns: list[tuple[str, str]] = [
    (r"(?i)camera|cam|hikvi|dahua|reolink|axis", "camera"),
    (r"(?i)sensor|temp|pressure|siemens|honeywell", "sensor"),
    (r"(?i)plug|smartplug|tplink|hs1[10]", "plug"),
    (r"(?i)mqtt|mosquitto|broker", "server"),
    (r"(?i)router|gateway|openwrt|ap-", "gateway"),
    (r"(?i)switch|core|bridge", "switch"),
    (r"(?i)nmap|scanner|kali|scanner", "pc"),
]
_port_type_map: dict[int, str] = {
    554: "camera", 37777: "camera", 8000: "camera",
    502: "sensor", 4840: "sensor", 102: "sensor",
    9999: "plug",
    1883: "server", 8883: "server",
}

_last_result: DiscoveryResult | None = None
_result_cache_time: float = 0
_CACHE_TTL = 300  # 5 minutes


def _load_vendor_oui() -> dict:
    global _vendor_cache
    if _vendor_cache is not None:
        return _vendor_cache
    try:
        with open(_VENDOR_OUI_PATH, encoding="utf-8") as f:
            _vendor_cache = json.load(f)
        logger.info(f"Loaded vendor OUI: {len(_vendor_cache)} vendors")
    except Exception as e:
        logger.error(f"Failed to load vendor OUI: {e}")
        _vendor_cache = {}
    return _vendor_cache


def _normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


def identify_vendor(mac: str) -> str | None:
    """Look up vendor name from MAC OUI prefix."""
    if not mac:
        return None
    oui_db = _load_vendor_oui()
    mac_clean = _normalize_mac(mac)
    for vendor_key, info in oui_db.items():
        for prefix in info.get("prefixes", []):
            if mac_clean.startswith(_normalize_mac(prefix)):
                return info.get("name", vendor_key)
    return None


def identify_type(mac: str | None, hostname: str | None, ports: list[int]) -> str:
    """Multi-layer device type identification.

    Priority: MAC OUI → hostname regex → port signature → default
    """
    # Layer 1: MAC OUI vendor lookup
    if mac:
        oui_db = _load_vendor_oui()
        mac_clean = _normalize_mac(mac)
        for vendor_key, info in oui_db.items():
            for prefix in info.get("prefixes", []):
                if mac_clean.startswith(_normalize_mac(prefix)):
                    return info.get("type", "unknown")

    # Layer 2: Hostname pattern matching
    if hostname:
        for pattern, dtype in _hostname_patterns:
            if re.search(pattern, hostname):
                return dtype

    # Layer 3: Port-based identification
    for port in ports:
        if port in _port_type_map:
            return _port_type_map[port]

    return "unknown"


class DiscoveryService:
    def __init__(self):
        self._nmap_available: bool | None = None
        self._scapy_available: bool | None = None

    def _check_nmap(self) -> bool:
        if self._nmap_available is not None:
            return self._nmap_available
        import shutil
        self._nmap_available = shutil.which("nmap") is not None
        return self._nmap_available

    def _check_scapy(self) -> bool:
        if self._scapy_available is not None:
            return self._scapy_available
        try:
            import scapy  # noqa: F401
            self._scapy_available = True
        except ImportError:
            self._scapy_available = False
        return self._scapy_available

    async def scan_network(self, subnet: str = "10.0.0.0/24",
                           methods: list[str] | None = None) -> DiscoveryResult:
        """Run network discovery using specified methods."""
        if methods is None:
            methods = ["nmap", "arp"]

        start = time.time()
        all_devices: dict[str, DiscoveredDevice] = {}
        errors: list[str] = []

        for method in methods:
            try:
                if method == "nmap" and self._check_nmap():
                    found = await self.discover_via_nmap(subnet)
                elif method == "arp" and self._check_scapy():
                    found = await self.discover_via_arp(subnet)
                else:
                    errors.append(f"Method '{method}' unavailable (tool not installed)")
                    continue
                for dev in found:
                    key = dev.mac or dev.ip
                    if key not in all_devices:
                        all_devices[key] = dev
            except Exception as e:
                errors.append(f"{method}: {e}")
                logger.error(f"Discovery error ({method}): {e}")

        duration_ms = int((time.time() - start) * 1000)
        result = DiscoveryResult(
            scan_time=datetime.now().isoformat(),
            subnet=subnet, methods=methods,
            found=len(all_devices),
            devices=list(all_devices.values()),
            duration_ms=duration_ms,
            error="; ".join(errors) if errors else None,
        )

        global _last_result, _result_cache_time
        _last_result = result
        _result_cache_time = time.time()

        return result

    async def discover_via_nmap(self, subnet: str) -> list[DiscoveredDevice]:
        """Discover hosts using nmap ping sweep."""
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn -T4 --max-retries 1")

        devices = []
        for host in nm.all_hosts():
            h = nm[host]
            mac = ""
            vendor = None
            if "addresses" in h:
                mac = h["addresses"].get("mac", "")
            if "vendor" in h and mac:
                vendor = h["vendor"].get(mac, "")

            hostname = h.hostname() if h.hostname() else None
            if not vendor and mac:
                vendor = identify_vendor(mac)
            device_type = identify_type(mac, hostname, [])

            devices.append(DiscoveredDevice(
                ip=host, mac=mac or None, hostname=hostname,
                vendor=vendor, device_type=device_type,
                open_ports=[], discovery_method="nmap",
            ))

        return devices

    async def discover_via_arp(self, subnet: str) -> list[DiscoveredDevice]:
        """Discover hosts using scapy ARP scan."""
        from scapy.all import ARP, Ether, srp
        import ipaddress

        net = ipaddress.ip_network(subnet, strict=False)
        target = str(net)

        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                     timeout=5, verbose=0)

        devices = []
        for sent, received in ans:
            mac = received.hwsrc
            ip = received.psrc
            vendor = identify_vendor(mac)
            device_type = identify_type(mac, None, [])

            devices.append(DiscoveredDevice(
                ip=ip, mac=mac, hostname=None,
                vendor=vendor, device_type=device_type,
                open_ports=[], discovery_method="arp",
            ))

        return devices

    def get_last_result(self) -> DiscoveryResult | None:
        """Get cached discovery result (valid for CACHE_TTL seconds)."""
        global _result_cache_time
        if time.time() - _result_cache_time > _CACHE_TTL:
            return None
        return _last_result


# Singleton
_service: DiscoveryService | None = None


def get_discovery_service() -> DiscoveryService:
    global _service
    if _service is None:
        _service = DiscoveryService()
    return _service
