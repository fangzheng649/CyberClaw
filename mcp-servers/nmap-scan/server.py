"""CyberClaw Nmap Scan MCP Server — network scanning and IoT device fingerprinting.

Provides 6 tools:
  - network_scan: Full port scan with service detection
  - host_discovery: Ping sweep to find live hosts
  - service_detection: Service/version fingerprinting
  - vuln_scan: NSE vulnerability scanning
  - iot_fingerprint: IoT device identification via MAC OUI + port heuristics
  - default_credential_check: Detect devices using default credentials

Supports two modes:
  - nmap mode: Requires nmap binary installed (real scanning)
  - mock mode: Returns simulated results based on topology data (for development)
"""
import asyncio
import ipaddress
import json
import logging
import random
import re
import shutil
import sys
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("nmap-scan", "Network scanning, service detection, vulnerability scanning, IoT fingerprinting, and default credential checking")


# ═══════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class ServiceInfo(BaseModel):
    name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[list[str]] = None


class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: PortState = PortState.OPEN
    service: Optional[ServiceInfo] = None


class OSMatch(BaseModel):
    name: str
    accuracy: int = 0


class HostResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    state: str = "up"
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    ports: list[PortResult] = Field(default_factory=list)
    os_matches: list[OSMatch] = Field(default_factory=list)


class ScanResult(BaseModel):
    command: str = ""
    hosts: list[HostResult] = Field(default_factory=list)
    scan_stats: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class VulnFinding(BaseModel):
    host: str
    port: Optional[int] = None
    script_id: str = ""
    title: Optional[str] = None
    state: Optional[str] = None
    output: str = ""


# ═══════════════════════════════════════════════════════════════════
# Safety Constants
# ═══════════════════════════════════════════════════════════════════

MAX_TARGETS = 256
FORBIDDEN_CHARS = frozenset(";&|`$(){}<>\n\r")
SCAN_TYPES = {
    "connect": "-sT", "syn": "-sS", "udp": "-sU",
    "fin": "-sF", "xmas": "-sX", "null": "-sN",
}
TIMING = {
    "paranoid": "-T0", "sneaky": "-T1", "polite": "-T2",
    "normal": "-T3", "aggressive": "-T4", "insane": "-T5",
}

# IoT vendor fingerprint database (MAC OUI prefixes + characteristic ports)
IOT_SIGNATURES = {
    "Hikvision": {"mac_prefix": ["44:19:b6", "c0:56:e3", "e0:50:8b", "aa:bb:cc"], "ports": [80, 443, 554, 8000], "type": "camera"},
    "Dahua": {"mac_prefix": ["3c:ef:8c", "4c:11:bf", "a0:bd:1d"], "ports": [80, 443, 554, 37777], "type": "camera"},
    "Siemens": {"mac_prefix": ["00:1c:06", "00:1e:c1", "dd:ee:ff"], "ports": [443, 4840, 102], "type": "sensor"},
    "Honeywell": {"mac_prefix": ["00:0b:46", "00:16:ce"], "ports": [80, 443, 502], "type": "sensor"},
    "TP-Link": {"mac_prefix": ["50:c7:bf", "60:32:b1", "11:22:33"], "ports": [80, 443, 9999], "type": "plug"},
    "Cisco": {"mac_prefix": ["00:1a:2b", "00:26:0b", "00:23:04"], "ports": [22, 23, 80, 161], "type": "network"},
}

PORT_SERVICE_MAP = {
    22: "ssh", 23: "telnet", 80: "http", 443: "https", 554: "rtsp",
    161: "snmp", 502: "modbus", 4840: "opc-ua", 102: "s7comm",
    37777: "dahua", 8000: "http-alt", 9999: "http-alt",
    8080: "http-proxy", 1883: "mqtt", 8443: "https-alt",
    3306: "mysql", 445: "microsoft-ds", 135: "msrpc", 3389: "ms-wbt-server",
}

# ═══════════════════════════════════════════════════════════════════
# Device Database — loaded from topology config (mock-aware)
# ═══════════════════════════════════════════════════════════════════

_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"
_mock_devices_cache: list | None = None
_mock_devices_cache_mode: bool | None = None


def _is_mock_mode() -> bool:
    """Check if system is in mock mode (safe fallback if server not loaded)."""
    try:
        from server.services.topology_service import is_mock_mode
        return is_mock_mode()
    except Exception:
        return False


def _load_mock_devices() -> list:
    """Load device definitions from topology config — picks mock or real based on mode."""
    global _mock_devices_cache, _mock_devices_cache_mode
    current_mode = _is_mock_mode()
    if _mock_devices_cache is not None and _mock_devices_cache_mode == current_mode:
        return _mock_devices_cache
    config_name = "mock_topology.json" if current_mode else "topology.json"
    config_path = _CONFIG_DIR / config_name
    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        _mock_devices_cache = [
            {
                "ip": d["ip"], "mac": d.get("mac", ""), "vendor": d.get("vendor", ""),
                "type": d["type"], "model": d.get("model", ""),
                "ports": d.get("expected_ports", []), "os": d.get("os_guess", "Unknown"),
            }
            for d in config["devices"]
        ]
        _mock_devices_cache_mode = current_mode
        logger.info(f"Loaded {len(_mock_devices_cache)} devices from {config_name} (mock={current_mode})")
    except Exception as e:
        logger.error(f"Failed to load {config_name}: {e}")
        _mock_devices_cache = []
    return _mock_devices_cache


# ═══════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════

def _has_nmap() -> bool:
    return shutil.which("nmap") is not None


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target or any(c in target for c in FORBIDDEN_CHARS):
        raise ValueError(f"Invalid target: {target}")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > MAX_TARGETS:
            raise ValueError(f"Network too large (max /24): {target}")
        return target
    except ValueError:
        pass
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', target):
        return target
    raise ValueError(f"Invalid target: {target}")


def _validate_ports(ports: str) -> str:
    ports = ports.strip()
    if not ports or not re.match(r'^[TU:,\-0-9\s]+$', ports):
        raise ValueError(f"Invalid port spec: {ports}")
    return ports


# ═══════════════════════════════════════════════════════════════════
# Real nmap Execution
# ═══════════════════════════════════════════════════════════════════

async def _run_nmap(args: list[str], timeout: int = 300) -> tuple[str, str, int]:
    nmap = shutil.which("nmap")
    if not nmap:
        raise FileNotFoundError("nmap binary not found")
    cmd = [nmap] + args
    logger.info(f"Running: {' '.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"nmap timed out after {timeout}s")
    return out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace"), proc.returncode or 0


def _parse_xml(xml_str: str) -> ScanResult:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return ScanResult(warnings=["XML parse failed"])
    hosts = []
    for h in root.findall("host"):
        status_el = h.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"
        ip, mac, vendor = "", None, None
        for addr in h.findall("address"):
            atype = addr.get("addrtype", "")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            if atype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        if not ip:
            continue
        hostname = None
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        ports = []
        for p in h.findall("ports/port"):
            pid = p.get("portid")
            if not pid:
                continue
            ps = p.find("state")
            pstate_str = ps.get("state", "unknown") if ps is not None else "unknown"
            try:
                pstate = PortState(pstate_str)
            except ValueError:
                pstate = PortState.FILTERED
            svc = None
            se = p.find("service")
            if se is not None:
                svc = ServiceInfo(
                    name=se.get("name", "unknown"),
                    product=se.get("product"),
                    version=se.get("version"),
                    cpe=[c.text for c in p.findall(".//cpe") if c.text] or None,
                )
            ports.append(PortResult(port=int(pid), protocol=p.get("protocol", "tcp"), state=pstate, service=svc))
        os_matches = []
        for om in h.findall("os/osmatch"):
            os_matches.append(OSMatch(name=om.get("name", ""), accuracy=int(om.get("accuracy", 0))))
        hosts.append(HostResult(ip=ip, hostname=hostname, mac=mac, state=state, vendor=vendor, ports=ports, os_matches=os_matches))
    stats = {}
    fin = root.find("runstats/finished")
    if fin is not None:
        stats["elapsed"] = fin.get("elapsed", "")
    return ScanResult(command=root.get("args", ""), hosts=hosts, scan_stats=stats)


def _parse_vuln_xml(xml_str: str) -> list[VulnFinding]:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return []
    vulns = []
    for h in root.findall("host"):
        ip = ""
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
        for p in h.findall("ports/port"):
            pid = int(p.get("portid", "0"))
            for s in p.findall("script"):
                vulns.append(VulnFinding(host=ip, port=pid, script_id=s.get("id", ""), output=s.get("output", "")))
        for s in h.findall("hostscript/script"):
            vulns.append(VulnFinding(host=ip, script_id=s.get("id", ""), output=s.get("output", "")))
    return vulns


# ═══════════════════════════════════════════════════════════════════
# Mock Scan Results
# ═══════════════════════════════════════════════════════════════════

def _mock_scan(target: str = "10.0.0.0/24", port_filter: str | None = None) -> ScanResult:
    hosts = []
    for d in _load_mock_devices():
        h_ports = []
        for p in d["ports"]:
            if port_filter and str(p) not in port_filter.split(","):
                continue
            h_ports.append(PortResult(
                port=p, state=PortState.OPEN,
                service=ServiceInfo(name=PORT_SERVICE_MAP.get(p, "unknown")),
            ))
        os_list = [OSMatch(name=d["os"], accuracy=random.randint(90, 99))] if d.get("os") else []
        hosts.append(HostResult(
            ip=d["ip"], mac=d["mac"], state="up", vendor=d.get("vendor"),
            device_type=d.get("type"), ports=h_ports, os_matches=os_list,
        ))
    return ScanResult(command=f"[mock] nmap -sT {target}", hosts=hosts, scan_stats={"elapsed": "2.5", "mode": "mock"})


def _mock_vulns() -> list[VulnFinding]:
    vulns = []
    for d in _load_mock_devices():
        if 23 in d["ports"]:
            vulns.append(VulnFinding(host=d["ip"], port=23, script_id="telnet-brute",
                                     title="Telnet default credentials", state="VULNERABLE",
                                     output=f"Telnet on {d['ip']}:23 accepts default credentials"))
        if d.get("vendor") == "Hikvision":
            vulns.append(VulnFinding(host=d["ip"], port=80, script_id="http-vuln-cve2021-36260",
                                     title="CVE-2021-36260: Hikvision RCE", state="VULNERABLE",
                                     output="Hikvision camera vulnerable to remote code execution (CVSS 9.8)"))
    return vulns


# ═══════════════════════════════════════════════════════════════════
# IoT Fingerprinting
# ═══════════════════════════════════════════════════════════════════

def _fingerprint_iot(scan: ScanResult) -> list[dict]:
    devices = []
    for host in scan.hosts:
        if not host.mac:
            continue
        mac_prefix = host.mac.lower()[:8]
        open_ports = [p.port for p in host.ports if p.state == PortState.OPEN]
        matched_vendor = host.vendor
        # DB devType (from scan_service) is authoritative — use it first so a
        # 554-opening NVR isn't misclassed as a camera by the port heuristic.
        matched_type = host.device_type or None
        confidence = 95 if host.device_type else 60

        for vendor, sig in IOT_SIGNATURES.items():
            if any(mac_prefix.startswith(pfx.lower()) for pfx in sig["mac_prefix"]):
                matched_vendor = vendor
                matched_type = sig["type"]
                confidence = 90
                break

        if not matched_type and open_ports:
            if 554 in open_ports:
                matched_type, confidence = "camera", 75
            elif any(p in open_ports for p in (502, 102, 4840)):
                matched_type, confidence = "plc", 70
            elif 1883 in open_ports:
                matched_type, confidence = "gateway", 70

        if matched_type:
            # Look up model from mock data
            model = None
            for d in _load_mock_devices():
                if d["ip"] == host.ip:
                    model = d.get("model")
                    break
            devices.append({
                "ip": host.ip, "mac": host.mac, "vendor": matched_vendor,
                "type": matched_type, "model": model,
                "confidence": confidence, "open_ports": open_ports,
            })
    return devices


def _check_credentials(scan: ScanResult) -> list[dict]:
    results = []
    for host in scan.hosts:
        for port in host.ports:
            if port.state != PortState.OPEN:
                continue
            if port.port == 23:
                results.append({
                    "host": host.ip, "port": 23, "service": "telnet",
                    "vulnerable": True, "username": "admin",
                    "detail": f"Telnet on {host.ip}:23 — default credential likely (admin:admin)",
                })
            elif port.port == 22:
                results.append({
                    "host": host.ip, "port": 22, "service": "ssh",
                    "vulnerable": False,
                    "detail": "SSH — key-based auth recommended",
                })
    return results


# ═══════════════════════════════════════════════════════════════════
# Scan Execution (dispatches to real or mock)
# ═══════════════════════════════════════════════════════════════════

async def _is_subnet_reachable(target: str) -> bool:
    """Check if the subnet has REAL IoT devices (not just a stray port).

    Strategy: if nmap is installed, trust it to scan the network directly.
    Only use socket probing as a fallback when nmap is unavailable.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.prefixlen == 32:
            return True  # Single host, skip check

        # If nmap is installed, trust it — run the scan directly
        if _has_nmap():
            return True

        import socket as _socket

        def _probe(ip_port):
            ip, port = ip_port
            try:
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                sock.close()
                return (ip, port, result == 0)
            except (_socket.error, OSError):
                return (ip, port, False)

        devices = _load_mock_devices()
        test_ips = [d["ip"] for d in devices[:5]]
        check_ports = [80, 443, 554, 8080, 22, 161]
        # Build all (ip, port) combos and probe concurrently
        targets = [(ip, p) for ip in test_ips for p in check_ports]
        loop = asyncio.get_event_loop()
        results = await asyncio.gather(
            *[loop.run_in_executor(None, _probe, t) for t in targets]
        )
        hits = sum(1 for _, _, ok in results if ok)
        responding_ips = {ip for ip, _, ok in results if ok}

        if hits >= 3 and len(responding_ips) >= 2:
            return True
        if hits == 0:
            logger.warning(f"Subnet {target} has no live devices, falling back to mock mode")
        else:
            logger.warning(
                f"Subnet {target} has only {hits} port(s) on {len(responding_ips)} IP(s) "
                f"— likely not a real IoT network, falling back to mock"
            )
        return False
    except Exception:
        return False  # On error, use mock


# ═══════════════════════════════════════════════════════════════════
# DB-backed real scanning (preferred over blind nmap in real mode)
# ═══════════════════════════════════════════════════════════════════
# In real mode, scan_service already discovers live devices via ARP and
# fingerprints their ports — storing them in the DB (devOpenPorts). Reading
# that is instant, always matches the HUD, and never times out. Blind nmap
# of an entire /24 (254 hosts × 1000 ports) blows past call_tool's 120s
# timeout, which is why network_scan/iot_fingerprint reported "执行失败".

_REAL_MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', re.IGNORECASE)


def _parse_port_list(raw) -> list[int]:
    """Coerce a DB devOpenPorts value (JSON string or list) into list[int]."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    if not isinstance(raw, (list, tuple)):
        return []
    ports = []
    for p in raw:
        try:
            ports.append(int(p))
        except (TypeError, ValueError):
            continue
    return ports


def _filter_db_devices(devices: list, target: str) -> list[dict]:
    """Filter raw DB device rows to in-subnet, online, real-MAC devices.

    Returns a normalized list: [{ip, mac, vendor, type, model, ports:[int]}].
    Mock/offline devices and config-id placeholder MACs are excluded so the
    scan reflects only real, currently-online devices.
    """
    net = None
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        pass  # unparseable target (e.g. hostname) → don't filter by subnet

    out = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        mac = (d.get("devMac") or "").strip()
        if not _REAL_MAC_RE.match(mac):
            continue  # skip placeholder/empty/mock MACs
        if not bool(d.get("devPresentLastScan", 0)):
            continue  # offline
        ip = (d.get("devLastIP") or "").strip()
        if not ip:
            continue
        if net is not None:
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
        out.append({
            "ip": ip, "mac": mac,
            "vendor": d.get("devVendor", ""),
            "type": d.get("devType", ""),
            "model": d.get("devModel", ""),
            "ports": _parse_port_list(d.get("devOpenPorts")),
        })
    return out


def _db_devices_to_scan_result(devices: list[dict], target: str, command_tag: str) -> ScanResult:
    """Convert normalized DB devices (from _filter_db_devices) into a ScanResult."""
    hosts = []
    for d in devices:
        ports = []
        for p in d.get("ports") or []:
            try:
                pid = int(p)
            except (TypeError, ValueError):
                continue
            ports.append(PortResult(
                port=pid, state=PortState.OPEN,
                service=ServiceInfo(name=PORT_SERVICE_MAP.get(pid, "unknown")),
            ))
        hosts.append(HostResult(
            ip=d["ip"], mac=d.get("mac"), state="up",
            vendor=d.get("vendor"), device_type=d.get("type"), ports=ports,
        ))
    return ScanResult(
        command=f"[real-db] {command_tag} {target}",
        hosts=hosts,
        scan_stats={"hosts_up": str(len(hosts)), "mode": "real-db", "source": "scan_service"},
    )


def _known_device_ips(target: str) -> list[str]:
    """Resolve a subnet target to known device IPs from the topology config
    (real-mode topology.json). Used by the nmap fallback to scan only known
    live hosts instead of an entire /24."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return []
    ips = []
    for d in _load_mock_devices():  # real mode → topology.json devices
        ip = (d.get("ip") or "").strip()
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in net:
                ips.append(ip)
        except ValueError:
            continue
    return ips


async def _load_real_devices_from_db(target: str) -> list[dict] | None:
    """Read scan_service's discovered live devices (with ports) from the DB.

    Returns the filtered normalized list (may be empty if no devices online),
    or None when the DB is unavailable (so the caller can fall back to nmap).
    """
    try:
        from server.services.nx_bridge import get_bridge
        devices = await get_bridge().get_all_devices()
    except Exception as e:
        logger.warning(f"DB load failed, will fall back to nmap/mock: {e}")
        return None
    if not devices:
        return None
    return _filter_db_devices(devices, target)


async def _targeted_nmap_scan(target: str, ports: str | None, scan_type: str,
                              timing: str, timeout: int) -> ScanResult:
    """Fallback when the DB has no devices: run a fast targeted nmap on the
    known device IPs only (-Pn skips host discovery so ICMP-only cameras are
    still port-scanned), with a limited IoT port set and per-host timeout."""
    ips = _known_device_ips(target)
    if not ips:
        logger.warning(f"No known device IPs in {target} for targeted scan — using mock")
        return _mock_scan(target, ports)
    effective_ports = ports or "80,443,554,8000,8080,22,23,1883,502,8443"
    _validate_ports(effective_ports)
    args = ["-oX", "-Pn", SCAN_TYPES.get(scan_type, "-sT"),
            TIMING.get(timing, "-T4"), "--host-timeout=30s", "-p", effective_ports]
    args.extend(ips)
    # Cap below call_tool's 120s so a slow scan fails fast instead of hanging.
    stdout, stderr, rc = await _run_nmap(args, timeout=min(timeout, 90))
    result = _parse_xml(stdout)
    if stderr:
        result.warnings.append(stderr.strip())
    return result


async def _exec_scan(target: str, ports: str | None, scan_type: str, timing: str, timeout: int) -> ScanResult:
    _validate_target(target)
    if _is_mock_mode():
        return _mock_scan(target, ports)
    # Real mode: prefer scan_service's DB (live devices + ports) — instant,
    # never times out, and matches the HUD. Falls back to targeted nmap only
    # when the DB is unavailable; mock is the last resort.
    db_devices = await _load_real_devices_from_db(target)
    if db_devices is not None:
        result = _db_devices_to_scan_result(db_devices, target, "nmap -sT")
        if ports:
            allowed = {p.strip() for p in ports.split(",")}
            for h in result.hosts:
                h.ports = [p for p in h.ports if str(p.port) in allowed]
        return result
    if _has_nmap():
        return await _targeted_nmap_scan(target, ports, scan_type, timing, timeout)
    return _mock_scan(target, ports)


async def _exec_discover(target: str, timing: str, timeout: int) -> ScanResult:
    _validate_target(target)
    if _is_mock_mode():
        devices = _load_mock_devices()
        hosts = [HostResult(ip=d["ip"], mac=d["mac"], state="up", vendor=d.get("vendor")) for d in devices]
        return ScanResult(command=f"[mock] nmap -sn {target}", hosts=hosts, scan_stats={"hosts_up": str(len(devices)), "mode": "mock"})
    # Real mode: ARP 快速发现(即时报设备数) + 后台 trigger_scan 入库广播(与 S 键一致)。
    # _arp_table_scan 即时返回在线设备(消息报告发现 N 台)；trigger_scan_background 后台走
    # 完整流程(端口指纹 + 写 Devices + 广播 device_discovered)，保证入库又不阻塞本任务。
    try:
        from server.services.scan_service import _arp_table_scan, get_scan_service
        loop = asyncio.get_event_loop()
        found = await loop.run_in_executor(None, _arp_table_scan, target)
        get_scan_service().trigger_scan_background()
        hosts = [HostResult(ip=d["ip"], mac=d.get("mac"), state="up", vendor=d.get("vendor")) for d in found]
        return ScanResult(command=f"[real-scan] nmap -sn {target}", hosts=hosts,
                          scan_stats={"hosts_up": str(len(hosts)), "mode": "real-scan", "source": "arp+scan_service"})
    except Exception as e:
        logger.warning(f"network scan failed, fallback to nmap/mock: {e}")
    if _has_nmap():
        ips = _known_device_ips(target)
        if ips:
            args = ["-oX", "-sn", "-T4", "--host-timeout=10s"]
            args.extend(ips)
            stdout, stderr, rc = await _run_nmap(args, timeout=min(timeout, 60))
            return _parse_xml(stdout)
    devices = _load_mock_devices()
    hosts = [HostResult(ip=d["ip"], mac=d["mac"], state="up", vendor=d.get("vendor")) for d in devices]
    return ScanResult(command=f"[mock] nmap -sn {target}", hosts=hosts, scan_stats={"hosts_up": str(len(devices)), "mode": "mock"})


async def _exec_service_detect(target: str, ports: str | None, intensity: int, timeout: int) -> ScanResult:
    _validate_target(target)
    if _is_mock_mode():
        return _mock_scan(target, ports)
    if _has_nmap():
        reachable = await _is_subnet_reachable(target)
        if not reachable:
            return _mock_scan(target, ports)
        args = ["-oX", "-", "-sV", f"--version-intensity={intensity}", "-T4"]
        if ports:
            _validate_ports(ports)
            args.extend(["-p", ports])
        args.append(target)
        stdout, stderr, rc = await _run_nmap(args, timeout)
        result = _parse_xml(stdout)
        if stderr:
            result.warnings.append(stderr.strip())
        return result
    return _mock_scan(target, ports)


async def _exec_vuln_scan(target: str, scripts: str, timeout: int) -> list[VulnFinding]:
    _validate_target(target)
    if _is_mock_mode():
        return _mock_vulns()
    if _has_nmap():
        reachable = await _is_subnet_reachable(target)
        if not reachable:
            return _mock_vulns()
        args = ["-oX", "-", "-sV", f"--script={scripts}", "-T4", target]
        stdout, stderr, rc = await _run_nmap(args, timeout)
        return _parse_vuln_xml(stdout)
    return _mock_vulns()


# ═══════════════════════════════════════════════════════════════════
# MCP Tool Definitions
# ═══════════════════════════════════════════════════════════════════

MODE = "nmap" if _has_nmap() else "mock"


def _host_summary(h: HostResult) -> dict:
    return {
        "ip": h.ip, "mac": h.mac, "hostname": h.hostname,
        "state": h.state, "vendor": h.vendor, "type": h.device_type,
        "open_ports": [
            {"port": p.port, "protocol": p.protocol,
             "service": p.service.name if p.service else "unknown",
             "product": p.service.product if p.service else None}
            for p in h.ports if p.state == PortState.OPEN
        ],
        "os": [o.name for o in h.os_matches][:1],
    }


@mcp.tool()
async def network_scan(target: str, ports: str = "", scan_type: str = "connect", timing: str = "normal", timeout: int = 300) -> str:
    """Perform a network/port scan on target hosts.

    Args:
        target: IP, hostname, or CIDR (e.g. 10.0.0.0/24). Max /24.
        ports: Port spec: '22', '1-1024', '22,80,443'. Empty = default.
        scan_type: connect|syn|udp|fin|xmas|null. Default: connect.
        timing: paranoid through insane. Default: normal.
        timeout: Max seconds. Default: 300.
    """
    logger.info(f"network_scan: target={target} ports={ports} [{MODE}]")
    try:
        result = await _exec_scan(target, ports or None, scan_type, timing, timeout)
        out = {"mode": result.scan_stats.get("mode", MODE), "command": result.command, "hosts_found": len(result.hosts),
               "hosts": [_host_summary(h) for h in result.hosts], "scan_stats": result.scan_stats}
        if result.warnings:
            out["warnings"] = result.warnings
        return json.dumps(out, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def host_discovery(target: str, timing: str = "normal", timeout: int = 300) -> str:
    """Discover live hosts on a network (ping scan, no port scan).

    Args:
        target: CIDR network (e.g. 192.168.1.0/24).
        timing: Timing template. Default: normal.
        timeout: Max seconds. Default: 300.
    """
    logger.info(f"host_discovery: target={target} [{MODE}]")
    try:
        result = await _exec_discover(target, timing, timeout)
        return json.dumps({
            "mode": result.scan_stats.get("mode", MODE), "command": result.command,
            "hosts_up": len([h for h in result.hosts if h.state == "up"]),
            "hosts": [{"ip": h.ip, "mac": h.mac, "hostname": h.hostname, "vendor": h.vendor} for h in result.hosts],
            "scan_stats": result.scan_stats,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def service_detection(target: str, ports: str = "", intensity: int = 7, timeout: int = 300) -> str:
    """Detect services and versions on open ports.

    Args:
        target: IP or hostname.
        ports: Port spec. Empty = default.
        intensity: 0-9. Default: 7.
        timeout: Max seconds. Default: 300.
    """
    logger.info(f"service_detection: target={target} [{MODE}]")
    try:
        result = await _exec_service_detect(target, ports or None, intensity, timeout)
        svcs = []
        for h in result.hosts:
            for p in h.ports:
                if p.service and p.state == PortState.OPEN:
                    svcs.append({"host": h.ip, "port": p.port, "service": p.service.name,
                                 "product": p.service.product, "version": p.service.version, "cpe": p.service.cpe})
        return json.dumps({"mode": MODE, "command": result.command, "services_found": len(svcs), "services": svcs},
                          ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def vuln_scan(target: str, scripts: str = "vuln", timeout: int = 300) -> str:
    """Scan for vulnerabilities using Nmap NSE scripts.

    Args:
        target: IP or hostname.
        scripts: NSE category. Default: vuln.
        timeout: Max seconds. Default: 300.
    """
    logger.info(f"vuln_scan: target={target} scripts={scripts} [{MODE}]")
    try:
        vulns = await _exec_vuln_scan(target, scripts, timeout)
        findings = [{"host": v.host, "port": v.port, "script": v.script_id,
                     "title": v.title, "state": v.state, "output": v.output} for v in vulns]
        return json.dumps({"mode": MODE, "target": target,
                           "vulnerabilities_found": len(findings), "findings": findings},
                          ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def iot_fingerprint(target: str = "10.0.0.0/24") -> str:
    """Identify IoT devices via MAC OUI lookup and port heuristics.

    Performs a network scan, then applies fingerprinting rules to identify
    cameras, sensors, PLCs, smart plugs, gateways, etc.

    Args:
        target: Network to scan. Default: 10.0.0.0/24.
    """
    logger.info(f"iot_fingerprint: target={target} [{MODE}]")
    try:
        scan = await _exec_scan(target, None, "connect", "normal", 300)
        devices = _fingerprint_iot(scan)
        return json.dumps({"mode": scan.scan_stats.get("mode", MODE), "target": target, "iot_devices_found": len(devices), "devices": devices},
                          ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


# ── 弱口令真验证（限量默认口令，避免锁账户）──────────────────────────
# IoT 头号风险：Mirai 僵尸网靠扫默认口令感染百万设备。这里只试顶部 3 对最高概率
# 默认口令，命中即停，慢速（1s 间隔）—— 是"验证"而非"爆破"，把锁账户风险降到很低。
_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", ""),
    ("admin", "password"),
    ("root", "root"),
]


def _probe_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        import socket as _s
        sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        sock.settimeout(timeout)
        r = sock.connect_ex((ip, port))
        sock.close()
        return r == 0
    except Exception:
        return False


async def _try_telnet_login(ip: str, username: str, password: str) -> bool:
    """Telnet 登录尝试。返回 True=凭证有效。"""
    try:
        import telnetlib
    except ImportError:
        return False
    try:
        tn = telnetlib.Telnet(ip, timeout=5)
        try:
            tn.read_until(b"ogin:", timeout=4)
            tn.write(username.encode() + b"\r\n")
            tn.read_until(b"assword:", timeout=4)
            tn.write(password.encode() + b"\r\n")
            await asyncio.sleep(1.0)
            resp = tn.read_very_eager().decode("utf-8", errors="replace")
        finally:
            tn.close()
        low = resp.lower()
        if any(m in low for m in ["invalid", "incorrect", "fail", "denied", "wrong", "bad "]):
            return False
        return any(p in resp for p in ["#", "$", ">", "welcome"]) or len(resp.strip()) > 3
    except Exception:
        return False


async def _try_ssh_login(ip: str, username: str, password: str) -> bool:
    """SSH 登录尝试。返回 True=凭证有效。"""
    try:
        import paramiko
    except ImportError:
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=22, username=username, password=password,
                       timeout=5, allow_agent=False, look_for_keys=False)
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass


@mcp.tool()
async def default_credential_check(target: str = "topology", services: str = "telnet,ssh") -> str:
    """弱口令真验证：对设备的 Telnet/SSH 服务尝试限量默认口令登录。

    安全策略（避免锁账户/封 IP）：
    - 每设备每服务只试顶部 3 对最高概率默认口令，命中即停
    - 只试常见默认账户（admin/root），不枚举用户名
    - 慢速：每次尝试间隔 1s
    - 默认只测 topology 白名单设备

    Args:
        target: 设备 IP 或 'topology'（遍历 topology 全部设备）。默认 topology。
        services: 检测服务，逗号分隔。默认 'telnet,ssh'。
    """
    logger.info(f"default_credential_check: target={target} services={services}")
    if target == "topology" or not target:
        if _is_mock_mode():
            ips = [d["ip"] for d in _load_mock_devices() if d.get("ip")]
        else:
            # real: scan_service 发现的在线设备(DB devPresentLastScan=1)
            try:
                from server.services.nx_bridge import get_bridge
                all_devs = await get_bridge().get_all_devices()
                ips = [d.get("devLastIP") for d in all_devs
                       if d.get("devPresentLastScan") and d.get("devLastIP")]
            except Exception:
                ips = []
    else:
        ips = [target]

    svc_set = {s.strip().lower() for s in services.split(",") if s.strip()}
    results = []

    for ip in ips:
        dev = {"ip": ip, "services_checked": [], "weak": False, "credentials": []}
        open_ports = await asyncio.get_event_loop().run_in_executor(
            None, lambda: {p: _probe_port(ip, p) for p in (22, 23)})
        if open_ports.get(23) and "telnet" in svc_set:
            for username, password in _DEFAULT_CREDS[:3]:
                await asyncio.sleep(1.0)
                if await _try_telnet_login(ip, username, password):
                    dev["credentials"].append({"service": "telnet", "username": username,
                                               "password": password or "(空)"})
                    dev["weak"] = True
                    break
            dev["services_checked"].append("telnet")
        if open_ports.get(22) and "ssh" in svc_set:
            for username, password in _DEFAULT_CREDS[:3]:
                await asyncio.sleep(1.0)
                if await _try_ssh_login(ip, username, password):
                    dev["credentials"].append({"service": "ssh", "username": username,
                                               "password": password or "(空)"})
                    dev["weak"] = True
                    break
            dev["services_checked"].append("ssh")
        results.append(dev)  # 所有检测设备计入(含 22/23 未开放的)，不只弱口令命中的

    weak_count = sum(1 for r in results if r["weak"])
    return json.dumps({
        "mode": "real_credential_check",
        "devices_checked": len(results),
        "weak_devices": weak_count,
        "note": "限量默认口令真验证（每服务最多 3 对，命中即停，1s 间隔避免锁账户）",
        "results": results,
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info(f"Starting CyberClaw nmap-scan MCP (mode: {MODE})")
    mcp.run()
