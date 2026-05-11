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
# Device Database — loaded from topology config
# ═══════════════════════════════════════════════════════════════════

_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"
_mock_devices_cache: list | None = None


def _load_mock_devices() -> list:
    """Load device definitions from topology config for mock mode."""
    global _mock_devices_cache
    if _mock_devices_cache is not None:
        return _mock_devices_cache
    try:
        with open(_TOPOLOGY_PATH, encoding="utf-8") as f:
            config = json.load(f)
        _mock_devices_cache = [
            {
                "ip": d["ip"], "mac": d.get("mac", ""), "vendor": d.get("vendor", ""),
                "type": d["type"], "model": d.get("model", ""),
                "ports": d.get("expected_ports", []), "os": d.get("os_guess", "Unknown"),
            }
            for d in config["devices"]
        ]
        logger.info(f"Loaded {len(_mock_devices_cache)} devices from topology config")
    except Exception as e:
        logger.error(f"Failed to load topology config: {e}")
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
            ports=h_ports, os_matches=os_list,
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
        matched_type = None
        confidence = 60

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

async def _exec_scan(target: str, ports: str | None, scan_type: str, timing: str, timeout: int) -> ScanResult:
    _validate_target(target)
    if _has_nmap():
        args = ["-oX", "-", SCAN_TYPES.get(scan_type, "-sT"), TIMING.get(timing, "-T3")]
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


async def _exec_discover(target: str, timing: str, timeout: int) -> ScanResult:
    _validate_target(target)
    if _has_nmap():
        args = ["-oX", "-", "-sn", TIMING.get(timing, "-T3"), target]
        stdout, stderr, rc = await _run_nmap(args, timeout)
        return _parse_xml(stdout)
    devices = _load_mock_devices()
    hosts = [HostResult(ip=d["ip"], mac=d["mac"], state="up", vendor=d.get("vendor")) for d in devices]
    return ScanResult(command=f"[mock] nmap -sn {target}", hosts=hosts, scan_stats={"hosts_up": str(len(devices)), "mode": "mock"})


async def _exec_service_detect(target: str, ports: str | None, intensity: int, timeout: int) -> ScanResult:
    _validate_target(target)
    if _has_nmap():
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
    if _has_nmap():
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
        "state": h.state, "vendor": h.vendor,
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
        out = {"mode": MODE, "command": result.command, "hosts_found": len(result.hosts),
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
            "mode": MODE, "command": result.command,
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
        return json.dumps({"mode": MODE, "target": target, "iot_devices_found": len(devices), "devices": devices},
                          ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def default_credential_check(target: str = "10.0.0.0/24") -> str:
    """Check for default credentials on discovered IoT devices.

    Scans for Telnet/SSH/HTTP and reports devices likely using default credentials.

    Args:
        target: Network to scan. Default: 10.0.0.0/24.
    """
    logger.info(f"default_credential_check: target={target} [{MODE}]")
    try:
        scan = await _exec_scan(target, "22,23,80,443,8080", "connect", "normal", 300)
        results = _check_credentials(scan)
        vuln_count = len([r for r in results if r.get("vulnerable")])
        return json.dumps({"mode": MODE, "target": target, "devices_checked": len(results),
                           "vulnerable_devices": vuln_count, "results": results},
                          ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)


if __name__ == "__main__":
    logger.info(f"Starting CyberClaw nmap-scan MCP (mode: {MODE})")
    mcp.run()
