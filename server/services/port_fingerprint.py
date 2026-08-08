"""Lightweight device fingerprinting by port probe (pillar 3: device type ID).

The background scan only does host discovery (nmap -sn), so newly found devices
sit at devType="unknown". This module adds a fast, dependency-light port probe
(nmap if available, else concurrent socket connect) plus a port→type mapping, so
scan_service can fingerprint each new device BEFORE broadcasting it to the HUD.

Mirrors the heuristics in mcp-servers/nmap-scan/server.py but with no
MCP / Pydantic coupling so the background scanner can import it directly.
"""
import asyncio
import json
import logging
import re
import shutil
import socket

logger = logging.getLogger(__name__)

# Common IoT / management ports used for type inference.
COMMON_IOT_PORTS = [22, 23, 80, 443, 554, 161, 502, 102, 4840,
                    1883, 37777, 8000, 8080, 8443, 445, 3389]

# Vendor OUI prefix → likely type. Only vendors whose products are
# overwhelmingly one type (camera / ICS vendors). Network-gear vendors
# (TP-Link / Cisco / H3C) are intentionally NOT mapped here — too diverse —
# their type is decided by the port probe instead.
IOT_SIGNATURES = {
    "Hikvision": {"mac_prefix": ["44:19:b6", "c0:56:e3", "e0:50:8b"], "type": "camera"},
    "Dahua":     {"mac_prefix": ["3c:ef:8c", "4c:11:bf", "a0:bd:1d"], "type": "camera"},
    "Siemens":   {"mac_prefix": ["00:1c:06", "00:1e:c1"],             "type": "plc"},
    "Honeywell": {"mac_prefix": ["00:0b:46", "00:16:ce"],             "type": "sensor"},
}

# Vendor-name substring → likely type. The OUI DB resolves MAC→vendor reliably,
# so a known vendor is a strong signal (e.g. "TP-LINK"→switch, "Hikvision"→camera)
# even when the narrow MAC-prefix list above doesn't cover every OUI a vendor owns.
_VENDOR_TYPE = [
    (("hikvision", "dahua", "axis", "foscam", "reolink", "amcrest"), "camera"),
    (("tp-link", "tp link", "cisco", "h3c", "huawei", "juniper", "arista",
      "netgear", "d-link", "mikrotik", "extreme", "ruckus", "ubiquiti"), "switch"),
    (("siemens", "schneider", "rockwell", "allen-bradley", "mitsubishi",
      "omron", "abb ", "wago"), "plc"),
]


def infer_device_type(open_ports, vendor="", mac=""):
    """Map MAC / vendor / open ports → (device_type, confidence 0-99).

    Order: exact MAC OUI signature (90) → vendor-name substring from the OUI
    DB (80) → port heuristics (60-75). Returns ("unknown", 0) when there is no
    decisive signal — honest, never a guess. SNMP/161 is intentionally NOT
    used: it is UDP and a TCP probe cannot detect it reliably.
    """
    # 1. Exact MAC OUI signature.
    if mac:
        prefix = mac.replace(":", "").lower()[:6]
        for sig in IOT_SIGNATURES.values():
            if any(prefix.startswith(p.replace(":", "").lower()) for p in sig["mac_prefix"]):
                return (sig["type"], 90)
    # 2. Vendor-name substring (OUI-resolved vendor is a strong, reliable signal).
    v = (vendor or "").lower()
    if v:
        for substrs, dev_type in _VENDOR_TYPE:
            if any(s in v for s in substrs):
                return (dev_type, 80)
    # 3. Port heuristics.
    ports = set(open_ports or [])
    if 554 in ports or 37777 in ports:
        return ("camera", 75)
    if 502 in ports or 102 in ports or 4840 in ports:
        return ("plc", 70)
    if 1883 in ports:
        return ("gateway", 70)
    return ("unknown", 0)


async def probe_open_ports(ip, ports=COMMON_IOT_PORTS, timeout_per_port=0.4):
    """Return open TCP ports on `ip`. Uses nmap when available (one subprocess),
    else concurrent socket connect probes. Never raises — returns [] on failure."""
    if not ip:
        return []
    try:
        if shutil.which("nmap"):
            return await _probe_via_nmap(ip, ports)
        return await _probe_via_sockets(ip, ports, timeout_per_port)
    except Exception as e:  # never let fingerprinting break the scan loop
        logger.debug(f"probe_open_ports({ip}) failed: {e}")
        return []


async def _probe_via_nmap(ip, ports):
    port_arg = ",".join(str(p) for p in ports)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "--open", "-T4", "-n", "-p", port_arg, ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        text = out.decode("utf-8", errors="replace")
        return [int(m) for m in re.findall(r"(\d+)/tcp\s+open", text)]
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
        logger.debug(f"nmap probe failed for {ip}: {e}")
        return []
    finally:
        # Reap the subprocess on every path — especially timeout, where nmap
        # would otherwise keep running (zombie on POSIX, leaked handle on Windows).
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except (ProcessLookupError, OSError):
                pass


async def _probe_via_sockets(ip, ports, timeout_per_port):
    loop = asyncio.get_event_loop()

    def _check(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_per_port)
            try:
                return p if s.connect_ex((ip, p)) == 0 else None
            finally:
                s.close()
        except OSError:
            return None

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*[loop.run_in_executor(None, _check, p) for p in ports]),
            timeout=8,
        )
    except asyncio.TimeoutError:
        return []
    return [p for p in results if p]


async def fingerprint_device(ip, mac="", vendor=""):
    """Probe + infer → {type, open_ports, confidence}. Best-effort, never raises."""
    open_ports = await probe_open_ports(ip)
    dev_type, confidence = infer_device_type(open_ports, vendor=vendor, mac=mac)
    return {"type": dev_type, "open_ports": open_ports, "confidence": confidence}
