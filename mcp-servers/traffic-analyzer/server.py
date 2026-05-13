"""CyberClaw Traffic Analyzer MCP Server — deep packet inspection and IoC extraction.

Tools:
  - start_capture: Start packet capture on a network interface
  - get_capture_result: Retrieve capture analysis results
  - extract_ioc: Extract indicators of compromise from captured traffic
  - analyze_flow: Analyze flow patterns for C2/scan/lateral movement detection
"""
import asyncio
import json
import logging
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("traffic-analyzer", "Deep traffic analysis, packet capture, IoC extraction, and flow anomaly detection")

TSHARK_PATH = os.getenv("TSHARK_PATH", "tshark")

# In-memory capture sessions
_captures: dict[str, dict] = {}

# Suspicious ports commonly used in attacks
SUSPICIOUS_PORTS = {
    23: {"name": "Telnet", "severity": "high", "reason": "Unencrypted remote access — often targeted for brute-force or Mirai-style botnets"},
    445: {"name": "SMB", "severity": "high", "reason": "SMB exploitation — EternalBlue, WannaCry, lateral movement"},
    3389: {"name": "RDP", "severity": "high", "reason": "Remote Desktop — BlueKeep exploit, credential theft"},
    6667: {"name": "IRC", "severity": "medium", "reason": "IRC protocol — common C2 channel for botnets"},
    4444: {"name": "Reverse Shell", "severity": "critical", "reason": "Common Metasploit reverse shell port"},
    6666: {"name": "IRC Alt", "severity": "medium", "reason": "Alternate IRC port — potential C2 channel"},
    6668: {"name": "IRC Alt", "severity": "medium", "reason": "Alternate IRC port — potential C2 channel"},
    31337: {"name": "Backdoor", "severity": "critical", "reason": "Common backdoor / BEAST port"},
    1234: {"name": "Backdoor", "severity": "high", "reason": "Frequently used backdoor port"},
    4443: {"name": "HTTPS Alt", "severity": "low", "reason": "Alternate HTTPS — possible C2 over encrypted channel"},
}

# Malicious / suspicious TLDs
MALICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".club"}


def _has_tshark() -> bool:
    import shutil
    return shutil.which(TSHARK_PATH) is not None


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP address is internal/private."""
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        # 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
    except (ValueError, IndexError):
        pass
    return False


def _extract_packets_from_tshark_json(raw_json: list) -> list[dict]:
    """Parse tshark JSON output into a normalized packet list."""
    packets = []
    for pkt in raw_json:
        layers = pkt.get("_source", {}).get("layers", {})
        info = {
            "frame_number": layers.get("frame.number", [""])[0] if isinstance(layers.get("frame.number"), list) else layers.get("frame.number", ""),
            "timestamp": layers.get("frame.time", [""])[0] if isinstance(layers.get("frame.time"), list) else layers.get("frame.time", ""),
            "src_ip": layers.get("ip.src", [""])[0] if isinstance(layers.get("ip.src"), list) else layers.get("ip.src", ""),
            "dst_ip": layers.get("ip.dst", [""])[0] if isinstance(layers.get("ip.dst"), list) else layers.get("ip.dst", ""),
            "src_port": "",
            "dst_port": "",
            "protocol": "",
            "length": int(layers.get("frame.len", ["0"])[0]) if isinstance(layers.get("frame.len"), list) else int(layers.get("frame.len", "0") or "0"),
        }
        # TCP layer
        tcp = layers.get("tcp", {})
        if tcp:
            info["protocol"] = "TCP"
            info["src_port"] = str(tcp.get("tcp.srcport", [""])[0]) if isinstance(tcp.get("tcp.srcport"), list) else str(tcp.get("tcp.srcport", ""))
            info["dst_port"] = str(tcp.get("tcp.dstport", [""])[0]) if isinstance(tcp.get("tcp.dstport"), list) else str(tcp.get("tcp.dstport", ""))
        # UDP layer
        udp = layers.get("udp", {})
        if udp:
            info["protocol"] = "UDP"
            info["src_port"] = str(udp.get("udp.srcport", [""])[0]) if isinstance(udp.get("udp.srcport"), list) else str(udp.get("udp.srcport", ""))
            info["dst_port"] = str(udp.get("udp.dstport", [""])[0]) if isinstance(udp.get("udp.dstport"), list) else str(udp.get("udp.dstport", ""))
        # DNS layer
        dns = layers.get("dns", {})
        if dns:
            info["protocol"] = "DNS"
            qry = dns.get("dns.qry.name", [])
            info["dns_query"] = qry[0] if isinstance(qry, list) and qry else (qry or "")
        packets.append(info)
    return packets


def _extract_packets_from_scapy(capture_data: dict) -> list[dict]:
    """Build packet-like records from scapy summary statistics."""
    packets = []
    stats = capture_data.get("stats", {})
    sessions = stats.get("sessions", [])
    for sess in sessions:
        src = sess.get("src", "")
        dst = sess.get("dst", "")
        src_port = str(sess.get("sport", ""))
        dst_port = str(sess.get("dport", ""))
        packets.append({
            "src_ip": src, "dst_ip": dst,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": sess.get("proto", "TCP"),
            "length": sess.get("size", 0),
            "timestamp": sess.get("time", ""),
        })
    # Also handle raw packet list format
    raw_pkts = capture_data.get("packets", [])
    for rp in raw_pkts:
        if isinstance(rp, dict):
            packets.append({
                "src_ip": rp.get("src", rp.get("src_ip", "")),
                "dst_ip": rp.get("dst", rp.get("dst_ip", "")),
                "src_port": str(rp.get("sport", rp.get("src_port", ""))),
                "dst_port": str(rp.get("dport", rp.get("dst_port", ""))),
                "protocol": rp.get("proto", rp.get("protocol", "TCP")),
                "length": rp.get("size", rp.get("length", 0)),
                "timestamp": rp.get("time", rp.get("timestamp", "")),
            })
    return packets


def _get_packets_for_capture(cap: dict) -> list[dict]:
    """Get normalized packet list from any capture source."""
    # If tshark raw JSON was already parsed
    if cap.get("parsed_packets"):
        return cap["parsed_packets"]
    # If scapy or other summary data exists
    if cap.get("stats") or cap.get("packets"):
        pkts = _extract_packets_from_scapy(cap)
        cap["parsed_packets"] = pkts
        return pkts
    return []


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _detect_suspicious_ports(packets: list[dict]) -> list[dict]:
    """Detect connections to suspicious ports."""
    indicators = []
    for pkt in packets:
        dst_port_str = pkt.get("dst_port", "")
        try:
            dst_port = int(dst_port_str)
        except (ValueError, TypeError):
            continue
        if dst_port in SUSPICIOUS_PORTS:
            info = SUSPICIOUS_PORTS[dst_port]
            indicators.append({
                "type": "suspicious_port",
                "detail": f"Connection to {info['name']} port {dst_port} — {info['reason']}",
                "severity": info["severity"],
                "source": pkt.get("src_ip", "unknown"),
                "target": f"{pkt.get('dst_ip', 'unknown')}:{dst_port}",
                "port": dst_port,
            })
    return indicators


def _detect_suspicious_dns(packets: list[dict]) -> list[dict]:
    """Detect anomalous DNS queries."""
    indicators = []
    seen = set()
    for pkt in packets:
        dns_query = pkt.get("dns_query", "")
        if not dns_query:
            continue
        domain = dns_query.lower().rstrip(".")
        if domain in seen:
            continue
        seen.add(domain)

        # Overly long domain name
        if len(domain) > 50:
            indicators.append({
                "type": "suspicious_dns",
                "detail": f"Abnormally long domain ({len(domain)} chars): {domain[:60]}...",
                "severity": "medium",
                "source": pkt.get("src_ip", "unknown"),
                "target": domain,
            })
            continue

        # Random-looking subdomain (high entropy: mix of digits and letters in labels)
        parts = domain.split(".")
        if len(parts) >= 3:
            sub = parts[0]
            if len(sub) >= 8 and re.match(r'^[a-z0-9]+$', sub):
                digit_count = sum(c.isdigit() for c in sub)
                alpha_count = sum(c.isalpha() for c in sub)
                if digit_count >= 3 and alpha_count >= 3:
                    indicators.append({
                        "type": "suspicious_dns",
                        "detail": f"Random-looking subdomain (possible DGA): {domain}",
                        "severity": "high",
                        "source": pkt.get("src_ip", "unknown"),
                        "target": domain,
                    })
                    continue

        # Known malicious TLD
        for tld in MALICIOUS_TLDS:
            if domain.endswith(tld):
                indicators.append({
                    "type": "suspicious_dns",
                    "detail": f"Suspicious TLD ({tld}): {domain}",
                    "severity": "medium",
                    "source": pkt.get("src_ip", "unknown"),
                    "target": domain,
                })
                break
    return indicators


def _detect_scan_behavior(packets: list[dict]) -> list[dict]:
    """Detect port scanning: one source hitting many different destination ports."""
    indicators = []
    # Group destination ports by source IP
    src_to_ports: dict[str, set] = defaultdict(set)
    src_to_targets: dict[str, list[dict]] = defaultdict(list)
    for pkt in packets:
        src = pkt.get("src_ip", "")
        dst_port = pkt.get("dst_port", "")
        dst_ip = pkt.get("dst_ip", "")
        if src and dst_port:
            src_to_ports[src].add(dst_port)
            src_to_targets[src].append(pkt)

    SCAN_THRESHOLD = 10  # connecting to 10+ distinct ports is suspicious
    for src, ports in src_to_ports.items():
        if len(ports) >= SCAN_THRESHOLD:
            sorted_ports = sorted(ports, key=lambda p: int(p) if p.isdigit() else 0)
            indicators.append({
                "type": "scan_behavior",
                "detail": f"Source {src} scanned {len(ports)} distinct ports: {','.join(sorted_ports[:20])}{'...' if len(sorted_ports) > 20 else ''}",
                "severity": "critical" if len(ports) >= 50 else "high",
                "source": src,
                "target": f"{len(ports)} ports",
                "ports_scanned": len(ports),
            })
    return indicators


def _detect_c2_pattern(sessions: dict) -> list[dict]:
    """Detect potential C2 communication: fixed-interval heartbeat, small payload, persistent connection."""
    anomalies = []
    for flow_key, pkts in sessions.items():
        if len(pkts) < 5:
            continue
        # Check for consistent small payloads
        sizes = [p.get("length", 0) for p in pkts]
        avg_size = sum(sizes) / len(sizes) if sizes else 0
        consistent_small = all(s < 200 for s in sizes) and avg_size > 0
        # Check for regular intervals (low variance in time gaps)
        timestamps = []
        for p in pkts:
            ts = p.get("timestamp", "")
            if ts:
                try:
                    timestamps.append(ts)
                except Exception:
                    pass
        regular_interval = False
        if len(timestamps) >= 4:
            regular_interval = True  # simplified heuristic: many packets with small payloads
        if consistent_small and len(pkts) >= 10:
            parts = flow_key.split("<->")
            anomalies.append({
                "type": "c2_pattern",
                "detail": f"Suspected C2 heartbeat: {len(pkts)} small packets (avg {avg_size:.0f}B) on {flow_key}",
                "severity": "high",
                "source": parts[0].strip() if len(parts) == 2 else "unknown",
                "target": parts[1].strip() if len(parts) == 2 else "unknown",
                "packet_count": len(pkts),
                "avg_size": round(avg_size, 1),
            })
    return anomalies


def _detect_lateral_movement(sessions: dict) -> list[dict]:
    """Detect lateral movement: internal-to-internal port scanning."""
    anomalies = []
    for flow_key, pkts in sessions.items():
        parts = flow_key.split("<->")
        if len(parts) != 2:
            continue
        src = parts[0].strip().rsplit(":", 1)[0]
        dst = parts[1].strip().rsplit(":", 1)[0]
        if _is_internal_ip(src) and _is_internal_ip(dst) and len(pkts) >= 5:
            dst_ports = set()
            for p in pkts:
                dp = p.get("dst_port", "")
                if dp:
                    dst_ports.add(dp)
            if len(dst_ports) >= 3:
                anomalies.append({
                    "type": "lateral_movement",
                    "detail": f"Internal scanning from {src} to {dst} on {len(dst_ports)} ports",
                    "severity": "critical",
                    "source": src,
                    "target": dst,
                    "ports": sorted(list(dst_ports)),
                })
    return anomalies


def _detect_data_exfiltration(sessions: dict) -> list[dict]:
    """Detect potential data exfiltration: large outbound traffic to unknown destinations."""
    anomalies = []
    for flow_key, pkts in sessions.items():
        parts = flow_key.split("<->")
        if len(parts) != 2:
            continue
        src = parts[0].strip().rsplit(":", 1)[0]
        dst = parts[1].strip().rsplit(":", 1)[0]
        # Internal source sending lots of data to external destination
        if _is_internal_ip(src) and not _is_internal_ip(dst) and dst:
            total_bytes = sum(p.get("length", 0) for p in pkts)
            if total_bytes > 1_000_000:  # >1MB
                anomalies.append({
                    "type": "data_exfiltration",
                    "detail": f"Large outbound transfer ({total_bytes / 1_000_000:.1f}MB) from {src} to external {dst}",
                    "severity": "critical" if total_bytes > 10_000_000 else "high",
                    "source": src,
                    "target": dst,
                    "total_bytes": total_bytes,
                })
    return anomalies


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def start_capture(interface: str = "eth0", filter_expr: str = "", duration: int = 60) -> str:
    """Start a packet capture session.

    Args:
        interface: Network interface. Default: eth0.
        filter_expr: BPF filter expression. Empty = capture all.
        duration: Capture duration in seconds. Default: 60.
    """
    capture_id = f"cap-{int(time.time())}"
    logger.info(f"start_capture: id={capture_id} interface={interface}")

    if _has_tshark():
        try:
            cmd = [TSHARK_PATH, "-i", interface, "-a", f"duration:{duration}", "-T", "json"]
            if filter_expr:
                cmd.extend(["-f", filter_expr])
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _captures[capture_id] = {"id": capture_id, "interface": interface, "filter": filter_expr,
                                     "duration": duration, "status": "capturing", "proc": proc,
                                     "started": datetime.now().isoformat()}
            return json.dumps({"capture_id": capture_id, "status": "capturing",
                               "interface": interface, "filter": filter_expr,
                               "duration": duration}, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"tshark failed: {e}")

    # No tshark available — cannot capture real traffic
    _captures[capture_id] = {"id": capture_id, "interface": interface, "filter": filter_expr,
                             "duration": duration, "status": "unavailable",
                             "started": datetime.now().isoformat()}
    return json.dumps({"capture_id": capture_id, "status": "unavailable",
                       "mode": "no_tshark",
                       "message": "tshark not installed. Install Wireshark/tshark to enable real traffic capture.",
                       "interface": interface},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def get_capture_result(capture_id: str) -> str:
    """Retrieve capture analysis results.

    Args:
        capture_id: Capture session ID.
    """
    cap = _captures.get(capture_id)
    if not cap:
        return json.dumps({"error": f"Capture {capture_id} not found"})

    if cap.get("status") == "unavailable":
        # Check if scapy or other summary data is attached
        packets = _get_packets_for_capture(cap)
        if packets:
            return json.dumps({
                "capture_id": capture_id, "status": "completed",
                "mode": "scapy_summary",
                "total_packets": len(packets),
                "packets_sample": packets[:50],
                "message": "Parsed from scapy capture summary (tshark not available)",
            }, ensure_ascii=False, indent=2)
        return json.dumps({"capture_id": capture_id, "status": "unavailable",
                           "message": "No tshark or scapy capture data available for this session"},
                          ensure_ascii=False, indent=2)

    # Real capture: parse tshark JSON output if process completed
    proc = cap.get("proc")
    if proc and proc.returncode is not None:
        raw = await proc.stdout.read()
        try:
            raw_packets = json.loads(raw)
            parsed = _extract_packets_from_tshark_json(raw_packets)
            cap["parsed_packets"] = parsed
            return json.dumps({
                "capture_id": capture_id, "status": "completed",
                "mode": "tshark",
                "total_packets": len(parsed),
                "packets_sample": parsed[:50],
            }, ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning(f"Failed to parse tshark JSON: {exc}")

    # Process still running — try reading from scapy summary if present
    packets = _get_packets_for_capture(cap)
    if packets:
        return json.dumps({
            "capture_id": capture_id, "status": cap.get("status", "capturing"),
            "mode": "scapy_partial",
            "total_packets": len(packets),
            "packets_sample": packets[:50],
            "message": "Partial data from scapy summary (tshark still running or failed)",
        }, ensure_ascii=False, indent=2)

    return json.dumps({"capture_id": capture_id, "status": cap.get("status", "unknown"),
                       "message": "Capture data not yet available — process may still be running"},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def extract_ioc(capture_id: str = "") -> str:
    """Extract indicators of compromise from captured traffic.

    Args:
        capture_id: Capture session ID. Empty = use latest.
    """
    logger.info(f"extract_ioc: capture={capture_id or 'latest'}")
    cap_id = capture_id or (max(_captures, key=lambda k: _captures[k].get("started", "")) if _captures else "")
    if not cap_id or cap_id not in _captures:
        return json.dumps({"iocs_found": 0, "indicators": [],
                           "message": "No capture data available. Start a capture first."},
                          ensure_ascii=False, indent=2)

    cap = _captures[cap_id]
    packets = _get_packets_for_capture(cap)

    # Attempt to parse tshark output if not yet parsed and process is done
    if not packets:
        proc = cap.get("proc")
        if proc and proc.returncode is not None:
            raw = await proc.stdout.read()
            try:
                raw_packets = json.loads(raw)
                packets = _extract_packets_from_tshark_json(raw_packets)
                cap["parsed_packets"] = packets
            except (json.JSONDecodeError, Exception):
                pass

    if not packets:
        return json.dumps({"capture_id": cap_id, "iocs_found": 0, "indicators": [],
                           "message": "No parseable packet data in this capture session"},
                          ensure_ascii=False, indent=2)

    # Run all IoC detectors
    indicators = []
    indicators.extend(_detect_suspicious_ports(packets))
    indicators.extend(_detect_suspicious_dns(packets))
    indicators.extend(_detect_scan_behavior(packets))

    mode = "tshark" if cap.get("proc") else "scapy"
    return json.dumps({
        "mode": mode,
        "capture_id": cap_id,
        "iocs_found": len(indicators),
        "indicators": indicators,
        "packets_analyzed": len(packets),
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def analyze_flow(target: str = "") -> str:
    """Analyze flow patterns for C2, scanning, and lateral movement detection.

    Args:
        target: Target IP to focus analysis. Empty = analyze all.
    """
    logger.info(f"analyze_flow: target={target or 'all'}")
    if not _captures:
        return json.dumps({"sessions_analyzed": 0, "anomalies_found": 0, "anomalies": [],
                           "message": "No capture sessions. Start a capture first."},
                          ensure_ascii=False, indent=2)

    # Collect packets from all captures (or filter by target)
    all_packets = []
    for cap in _captures.values():
        pkts = _get_packets_for_capture(cap)
        # Attempt tshark parse if needed
        if not pkts:
            proc = cap.get("proc")
            if proc and proc.returncode is not None:
                raw = await proc.stdout.read()
                try:
                    raw_packets = json.loads(raw)
                    pkts = _extract_packets_from_tshark_json(raw_packets)
                    cap["parsed_packets"] = pkts
                except (json.JSONDecodeError, Exception):
                    pass
        if target:
            pkts = [p for p in pkts if target in (p.get("src_ip", ""), p.get("dst_ip", ""))]
        all_packets.extend(pkts)

    if not all_packets:
        return json.dumps({"sessions_analyzed": 0, "anomalies_found": 0, "anomalies": [],
                           "message": "No packet data available in capture sessions"},
                          ensure_ascii=False, indent=2)

    # Build flow sessions: key = "src_ip:src_port <-> dst_ip:dst_port"
    sessions: dict[str, list[dict]] = defaultdict(list)
    for pkt in all_packets:
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        sp = pkt.get("src_port", "")
        dp = pkt.get("dst_port", "")
        if not src or not dst:
            continue
        flow_key = f"{src}:{sp} <-> {dst}:{dp}"
        sessions[flow_key].append(pkt)

    # Run anomaly detectors
    anomalies = []
    anomalies.extend(_detect_c2_pattern(sessions))
    anomalies.extend(_detect_lateral_movement(sessions))
    anomalies.extend(_detect_data_exfiltration(sessions))

    # Build flow summary
    top_talkers = Counter()
    protocol_counts = Counter()
    for pkt in all_packets:
        src = pkt.get("src_ip", "")
        if src:
            top_talkers[src] += 1
        proto = pkt.get("protocol", "unknown")
        if proto:
            protocol_counts[proto] += 1

    mode = "tshark" if any(c.get("proc") for c in _captures.values()) else "scapy"
    return json.dumps({
        "mode": mode,
        "sessions_analyzed": len(sessions),
        "anomalies_found": len(anomalies),
        "anomalies": anomalies,
        "flow_summary": {
            "total_packets": len(all_packets),
            "unique_sessions": len(sessions),
            "top_talkers": dict(top_talkers.most_common(10)),
            "protocols": dict(protocol_counts.most_common()),
        },
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw traffic-analyzer MCP")
    mcp.run()
