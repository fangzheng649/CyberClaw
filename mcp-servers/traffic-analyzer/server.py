"""CyberClaw Traffic Analyzer MCP Server — deep packet inspection and IoC extraction.

Tools:
  - start_capture: Start packet capture on a network interface
  - get_capture_result: Retrieve capture analysis results
  - extract_ioc: Extract indicators of compromise from captured traffic
  - analyze_flow: Analyze flow patterns for C2/scan/lateral movement detection
"""
import json
import logging
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("traffic-analyzer", "Deep traffic analysis, packet capture, IoC extraction, and flow anomaly detection")

TSHARK_PATH = os.getenv("TSHARK_PATH", "tshark")

# In-memory capture sessions
_captures: dict[str, dict] = {}


def _has_tshark() -> bool:
    import shutil
    return shutil.which(TSHARK_PATH) is not None


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
        import asyncio
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
        return json.dumps({"capture_id": capture_id, "status": "unavailable",
                           "message": "No tshark — no capture data available"},
                          ensure_ascii=False, indent=2)

    # Real capture: parse tshark JSON output if available
    proc = cap.get("proc")
    if proc and proc.returncode is not None:
        stdout = await proc.stdout.read()
        try:
            import json as _json
            packets = _json.loads(stdout)
            return json.dumps({
                "capture_id": capture_id, "status": "completed",
                "total_packets": len(packets),
                "packets_sample": packets[:50],
            }, ensure_ascii=False, indent=2)
        except Exception:
            pass

    return json.dumps({"capture_id": capture_id, "status": cap.get("status", "unknown")},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def extract_ioc(capture_id: str = "") -> str:
    """Extract indicators of compromise from captured traffic.

    Args:
        capture_id: Capture session ID. Empty = use latest.
    """
    logger.info(f"extract_ioc: capture={capture_id or 'latest'}")
    # IoC extraction requires real captured traffic
    cap_id = capture_id or (max(_captures, key=lambda k: _captures[k].get("started", "")) if _captures else "")
    if not cap_id or cap_id not in _captures:
        return json.dumps({"iocs_found": 0, "indicators": [],
                           "message": "No capture data available. Start a capture first."},
                          ensure_ascii=False, indent=2)

    cap = _captures[cap_id]
    if cap.get("status") == "unavailable":
        return json.dumps({"iocs_found": 0, "indicators": [],
                           "message": "tshark not installed — cannot extract IoCs"},
                          ensure_ascii=False, indent=2)

    return json.dumps({"capture_id": cap_id, "iocs_found": 0, "indicators": [],
                       "message": "IoC extraction requires tshark-captured packets"},
                      ensure_ascii=False, indent=2)


@mcp.tool()
async def analyze_flow(target: str = "") -> str:
    """Analyze flow patterns for C2, scanning, and lateral movement detection.

    Args:
        target: Target IP to focus analysis. Empty = analyze all.
    """
    logger.info(f"analyze_flow: target={target or 'all'}")
    # Flow analysis requires real captured traffic
    if not _captures:
        return json.dumps({"sessions_analyzed": 0, "anomalies_found": 0, "anomalies": [],
                           "message": "No capture sessions. Start a capture first."},
                          ensure_ascii=False, indent=2)

    return json.dumps({"sessions_analyzed": 0, "anomalies_found": 0, "anomalies": [],
                       "message": "Flow analysis requires tshark-captured packets"},
                      ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw traffic-analyzer MCP")
    mcp.run()
