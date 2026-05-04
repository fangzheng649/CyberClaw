"""CyberClaw Traffic Analyzer MCP Server — deep packet inspection."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("traffic-analyzer", "Deep traffic analysis with tshark")


@mcp.tool()
async def start_capture(interface: str, filter_expr: str = "") -> str:
    """Start a packet capture session."""
    return f"[Phase 3] start_capture: interface={interface}"


@mcp.tool()
async def get_capture_result(capture_id: str) -> str:
    """Retrieve capture analysis results."""
    return f"[Phase 3] get_capture_result: id={capture_id}"


@mcp.tool()
async def extract_ioc(pcap_data: str) -> str:
    """Extract indicators of compromise from packet data."""
    return f"[Phase 3] extract_ioc"


if __name__ == "__main__":
    mcp.run()
