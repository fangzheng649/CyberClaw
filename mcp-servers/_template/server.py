"""CyberClaw MCP Server Template."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from cyberclaw_core.mcp_base import create_mcp_server

mcp = create_mcp_server("TEMPLATE_NAME", "TEMPLATE_DESCRIPTION")


@mcp.tool()
async def template_tool(param: str) -> str:
    """Tool description."""
    return f"Result: {param}"


if __name__ == "__main__":
    mcp.run()
