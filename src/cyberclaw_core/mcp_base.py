import logging
from mcp.server.fastmcp import FastMCP


logger = logging.getLogger(__name__)


def create_mcp_server(name: str, description: str = "") -> FastMCP:
    """Create a FastMCP server with standard CyberClaw configuration."""
    return FastMCP(
        name=f"cyberclaw-{name}",
        instructions=description or f"CyberClaw {name} MCP server",
    )
