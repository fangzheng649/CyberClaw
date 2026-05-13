"""Phase 3 测试 — MCP 服务器升级"""
import pytest
import json
from pathlib import Path


@pytest.mark.asyncio
async def test_attack_timeline_module():
    """attack-timeline MCP 应可导入"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "attack_timeline",
        str(Path(__file__).resolve().parent.parent / "mcp-servers" / "attack-timeline" / "server.py")
    )
    assert spec is not None
