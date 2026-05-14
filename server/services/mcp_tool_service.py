"""CyberClaw MCP Tool Service — direct tool invocation for backend integration.

Imports MCP server modules and exposes tool functions for the chat API.
Each tool returns a JSON string result (same as MCP stdio output).
"""
import importlib.util
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MCP_DIR = PROJECT_ROOT / "mcp-servers"
SRC_DIR = PROJECT_ROOT / "src"

# Ensure src/ is on sys.path for cyberclaw_core
_src_str = str(SRC_DIR)
if _src_str not in sys.path:
    sys.path.insert(0, _src_str)

# MCP server module definitions: name -> (file_path, tool_functions)
_MCP_REGISTRY: dict[str, dict[str, Callable]] = {}


def _load_mcp_module(name: str, filename: str) -> dict[str, Callable]:
    """Load an MCP server module and extract tool functions."""
    if name in _MCP_REGISTRY:
        return _MCP_REGISTRY[name]

    filepath = MCP_DIR / name / filename
    if not filepath.exists():
        logger.warning(f"MCP module not found: {filepath}")
        return {}

    try:
        spec = importlib.util.spec_from_file_location(f"mcp_{name}", str(filepath))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        tools = {}
        for tool_name in mod.mcp._tool_manager._tools:
            tool_fn = getattr(mod, tool_name, None)
            if tool_fn and callable(tool_fn):
                tools[tool_name] = tool_fn

        _MCP_REGISTRY[name] = tools
        logger.info(f"Loaded MCP {name}: {len(tools)} tools ({', '.join(tools.keys())})")
        return tools
    except Exception as e:
        logger.error(f"Failed to load MCP {name}: {e}")
        return {}


def _load_all():
    """Load all MCP server modules."""
    _load_mcp_module("nmap-scan", "server.py")
    _load_mcp_module("cve-intel", "server.py")
    _load_mcp_module("security-baseline", "server.py")
    _load_mcp_module("auto-response", "server.py")
    _load_mcp_module("traffic-analyzer", "server.py")
    _load_mcp_module("config-audit", "server.py")
    _load_mcp_module("attack-timeline", "server.py")


def get_available_tools() -> list[dict]:
    """List all available MCP tools."""
    if not _MCP_REGISTRY:
        _load_all()
    tools = []
    for server_name, tool_map in _MCP_REGISTRY.items():
        for tool_name in tool_map:
            tools.append({"server": server_name, "tool": tool_name})
    return tools


async def call_tool(server: str, tool: str, **kwargs) -> dict:
    """Call an MCP tool and return parsed JSON result."""
    if not _MCP_REGISTRY:
        _load_all()

    tools = _MCP_REGISTRY.get(server, {})
    fn = tools.get(tool)
    if not fn:
        return {"error": f"Tool {server}/{tool} not found"}

    try:
        result = await fn(**kwargs)
        if isinstance(result, str):
            return json.loads(result)
        return result
    except Exception as e:
        logger.error(f"MCP tool call failed: {server}/{tool}: {e}")
        return {"error": str(e)}


# ── Intent-based tool orchestration ───────────────────────────────

def _load_subnet() -> str:
    """Load the target subnet from topology config."""
    topo_path = PROJECT_ROOT / "config" / "topology.json"
    try:
        with open(topo_path, encoding="utf-8") as f:
            topo = json.load(f)
            return topo.get("network", {}).get("subnet", "192.168.10.0/24")
    except Exception:
        return "192.168.10.0/24"


_SUBNET = _load_subnet()

INTENT_TOOL_MAP = {
    r"扫描|scan|检查|发现|网络设备": [
        {"server": "nmap-scan", "tool": "network_scan", "args": {"target": _SUBNET}},
        {"server": "nmap-scan", "tool": "iot_fingerprint", "args": {"target": _SUBNET}},
    ],
    r"发现主机|discover": [
        {"server": "nmap-scan", "tool": "host_discovery", "args": {"target": _SUBNET}},
    ],
    r"漏洞|vuln|CVE|cve": [
        {"server": "cve-intel", "tool": "check_device_vulns", "args": {"vendor": "Hikvision", "min_severity": "HIGH"}},
    ],
    r"基线|baseline|合规": [
        {"server": "security-baseline", "tool": "check_baseline", "args": {"detailed": True}},
    ],
    r"审计|audit|配置": [
        {"server": "config-audit", "tool": "audit_config", "args": {}},
        {"server": "config-audit", "tool": "check_acl_conflicts", "args": {}},
    ],
    r"隔离|isolat|封禁|block": [
        {"server": "auto-response", "tool": "get_response_status", "args": {}},
    ],
    r"攻击|回放|复盘|时间线|timeline|attack|根因": [
        {"server": "attack-timeline", "tool": "get_timeline", "args": {}},
        {"server": "attack-timeline", "tool": "analyze_root_cause", "args": {}},
    ],
    r"流量|traffic|IOC|指标|异常": [
        {"server": "traffic-analyzer", "tool": "extract_ioc", "args": {}},
        {"server": "traffic-analyzer", "tool": "analyze_flow", "args": {}},
    ],
}


def match_intent(message: str) -> list[dict]:
    """Match user message to tool call intents. Max 3 intent groups to avoid overload."""
    import re
    intents = []
    matched = 0
    for pattern, tools in INTENT_TOOL_MAP.items():
        if matched >= 3:
            break
        if re.search(pattern, message, re.IGNORECASE):
            intents.extend(tools)
            matched += 1
    return intents


async def execute_intent(message: str) -> list[dict]:
    """Execute tool calls matching the user's message intent, in parallel."""
    import asyncio
    tool_calls = match_intent(message)
    if not tool_calls:
        return []

    async def _run_one(tc):
        args = dict(tc["args"])
        result = await call_tool(tc["server"], tc["tool"], **args)
        return {"server": tc["server"], "tool": tc["tool"], "result": result}

    return await asyncio.gather(*[_run_one(tc) for tc in tool_calls])


def format_tool_results_for_llm(results: list[dict]) -> str:
    """Format tool results for inclusion in LLM prompt."""
    if not results:
        return ""
    parts = ["[工具调用结果]"]
    for r in results:
        result = r["result"]
        is_error = isinstance(result, dict) and "error" in result
        status_tag = "❌ 失败" if is_error else "✅ 成功"
        parts.append(f"\n## {r['server']}/{r['tool']} — {status_tag}")
        if isinstance(result, dict):
            if is_error:
                parts.append(f"错误信息: {result['error']}")
            else:
                summary = {}
                for k, v in result.items():
                    if isinstance(v, list) and len(v) > 10:
                        summary[k] = v[:10]
                        summary[f"{k}_total"] = len(v)
                    else:
                        summary[k] = v
                parts.append(json.dumps(summary, ensure_ascii=False, indent=2)[:2000])
        else:
            parts.append(str(result)[:2000])
    return "\n".join(parts)
