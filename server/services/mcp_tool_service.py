"""CyberClaw MCP Tool Service — direct tool invocation for backend integration.

Supports two MCP framework types:
  1. FastMCP servers (cyberclaw_core.mcp_base / FastMCP): tools loaded via _tool_manager
  2. Low-level mcp.server.Server: mock wrappers provided (servers require real network)

Each tool returns a JSON string result (same as MCP stdio output).
"""
import asyncio
import importlib.util
import json
import logging
import os
import sys
from datetime import datetime, timedelta
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

# MCP server module registry: name -> (filename, framework)
_MCP_REGISTRY_DEF = {
    # FastMCP servers — loaded via _tool_manager
    "nmap-scan":           ("server.py",              "fastmcp"),
    "cve-intel":           ("server.py",              "fastmcp"),
    "security-baseline":   ("server.py",              "fastmcp"),
    "traffic-analyzer":    ("server.py",              "fastmcp"),
    "auto-response":       ("server.py",              "fastmcp"),
    "config-audit":        ("server.py",              "fastmcp"),
    "attack-timeline":     ("server.py",              "fastmcp"),
    "device-config":       ("gnmi_mcp_server.py",     "fastmcp"),
    "simulation":          ("gns3_mcp_server.py",     "fastmcp"),
    # Low-level mcp.server.Server — use mock wrappers
    "syslog-collector":    ("syslog_mcp_server.py",   "lowlevel"),
    "snmp-collector":      ("snmptrap_mcp_server.py", "lowlevel"),
    "flow-analyzer":       ("ipfix_mcp_server.py",    "lowlevel"),
}

# Loaded tool registry: name -> {tool_name: callable}
_MCP_REGISTRY: dict[str, dict[str, Callable]] = {}


def _load_fastmcp_module(name: str, filename: str) -> dict[str, Callable]:
    """Load a FastMCP server module and extract tool functions.
    Falls back to mock wrappers if the module cannot be loaded."""
    filepath = MCP_DIR / name / filename
    if not filepath.exists():
        logger.warning(f"FastMCP module not found: {filepath}, using mock")
        return _load_mock_module(name)

    try:
        spec = importlib.util.spec_from_file_location(f"mcp_{name}", str(filepath))
        mod = importlib.util.module_from_spec(spec)
        # Add server directory to sys.path for local imports
        server_dir = str(filepath.parent)
        if server_dir not in sys.path:
            sys.path.insert(0, server_dir)
        spec.loader.exec_module(mod)

        mcp_instance = getattr(mod, "mcp", None)
        if not mcp_instance:
            logger.warning(f"No 'mcp' instance in {name}, using mock")
            return _load_mock_module(name)

        tool_manager = getattr(mcp_instance, "_tool_manager", None)
        if not tool_manager:
            logger.warning(f"No _tool_manager in {name}, using mock")
            return _load_mock_module(name)
            return {}

        tools = {}
        for tool_name in tool_manager._tools:
            tool_fn = getattr(mod, tool_name, None)
            if tool_fn and callable(tool_fn):
                tools[tool_name] = tool_fn

        _MCP_REGISTRY[name] = tools
        logger.info(f"Loaded MCP {name}: {len(tools)} tools ({', '.join(tools.keys())})")
        return tools
    except (SystemExit, Exception) as e:
        logger.warning(f"Failed to load FastMCP {name}: {e}, using mock")
        return _load_mock_module(name)

def _load_lowlevel_module(name: str, filename: str) -> dict[str, Callable]:
    """Load mock wrappers for low-level mcp.server.Server modules."""
    wrappers = _get_lowlevel_mocks(name)
    _MCP_REGISTRY[name] = wrappers
    logger.info(f"Loaded MCP {name} (mock): {len(wrappers)} tools ({', '.join(wrappers.keys())})")
    return wrappers


def _load_mock_module(name: str) -> dict[str, Callable]:
    """Load mock wrappers for FastMCP modules that failed to load."""
    wrappers = _get_fastmcp_mocks(name)
    _MCP_REGISTRY[name] = wrappers
    logger.info(f"Loaded MCP {name} (mock fallback): {len(wrappers)} tools ({', '.join(wrappers.keys())})")
    return wrappers


def _get_fastmcp_mocks(name: str) -> dict[str, Callable]:
    """Return mock tool functions for FastMCP servers that can't be loaded."""
    mocks: dict[str, Callable] = {}

    def _json_tool(fn):
        async def wrapper(**kwargs):
            result = await fn(**kwargs)
            if isinstance(result, str):
                return result
            return json.dumps(result, ensure_ascii=False)
        wrapper.__name__ = fn.__name__
        return wrapper

    if name == "device-config":
        @_json_tool
        async def gnmi_get(**kw):
            return {"source": kw.get("target", "mock"), "path": kw.get("path", "/"), "data": "mock-config-data", "encoding": "JSON"}

        @_json_tool
        async def gnmi_set(**kw):
            return {"status": "applied", "target": kw.get("target", "mock"), "changes": 1}

        @_json_tool
        async def gnmi_list_targets(**kw):
            devices = _load_topology_devices()
            targets = [{"name": d.get("name", "unknown"), "address": d.get("ip", ""), "port": 57400,
                        "vendor": d.get("vendor", "unknown")} for d in devices[:10]]
            return {"targets": targets, "total": len(targets)}

        @_json_tool
        async def ssh_run_command(**kw):
            return {"output": "! Command: show version\nCyberClaw Mock Device v1.0\nUptime: 4 hours", "exit_code": 0}

        @_json_tool
        async def ssh_get_config(**kw):
            config_lines = [
                "hostname Camera-Hall-01", "interface GigabitEthernet0/1",
                " ip address 192.168.10.12 255.255.255.0", " no shutdown",
                "snmp-server community public RO", "ssh version 2",
            ]
            return {"output": "\n".join(config_lines), "target": kw.get("target", "mock")}

        @_json_tool
        async def ssh_configure(**kw):
            return {"status": "applied", "target": kw.get("target", "mock"), "commands_applied": len(kw.get("commands", []))}

        @_json_tool
        async def gnmi_capabilities(**kw):
            return {"models": [{"name": "openconfig-interfaces", "version": "2.4.0"},
                               {"name": "openconfig-system", "version": "0.6.0"}],
                    "encodings": ["JSON", "PROTOBUF"]}

        mocks = {
            "gnmi_get": gnmi_get, "gnmi_set": gnmi_set, "gnmi_list_targets": gnmi_list_targets,
            "ssh_run_command": ssh_run_command, "ssh_get_config": ssh_get_config,
            "ssh_configure": ssh_configure, "gnmi_capabilities": gnmi_capabilities,
        }

    elif name == "simulation":
        @_json_tool
        async def gns3_list_projects(**kw):
            return {"projects": [{"project_id": "mock-001", "name": "IoT-Security-Lab", "status": "opened",
                                  "nodes": 15, "links": 20}]}

        @_json_tool
        async def gns3_list_templates(**kw):
            return {"templates": [{"template_id": "tpl-001", "name": "IoT Camera", "category": "router"},
                                  {"template_id": "tpl-002", "name": "Switch L2", "category": "switch"}]}

        @_json_tool
        async def gns3_list_nodes(**kw):
            devices = _load_topology_devices()
            nodes = [{"node_id": f"node-{i}", "name": d.get("name", f"node-{i}"),
                      "status": "started", "console": 5000 + i,
                      "template": "IoT Camera"} for i, d in enumerate(devices[:10])]
            return {"nodes": nodes, "total": len(nodes)}

        @_json_tool
        async def gns3_deploy_iot_topology(**kw):
            return {"project_id": "mock-001", "status": "deployed", "nodes_created": 15, "links_created": 20}

        @_json_tool
        async def gns3_start_node(**kw):
            return {"node_id": kw.get("node_id", "mock"), "status": "started"}

        @_json_tool
        async def gns3_stop_node(**kw):
            return {"node_id": kw.get("node_id", "mock"), "status": "stopped"}

        mocks = {
            "gns3_list_projects": gns3_list_projects, "gns3_list_templates": gns3_list_templates,
            "gns3_list_nodes": gns3_list_nodes, "gns3_deploy_iot_topology": gns3_deploy_iot_topology,
            "gns3_start_node": gns3_start_node, "gns3_stop_node": gns3_stop_node,
        }

    return mocks


def _get_lowlevel_mocks(name: str) -> dict[str, Callable]:
    """Return mock tool functions for low-level MCP servers."""
    mocks: dict[str, Callable] = {}

    def _json_tool(fn):
        """Decorator to ensure JSON-serializable output."""
        async def wrapper(**kwargs):
            result = await fn(**kwargs)
            if isinstance(result, str):
                return result
            return json.dumps(result, ensure_ascii=False)
        wrapper.__name__ = fn.__name__
        return wrapper

    if name == "syslog-collector":
        @_json_tool
        async def syslog_start_receiver(**kw):
            return {"status": "started", "port": kw.get("port", 514), "protocol": kw.get("protocol", "udp")}

        @_json_tool
        async def syslog_stop_receiver(**kw):
            return {"status": "stopped"}

        @_json_tool
        async def syslog_get_status(**kw):
            return {"status": "running", "port": 514, "messages_received": 847, "messages_stored": 623,
                    "started_at": (datetime.utcnow() - timedelta(hours=4)).isoformat(), "protocol": "udp"}

        @_json_tool
        async def syslog_query(**kw):
            return _mock_syslog_data()

        @_json_tool
        async def syslog_get_message(**kw):
            return {"id": kw.get("message_id", "mock-001"), "severity": "warning", "facility": 1,
                    "hostname": "Camera-Hall-01", "message": "Authentication failure from 192.168.10.55",
                    "source_ip": "192.168.10.12", "received_at": datetime.utcnow().isoformat()}

        @_json_tool
        async def syslog_get_severity_counts(**kw):
            return {"counts": {"emergency": 0, "alert": 1, "critical": 3, "error": 12,
                               "warning": 45, "notice": 234, "informational": 512, "debug": 0},
                    "total": 807}

        mocks = {
            "syslog_start_receiver": syslog_start_receiver,
            "syslog_stop_receiver": syslog_stop_receiver,
            "syslog_get_status": syslog_get_status,
            "syslog_query": syslog_query,
            "syslog_get_message": syslog_get_message,
            "syslog_get_severity_counts": syslog_get_severity_counts,
        }

    elif name == "snmp-collector":
        @_json_tool
        async def snmptrap_start_receiver(**kw):
            return {"status": "started", "port": kw.get("port", 162)}

        @_json_tool
        async def snmptrap_stop_receiver(**kw):
            return {"status": "stopped"}

        @_json_tool
        async def snmptrap_get_status(**kw):
            return {"status": "running", "port": 162, "traps_received": 156,
                    "started_at": (datetime.utcnow() - timedelta(hours=4)).isoformat()}

        @_json_tool
        async def snmptrap_query(**kw):
            return _mock_snmptrap_data()

        @_json_tool
        async def snmptrap_get_trap(**kw):
            return {"id": kw.get("trap_id", "mock-001"), "source_ip": "192.168.10.11",
                    "trap_oid": "1.3.6.1.2.1.1.3.0", "version": "2c",
                    "variables": [{"oid": "1.3.6.1.2.1.1.1.0", "value": "Hikvision Camera"}],
                    "received_at": datetime.utcnow().isoformat()}

        @_json_tool
        async def snmptrap_get_counts(**kw):
            return {"counts": {"linkUp": 23, "linkDown": 2, "authenticationFailure": 5,
                               "coldStart": 1, "warmStart": 0}, "total": 31}

        mocks = {
            "snmptrap_start_receiver": snmptrap_start_receiver,
            "snmptrap_stop_receiver": snmptrap_stop_receiver,
            "snmptrap_get_status": snmptrap_get_status,
            "snmptrap_query": snmptrap_query,
            "snmptrap_get_trap": snmptrap_get_trap,
            "snmptrap_get_counts": snmptrap_get_counts,
        }

    elif name == "flow-analyzer":
        @_json_tool
        async def ipfix_start_receiver(**kw):
            return {"status": "started", "port": kw.get("port", 2055)}

        @_json_tool
        async def ipfix_stop_receiver(**kw):
            return {"status": "stopped"}

        @_json_tool
        async def ipfix_get_status(**kw):
            return {"status": "running", "port": 2055, "flows_received": 2341,
                    "started_at": (datetime.utcnow() - timedelta(hours=4)).isoformat()}

        @_json_tool
        async def ipfix_query_flows(**kw):
            return _mock_flow_data()

        @_json_tool
        async def ipfix_get_flow(**kw):
            return {"id": kw.get("flow_id", "mock-001"), "src_ip": "192.168.10.100",
                    "dst_ip": "10.0.0.5", "src_port": 49152, "dst_port": 443,
                    "protocol": "TCP", "bytes": 4567, "packets": 32,
                    "start_time": datetime.utcnow().isoformat(), "duration_seconds": 5.2}

        @_json_tool
        async def ipfix_top_talkers(**kw):
            return {"top_by_bytes": [
                {"ip": "192.168.10.100", "bytes": 524288, "flows": 45},
                {"ip": "192.168.10.55", "bytes": 262144, "flows": 23},
                {"ip": "192.168.10.12", "bytes": 131072, "flows": 12},
            ], "top_by_flows": [
                {"ip": "192.168.10.100", "flows": 45, "bytes": 524288},
                {"ip": "192.168.10.55", "flows": 23, "bytes": 262144},
            ]}

        @_json_tool
        async def ipfix_get_templates(**kw):
            return {"templates": [
                {"template_id": 256, "field_count": 12, "source_ip": "192.168.10.1"},
                {"template_id": 257, "field_count": 8, "source_ip": "192.168.10.1"},
            ], "total": 2}

        mocks = {
            "ipfix_start_receiver": ipfix_start_receiver,
            "ipfix_stop_receiver": ipfix_stop_receiver,
            "ipfix_get_status": ipfix_get_status,
            "ipfix_query_flows": ipfix_query_flows,
            "ipfix_get_flow": ipfix_get_flow,
            "ipfix_top_talkers": ipfix_top_talkers,
            "ipfix_get_templates": ipfix_get_templates,
        }

    return mocks


def _load_subnet() -> str:
    """Load the target subnet from topology config."""
    topo_path = PROJECT_ROOT / "config" / "topology.json"
    try:
        with open(topo_path, encoding="utf-8") as f:
            topo = json.load(f)
            return topo.get("network", {}).get("subnet", "192.168.10.0/24")
    except Exception:
        return "192.168.10.0/24"


def _load_topology_devices() -> list[dict]:
    """Load device list from topology config for mock data."""
    topo_path = PROJECT_ROOT / "config" / "topology.json"
    try:
        with open(topo_path, encoding="utf-8") as f:
            topo = json.load(f)
            return topo.get("devices", [])
    except Exception:
        return []


def _mock_syslog_data() -> dict:
    """Generate mock syslog data based on topology devices."""
    devices = _load_topology_devices()
    messages = []
    severities = ["informational", "notice", "warning", "error", "critical"]
    templates = [
        "Authentication failure from {ip}",
        "Interface GigabitEthernet0/1 link status changed to down",
        "Config changed by admin from {ip}",
        "TCP connection timeout to {ip}:443",
        "Firmware update available: v{ver}",
        "Memory usage exceeded 80% threshold",
        "SSH login successful from {ip}",
        "Certificate expires in 7 days",
    ]
    import random
    for i, dev in enumerate(devices[:15]):
        for j in range(random.randint(1, 4)):
            ip = dev.get("ip", f"192.168.10.{i+1}")
            tmpl = random.choice(templates)
            messages.append({
                "id": f"syslog-{i:03d}-{j:03d}",
                "severity": random.choice(severities),
                "facility": random.randint(0, 23),
                "hostname": dev.get("name", f"device-{i}"),
                "source_ip": ip,
                "message": tmpl.format(ip=f"192.168.10.{random.randint(1,254)}", ver=f"2.{random.randint(0,9)}.{random.randint(0,9)}"),
                "received_at": (datetime.utcnow() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            })
    return {"messages": messages[:50], "total": len(messages), "query": {"limit": 50}}


def _mock_snmptrap_data() -> dict:
    """Generate mock SNMP trap data based on topology devices."""
    devices = _load_topology_devices()
    traps = []
    trap_types = [
        ("linkUp", "1.3.6.1.2.1.2.2.1.8.1", "Interface up"),
        ("linkDown", "1.3.6.1.2.1.2.2.1.8.1", "Interface down"),
        ("authenticationFailure", "1.3.6.1.2.1.11.0", "Auth failure"),
        ("coldStart", "1.3.6.1.2.1.1.3.0", "Device restarted"),
    ]
    import random
    for i, dev in enumerate(devices[:15]):
        if random.random() > 0.6:
            t_type, t_oid, t_desc = random.choice(trap_types)
            traps.append({
                "id": f"trap-{i:03d}",
                "source_ip": dev.get("ip", f"192.168.10.{i+1}"),
                "trap_type": t_type,
                "trap_oid": t_oid,
                "version": "2c",
                "description": t_desc,
                "variables": [{"oid": t_oid, "value": t_desc}],
                "received_at": (datetime.utcnow() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            })
    return {"traps": traps, "total": len(traps), "query": {}}


def _mock_flow_data() -> dict:
    """Generate mock IPFIX/NetFlow data based on topology devices."""
    devices = _load_topology_devices()
    flows = []
    import random
    for i in range(30):
        src_dev = random.choice(devices) if devices else {"ip": f"192.168.10.{random.randint(1,20)}"}
        flows.append({
            "id": f"flow-{i:04d}",
            "src_ip": src_dev.get("ip", f"192.168.10.{random.randint(1,20)}"),
            "dst_ip": f"10.0.0.{random.randint(1,10)}",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 554, 8080, 8443, 161, 502]),
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes": random.randint(64, 1048576),
            "packets": random.randint(1, 500),
            "start_time": (datetime.utcnow() - timedelta(seconds=random.randint(1, 3600))).isoformat(),
            "duration_seconds": round(random.uniform(0.1, 60.0), 2),
        })
    return {"flows": flows, "total": len(flows), "query": {}}


def _load_all():
    """Load all MCP server modules."""
    for name, (filename, framework) in _MCP_REGISTRY_DEF.items():
        if framework == "fastmcp":
            _load_fastmcp_module(name, filename)
        elif framework == "lowlevel":
            _load_lowlevel_module(name, filename)


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
        result = await asyncio.wait_for(fn(**kwargs), timeout=120.0)
        if isinstance(result, str):
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw": result}
        return result
    except asyncio.TimeoutError:
        logger.warning(f"MCP tool timed out: {server}/{tool} (120s)")
        return {"error": f"Tool {server}/{tool} timed out after 120s"}
    except Exception as e:
        logger.error(f"MCP tool call failed: {server}/{tool}: {e}")
        return {"error": str(e)}


# ── Intent-based tool orchestration ───────────────────────────────

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
        {"server": "nmap-scan", "tool": "iot_fingerprint", "args": {"target": _SUBNET}},
    ],
    r"恢复|restore|解除|解封": [
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
    r"syslog|日志|系统日志": [
        {"server": "syslog-collector", "tool": "syslog_query", "args": {}},
    ],
    r"SNMP|trap|snmp": [
        {"server": "snmp-collector", "tool": "snmptrap_query", "args": {}},
    ],
    r"netflow|ipfix|flow.*分析": [
        {"server": "flow-analyzer", "tool": "ipfix_query_flows", "args": {}},
    ],
    r"配置管理|设备配置|device.config": [
        {"server": "device-config", "tool": "ssh_get_config", "args": {}},
    ],
    r"仿真|模拟|GNS3|gns3|拓扑.*模拟": [
        {"server": "simulation", "tool": "gns3_list_projects", "args": {}},
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
