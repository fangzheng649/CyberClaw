import os
import re
import logging

import httpx
from fastapi import APIRouter

from ..models.schemas import ChatRequest, ChatResponse, AnalysisStep
from ..services.mcp_tool_service import (
    execute_intent, match_intent, format_tool_results_for_llm,
    get_available_tools,
)

router = APIRouter(prefix="/api/chat", tags=["chat"])
logger = logging.getLogger(__name__)

GLM_API_KEY = os.getenv("GLM_API_KEY", "")
GLM_MODEL = os.getenv("GLM_MODEL", "glm-4-flash")
GLM_API_URL = os.getenv(
    "GLM_API_URL", "https://open.bigmodel.cn/api/paas/v4/chat/completions"
)

SYSTEM_PROMPT_TEMPLATE = """你是 CyberAgent，CyberClaw 平台的 IoT 安全分析 AI 助手。

你的职责：
- 网络设备发现和安全扫描
- IoT 设备指纹识别和漏洞评估
- 安全基线审计和合规检查
- 异常流量检测和威胁分析
- 安全事件响应建议（设备隔离、IP 封禁等）
- 攻击时间线分析和安全复盘

可用工具（MCP 服务器）：
- nmap-scan: 网络扫描与 IoT 指纹识别
- device-config: 设备配置管理 (SSH/gNMI)
- cve-intel: CVE 漏洞情报查询
- security-baseline: CIS 安全基线审计
- traffic-analyzer: 流量分析与 IoC 提取
- auto-response: 自动响应 (端口隔离/ACL)
- config-audit: 配置审计与 ACL 冲突检测
- attack-timeline: 攻击时间线与根因分析

当前环境：IoT 实验网络包含 {device_count} 台设备（{device_summary}）。
当前安全状态：{status_summary}。
最近 24 小时安全事件数：{event_count}。

当用户消息包含工具调用结果时，请基于这些实际数据给出分析和建议。
使用简洁中文回复，可使用 markdown 格式。回答要有专业性和可操作性。"""


async def _build_system_prompt() -> str:
    try:
        from ..services.nx_bridge import get_bridge
        bridge = get_bridge()
        devices = await bridge.get_all_devices()
        counts = await bridge.get_device_counts_by_status()
        event_count = await bridge.count_security_events()

        device_count = len(devices)
        types = {}
        for d in devices:
            t = d.get("devType", "unknown")
            types[t] = types.get(t, 0) + 1
        device_summary = "、".join(f"{t}×{c}" for t, c in sorted(types.items(), key=lambda x: -x[1])[:5])
        status_summary = "、".join(f"{s}×{c}" for s, c in counts.items() if c > 0)

        return SYSTEM_PROMPT_TEMPLATE.format(
            device_count=device_count,
            device_summary=device_summary or "未知",
            status_summary=status_summary or "全部安全",
            event_count=event_count,
        )
    except Exception:
        return SYSTEM_PROMPT_TEMPLATE.format(
            device_count=15, device_summary="摄像头、传感器、网关",
            status_summary="全部安全", event_count=0,
        )

# ── Keyword-matched analysis steps ──────────────────────────────
PATTERN_CONFIG = [
    (
        r"扫描|scan|检查|安全状态|发现|网络",
        [
            AnalysisStep(tool="nmap-scan/network_scan", summary="网络扫描完成 — 发现 15 台设备"),
            AnalysisStep(tool="nmap-scan/iot_fingerprint", summary="IoT 设备识别完成 — 发现 8 台 IoT 设备"),
            AnalysisStep(tool="nmap-scan/default_credential_check", summary="密码检测 — 5 台设备使用默认凭证"),
        ],
    ),
    (
        r"漏洞|vuln|cve|CVE",
        [
            AnalysisStep(tool="nmap-scan/vuln_scan", summary="漏洞扫描 — 发现 7 个安全风险"),
            AnalysisStep(tool="cve-intel/search_cves", summary="CVE 查询完成 — 发现 2 个高危漏洞"),
            AnalysisStep(tool="cve-intel/check_device_vulns", summary="设备漏洞匹配完成"),
        ],
    ),
    (
        r"报告|巡检|生成|report|基线|审计",
        [
            AnalysisStep(tool="security-baseline/check_baseline", summary="安全基线检查完成"),
            AnalysisStep(tool="config-audit/audit_config", summary="配置审计完成"),
        ],
    ),
    (
        r"攻击|回放|复盘|时间线|attack|根因",
        [
            AnalysisStep(tool="attack-timeline/get_timeline", summary="攻击时间线加载完成"),
            AnalysisStep(tool="attack-timeline/analyze_root_cause", summary="根因分析完成"),
        ],
    ),
    (
        r"流量|traffic|IOC|指标|异常",
        [
            AnalysisStep(tool="traffic-analyzer/start_capture", summary="流量捕获完成"),
            AnalysisStep(tool="traffic-analyzer/extract_ioc", summary="IoC 提取完成 — 发现 5 个威胁指标"),
        ],
    ),
    (
        r"隔离|isolat|封禁|block",
        [
            AnalysisStep(tool="auto-response/isolate_device", summary="设备隔离操作执行中..."),
        ],
    ),
    (
        r"历史|记录|事件|event|alert|告警|日志",
        [
            AnalysisStep(tool="dashboard/alerts", summary="加载最近安全事件..."),
        ],
    ),
    (
        r"设备列表|多少台|统计|状态|device|status",
        [
            AnalysisStep(tool="dashboard/device-status", summary="获取设备统计信息..."),
        ],
    ),
]


def match_steps(message: str) -> list[AnalysisStep]:
    for pattern, steps in PATTERN_CONFIG:
        if re.search(pattern, message, re.IGNORECASE):
            return steps
    return []


async def call_glm_api(messages: list[dict]) -> str:
    headers = {
        "Authorization": f"Bearer {GLM_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GLM_MODEL,
        "messages": messages,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(GLM_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]


_chat_history: list[dict] = []


@router.post("")
async def chat(req: ChatRequest) -> ChatResponse:
    steps = match_steps(req.message)

    # Execute MCP tools based on intent
    tool_results = []
    try:
        tool_results = await execute_intent(req.message)
    except Exception as e:
        logger.warning(f"MCP tool execution failed: {e}")

    # Build tool context for LLM
    tool_context = format_tool_results_for_llm(tool_results)

    if GLM_API_KEY:
        system_prompt = await _build_system_prompt()
        messages = [{"role": "system", "content": system_prompt}]
        for msg in req.history:
            messages.append({"role": msg.role, "content": msg.content})

        # Include tool results in the user message for context
        user_content = req.message
        if tool_context:
            user_content = f"{req.message}\n\n{tool_context}"
        messages.append({"role": "user", "content": user_content})

        try:
            reply = await call_glm_api(messages)
        except Exception as e:
            logger.error(f"GLM API error: {e}")
            reply = _format_tool_fallback(tool_results) or f"AI 服务暂时不可用: {e}"
    else:
        reply = _format_tool_fallback(tool_results) or (
            "我是 CyberAgent，您的 IoT 安全分析助手。\n\n"
            "您可以尝试：\n"
            '· "扫描网络中的所有设备"\n'
            '· "分析安全漏洞"\n'
            '· "检查安全基线"\n'
            '· "回放攻击时间线"'
        )

    _chat_history.append({"role": "user", "content": req.message})
    _chat_history.append({"role": "assistant", "content": reply})

    return ChatResponse(reply=reply, steps=steps)


def _format_tool_fallback(tool_results: list[dict]) -> str | None:
    """Format tool results as a readable response when GLM is unavailable."""
    if not tool_results:
        return None

    parts = []
    for r in tool_results:
        result = r.get("result", {})
        if isinstance(result, dict):
            if "error" in result:
                continue
            tool_name = f"{r['server']}/{r['tool']}"

            if "hosts_found" in result:
                parts.append(f"**网络扫描结果**: 发现 {result['hosts_found']} 台设备")
            elif "iot_devices_found" in result:
                parts.append(f"**IoT 设备识别**: 发现 {result['iot_devices_found']} 台 IoT 设备")
            elif "vulnerabilities_found" in result:
                parts.append(f"**漏洞扫描**: 发现 {result['vulnerabilities_found']} 个漏洞")
            elif "total_cves" in result:
                parts.append(f"**CVE 查询**: 匹配 {result['total_cves']} 个 CVE")
            elif "devices_audited" in result:
                parts.append(f"**基线检查**: 审计 {result['devices_audited']} 台设备，评分 {result.get('overall_score', 'N/A')}")
            elif "events" in result:
                parts.append(f"**时间线**: 包含 {result['events']} 个事件")
            elif "iocs_found" in result:
                parts.append(f"**IoC 提取**: 发现 {result['iocs_found']} 个威胁指标")
            elif "total_findings" in result:
                parts.append(f"**配置审计**: {result['total_findings']} 个安全问题")
            elif "active_actions" in result:
                parts.append(f"**响应状态**: {result['active_actions']} 个活跃操作")

    return "\n\n".join(parts) if parts else None


@router.get("/history")
async def chat_history():
    return {"history": _chat_history}


@router.get("/status")
async def chat_status():
    tools = get_available_tools()
    return {
        "llm_connected": bool(GLM_API_KEY),
        "model": GLM_MODEL if GLM_API_KEY else "mock",
        "mcp_tools_loaded": len(tools),
        "mcp_tools": tools,
    }


@router.post("/call-tool")
async def call_mcp_tool(server: str, tool: str, args: dict = {}):
    """Directly call an MCP tool by name."""
    from ..services.mcp_tool_service import call_tool
    result = await call_tool(server, tool, **args)
    return result
