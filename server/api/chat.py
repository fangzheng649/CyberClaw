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

重要行为规则（必须严格遵守）：
1. 工具结果中标记为「❌ 失败」的 = 执行失败。必须如实告知用户失败原因，绝不能说"执行成功"或"未报错"。
2. 工具已经由系统自动执行完毕，你不需要建议用户去运行任何工具或命令。
3. 直接基于工具返回的数据进行分析。如果工具返回了设备列表、漏洞信息、审计结果等，就分析这些数据；如果工具失败了，就解释失败原因和可能的解决办法。
4. 回答要简洁、聚焦、有针对性。禁止列举泛泛的"操作步骤"或"建议使用XX工具"。
5. 不要假装有数据。如果工具结果为空或失败，就说"未能获取到数据"并解释原因。
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

# ── Tool result → steps ────────────────────────────────────────


def _build_steps_from_results(tool_results: list[dict]) -> list[AnalysisStep]:
    """Generate analysis steps from real tool execution results."""
    steps = []
    for r in tool_results:
        server = r.get("server", "")
        tool = r.get("tool", "")
        result = r.get("result", {})
        if isinstance(result, str):
            try:
                import json
                result = json.loads(result)
            except Exception:
                result = {}
        if not isinstance(result, dict):
            result = {}
        if "error" in result:
            steps.append(AnalysisStep(
                tool=f"{server}/{tool}",
                summary=f"{tool} — 执行失败: {result['error']}",
            ))
            continue

        tool_key = f"{server}/{tool}"
        summary = _summarize_tool(tool_key, result)
        if summary:
            steps.append(AnalysisStep(tool=tool_key, summary=summary, detail=str(result)[:500]))
    return steps


def _summarize_tool(tool_key: str, result: dict) -> str | None:
    """Generate a human-readable summary from a tool result."""
    if "hosts_found" in result:
        n = result["hosts_found"]
        hosts = result.get("hosts", [])
        vendors = set()
        for h in hosts[:20]:
            v = h.get("vendor", "")
            if v:
                vendors.add(v)
        vendor_str = f"（{', '.join(list(vendors)[:4])}）" if vendors else ""
        return f"网络扫描完成 — 发现 {n} 台存活主机{vendor_str}"

    if "iot_devices_found" in result:
        n = result["iot_devices_found"]
        devices = result.get("devices", [])
        types = {}
        for d in devices[:20]:
            t = d.get("type", "unknown")
            types[t] = types.get(t, 0) + 1
        type_str = "、".join(f"{t}×{c}" for t, c in sorted(types.items(), key=lambda x: -x[1])[:4])
        return f"IoT 指纹识别 — {n} 台 IoT 设备（{type_str}）" if type_str else f"IoT 指纹识别 — {n} 台 IoT 设备"

    if "weak_credential_count" in result or "default_creds_found" in result:
        n = result.get("weak_credential_count", result.get("default_creds_found", 0))
        return f"弱密码检测 — {n} 台设备使用默认凭证" if n > 0 else "弱密码检测 — 所有设备密码安全"

    if "vulnerabilities_found" in result:
        n = result["vulnerabilities_found"]
        return f"漏洞扫描 — 发现 {n} 个安全风险" if n > 0 else "漏洞扫描 — 未发现安全风险"

    if "total_cves" in result:
        n = result["total_cves"]
        cves = result.get("cves", [])
        max_cvss = max((c.get("cvss", 0) for c in cves), default=0)
        severity = "高危" if max_cvss >= 7 else "中危" if max_cvss >= 4 else "低危"
        return f"CVE 查询 — 匹配 {n} 个漏洞，最高 CVSS {max_cvss}（{severity}）"

    if "devices_audited" in result:
        n = result["devices_audited"]
        score = result.get("overall_score", "N/A")
        failed = result.get("failed_checks", 0)
        return f"基线审计 — {n} 台设备，合规评分 {score}%，{failed} 项违规" if failed else f"基线审计 — {n} 台设备，合规评分 {score}%"

    if "events" in result:
        n = result["events"]
        return f"时间线加载 — 包含 {n} 个事件"

    if "iocs_found" in result:
        n = result["iocs_found"]
        return f"IoC 提取 — 发现 {n} 个威胁指标" if n > 0 else "IoC 提取 — 未发现威胁指标"

    if "total_findings" in result:
        n = result["total_findings"]
        return f"配置审计 — {n} 个安全问题" if n > 0 else "配置审计 — 未发现问题"

    if "active_actions" in result:
        n = result["active_actions"]
        return f"响应状态 — {n} 个活跃操作"

    if "status" in result:
        s = result["status"]
        if s in ("started", "running"):
            return f"{tool_key.split('/')[-1]} — 任务已启动"
        if s == "completed":
            return f"{tool_key.split('/')[-1]} — 执行完成"

    return None


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
    # Execute MCP tools based on intent
    tool_results = []
    try:
        tool_results = await execute_intent(req.message)
    except Exception as e:
        logger.warning(f"MCP tool execution failed: {e}")

    # Build steps from real tool results
    steps = _build_steps_from_results(tool_results)

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

    # Serialize tool_results for frontend
    serialized_results = []
    for r in tool_results:
        result = r.get("result", {})
        if not isinstance(result, dict):
            result = {"raw": str(result)}
        serialized_results.append({
            "server": r.get("server", ""),
            "tool": r.get("tool", ""),
            "result": result,
        })

    return ChatResponse(reply=reply, steps=steps, tool_results=serialized_results)


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
