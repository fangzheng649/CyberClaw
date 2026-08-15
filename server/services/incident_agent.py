"""CyberClaw Incident Agent — 告警驱动的智能体研判（闭环核心）。

Suricata sev1/sev2 告警 → ReAct 证据链推理(时间线/攻击面/CVE关联/基线)
→ 威胁判定(置信度+风险级) → LLM 生成研判报告 → security_events 落库
+ attack-timeline 记录 + notification WS 推送 chat。

设计要点:
- 去抖: 同 (目标, 攻击特征) 120s 只研判一次(一次攻击可能触发多条告警)
- 双层智能: 证据链(react_engine, 确定性/断网可用) + LLM 研判(DeepSeek, 失败自动
  退化为规则 verdict —— 演示现场断网闭环不断)
- 本模块只研判不动手: 响应执行(隔离等)由响应策略层按 verdict 决定。
"""
import asyncio
import logging
import time

logger = logging.getLogger(__name__)

# (dest_ip, signature) → 上次研判时刻
_recent_incidents: dict[tuple[str, str], float] = {}
_DEBOUNCE_SECONDS = 120

_RISK_SEVERITY = {"严重": "critical", "高危": "warning", "中危": "info", "低危": "info"}


def _should_analyze(dest_ip: str, signature: str) -> bool:
    """去抖: 同目标同攻击特征 120s 内只研判一次。"""
    now = time.time()
    key = (dest_ip, signature)
    last = _recent_incidents.get(key, 0)
    if now - last < _DEBOUNCE_SECONDS:
        return False
    _recent_incidents[key] = now
    # 防止字典无限增长
    if len(_recent_incidents) > 200:
        for k, t in list(_recent_incidents.items()):
            if now - t > _DEBOUNCE_SECONDS * 10:
                _recent_incidents.pop(k, None)
    return True


async def handle_alert_incident(eve_alert: dict):
    """单条 sev1/sev2 Suricata 告警的完整研判流程(独立 task 运行)。"""
    alert = eve_alert.get("alert", {})
    signature = alert.get("signature", "Unknown Alert")
    severity = alert.get("severity", 3)
    src_ip = eve_alert.get("src_ip", "")
    dst_ip = eve_alert.get("dest_ip", "")
    try:
        if not _should_analyze(dst_ip, signature):
            return

        logger.info(f"[incident_agent] 研判启动: {signature} → {dst_ip}")

        # ── 1. 目标设备身份(从 DB) ──────────────────────────────
        target_name = dst_ip
        try:
            from .nx_bridge import get_bridge
            dev = await get_bridge().get_device_by_ip(dst_ip)
            if dev:
                target_name = dev.get("devName") or dst_ip
        except Exception:
            pass

        # ── 2. ReAct 证据链(确定性工具编排) ────────────────────
        from .react_engine import react_analyze, format_react_evidence_for_llm
        message = (f"分析 {dst_ip} 的安全状况：IDS 告警 [{signature}]（严重级 {severity}），"
                   f"攻击源 {src_ip}，疑似正在遭受攻击，请研判")
        result = await react_analyze(message)
        confidence = result.get("confidence", 0.0)
        risk_label, recommendation = result.get("risk", ("未知", "持续观察"))
        steps = result.get("steps", [])

        # ── 3. LLM 研判报告(失败退化为规则 verdict) ─────────────
        report = ""
        try:
            from ..api.chat import call_deepseek_api
            evidence_text = format_react_evidence_for_llm(result)
            messages = [
                {"role": "system", "content":
                    "你是 IoT 安全平台的威胁研判智能体。基于 IDS 告警与证据链，"
                    "输出简明中文研判报告，格式：①威胁定性 ②证据要点(3条以内) "
                    "③影响评估 ④处置建议(明确是否建议隔离)。全文 150 字以内。"},
                {"role": "user", "content":
                    f"IDS 告警: {signature} (严重级 {severity})\n攻击源: {src_ip} → 目标: {target_name} ({dst_ip})\n"
                    f"ReAct 推理置信度: {confidence:.2f}, 风险判定: {risk_label}\n\n{evidence_text}"},
            ]
            report = await call_deepseek_api(messages)
        except Exception as e:
            logger.warning(f"[incident_agent] LLM 研判不可用, 使用规则判定: {e}")
        if not report:
            report = (f"规则研判：{target_name} 疑似遭受攻击（{signature}）。"
                      f"证据链置信度 {confidence:.2f}，风险等级 {risk_label}。{recommendation}。")

        # ── 4. 结果落库 + 时间线 + chat 推送 ───────────────────
        sev = _RISK_SEVERITY.get(risk_label, "warning")
        headline = f"智能体研判 · {target_name}：{risk_label}（置信度 {confidence:.2f}）"
        try:
            from .nx_bridge import get_bridge
            await get_bridge().record_security_event(
                source_type="incident_agent", severity=sev,
                message=f"{headline}。{report[:200]}",
                target=dst_ip, source=src_ip,
                details={"signature": signature, "confidence": confidence,
                         "risk": risk_label, "rounds": len(steps)})
        except Exception as e:
            logger.debug(f"record incident failed: {e}")

        try:
            from .mcp_tool_service import call_tool
            await call_tool("attack-timeline", "record_event",
                            event_type="incident_analysis", source=src_ip,
                            detail=f"{signature} → {target_name}({dst_ip}) | "
                                   f"{risk_label} 置信度{confidence:.2f} | {report[:120]}",
                            severity=sev)
        except Exception as e:
            logger.debug(f"timeline record failed: {e}")

        try:
            from .notification_bridge import get_notification_bridge
            await get_notification_bridge()._send(
                title=headline, message=report[:300], severity=sev,
                section="security_events", task_type="incident_agent",
                bypass_dedup=True)
        except Exception as e:
            logger.debug(f"incident notify failed: {e}")

        logger.info(f"[incident_agent] 研判完成: {target_name} {risk_label} "
                    f"(置信度 {confidence:.2f})")
    except Exception as e:
        logger.warning(f"[incident_agent] 研判失败 {signature}→{dst_ip}: {e}")
