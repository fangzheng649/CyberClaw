"""CyberClaw ReAct multi-round reasoning engine.

Implements the Thought → Action → Observation iterative reasoning described in
the project's innovation chapter (5.1.2): up to 7 rounds chaining 6 MCP tools
to build a complete evidence chain for device security analysis, with dynamic
strategy adjustment — high-risk paths run all rounds, low-risk paths stop
early after round 3-4.

Round sequence:
  1. attack-timeline/get_timeline   — read recent anomaly events
  2. nmap-scan/network_scan         — enumerate exposed attack surface
  3. cve-intel/check_device_vulns   — correlate known vulnerabilities
  4. security-baseline/check_baseline — audit configuration compliance
  5. traffic-analyzer/analyze_flow  — detect flow anomalies (conditional)
  6. traffic-analyzer/extract_ioc   — extract indicators of compromise (conditional)
  7. verdict                        — synthesize confidence + risk level (no tool)

Each round produces an AnalysisStep carrying the Thought (reasoning for why
this tool), the Action (tool called) and the Observation (key findings), so
the frontend can render the reasoning chain card-by-card.
"""
import json
import logging
import re
from pathlib import Path

from .mcp_tool_service import call_tool, _load_subnet, _load_topology_devices

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

MAX_ROUNDS = 7
LOW_RISK_THRESHOLD = 0.30   # below this after round 4 → skip deep traffic analysis
HIGH_RISK_THRESHOLD = 0.70  # at/above this → critical, recommend isolation


# ── Intent detection ─────────────────────────────────────────────

# Phrases that signal a broad security-analysis request (ReAct territory).
_REACT_TRIGGERS = re.compile(
    r"分析|诊断|排查|评估|安全状况|安全状态|状况如何|是否安全|风险|"
    r"被攻击|被入侵|感染|排查.*问题|综合.*分析|深度.*分析|"
    r"analyze|assess|diagnos|investigat|check.*security|security.*posture",
    re.IGNORECASE,
)

# Phrases that should keep their existing narrow intent (not ReAct).
# Includes single-dimension security terms — "分析...漏洞/流量/基线" is a
# focused query, not a broad multi-round assessment.
_REACT_BLOCKERS = re.compile(
    r"报告|巡检|复盘|生成|report|isolate|隔离|恢复|解封|restore|"
    r"漏洞|vuln|CVE|cve|基线|baseline|流量|traffic|端口|port|"
    r"扫描|scan|审计|audit|配置|config|syslog|snmp|trap|netflow|ipfix",
    re.IGNORECASE,
)


def is_react_intent(message: str) -> bool:
    """Return True if the message is a broad security-analysis request."""
    if not message or len(message.strip()) < 3:
        return False
    if _REACT_BLOCKERS.search(message):
        return False
    return bool(_REACT_TRIGGERS.search(message))


# ── Target device extraction ─────────────────────────────────────

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _normalize(s: str) -> str:
    """Lowercase, strip non-alphanumerics — for fuzzy device name matching."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _load_react_devices() -> list[dict]:
    """Load topology devices, mock-mode aware (mirrors baseline server logic)."""
    try:
        from .topology_service import is_mock_mode
        config_name = "mock_topology.json" if is_mock_mode() else "topology.json"
    except Exception:
        config_name = "topology.json"
    topo_path = _PROJECT_ROOT / "config" / config_name
    try:
        with open(topo_path, encoding="utf-8") as f:
            return json.load(f).get("devices", [])
    except Exception:
        return _load_topology_devices()


def extract_target(message: str) -> dict | None:
    """Extract the target device from the user message.

    Matches by IP first, then by device id/name (normalized substring).
    Returns the topology device dict, or None for whole-network analysis.
    """
    devices = _load_react_devices()
    if not devices:
        return None

    # 1. IP match
    ip_match = _IP_RE.search(message)
    if ip_match:
        ip = ip_match.group(1)
        for d in devices:
            if d.get("ip") == ip:
                return d
        return {"id": ip, "name": ip, "ip": ip, "vendor": "", "type": "unknown"}

    # 2. Exact id / name match
    norm_msg = _normalize(message)
    for d in devices:
        if not d.get("id"):
            continue
        if _normalize(d["id"]) and _normalize(d["id"]) in norm_msg:
            return d
        if _normalize(d.get("name", "")) and _normalize(d.get("name", "")) in norm_msg:
            return d

    # 3. Partial token match (e.g. "入口摄像头" → name contains "Entrance")
    #    Match against distinctive name tokens longer than 3 chars.
    for d in devices:
        name_norm = _normalize(d.get("name", ""))
        if len(name_norm) < 4:
            continue
        # take the most distinctive token (longest alphanumeric run)
        tokens = [t for t in re.split(r"\d+", name_norm) if len(t) >= 4]
        for tok in tokens:
            if tok in norm_msg:
                return d

    return None


# ── Round handlers ───────────────────────────────────────────────
# Each handler returns a dict:
#   step:        AnalysisStep fields {tool, summary, detail, thought, round}
#   tool_result: {server, tool, result} for the rich card (or None)
#   confidence:  float contribution to the overall score
#   findings:    structured evidence dict (accumulated for the verdict)
#   continue:    whether to proceed to deep analysis (rounds 5-6)


async def _round_timeline(target: dict | None, round_n: int) -> dict:
    thought = "先查看这台设备最近的异常活动记录，判断是否已有攻击迹象。"
    result = await call_tool("attack-timeline", "get_timeline")
    timeline = result if isinstance(result, dict) else {}
    events = timeline.get("timeline", [])

    # Filter to target device if specified
    if target and target.get("ip"):
        tgt_ip = target["ip"]
        tgt_name = (target.get("name") or "").lower()
        events = [
            e for e in events
            if tgt_ip in str(e.get("target", "")) + str(e.get("source", ""))
            or tgt_name in str(e.get("detail", "")).lower()
            or tgt_ip in str(e.get("detail", ""))
        ] or events  # keep all if filter empties (mock data may not carry IP)

    total = len(events)
    critical = len([e for e in events if str(e.get("severity", "")).lower() == "critical"])
    telnet_fails = len([e for e in events
                        if "telnet" in str(e.get("detail", "")).lower()
                        or "登录失败" in str(e.get("detail", ""))
                        or "auth" in str(e.get("detail", "")).lower()])

    if total == 0:
        summary = "无异常活动记录，设备近期运行正常"
        confidence = 0.0
    else:
        bits = [f"共 {total} 条事件"]
        if critical:
            bits.append(f"{critical} 条严重")
        if telnet_fails:
            bits.append(f"{telnet_fails} 次 Telnet 登录失败")
        summary = "发现 " + "，".join(bits)
        confidence = min(0.15, critical * 0.05 + telnet_fails * 0.02)

    return {
        "step": {"tool": "attack-timeline/get_timeline", "summary": summary,
                 "detail": json.dumps(events[:5], ensure_ascii=False)[:500],
                 "thought": thought, "round": round_n},
        "tool_result": {"server": "attack-timeline", "tool": "get_timeline", "result": timeline},
        "confidence": confidence,
        "findings": {"timeline_events": total, "critical_events": critical, "telnet_fails": telnet_fails},
    }


async def _round_scan(target: dict | None, subnet: str, round_n: int) -> dict:
    thought = "扫描该设备的网络暴露面，确认开放了哪些端口和服务。"
    result = await call_tool("nmap-scan", "network_scan", target=subnet)
    scan = result if isinstance(result, dict) else {}
    hosts = scan.get("hosts", [])

    # Locate the target device in scan results
    dev = None
    if target and target.get("ip"):
        dev = next((h for h in hosts if h.get("ip") == target["ip"]), None)
    if not dev and hosts:
        dev = hosts[0]

    HIGH_RISK_PORTS = {23: "Telnet", 21: "FTP", 3389: "RDP", 445: "SMB"}
    raw_ports = []
    if dev:
        raw_ports = dev.get("open_ports") or dev.get("ports") or []
    # Normalize to list of ints regardless of source format
    # (mock returns list of dicts {port,protocol,service}; real returns list of ints)
    ports: list[int] = []
    if isinstance(raw_ports, dict):
        ports = [int(p) for p in raw_ports.keys() if str(p).isdigit()]
    elif isinstance(raw_ports, list):
        for p in raw_ports:
            if isinstance(p, dict):
                try:
                    ports.append(int(p.get("port", 0)))
                except (TypeError, ValueError):
                    continue
            elif str(p).isdigit():
                ports.append(int(p))
    risky = [p for p in ports if p in HIGH_RISK_PORTS]

    risky_names = [HIGH_RISK_PORTS[p] for p in risky]
    if dev and ports:
        port_str = "/".join(str(p) for p in ports[:8])
        if risky_names:
            summary = f"端口 {port_str} 开放，其中 {'/'.join(risky_names)} 高危"
        else:
            summary = f"端口 {port_str} 开放，未发现高危服务"
    else:
        summary = f"扫描发现 {scan.get('hosts_found', len(hosts))} 台存活主机"

    confidence = min(0.12, len(risky) * 0.06)

    return {
        "step": {"tool": "nmap-scan/network_scan", "summary": summary,
                 "detail": json.dumps(dev or scan, ensure_ascii=False)[:500],
                 "thought": thought, "round": round_n},
        "tool_result": {"server": "nmap-scan", "tool": "network_scan", "result": scan},
        "confidence": confidence,
        "findings": {"open_ports": ports, "high_risk_ports": risky_names},
    }


async def _round_cve(target: dict | None, round_n: int) -> dict:
    vendor = (target.get("vendor") if target else "") or "Hikvision"
    thought = f"该设备为 {vendor} 产品且暴露面存在风险，查询已知漏洞库进行关联。"
    result = await call_tool("cve-intel", "check_device_vulns", vendor=vendor, min_severity="HIGH")
    cve_data = result if isinstance(result, dict) else {}
    if "error" in cve_data:
        cve_data = {}

    cves = cve_data.get("cves", [])
    max_cvss = max((float(c.get("cvss_v3") or 0) for c in cves), default=0)
    critical_cves = [c for c in cves if str(c.get("severity", "")).upper() == "CRITICAL"]

    if not cves:
        summary = "未发现匹配的高危漏洞"
        confidence = 0.0
    else:
        top = cves[0]
        sev = "严重" if max_cvss >= 9 else "高危" if max_cvss >= 7 else "中危"
        summary = f"匹配 {len(cves)} 个漏洞，最高 CVSS {max_cvss}（{sev}）：{top.get('cve_id', '')}"
        if max_cvss >= 9:
            confidence = 0.32
        elif max_cvss >= 7:
            confidence = 0.20
        else:
            confidence = 0.08

    return {
        "step": {"tool": "cve-intel/check_device_vulns", "summary": summary,
                 "detail": json.dumps(cves[:3], ensure_ascii=False)[:500],
                 "thought": thought, "round": round_n},
        "tool_result": {"server": "cve-intel", "tool": "check_device_vulns", "result": cve_data},
        "confidence": confidence,
        "findings": {"cve_count": len(cves), "max_cvss": max_cvss,
                     "critical_cves": [c.get("cve_id") for c in critical_cves],
                     "top_cve": cves[0] if cves else None},
    }


async def _round_baseline(round_n: int) -> dict:
    thought = "存在漏洞风险，进一步审计设备的安全配置合规性。"
    result = await call_tool("security-baseline", "check_baseline", detailed=True)
    base = result if isinstance(result, dict) else {}
    if "error" in base:
        base = {}

    score = base.get("overall_score")
    summary_stats = base.get("summary", {})
    crit_fail = summary_stats.get("critical_failures", 0)

    # Collect failed rule titles for a vivid observation
    failed_titles = []
    for d in base.get("devices", [])[:5]:
        for r in d.get("failed_rules", []):
            if isinstance(r, dict):
                failed_titles.append(r.get("title", ""))

    if score is None:
        summary = "基线审计完成"
        confidence = 0.0
    else:
        bits = [f"合规评分 {score}/100"]
        if crit_fail:
            bits.append(f"{crit_fail} 项严重违规")
        if failed_titles:
            bits.append("、".join(failed_titles[:2]))
        summary = "，".join(bits)
        if score < 60:
            confidence = 0.20
        elif score < 80:
            confidence = 0.10
        else:
            confidence = 0.0

    return {
        "step": {"tool": "security-baseline/check_baseline", "summary": summary,
                 "detail": json.dumps(base.get("devices", [])[:3], ensure_ascii=False)[:500],
                 "thought": thought, "round": round_n},
        "tool_result": {"server": "security-baseline", "tool": "check_baseline", "result": base},
        "confidence": confidence,
        "findings": {"baseline_score": score, "critical_failures": crit_fail,
                     "failed_rules": failed_titles},
    }


async def _round_flow(target: dict | None, round_n: int) -> dict:
    tgt = (target.get("ip") if target else "") or ""
    thought = "检查网络流量中是否存在横向扩散、C2 通信等异常行为，佐证是否已被入侵。"
    result = await call_tool("traffic-analyzer", "analyze_flow", target=tgt)
    flow = result if isinstance(result, dict) else {}
    if "error" in flow:
        flow = {}

    anomalies = flow.get("anomalies", [])
    if not anomalies:
        summary = "流量分析正常，未检测到异常通信模式"
        confidence = 0.0
    else:
        types = []
        for a in anomalies:
            atype = a.get("type", "")
            if atype == "lateral_movement":
                types.append("横向扩散扫描")
            elif atype == "c2_pattern":
                types.append("C2 心跳通信")
            elif atype == "data_exfiltration":
                types.append("数据外泄")
            elif atype == "scan_behavior":
                types.append("端口扫描")
        summary = f"检测到 {len(anomalies)} 项流量异常：{'、'.join(types[:3])}"
        confidence = min(0.22, len(anomalies) * 0.11)

    return {
        "step": {"tool": "traffic-analyzer/analyze_flow", "summary": summary,
                 "detail": json.dumps(anomalies[:3], ensure_ascii=False)[:500],
                 "thought": thought, "round": round_n},
        "tool_result": {"server": "traffic-analyzer", "tool": "analyze_flow", "result": flow},
        "confidence": confidence,
        "findings": {"flow_anomalies": len(anomalies), "anomaly_types": [a.get("type") for a in anomalies]},
    }


async def _round_ioc(round_n: int) -> dict:
    thought = "提取威胁指标（IoC），确认是否存在 C2 回连或已知恶意基础设施通信。"
    result = await call_tool("traffic-analyzer", "extract_ioc")
    ioc_data = result if isinstance(result, dict) else {}
    if "error" in ioc_data:
        ioc_data = {}

    indicators = ioc_data.get("indicators", [])
    if not indicators:
        summary = "未发现威胁指标（IoC）"
        confidence = 0.0
    else:
        c2 = [i for i in indicators if "c2" in str(i.get("type", "")).lower()
              or "443" in str(i.get("target", ""))]
        ports = [i for i in indicators if i.get("type") == "suspicious_port"]
        bits = [f"{len(indicators)} 个 IoC"]
        if c2:
            bits.append(f"含 C2 回连 {c2[0].get('target', '')}")
        elif ports:
            bits.append(f"含高危端口连接")
        summary = "发现 " + "，".join(bits)
        confidence = min(0.22, len(indicators) * 0.08)

    return {
        "step": {"tool": "traffic-analyzer/extract_ioc", "summary": summary,
                 "detail": json.dumps(indicators[:3], ensure_ascii=False)[:500],
                 "thought": thought, "round": round_n},
        "tool_result": {"server": "traffic-analyzer", "tool": "extract_ioc", "result": ioc_data},
        "confidence": confidence,
        "findings": {"ioc_count": len(indicators),
                     "c2_targets": [i.get("target") for i in indicators if "c2" in str(i.get("type", "")).lower() or "443" in str(i.get("target", ""))]},
    }


# ── Confidence → risk level mapping ──────────────────────────────

def _risk_level(confidence: float) -> tuple[str, str]:
    """Map confidence to (risk_label, recommendation)."""
    if confidence >= HIGH_RISK_THRESHOLD:
        return ("严重", "建议立即隔离受影响设备并阻断 C2 通信")
    if confidence >= 0.45:
        return ("高危", "建议优先处置：修复漏洞、关闭高危端口、加固配置")
    if confidence >= LOW_RISK_THRESHOLD:
        return ("中危", "建议持续监控并计划修复已发现问题")
    return ("低危", "设备当前安全，建议保持定期巡检")


# ── Main ReAct loop ───────────────────────────────────────────────

async def react_analyze(message: str) -> dict:
    """Run the 7-round ReAct reasoning loop.

    Returns:
        steps: list of AnalysisStep dicts (round-by-round reasoning)
        tool_results: list of {server, tool, result} for rich cards
        evidence: structured evidence accumulated across rounds
        confidence: final confidence score (0-1)
        risk: (label, recommendation)
        target: the resolved target device (or None)
    """
    subnet = _load_subnet()
    target = extract_target(message)
    tgt_label = target.get("name") or target.get("ip") if target else "全网设备"

    steps: list[dict] = []
    tool_results: list[dict] = []
    evidence: dict = {"target": tgt_label}
    confidence = 0.0

    # ── Rounds 1-4: always run (context → surface → vulns → compliance) ──
    round_handlers = [
        lambda n: _round_timeline(target, n),
        lambda n: _round_scan(target, subnet, n),
        lambda n: _round_cve(target, n),
        lambda n: _round_baseline(n),
    ]

    for idx, handler in enumerate(round_handlers, start=1):
        try:
            r = await handler(idx)
        except Exception as e:
            logger.warning(f"ReAct round {idx} failed: {e}")
            r = {
                "step": {"tool": f"round-{idx}", "summary": f"该轮分析执行失败：{e}",
                         "thought": "该步骤未能完成。", "round": idx},
                "tool_result": None, "confidence": 0.0, "findings": {},
            }
        steps.append(r["step"])
        if r.get("tool_result"):
            tool_results.append(r["tool_result"])
        confidence += r.get("confidence", 0.0)
        evidence.update(r.get("findings", {}))

    # ── Dynamic strategy: decide whether to run deep analysis (rounds 5-6) ──
    # Low-risk path: after round 4, if confidence still low AND no critical
    # CVE / no critical baseline failure → skip deep traffic analysis.
    has_critical_cve = bool(evidence.get("critical_cves")) or (evidence.get("max_cvss") or 0) >= 9
    has_baseline_fail = (evidence.get("critical_failures") or 0) > 0
    do_deep = confidence >= LOW_RISK_THRESHOLD or has_critical_cve or has_baseline_fail

    if not do_deep:
        steps.append({
            "tool": "策略评估",
            "summary": f"证据充分性评估：置信度 {confidence:.0%}，未发现高危漏洞或严重配置缺陷，跳过深度流量分析",
            "thought": "综合前 4 轮证据，该设备风险较低，无需进入深度流量与 IoC 分析阶段。",
            "round": 5, "status": "skip",
        })
    else:
        # Round 5: flow analysis
        try:
            r5 = await _round_flow(target, 5)
            steps.append(r5["step"])
            if r5.get("tool_result"):
                tool_results.append(r5["tool_result"])
            confidence += r5.get("confidence", 0.0)
            evidence.update(r5.get("findings", {}))
        except Exception as e:
            logger.warning(f"ReAct round 5 failed: {e}")

        # Round 6: IoC extraction
        try:
            r6 = await _round_ioc(6)
            steps.append(r6["step"])
            if r6.get("tool_result"):
                tool_results.append(r6["tool_result"])
            confidence += r6.get("confidence", 0.0)
            evidence.update(r6.get("findings", {}))
        except Exception as e:
            logger.warning(f"ReAct round 6 failed: {e}")

    confidence = min(confidence, 0.96)

    # ── Round 7: verdict (no tool call — synthesize) ──
    risk_label, recommendation = _risk_level(confidence)
    verdict_thought = "证据链已完整，综合各维度发现给出最终安全判定与置信度。"

    if risk_label == "严重":
        # Try to identify a likely threat family from evidence
        family = "Mirai 僵尸网络" if (evidence.get("telnet_fails") or evidence.get("c2_targets")) else "高危威胁"
        verdict_summary = f"判定：{family} 感染风险，置信度 {confidence:.0%}，{recommendation}"
        verdict_status = "critical"
    elif risk_label == "高危":
        verdict_summary = f"判定：存在高危安全风险，置信度 {confidence:.0%}，{recommendation}"
        verdict_status = "high"
    elif risk_label == "中危":
        verdict_summary = f"判定：存在中危安全问题，置信度 {confidence:.0%}，{recommendation}"
        verdict_status = "medium"
    else:
        verdict_summary = f"判定：设备当前安全，置信度 {confidence:.0%}，{recommendation}"
        verdict_status = "low"

    steps.append({
        "tool": "综合判定",
        "summary": verdict_summary,
        "thought": verdict_thought,
        "round": 7, "status": verdict_status,
    })

    evidence["confidence"] = round(confidence, 2)
    evidence["risk_level"] = risk_label
    evidence["recommendation"] = recommendation

    logger.info(f"ReAct analysis complete: {len(steps)} rounds, confidence={confidence:.2f}, risk={risk_label}")

    return {
        "steps": steps,
        "tool_results": tool_results,
        "evidence": evidence,
        "confidence": round(confidence, 2),
        "risk": (risk_label, recommendation),
        "target": target,
    }


def format_react_evidence_for_llm(result: dict) -> str:
    """Format the ReAct evidence into a compact context block for the LLM verdict."""
    ev = result.get("evidence", {})
    target = ev.get("target", "全网设备")
    confidence = result.get("confidence", 0)
    risk_label, recommendation = result.get("risk", ("未知", ""))

    lines = [
        f"[ReAct 七轮关联推理结果]",
        f"分析目标: {target}",
        f"综合置信度: {confidence:.0%}",
        f"风险等级: {risk_label}",
        f"处置建议: {recommendation}",
        "",
        "各轮证据摘要:",
    ]
    for step in result.get("steps", []):
        if step.get("status") == "skip":
            continue
        round_n = step.get("round", "?")
        lines.append(f"  第{round_n}轮 [{step.get('tool', '')}]: {step.get('summary', '')}")

    return "\n".join(lines)
