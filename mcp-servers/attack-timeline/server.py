"""CyberClaw Attack Timeline MCP Server — event timeline and root cause analysis.

Tools:
  - record_event: Record a security event to the timeline
  - get_timeline: Retrieve the attack timeline for an incident
  - analyze_root_cause: Perform root cause analysis for an incident
  - generate_report: Generate a post-incident review report
"""
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("attack-timeline", "Attack timeline reconstruction, root cause analysis, and incident review")

# In-memory event store
_events: list[dict] = []
_incident_counter = 0

# Attack timeline is built from real events (record_event).
# When empty, get_timeline returns an empty list — no fabricated data.


@mcp.tool()
async def record_event(event_type: str, source: str = "", target: str = "", detail: str = "",
                       severity: str = "info") -> str:
    """Record a security event to the attack timeline.

    Args:
        event_type: Event type (scan, exploit, infection, lateral, response, info).
        source: Source IP or entity.
        target: Target IP or entity.
        detail: Event description.
        severity: Severity: info, warning, critical. Default: info.
    """
    global _incident_counter
    if not _events:
        _incident_counter += 1
    event = {
        "id": f"evt-{int(time.time())}-{len(_events)}",
        "incident_id": f"inc-{_incident_counter:03d}",
        "type": event_type, "source": source, "target": target,
        "detail": detail, "severity": severity,
        "timestamp": datetime.now().isoformat(),
        "t": f"T+{len(_events) * 4}s" if _events else "T+0s",
    }
    _events.append(event)
    logger.info(f"record_event: {event_type} {source} → {target}")
    return json.dumps({"status": "recorded", "event": event}, ensure_ascii=False, indent=2)


@mcp.tool()
async def get_timeline(incident_id: str = "") -> str:
    """Retrieve the attack timeline for an incident.

    Args:
        incident_id: Incident ID. Empty = return mock Mirai attack timeline.
    """
    logger.info(f"get_timeline: incident={incident_id or 'all'}")
    phases = {}
    for evt in _events:
        phase = evt.get("phase", "unknown")
        phases.setdefault(phase, []).append(evt)

    return json.dumps({
        "incident_id": incident_id or "all",
        "events": len(_events),
        "phases": {k: len(v) for k, v in phases.items()},
        "timeline": _events,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def analyze_root_cause(incident_id: str = "") -> str:
    """Perform root cause analysis for an incident.

    Identifies the attack chain, entry point, and contributing factors.

    Args:
        incident_id: Incident ID. Empty = analyze mock incident.
    """
    logger.info(f"analyze_root_cause: {incident_id or 'latest'}")
    if not _events:
        return json.dumps({"error": "No events recorded. Record events first or use the event generator.",
                           "hint": "POST /api/tools/collector/start to begin collecting events."},

                          ensure_ascii=False, indent=2)

    # Build root cause from actual recorded events
    sources = set(e.get("source", "") for e in _events)
    targets = set(e.get("target", "") for e in _events)
    critical_events = [e for e in _events if e.get("severity") == "critical"]
    phases = set(e.get("phase", "unknown") for e in _events if "phase" in e)

    entry_event = _events[0] if _events else {}
    attack_chain = [f"{i+1}. [{e['timestamp'][:19]}] {e.get('detail', e.get('event', ''))}"
                    for i, e in enumerate(_events)]

    return json.dumps({
        "incident": f"事件分析 ({len(_events)} events)",
        "root_cause": {
            "entry_point": entry_event.get("source", "unknown"),
            "first_event": entry_event.get("event", ""),
            "attack_vector": ", ".join(phases) if phases else "unknown",
            "sources": list(sources),
            "targets": list(targets),
        },
        "summary": {
            "total_events": len(_events),
            "critical_events": len(critical_events),
            "phases": list(phases),
            "timespan": f"{_events[0]['timestamp'][:19]} ~ {_events[-1]['timestamp'][:19]}" if len(_events) > 1 else "single event",
        },
        "attack_chain": attack_chain,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def generate_report(incident_id: str = "") -> str:
    """Generate a post-incident review report.

    Args:
        incident_id: Incident ID. Empty = generate for mock incident.
    """
    logger.info(f"generate_report: {incident_id or 'latest'}")
    if not _events:
        return json.dumps({"error": "No events recorded. Cannot generate report.",
                           "hint": "Record events first via record_event or start the event collector."},

                          ensure_ascii=False, indent=2)

    critical = [e for e in _events if e.get("severity") == "critical"]
    targets = set(e.get("target", "") for e in _events)
    sources = set(e.get("source", "") for e in _events)

    return json.dumps({
        "report_id": f"rpt-{int(time.time())}",
        "title": f"安全事件分析报告 ({len(_events)} events)",
        "date": datetime.now().strftime("%Y-%m-%d"),
        "executive_summary": f"共记录 {len(_events)} 个安全事件，其中 {len(critical)} 个严重。涉及 {len(targets)} 个目标设备，{len(sources)} 个来源。",
        "timeline_summary": {
            "total_events": len(_events),
            "critical_events": len(critical),
            "first_event": _events[0]["timestamp"][:19],
            "last_event": _events[-1]["timestamp"][:19],
            "sources": list(sources),
            "targets": list(targets),
        },
        "events": _events,
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw attack-timeline MCP")
    mcp.run()
