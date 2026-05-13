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
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("attack-timeline", "Attack timeline reconstruction, root cause analysis, and incident review")

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
_DB_DIR = os.path.join(_PROJECT_ROOT, "data")
_DB_PATH = os.getenv("CYBERCLAW_TIMELINE_DB", os.path.join(_DB_DIR, "timeline.db"))


def _get_conn() -> sqlite3.Connection:
    """Return a connection to the SQLite database, creating tables if needed."""
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT DEFAULT '',
            event_type TEXT NOT NULL,
            source TEXT DEFAULT '',
            target TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            severity TEXT DEFAULT 'info',
            fsm_state TEXT DEFAULT '',
            timestamp TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


# In-memory event cache (loaded from DB on first access)
_events: list[dict] = []
_events_loaded = False
_incident_counter = 0


def _ensure_events_loaded() -> None:
    """Load events from database into memory cache on first access."""
    global _events, _events_loaded, _incident_counter
    if _events_loaded:
        return
    _events_loaded = True
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM timeline_events ORDER BY id ASC"
        ).fetchall()
        conn.close()
        _events = [dict(r) for r in rows]
        # Recover incident counter from existing data
        if _events:
            max_inc = max(
                (e.get("incident_id", "") for e in _events),
                key=lambda x: int(x.split("-")[1]) if x.startswith("inc-") and x.split("-")[1:].__len__() else 0
            )
            try:
                _incident_counter = int(max_inc.split("-")[1])
            except (ValueError, IndexError):
                _incident_counter = 1
        logger.info(f"Loaded {len(_events)} events from database")
    except Exception as exc:
        logger.warning(f"Failed to load events from database: {exc}")


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

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
    _ensure_events_loaded()

    if not _events:
        _incident_counter += 1
    event = {
        "id": f"evt-{int(time.time())}-{len(_events)}",
        "incident_id": f"inc-{_incident_counter:03d}",
        "event_type": event_type,
        "source": source,
        "target": target,
        "detail": detail,
        "severity": severity,
        "fsm_state": "",
        "timestamp": datetime.now().isoformat(),
    }
    event["t"] = f"T+{len(_events) * 4}s" if _events else "T+0s"

    # Persist to database
    try:
        conn = _get_conn()
        cursor = conn.execute(
            """INSERT INTO timeline_events
               (incident_id, event_type, source, target, detail, severity, fsm_state, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event["incident_id"], event_type, source, target, detail, severity,
             event["fsm_state"], event["timestamp"]),
        )
        event["id"] = cursor.lastrowid
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.warning(f"Failed to persist event to database: {exc}")

    # Update in-memory cache
    _events.append(event)
    logger.info(f"record_event: {event_type} {source} -> {target}")
    return json.dumps({"status": "recorded", "event": event}, ensure_ascii=False, indent=2)


@mcp.tool()
async def get_timeline(incident_id: str = "") -> str:
    """Retrieve the attack timeline for an incident.

    Args:
        incident_id: Incident ID. Empty = return all events.
    """
    logger.info(f"get_timeline: incident={incident_id or 'all'}")
    _ensure_events_loaded()

    # Load from database for freshest data
    try:
        conn = _get_conn()
        if incident_id:
            rows = conn.execute(
                "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY id ASC",
                (incident_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM timeline_events ORDER BY id ASC"
            ).fetchall()
        conn.close()
        events = [dict(r) for r in rows]
    except Exception:
        # Fallback to memory cache
        events = _events if not incident_id else [e for e in _events if e.get("incident_id") == incident_id]

    phases = {}
    for evt in events:
        phase = evt.get("event_type", "unknown")
        phases.setdefault(phase, []).append(evt)

    return json.dumps({
        "incident_id": incident_id or "all",
        "events": len(events),
        "phases": {k: len(v) for k, v in phases.items()},
        "timeline": events,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def analyze_root_cause(incident_id: str = "") -> str:
    """Perform root cause analysis for an incident.

    Identifies the attack chain, entry point, and contributing factors.

    Args:
        incident_id: Incident ID. Empty = analyze all events.
    """
    logger.info(f"analyze_root_cause: {incident_id or 'latest'}")
    _ensure_events_loaded()

    # Load from database
    try:
        conn = _get_conn()
        if incident_id:
            rows = conn.execute(
                "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY id ASC",
                (incident_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM timeline_events ORDER BY id ASC"
            ).fetchall()
        conn.close()
        events = [dict(r) for r in rows]
    except Exception:
        events = _events if not incident_id else [e for e in _events if e.get("incident_id") == incident_id]

    if not events:
        return json.dumps({"error": "No events recorded. Record events first or use the event generator.",
                           "hint": "POST /api/tools/collector/start to begin collecting events."},
                          ensure_ascii=False, indent=2)

    # Build root cause from actual recorded events
    sources = set(e.get("source", "") for e in events)
    targets = set(e.get("target", "") for e in events)
    critical_events = [e for e in events if e.get("severity") == "critical"]
    event_types = set(e.get("event_type", "unknown") for e in events)

    entry_event = events[0]

    # Determine most likely attack source (source with most critical events)
    source_counter = Counter(e.get("source", "") for e in critical_events)
    likely_attacker = source_counter.most_common(1)[0][0] if source_counter else entry_event.get("source", "unknown")

    # Determine primary target (target with most events)
    target_counter = Counter(e.get("target", "") for e in events)
    primary_target = target_counter.most_common(1)[0][0] if target_counter else "unknown"

    # Build confidence score
    confidence = 0.6
    if len(events) >= 5:
        confidence += 0.1
    if critical_events:
        confidence += 0.1
    if len(sources) <= 3:
        confidence += 0.1
    confidence = min(confidence, 0.95)

    attack_chain = [f"{i+1}. [{e.get('timestamp', '')[:19]}] {e.get('detail', e.get('event_type', ''))}"
                    for i, e in enumerate(events)]

    return json.dumps({
        "incident": f"事件分析 ({len(events)} events)",
        "root_cause": {
            "entry_point": entry_event.get("source", "unknown"),
            "first_event": entry_event.get("event_type", ""),
            "attack_vector": ", ".join(event_types) if event_types else "unknown",
            "likely_attacker": likely_attacker,
            "primary_target": primary_target,
            "sources": list(sources),
            "targets": list(targets),
            "confidence": round(confidence, 2),
        },
        "summary": {
            "total_events": len(events),
            "critical_events": len(critical_events),
            "event_types": list(event_types),
            "timespan": f"{events[0].get('timestamp', '')[:19]} ~ {events[-1].get('timestamp', '')[:19]}" if len(events) > 1 else "single event",
        },
        "attack_chain": attack_chain,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def generate_report(incident_id: str = "") -> str:
    """Generate a post-incident review report.

    Args:
        incident_id: Incident ID. Empty = generate for all events.
    """
    logger.info(f"generate_report: {incident_id or 'latest'}")
    _ensure_events_loaded()

    # Load from database
    try:
        conn = _get_conn()
        if incident_id:
            rows = conn.execute(
                "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY id ASC",
                (incident_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM timeline_events ORDER BY id ASC"
            ).fetchall()
        conn.close()
        events = [dict(r) for r in rows]
    except Exception:
        events = _events if not incident_id else [e for e in _events if e.get("incident_id") == incident_id]

    if not events:
        return json.dumps({"error": "No events recorded. Cannot generate report.",
                           "hint": "Record events first via record_event or start the event collector."},
                          ensure_ascii=False, indent=2)

    critical = [e for e in events if e.get("severity") == "critical"]
    warnings = [e for e in events if e.get("severity") == "warning"]
    targets = set(e.get("target", "") for e in events)
    sources = set(e.get("source", "") for e in events)

    # Severity distribution
    severity_dist = Counter(e.get("severity", "info") for e in events)

    # Event type distribution
    type_dist = Counter(e.get("event_type", "unknown") for e in events)

    # Incident IDs involved
    incident_ids = sorted(set(e.get("incident_id", "") for e in events))

    return json.dumps({
        "report_id": f"rpt-{int(time.time())}",
        "title": f"安全事件分析报告 ({len(events)} events)",
        "date": datetime.now().strftime("%Y-%m-%d"),
        "executive_summary": f"共记录 {len(events)} 个安全事件，其中 {len(critical)} 个严重，{len(warnings)} 个警告。涉及 {len(targets)} 个目标设备，{len(sources)} 个来源。",
        "timeline_summary": {
            "total_events": len(events),
            "critical_events": len(critical),
            "warning_events": len(warnings),
            "first_event": events[0].get("timestamp", "")[:19],
            "last_event": events[-1].get("timestamp", "")[:19],
            "sources": list(sources),
            "targets": list(targets),
            "incident_ids": incident_ids,
        },
        "severity_distribution": dict(severity_dist),
        "event_type_distribution": dict(type_dist),
        "events": events,
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw attack-timeline MCP")
    mcp.run()
