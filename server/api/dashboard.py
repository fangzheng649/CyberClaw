"""Dashboard API for CyberClaw SOC panels.

Provides aggregated data for alert list, trend charts, and unified log search.
Data sources: Database (primary) → in-memory (fallback).
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query

from ..services.collector_service import get_receiver
from ..services.snmp_service import get_snmp_service
from ..services.mqtt_service import get_mqtt_service
from ..services.suricata_service import get_suricata_service
from ..services.topology_service import get_topology
from ..services.nx_bridge import get_bridge

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
logger = logging.getLogger(__name__)


# ── DB-backed alerts (primary) ────────────────────────────────────

@router.get("/db/alerts")
async def get_db_alerts(
    severity: str = "",
    source_type: str = "",
    limit: int = 100,
    offset: int = 0,
):
    bridge = get_bridge()
    events = await bridge.get_security_events(
        limit=limit, offset=offset,
        severity=severity or None,
        source_type=source_type or None,
    )
    total = await bridge.count_security_events()
    return {
        "alerts": events,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/db/device-events")
async def get_db_device_events(
    mac: str = "",
    limit: int = 50,
):
    bridge = get_bridge()
    events = await bridge.get_events(mac=mac or None, limit=limit)
    return {"events": events, "total": len(events)}


@router.get("/db/devices")
async def get_db_devices():
    bridge = get_bridge()
    devices = await bridge.get_all_devices()
    return {
        "devices": devices,
        "total": len(devices),
    }


# ── Unified Alert List (in-memory + DB) ──────────────────────────

@router.get("/alerts")
async def get_alerts(
    severity: str = "",
    limit: int = 100,
    offset: int = 0,
):
    alerts = []

    for evt in get_receiver().get_events(limit=500):
        alerts.append({
            "id": evt["id"],
            "timestamp": evt["timestamp"],
            "type": "syslog_event",
            "severity": evt["severity"],
            "message": evt["message"],
            "source": evt.get("hostname", ""),
            "source_type": "syslog",
        })

    for trap in get_snmp_service().get_traps(limit=200):
        alerts.append({
            "id": trap.get("id", f"snmp-{len(alerts)}"),
            "timestamp": trap["timestamp"],
            "type": "snmp_trap",
            "severity": "medium",
            "message": trap.get("message", str(trap)),
            "source": trap.get("agent_ip", ""),
            "source_type": "snmp",
        })

    for msg in get_mqtt_service().get_messages(limit=200):
        alerts.append({
            "id": f"mqtt-{len(alerts)}",
            "timestamp": msg["timestamp"],
            "type": "mqtt_message",
            "severity": "info",
            "message": f"MQTT [{msg['topic']}]: {msg['payload'][:100]}",
            "source": msg.get("topic", ""),
            "source_type": "mqtt",
        })

    for alert in get_suricata_service().get_events(limit=500):
        alerts.append({
            "id": alert["id"],
            "timestamp": alert["timestamp"],
            "type": "suricata_alert",
            "severity": alert["severity"],
            "message": alert["message"],
            "source": alert.get("source", ""),
            "target": alert.get("target", ""),
            "source_type": "suricata",
            "category": alert.get("category", ""),
            "fsm_state": alert.get("fsm_state", ""),
        })

    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]

    alerts.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "alerts": alerts[offset:offset + limit],
        "total": len(alerts),
        "offset": offset,
        "limit": limit,
    }


# ── Trend Charts ────────────────────────────────────────────────

@router.get("/trends/alert-count")
async def get_alert_count_trend(hours: int = 24):
    bridge = get_bridge()
    db_trend = await bridge.get_alert_counts_by_hour(hours)
    if db_trend:
        hourly = {}
        for row in db_trend:
            hour = row.get("hour", "")
            sev = row.get("severity", "info")
            count = row.get("count", 0)
            hourly.setdefault(hour, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
            if sev in hourly[hour]:
                hourly[hour][sev] = count
        return {
            "labels": list(hourly.keys()),
            "series": {
                sev: [h.get(sev, 0) for h in hourly.values()]
                for sev in ("critical", "high", "medium", "low", "info")
            },
        }

    now = datetime.now()
    hourly = {}
    for h in range(hours):
        bucket = (now - timedelta(hours=hours - h)).strftime("%Y-%m-%d %H:00")
        hourly[bucket] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def _inc(ts: str, sev: str):
        try:
            dt = datetime.fromisoformat(ts[:19])
        except (ValueError, IndexError):
            return
        bucket = dt.strftime("%Y-%m-%d %H:00")
        if bucket in hourly and sev in hourly[bucket]:
            hourly[bucket][sev] += 1

    for evt in get_receiver().get_events(limit=2000):
        _inc(evt["timestamp"], evt["severity"])

    for alert in get_suricata_service().get_events(limit=2000):
        _inc(alert["timestamp"], alert["severity"])

    return {
        "labels": list(hourly.keys()),
        "series": {
            "critical": [h["critical"] for h in hourly.values()],
            "high": [h["high"] for h in hourly.values()],
            "medium": [h["medium"] for h in hourly.values()],
            "low": [h["low"] for h in hourly.values()],
            "info": [h["info"] for h in hourly.values()],
            "total": [sum(h.values()) for h in hourly.values()],
        },
    }


@router.get("/trends/device-status")
async def get_device_status_distribution():
    bridge = get_bridge()
    counts = await bridge.get_device_counts_by_status()
    if counts:
        all_statuses = ["secure", "scanning", "vulnerable", "attacked", "isolated"]
        return {
            "labels": all_statuses,
            "data": [counts.get(s, 0) for s in all_statuses],
            "total": sum(counts.values()),
        }

    topology = get_topology()
    fallback = {"secure": 0, "scanning": 0, "vulnerable": 0, "attacked": 0, "isolated": 0}
    for d in topology.devices:
        status = d.status if isinstance(d.status, str) else str(d.status)
        if status in fallback:
            fallback[status] += 1
    return {
        "labels": list(fallback.keys()),
        "data": list(fallback.values()),
        "total": sum(fallback.values()),
    }


@router.get("/trends/protocol-traffic")
async def get_protocol_traffic():
    stats = get_suricata_service().get_stats()
    proto = stats.get("by_protocol", {})
    if not proto:
        scapy = get_suricata_service().get_scapy_stats()
        proto = scapy.get("by_protocol", {})
    return {
        "labels": list(proto.keys()),
        "data": list(proto.values()),
        "total": sum(proto.values()),
    }


@router.get("/trends/category-breakdown")
async def get_category_breakdown():
    stats = get_suricata_service().get_stats()
    cats = stats.get("by_category", {})
    top = sorted(cats.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "labels": [c[0] for c in top],
        "data": [c[1] for c in top],
    }


# ── Unified Log Search ──────────────────────────────────────────

@router.get("/logs/search")
async def search_logs(
    query: str = "",
    severity: str = "",
    source: str = "",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
):
    results = []

    def _match(text: str) -> bool:
        return not query or query.lower() in text.lower()

    def _time_ok(ts: str) -> bool:
        if not start_time and not end_time:
            return True
        try:
            dt = datetime.fromisoformat(ts[:19])
        except (ValueError, IndexError):
            return True
        if start_time:
            try:
                if dt < datetime.fromisoformat(start_time[:19]):
                    return False
            except ValueError:
                pass
        if end_time:
            try:
                if dt > datetime.fromisoformat(end_time[:19]):
                    return False
            except ValueError:
                pass
        return True

    if source in ("", "all", "syslog"):
        for evt in get_receiver().get_events(limit=500, severity=severity):
            if _match(evt["message"]) and _time_ok(evt["timestamp"]):
                evt["source_type"] = "syslog"
                results.append(evt)

    if source in ("", "all", "snmp"):
        for trap in get_snmp_service().get_traps(limit=300):
            text = json_safe(trap)
            if _match(text) and _time_ok(trap["timestamp"]):
                trap["source_type"] = "snmp"
                results.append(trap)

    if source in ("", "all", "mqtt"):
        for msg in get_mqtt_service().get_messages(limit=300):
            text = f"{msg['topic']} {msg['payload']}"
            if _match(text) and _time_ok(msg["timestamp"]):
                msg["source_type"] = "mqtt"
                results.append(msg)

    if source in ("", "all", "suricata"):
        for alert in get_suricata_service().get_events(limit=500, severity=severity):
            if _match(alert["message"]) and _time_ok(alert["timestamp"]):
                alert["source_type"] = "suricata"
                results.append(alert)

    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {
        "results": results[:limit],
        "total": len(results),
        "query": query,
        "source": source,
    }


def json_safe(d: dict) -> str:
    try:
        return json.dumps(d, ensure_ascii=False, default=str)
    except Exception:
        return str(d)
