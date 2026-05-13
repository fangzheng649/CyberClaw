"""CyberClaw Collector Service — real-time syslog event collection for HUD.

Embeds a lightweight UDP syslog receiver that:
1. Listens for syslog messages on a configurable port
2. Parses severity/facility/hostname/message
3. Stores events in memory
4. Broadcasts significant events to HUD via WebSocket
5. Auto-records critical events to the attack-timeline

This is a REAL receiver — events must come from actual sources
(e.g., lab/event_generator.py or real IoT devices).
"""
import asyncio
import json
import logging
import re
import sys
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Syslog parsing (RFC 3164 / RFC 5424 minimal) ────────────────

SEVERITY_NAMES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

_SEVERITY_LEVEL = {
    "emergency": 0, "alert": 0, "critical": 1, "error": 2,
    "warning": 3, "notice": 4, "info": 5, "debug": 6,
}


def _parse_syslog(data: bytes) -> dict:
    """Minimal syslog parser — extracts PRI, hostname, message."""
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        text = str(data)

    pri_match = re.match(r"^<(\d{1,3})>", text)
    if not pri_match:
        return {"severity": "info", "hostname": "unknown", "message": text[:500]}

    pri = int(pri_match.group(1))
    facility = pri >> 3
    severity_num = pri & 0x07
    rest = text[pri_match.end():]

    # Try RFC 5424: <PRI>1 TIMESTAMP HOSTNAME ...
    rfc5424 = re.match(r"^1\s+(\S+)\s+(\S+)", rest)
    if rfc5424:
        hostname = rfc5424.group(2) if rfc5424.group(2) != "-" else "unknown"
        msg_start = rest.find("-", rest.find(rfc5424.group(2)) + len(rfc5424.group(2)))
        # Find message after structured data
        msg_part = rest.split("-", 4)[-1] if rest.count("-") >= 4 else rest[rest.rfind("-") + 1:]
        message = msg_part.strip()
    else:
        # Try RFC 3164: <PRI>TIMESTAMP HOSTNAME ...
        parts = rest.split(None, 3)
        hostname = parts[1] if len(parts) > 1 else "unknown"
        message = parts[-1] if len(parts) > 2 else rest

    return {
        "severity": SEVERITY_NAMES.get(severity_num, "info"),
        "severity_num": severity_num,
        "facility": facility,
        "hostname": hostname,
        "message": message[:500],
    }


# ── Event store ──────────────────────────────────────────────────

MAX_EVENTS = 1000


class CollectorEvent:
    __slots__ = ("id", "timestamp", "severity", "hostname", "message", "facility")

    def __init__(self, severity: str, hostname: str, message: str, facility: int = 1):
        self.id = f"evt-{uuid.uuid4().hex[:12]}"
        self.timestamp = datetime.now().isoformat()
        self.severity = severity
        self.hostname = hostname
        self.message = message
        self.facility = facility

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}


# ── Syslog UDP receiver ──────────────────────────────────────────

class SyslogReceiver:
    def __init__(self, port: int = 8514):
        self.port = port
        self.transport = None
        self.protocol = None
        self.is_running = False
        self.events: deque[CollectorEvent] = deque(maxlen=MAX_EVENTS)
        self._stats = {"received": 0, "errors": 0, "last_time": None}
        self._broadcast_fn = None

    def set_broadcast(self, fn):
        self._broadcast_fn = fn

    async def start(self):
        if self.is_running:
            return
        loop = asyncio.get_event_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self._on_message),
            local_addr=("0.0.0.0", self.port),
        )
        self.is_running = True
        logger.info(f"Syslog receiver started on UDP port {self.port}")

    async def stop(self):
        if self.transport:
            self.transport.close()
            self.transport = None
        self.is_running = False
        logger.info("Syslog receiver stopped")

    def _on_message(self, data: bytes, addr):
        try:
            parsed = _parse_syslog(data)
            event = CollectorEvent(
                severity=parsed["severity"],
                hostname=parsed["hostname"],
                message=parsed["message"],
                facility=parsed.get("facility", 1),
            )
            self.events.append(event)
            self._stats["received"] += 1
            self._stats["last_time"] = event.timestamp

            # Broadcast to HUD
            if self._broadcast_fn:
                asyncio.create_task(self._broadcast_fn({
                    "type": "syslog_event",
                    "event": event.to_dict(),
                    "stats": dict(self._stats),
                }))

            # Auto-record critical/alert to attack-timeline
            if parsed["severity"] in ("critical", "alert", "emergency"):
                asyncio.create_task(self._record_to_timeline(event, parsed))

            # Persist to database
            try:
                from .nx_bridge import get_bridge
                asyncio.create_task(get_bridge().record_security_event(
                    "syslog", event.severity, event.message,
                    source=event.hostname,
                    details={"facility": event.facility}))
            except Exception:
                pass  # DB not available — continue without persistence

        except Exception as e:
            self._stats["errors"] += 1
            logger.error(f"Error processing syslog from {addr}: {e}")

    async def _record_to_timeline(self, event: CollectorEvent, parsed: dict):
        try:
            from .mcp_tool_service import call_tool
            await call_tool("attack-timeline", "record_event",
                            event_type="alert",
                            source=event.hostname,
                            detail=event.message,
                            severity=event.severity)
        except Exception as e:
            logger.debug(f"Failed to record to timeline: {e}")

    def get_events(self, limit: int = 50, severity: str = "") -> list[dict]:
        events = list(self.events)
        if severity:
            events = [e for e in events if e.severity == severity]
        return [e.to_dict() for e in events[-limit:]]

    def get_stats(self) -> dict:
        return {
            "is_running": self.is_running,
            "port": self.port,
            "total_received": self._stats["received"],
            "errors": self._stats["errors"],
            "last_event": self._stats["last_time"],
            "stored_events": len(self.events),
        }


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler):
        self.handler = handler
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.handler(data, addr)

    def error_received(self, exc):
        logger.error(f"Syslog UDP error: {exc}")


# ── Singleton instance ───────────────────────────────────────────

_receiver: Optional[SyslogReceiver] = None


def get_receiver() -> SyslogReceiver:
    global _receiver
    if _receiver is None:
        port = 8514  # Non-privileged port for syslog collection
        _receiver = SyslogReceiver(port)
    return _receiver
