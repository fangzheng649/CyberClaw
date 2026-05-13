"""Suricata IDS integration service for CyberClaw.

Monitors eve.json for real-time alerts, maps to 5-state FSM,
broadcasts via WebSocket. Falls back to scapy traffic statistics
when Suricata is unavailable.
"""
import asyncio
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)

MAX_EVENTS = 2000

SURICATA_TO_FSM = {
    1: "attacked",
    2: "attacked",
    3: "vulnerable",
    4: "scanning",
}

SEVERITY_NAMES = {1: "critical", 2: "high", 3: "medium", 4: "low"}

CRITICAL_PATTERNS = ["malware", "trojan", "shellcode", "exploit", "ransomware"]


class SuricataEvent:
    __slots__ = (
        "id", "timestamp", "signature", "severity", "severity_name",
        "src_ip", "dst_ip", "protocol", "category", "fsm_state",
    )

    def __init__(self, raw: dict):
        ts = time.time()
        self.id = f"sura-{int(ts * 1000)}"
        self.timestamp = raw.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))
        alert = raw.get("alert", {})
        self.signature = alert.get("signature", "Unknown Alert")
        self.severity = alert.get("severity", 3)
        self.severity_name = SEVERITY_NAMES.get(self.severity, "medium")
        self.src_ip = raw.get("src_ip", "0.0.0.0")
        self.dst_ip = raw.get("dest_ip", "0.0.0.0")
        self.protocol = raw.get("proto", "unknown")
        self.category = alert.get("category", "unknown")
        self.fsm_state = SURICATA_TO_FSM.get(self.severity, "vulnerable")
        sig_lower = self.signature.lower()
        for p in CRITICAL_PATTERNS:
            if p in sig_lower:
                self.fsm_state = "attacked"
                break

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "type": "suricata_alert",
            "severity": self.severity_name,
            "message": f"Suricata: {self.signature}",
            "source": self.src_ip,
            "target": self.dst_ip,
            "protocol": self.protocol,
            "category": self.category,
            "signature": self.signature,
            "fsm_state": self.fsm_state,
        }


class SuricataMonitor:
    def __init__(self, eve_json_path: str = ""):
        if not eve_json_path:
            eve_json_path = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
        self.eve_json_path = Path(eve_json_path)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._events: deque[SuricataEvent] = deque(maxlen=MAX_EVENTS)
        self._broadcast_fn: Optional[Callable] = None
        self._last_pos = 0
        self._stats = {
            "total_alerts": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {},
            "by_protocol": {},
        }
        self._scapy_task: Optional[asyncio.Task] = None
        self._scapy_stats = {
            "packet_count": 0,
            "by_protocol": {},
            "top_sources": {},
            "top_destinations": {},
        }
        self._mode = "idle"

    def set_broadcast(self, fn: Callable) -> None:
        self._broadcast_fn = fn

    async def start(self) -> dict:
        if self._running:
            return {"status": "already_running", "mode": self._mode}

        if self.eve_json_path.exists():
            self._running = True
            self._last_pos = self.eve_json_path.stat().st_size
            self._mode = "suricata"
            self._task = asyncio.create_task(self._monitor_eve_json())
            logger.info(f"Suricata monitor started on {self.eve_json_path}")
            return {"status": "started", "mode": "suricata", "eve_path": str(self.eve_json_path)}

        scapy_ok = await self._try_scapy()
        if scapy_ok:
            self._running = True
            self._mode = "scapy"
            logger.info("Suricata eve.json not found, using scapy fallback")
            return {"status": "started", "mode": "scapy_fallback"}

        self._mode = "idle"
        return {
            "status": "unavailable",
            "mode": "idle",
            "message": "Suricata not installed and scapy unavailable",
            "hint": "Install Suricata or scapy for traffic monitoring",
        }

    async def stop(self) -> dict:
        self._running = False
        for t in (self._task, self._scapy_task):
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        self._task = None
        self._scapy_task = None
        self._mode = "idle"
        logger.info("Suricata monitor stopped")
        return {"status": "stopped"}

    async def _monitor_eve_json(self):
        while self._running:
            try:
                if not self.eve_json_path.exists():
                    await asyncio.sleep(2)
                    continue

                current_size = self.eve_json_path.stat().st_size
                if current_size < self._last_pos:
                    self._last_pos = 0

                if current_size <= self._last_pos:
                    await asyncio.sleep(0.5)
                    continue

                with open(self.eve_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(self._last_pos)
                    new_content = f.read()
                    self._last_pos = current_size

                for line in new_content.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if event.get("event_type") == "alert":
                            self._process_alert(event)
                    except json.JSONDecodeError:
                        continue

                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"eve.json monitor error: {e}")
                await asyncio.sleep(2)

    def _process_alert(self, raw: dict):
        evt = SuricataEvent(raw)
        self._events.append(evt)
        self._stats["total_alerts"] += 1
        sev_name = evt.severity_name
        self._stats["by_severity"][sev_name] = self._stats["by_severity"].get(sev_name, 0) + 1
        self._stats["by_category"][evt.category] = self._stats["by_category"].get(evt.category, 0) + 1
        self._stats["by_protocol"][evt.protocol] = self._stats["by_protocol"].get(evt.protocol, 0) + 1

        if self._broadcast_fn:
            asyncio.create_task(self._broadcast_fn({
                "type": "suricata_alert",
                "event": evt.to_dict(),
                "stats": self.get_stats(),
            }))

        # Persist to database
        try:
            from .nx_bridge import get_bridge
            asyncio.create_task(get_bridge().record_security_event(
                "suricata", sev_name, evt.signature,
                source=evt.src_ip, target=evt.dst_ip,
                details={"category": evt.category, "protocol": evt.protocol},
                fsm_state=evt.fsm_state))
            # Update device FSM state if applicable
            if evt.fsm_state and evt.dst_ip:
                async def _update_fsm(ip=evt.dst_ip, state=evt.fsm_state):
                    dev = await get_bridge().get_device_by_ip(ip)
                    if dev:
                        await get_bridge().update_device_status(dev["devMac"], state)
                asyncio.create_task(_update_fsm())
        except Exception:
            pass

    async def _try_scapy(self) -> bool:
        try:
            from scapy.all import conf
            conf.sniff_promisc = False
            self._scapy_task = asyncio.create_task(self._scapy_capture())
            return True
        except ImportError:
            return False

    async def _scapy_capture(self):
        try:
            from scapy.all import sniff, IP

            def on_packet(pkt):
                self._scapy_stats["packet_count"] += 1
                if IP in pkt:
                    proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
                    proto = proto_map.get(pkt[IP].proto, "other")
                    self._scapy_stats["by_protocol"][proto] = (
                        self._scapy_stats["by_protocol"].get(proto, 0) + 1
                    )
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    self._scapy_stats["top_sources"][src] = self._scapy_stats["top_sources"].get(src, 0) + 1
                    self._scapy_stats["top_destinations"][dst] = (
                        self._scapy_stats["top_destinations"].get(dst, 0) + 1
                    )

                if self._scapy_stats["packet_count"] % 100 == 0 and self._broadcast_fn:
                    asyncio.create_task(self._broadcast_fn({
                        "type": "traffic_stats",
                        "stats": dict(self._scapy_stats),
                        "mode": "scapy",
                    }))

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: sniff(prn=on_packet, store=False, timeout=0))
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"scapy capture error: {e}")

    def get_events(self, limit: int = 100, severity: str = "") -> list[dict]:
        events = list(self._events)
        if severity:
            events = [e for e in events if e.severity_name == severity]
        return [e.to_dict() for e in events[-limit:]]

    def get_stats(self) -> dict:
        return {
            "is_running": self._running,
            "mode": self._mode,
            "eve_json_path": str(self.eve_json_path),
            "total_alerts": self._stats["total_alerts"],
            "by_severity": dict(self._stats["by_severity"]),
            "by_category": dict(self._stats["by_category"]),
            "by_protocol": dict(self._stats["by_protocol"]),
            "stored_events": len(self._events),
            "scapy_packet_count": self._scapy_stats["packet_count"],
        }

    def get_scapy_stats(self) -> dict:
        return dict(self._scapy_stats)


_singleton: Optional[SuricataMonitor] = None


def get_suricata_service() -> SuricataMonitor:
    global _singleton
    if _singleton is None:
        _singleton = SuricataMonitor()
    return _singleton
