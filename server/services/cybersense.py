"""CyberSense 多源关联引擎（展示层聚合，演示用）。

单点拦截四采集器已广播的 WS 事件（syslog_event / snmp_trap / suricata_alert），做
多源关联：syslog/ids 按设备 IP 聚合到 60s 滑动证据表，SNMP trap 发送方是本机无法
按 IP 关联 → 作为**全局辅助信号**（近期有 trap 即算一源）。三源（Syslog+SNMP+IDS）
命中 → 追加广播 cybersense_verdict（多源证据 + 置信度 + 判定）。

定位「展示层证据聚合」，**不改设备 FSM**——FSM 仍由 suricata 单源 dst_ip→FSM 驱动（零退化）。
任何一环出问题退化为现状（单源变色），不阻断演示。

置信度 = 命中源权重和（ids 0.45 + syslog 0.30 + snmp 0.15 = 0.90）。
"""
import time
import logging
from collections import defaultdict
from typing import Optional, Callable, Awaitable

logger = logging.getLogger(__name__)

_SOURCE_WEIGHT = {"ids": 0.45, "syslog": 0.30, "snmp": 0.15, "mqtt": 0.10}
_WINDOW_SEC = 60      # 滑动证据窗口
_DEBOUNCE_SEC = 5     # 同 IP 去抖
_MIN_SOURCES = 2      # ≥2 源(含 ids)触发


class CyberSenseCorrelator:
    """多源关联器：syslog/ids 按设备 IP 聚合 + snmp 全局辅助信号，多源命中发 verdict。"""

    def __init__(self):
        self._evidence: dict[str, dict] = defaultdict(dict)  # ip -> {source: {ts, detail}}
        self._snmp_signal: dict = {"ts": 0.0, "detail": ""}  # SNMP 全局辅助(发送方本机,不按IP)
        self._last_verdict_ts: dict[str, float] = {}
        self._ws_broadcast: Optional[Callable[[dict], Awaitable]] = None

    def set_broadcast(self, fn):
        self._ws_broadcast = fn

    def reset(self):
        self._evidence.clear()
        self._snmp_signal = {"ts": 0.0, "detail": ""}
        self._last_verdict_ts.clear()

    async def on_ws_event(self, event: dict):
        """拦截 WS 事件做关联。由 main.broadcast_event 在广播原始事件后调用。"""
        etype = event.get("type")
        source, ip, detail = self._extract(event, etype)
        if not source:
            return
        now = time.time()

        # SNMP 发送方是本机(127.0.0.1), 无法按设备IP关联 → 记全局辅助信号, 不直接触发
        if source == "snmp":
            self._snmp_signal = {"ts": now, "detail": detail}
            return

        if not ip:
            return
        # syslog/ids 按设备 IP 聚合(清过期)
        self._evidence[ip] = {
            s: d for s, d in self._evidence[ip].items() if now - d["ts"] < _WINDOW_SEC
        }
        self._evidence[ip][source] = {"ts": now, "detail": detail}

        # 合并近期 SNMP 全局信号作为辅助源
        sources_hit = list(self._evidence[ip].keys())
        snmp_active = now - self._snmp_signal["ts"] < _WINDOW_SEC
        if snmp_active and "snmp" not in sources_hit:
            sources_hit.append("snmp")

        # 判定：≥2 源 且 含 ids（演示：syslog+snmp+ids 三源命中同一虚拟设备）
        if len(sources_hit) >= _MIN_SOURCES and "ids" in sources_hit:
            if now - self._last_verdict_ts.get(ip, 0) < _DEBOUNCE_SEC:
                return
            self._last_verdict_ts[ip] = now
            confidence = sum(_SOURCE_WEIGHT.get(s, 0) for s in sources_hit)
            evidence = {s: self._evidence[ip][s]["detail"] for s in self._evidence[ip]}
            if snmp_active:
                evidence["snmp"] = self._snmp_signal["detail"]
            await self._emit_verdict(ip, sources_hit, confidence, evidence)

    def _extract(self, event: dict, etype: str):
        """从不同采集器事件提取 (source, ip, detail)。"""
        if etype == "syslog_event":
            evt = event.get("event") or {}
            return "syslog", evt.get("hostname", ""), evt.get("message", "")[:120]
        if etype == "snmp_trap":
            evt = event.get("trap") or event
            src = evt.get("source") or evt.get("agent") or ""
            return "snmp", src, str(evt.get("oids") or evt.get("oid") or "trap")[:120]
        if etype == "suricata_alert":
            evt = event.get("event") or {}
            ip = evt.get("dst_ip") or evt.get("dest_ip") or evt.get("target") or ""
            return "ids", ip, evt.get("signature", "")[:120]
        return None, None, None

    async def _emit_verdict(self, ip: str, sources_hit: list, confidence: float, evidence: dict):
        device = await self._lookup_device(ip)
        verdict = "compromised" if confidence >= 0.55 else "suspicious"
        out = {
            "type": "cybersense_verdict",
            "device_ip": ip,
            "device_mac": device.get("mac", ""),
            "device_id": device.get("id", ""),
            "device_name": device.get("name", ip),
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "sources_hit": sources_hit,
            "sources_count": len(sources_hit),
            "evidence": evidence,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if self._ws_broadcast:
            try:
                await self._ws_broadcast(out)
            except Exception as e:
                logger.debug(f"cybersense verdict broadcast failed: {e}")
        logger.info(f"[CyberSense] {ip} {verdict} conf={confidence:.2f} sources={sources_hit}")
        # 改进3: compromised → 自动隔离该设备(状态 isolated + 广播 device_isolated 触发防护盾+toast)
        if verdict == "compromised":
            await self._auto_isolate(ip, device, confidence, verdict)

    async def _auto_isolate(self, ip: str, device: dict, confidence: float, verdict: str):
        """CyberSense 判定 compromised 后自动隔离: 设备 FSM→isolated + 广播 device_isolated。"""
        try:
            from .nx_bridge import get_bridge
            mac = device.get("mac")
            if not mac:
                return
            await get_bridge().update_device_status(mac, "isolated")
            dev_id = device.get("id", "")
            dev_name = device.get("name", ip)
            if self._ws_broadcast:
                await self._ws_broadcast({
                    "type": "device_isolated",
                    "target": dev_id,
                    "severity": "warning",
                    "message": f"CyberSense 自动隔离: {dev_name} (多源关联 {verdict}, {int(confidence * 100)}%)",
                })
            logger.info(f"[CyberSense] auto-isolated {dev_name} ({ip})")
        except Exception as e:
            logger.debug(f"cybersense auto-isolate failed: {e}")

    async def _lookup_device(self, ip: str) -> dict:
        try:
            from .nx_bridge import get_bridge
            dev = await get_bridge().get_device_by_ip(ip)
            if dev:
                name = dev.get("devName") or ip
                dev_id = name.lower().replace("-", "_").replace(" ", "_")
                return {"mac": dev.get("devMac", ""), "name": name, "id": dev_id}
        except Exception as e:
            logger.debug(f"correlator device lookup failed: {e}")
        return {}


_service: Optional[CyberSenseCorrelator] = None


def get_correlator() -> CyberSenseCorrelator:
    global _service
    if _service is None:
        _service = CyberSenseCorrelator()
    return _service
