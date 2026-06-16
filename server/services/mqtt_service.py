"""MQTT monitor service for CyberClaw.

Subscribes to MQTT topics and monitors device telemetry messages.
- Auto-discovers ESP32 (and any cyberclaw/sensor/ publisher) into the Devices
  table via _upsert_esp32_device, so MQTT publishers appear as managed devices
  without manual registration and without relying on ICMP/ARP scans.
- Only anomalous publish rates are recorded as security events, so normal
  telemetry (e.g. temperature every 10s) does not flood the alert timeline.
- Tracks per-device last-seen timestamps for offline detection (_offline_watchdog).

Uses paho-mqtt v2.0+.
"""
import asyncio
import json as _json
import logging
import re
import time
from collections import deque
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

MAX_MESSAGES = 1000

# Valid MAC (lowercase, colon-separated). Matches the regex filter in
# async_get_topology() so MQTT-discovered devices are not filtered out of the view.
_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


class MQTTMonitor:
    def __init__(self):
        self._client = None
        self._connected = False
        self._broker: str = ""
        self._port: int = 1883
        self._messages: deque[dict] = deque(maxlen=MAX_MESSAGES)
        self._broadcast_fn = None
        self._topic_counts: dict[str, list[float]] = {}
        self._device_last_seen: dict[str, float] = {}  # mac → last epoch (offline watchdog)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._watchdog_task = None

    def set_broadcast(self, fn):
        self._broadcast_fn = fn

    async def connect(self, broker: str, port: int = 1883,
                      username: str | None = None,
                      password: str | None = None) -> dict:
        """Connect to MQTT broker.

        Returns status dict. Fails gracefully if paho-mqtt not installed
        or broker unreachable.
        """
        if self._connected:
            return {"status": "already_connected", "broker": self._broker}

        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            return {"status": "unavailable", "message": "paho-mqtt not installed"}

        self._broker = broker
        self._port = port
        # Capture the running event loop here (we are on the main thread, awaited).
        # paho's loop_start() runs on_message on a worker thread, where
        # asyncio.get_event_loop() is unreliable — so we reuse this captured loop.
        self._loop = asyncio.get_event_loop()

        def on_connect(client, userdata, flags, reason_code, properties=None):
            if reason_code == 0:
                self._connected = True
                logger.info(f"MQTT connected to {broker}:{port}")
            else:
                logger.warning(f"MQTT connect failed: reason_code={reason_code}")

        def on_message(client, userdata, msg):
            now = time.time()
            payload = ""
            try:
                payload = msg.payload.decode("utf-8", errors="replace")
            except Exception:
                payload = str(msg.payload)

            message = {
                "timestamp": datetime.now().isoformat(),
                "topic": msg.topic,
                "payload": payload[:500],
                "qos": msg.qos,
            }
            self._messages.append(message)

            self._topic_counts.setdefault(msg.topic, []).append(now)
            if len(self._topic_counts[msg.topic]) > 100:
                self._topic_counts[msg.topic] = self._topic_counts[msg.topic][-50:]

            # Anomaly rate: >50 msgs/min → warning; otherwise telemetry stays quiet.
            severity = "info"
            topic_times = self._topic_counts.get(msg.topic, [])
            if len(topic_times) >= 10:
                recent = [t for t in topic_times if now - t < 60]
                if len(recent) > 50:
                    severity = "warning"

            # ESP32 auto-discovery: parse cyberclaw/sensor/ telemetry, upsert device.
            if msg.topic.startswith("cyberclaw/sensor/"):
                try:
                    data = _json.loads(payload)
                    mac = (data.get("mac") or "").strip().lower()
                    if mac and _MAC_RE.fullmatch(mac):
                        self._device_last_seen[mac] = now
                        if self._loop and self._loop.is_running():
                            self._loop.create_task(_upsert_esp32_device(mac, data))
                except Exception as _e:
                    logger.debug(f"ESP32 MQTT discovery parse failed: {_e}")

            # Only record a security event for anomalous rates — normal telemetry
            # (e.g. temperature every 10s) must NOT flood the alert timeline.
            if severity == "warning":
                try:
                    from .nx_bridge import get_bridge
                    if self._loop and self._loop.is_running():
                        self._loop.create_task(
                            get_bridge().record_security_event(
                                "mqtt", severity, f"MQTT {msg.topic}: {payload[:100]}",
                                source=msg.topic))
                except Exception:
                    pass

            if self._broadcast_fn:
                try:
                    if self._loop and self._loop.is_running():
                        self._loop.create_task(self._broadcast_fn({
                            "type": "mqtt_message",
                            "message": message,
                        }))
                except RuntimeError:
                    pass

        def on_disconnect(client, userdata, flags, reason_code, properties=None):
            self._connected = False
            logger.info(f"MQTT disconnected from {broker}")

        try:
            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=f"cyberclaw-{int(time.time())}",
            )
            client.on_connect = on_connect
            client.on_message = on_message
            client.on_disconnect = on_disconnect

            if username:
                client.username_pw_set(username, password or "")

            client.connect_async(broker, port, keepalive=60)
            client.loop_start()

            self._client = client

            await asyncio.sleep(2)

            if self._connected:
                return {"status": "connected", "broker": broker, "port": port}
            else:
                client.loop_stop()
                return {"status": "timeout", "message": f"Could not connect to {broker}:{port} within 2s"}

        except Exception as e:
            logger.error(f"MQTT connect error: {e}")
            return {"status": "error", "message": str(e)}

    async def subscribe(self, topics: list[str]) -> dict:
        """Subscribe to MQTT topics."""
        if not self._client or not self._connected:
            return {"status": "not_connected"}

        results = {}
        for topic in topics:
            result, mid = self._client.subscribe(topic)
            results[topic] = "subscribed" if result == 0 else f"error_code={result}"

        return {"status": "ok", "topics": results}

    async def disconnect(self) -> dict:
        """Disconnect from MQTT broker."""
        if not self._client:
            return {"status": "not_connected"}

        try:
            self._client.loop_stop()
            self._client.disconnect()
            self._connected = False
            self._client = None
            return {"status": "disconnected"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_messages(self, limit: int = 50, topic: str = "") -> list[dict]:
        """Return recent MQTT messages."""
        msgs = list(self._messages)
        if topic:
            msgs = [m for m in msgs if topic in m["topic"]]
        return msgs[-limit:]

    def detect_anomalies(self, window_sec: int = 60,
                         threshold: int = 100) -> list[dict]:
        """Detect topics with anomalous publish rates."""
        now = time.time()
        anomalies = []

        for topic, timestamps in self._topic_counts.items():
            recent = [t for t in timestamps if now - t < window_sec]
            rate = len(recent)
            if rate > threshold:
                anomalies.append({
                    "topic": topic,
                    "rate_per_window": rate,
                    "window_sec": window_sec,
                    "threshold": threshold,
                })

        return anomalies

    def get_status(self) -> dict:
        return {
            "connected": self._connected,
            "broker": self._broker,
            "port": self._port,
            "messages_stored": len(self._messages),
            "topics_monitored": list(self._topic_counts.keys()),
        }

    async def start_offline_watchdog(self):
        """启动 ESP32 心跳超时离线检测。仅启动一次。"""
        if self._watchdog_task and not self._watchdog_task.done():
            return
        self._watchdog_task = asyncio.get_event_loop().create_task(
            self._offline_watchdog_loop())

    async def stop_offline_watchdog(self):
        if self._watchdog_task:
            self._watchdog_task.cancel()
            self._watchdog_task = None

    async def _offline_watchdog_loop(self):
        """每 15s 检查 _device_last_seen：超过 30s（3 个上报周期）没上报的 ESP32
        标记 present=0 + 广播 device_offline。ESP32 恢复上报时 _upsert 会设回 present=1。
        """
        from .nx_bridge import get_bridge
        OFFLINE_TIMEOUT = 30
        CHECK_INTERVAL = 15
        await asyncio.sleep(CHECK_INTERVAL)  # 启动后先等一轮，避免误判刚连上的设备
        while True:
            try:
                now = time.time()
                for mac, last_seen in list(self._device_last_seen.items()):
                    if now - last_seen <= OFFLINE_TIMEOUT:
                        continue
                    bridge = get_bridge()
                    try:
                        dev = await bridge.get_device_by_mac(mac)
                    except Exception:
                        dev = None
                    # 仅当前在线的才标记离线（避免重复广播）
                    if dev and dev.get("devPresentLastScan", 0):
                        await bridge.upsert_device(
                            mac, {"devPresentLastScan": 0}, source="MQTT")
                        name = dev.get("devName", mac)
                        logger.info(f"[MQTT-Watchdog] {name} ({mac}) offline — no telemetry > {OFFLINE_TIMEOUT}s")
                        self._device_last_seen.pop(mac, None)
                        if self._broadcast_fn:
                            await self._broadcast_fn({
                                "type": "device_offline",
                                "device": {
                                    "mac": mac,
                                    "id": _device_id_from_name(name),
                                    "name": name,
                                    "ip": dev.get("devLastIP", ""),
                                },
                            })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"watchdog loop error: {e}")
            await asyncio.sleep(CHECK_INTERVAL)


_service: Optional[MQTTMonitor] = None


def get_mqtt_service() -> MQTTMonitor:
    global _service
    if _service is None:
        _service = MQTTMonitor()
    return _service


# ---------------------------------------------------------------------------
# ESP32 auto-discovery: MQTT telemetry → Devices table
# ---------------------------------------------------------------------------
def _device_id_from_name(name: str) -> str:
    """Mirror async_get_topology()'s id derivation so broadcast ids match."""
    return name.lower().replace("-", "_").replace(" ", "_")


async def _upsert_esp32_device(mac: str, data: dict):
    """Upsert an ESP32-style sensor into Devices when its telemetry arrives.

    First sighting → full insert + broadcast device_discovered + logger.info.
    Subsequent sightings → only refresh devLastConnection/devLastIP/
    devPresentLastScan/devCustomProps (no log spam, ~every 10s).
    """
    from .nx_bridge import get_bridge
    bridge = get_bridge()

    try:
        existing = await bridge.get_device_by_mac(mac)
    except Exception:
        existing = None

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dev_name = (data.get("device") or "esp32-sensor").upper()  # e.g. "ESP32-01"
    custom = {
        "temp": data.get("temp"),
        "hum": data.get("hum"),
        "rssi": data.get("rssi"),
        "ts": data.get("ts"),
        "device": data.get("device"),
    }

    if not existing:
        svc = get_mqtt_service()
        payload = {
            "devMac": mac,
            "devName": dev_name,
            "devType": "sensor",
            "devVendor": "Espressif",
            "devModel": "ESP32-S3-DevKitC-1 + DHT22",
            "devLastIP": data.get("ip", ""),
            "devStatus": "secure",
            "devPresentLastScan": 1,
            "devIsNew": 1,
            "devIsArchived": 0,
            "devSourcePlugin": "MQTT",
            "devDiscoveryMethod": "mqtt",
            "devProtocols": _json.dumps(["mqtt", "wifi"]),
            "devRole": "target",
            "devPos": _json.dumps([3, 0, 12]),
            "devParentMAC": "",
            "devCustomProps": _json.dumps(custom),
            "devLastConnection": now,
            "devFirstConnection": now,
            "devNotes": "Auto-discovered via MQTT telemetry (WiFi segment)",
        }
        # ★ ESP32 upsert 必须最先执行：确保 DB 立刻有 ESP32(present=1, method=mqtt)。
        # 否则下面的 mock→real 广播(mode_changed + 逐台 device_discovered)耗时期间，
        # scan_service._check_mode_switch 会因 DB 无在线真实设备(any_online=False)切回 mock，
        # 删掉刚 seed 的设备 → mock→real→mock 死循环。
        try:
            await bridge.upsert_device(mac, payload, source="MQTT")
            logger.info(f"[MQTT-Discovery] New ESP32 device registered: {mac} ip={data.get('ip')}")
        except Exception as _e:
            logger.error(f"[MQTT-Discovery] upsert failed: {_e}")
        # ESP32 已在 DB(present=1)。现在处理 mock→real 切换 + 广播发现通知。
        try:
            from .topology_service import is_mock_mode, set_mock_mode
            if is_mock_mode():
                set_mock_mode(False)
                from server.services.db.seed_service import seed_from_config
                seeded_devs = await seed_from_config(force=True) or []
                logger.info(f"[MQTT-Discovery] ESP32 arrival → switched MOCK→REAL ({len(seeded_devs)} real devices re-seeded)")
                if svc._broadcast_fn:
                    # mode_changed：前端 buildTopology 重建到真实视图。快照含 config + ESP32
                    # （ESP32 已 upsert），mock 被 async_get_topology 过滤掉。
                    try:
                        from .topology_service import async_get_topology
                        topo = await async_get_topology()
                        _mc_devices = topo.model_dump()["devices"]
                        await svc._broadcast_fn({
                            "type": "mode_changed",
                            "mode": "real",
                            "reason": "esp32_arrival",
                            "mock_mode": False,
                            "devices": _mc_devices,
                            "links": [{"from": l.from_, "to": l.to} for l in topo.links],
                        })
                        _mc_mock = sum(1 for d in _mc_devices if d.get("discovery_method") == "mock")
                        logger.info(f"[MQTT-Discovery] mode_changed broadcast: {len(_mc_devices)} devices ({_mc_mock} mock)")
                    except Exception as _me:
                        logger.warning(f"[MQTT-Discovery] mode_changed broadcast failed: {_me}")
                    # 逐台 config 设备发现通知（波纹+toast；addDeviceToScene 靠 id 去重跳过重复添加）
                    for sd in seeded_devs:
                        try:
                            await svc._broadcast_fn({
                                "type": "device_discovered",
                                "device": {
                                    "mac": sd["mac"],
                                    "id": _device_id_from_name(sd["name"]) if sd.get("name") else sd["mac"].replace(":", ""),
                                    "name": sd.get("name", ""),
                                    "ip": sd.get("ip", ""),
                                    "type": sd.get("type", "unknown"),
                                    "device_type": sd.get("type", "unknown"),
                                    "vendor": sd.get("vendor", ""),
                                    "model": sd.get("model", ""),
                                    "pos": sd.get("pos", []),
                                    "status": "secure",
                                },
                            })
                        except Exception:
                            pass
                    # ESP32 发现通知（波纹+toast；mode_changed 快照已含 ESP32，addDeviceToScene 去重跳过）
                    try:
                        await svc._broadcast_fn({
                            "type": "device_discovered",
                            "device": {
                                "mac": mac,
                                "id": _device_id_from_name(dev_name),
                                "name": dev_name,
                                "ip": data.get("ip", ""),
                                "type": "sensor",
                                "device_type": "sensor",
                                "vendor": "Espressif",
                                "model": "ESP32-S3-DevKitC-1 + DHT22",
                                "pos": [3, 0, 12],
                                "status": "secure",
                            },
                        })
                    except Exception:
                        pass
        except Exception as _e:
            logger.warning(f"[MQTT-Discovery] mock→real switch failed: {_e}")
    else:
        _present = existing.get("devPresentLastScan", 0) if isinstance(existing, dict) else 0
        was_offline = not _present
        update = {
            "devLastConnection": now,
            "devLastIP": data.get("ip", ""),
            "devPresentLastScan": 1,
            "devCustomProps": _json.dumps(custom),
        }
        try:
            await bridge.upsert_device(mac, update, source="MQTT")
        except Exception as _e:
            logger.debug(f"[MQTT-Discovery] refresh failed: {_e}")
        # 设备恢复上线（之前离线，现在又上报）→ 广播 device_back_online（上线波纹+toast）
        if was_offline:
            logger.info(f"[MQTT-Discovery] ESP32 {mac} back online")
            svc = get_mqtt_service()
            if svc._broadcast_fn:
                try:
                    await svc._broadcast_fn({
                        "type": "device_back_online",
                        "device": {
                            "mac": mac,
                            "id": _device_id_from_name(dev_name),
                            "name": dev_name,
                            "ip": data.get("ip", ""),
                            "type": "sensor",
                            "device_type": "sensor",
                            "vendor": "Espressif",
                            "model": "ESP32-S3-DevKitC-1 + DHT22",
                            "pos": [3, 0, 12],
                            "status": "secure",
                        },
                    })
                except Exception:
                    pass
