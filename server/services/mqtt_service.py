"""MQTT monitor service for CyberClaw.

Subscribes to MQTT topics and monitors device telemetry messages.
Detects anomalous publish rates.

Uses paho-mqtt v2.0+.
"""
import logging
import time
from collections import deque
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

MAX_MESSAGES = 1000


class MQTTMonitor:
    def __init__(self):
        self._client = None
        self._connected = False
        self._broker: str = ""
        self._port: int = 1883
        self._messages: deque[dict] = deque(maxlen=MAX_MESSAGES)
        self._broadcast_fn = None
        self._topic_counts: dict[str, list[float]] = {}

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

            # Persist to database (check for anomalies)
            try:
                from .nx_bridge import get_bridge
                severity = "info"
                # Simple anomaly: high publish rate
                topic_times = self._topic_counts.get(msg.topic, [])
                if len(topic_times) >= 10:
                    recent = [t for t in topic_times if now - t < 60]
                    if len(recent) > 50:
                        severity = "warning"
                asyncio.get_event_loop().create_task(
                    get_bridge().record_security_event(
                        "mqtt", severity, f"MQTT {msg.topic}: {payload[:100]}",
                        source=msg.topic))
            except Exception:
                pass

            if self._broadcast_fn:
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._broadcast_fn({
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

            import asyncio
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


_service: Optional[MQTTMonitor] = None


def get_mqtt_service() -> MQTTMonitor:
    global _service
    if _service is None:
        _service = MQTTMonitor()
    return _service
