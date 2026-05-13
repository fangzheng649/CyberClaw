"""通知服务 — 支持 Webhook 和 ntfy 通道"""
import hashlib
import hmac
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PATH = Path("config/notifications.json")


class NotificationService:
    def __init__(self):
        self.config = self._load_config()

    def _load_config(self) -> dict:
        if CONFIG_PATH.exists():
            try:
                return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, Exception):
                pass
        return {"channels": {}, "rules": []}

    def reload(self):
        self.config = self._load_config()

    async def send(self, title: str, message: str, severity: str = "info",
                   device_info: dict = None):
        """根据严重程度匹配通知规则并发送到对应通道"""
        channels_to_notify = set()
        for rule in self.config.get("rules", []):
            if severity in rule.get("severity", []):
                channels_to_notify.update(rule.get("channels", []))

        if not channels_to_notify:
            return

        for channel_name in channels_to_notify:
            ch = self.config.get("channels", {}).get(channel_name)
            if not ch or not ch.get("enabled"):
                continue
            try:
                if channel_name == "webhook":
                    await self._send_webhook(ch, title, message, device_info)
                elif channel_name == "ntfy":
                    await self._send_ntfy(ch, title, message, severity)
            except Exception as e:
                logger.warning(f"Notification {channel_name} failed: {e}")
                self._record_failure(channel_name, title, str(e))

    async def _send_webhook(self, ch: dict, title: str, message: str,
                            device_info: dict = None):
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed, skipping webhook")
            return

        payload = {"title": title, "body": message, "device": device_info}
        headers = {"Content-Type": "application/json"}
        if ch.get("secret"):
            sig = hmac.new(
                ch["secret"].encode(), json.dumps(payload).encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Signature"] = sig

        async with httpx.AsyncClient() as client:
            await client.post(ch["url"], json=payload, headers=headers, timeout=10)
        logger.info(f"Webhook sent to {ch['url']}")

    async def _send_ntfy(self, ch: dict, title: str, message: str,
                         priority: str = "default"):
        try:
            import httpx
        except ImportError:
            logger.debug("httpx not installed, skipping ntfy")
            return

        priority_map = {"critical": "5", "warning": "4", "info": "3"}
        p = priority_map.get(priority, "default")

        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ch.get('server', 'https://ntfy.sh')}/{ch['topic']}",
                data=message.encode("utf-8"),
                headers={"Title": title, "Priority": p},
                timeout=10,
            )
        logger.info(f"ntfy sent to {ch['topic']}")

    def _record_failure(self, channel: str, title: str, error: str):
        try:
            from server.db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            conn.execute(
                """INSERT INTO notifications (channel, title, message, status, error)
                   VALUES (?, ?, ?, 'failed', ?)""",
                (channel, title, "", error),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass


_service = None


def get_notification_service() -> NotificationService:
    global _service
    if _service is None:
        _service = NotificationService()
    return _service
