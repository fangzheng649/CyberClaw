"""Notification Bridge — NetAlertX-inspired notification pipeline.

Architecture (adapted from NetAlertX):
  1. Event sources create pending notifications (DB-backed)
  2. Sections organize notifications by type:
     - new_devices: New devices joining the network
     - down_devices: Devices going offline
     - security_events: Intrusion/vulnerability alerts
     - scheduled_checks: Timer/scheduler results
     - system: General system notifications
  3. Publishers deliver via channels (webhook, ntfy)
  4. Frontend receives real-time updates via WebSocket + history polling
"""
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# NetAlertX-style notification sections
SECTION_ORDER = ["new_devices", "down_devices", "security_events", "scheduled_checks", "system"]

SECTION_TITLES = {
    "new_devices": "新设备",
    "down_devices": "设备离线",
    "security_events": "安全事件",
    "scheduled_checks": "定时任务",
    "system": "系统通知",
}

SECTION_ICONS = {
    "new_devices": "🆕",
    "down_devices": "🔴",
    "security_events": "⚡",
    "scheduled_checks": "⏰",
    "system": "ℹ️",
}

# Severity level ordering for dedup
SEVERITY_ORDER = {"info": 0, "warning": 1, "high": 2, "critical": 3}

_COOLDOWN_SECONDS = 300

# ── DB Schema (auto-created) ────────────────────────────────────────

_NOTIFICATIONS_DDL = """
CREATE TABLE IF NOT EXISTS cyberclaw_notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    guid       TEXT UNIQUE NOT NULL,
    section    TEXT NOT NULL,
    title      TEXT NOT NULL,
    message    TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT 'info',
    status     TEXT NOT NULL DEFAULT 'new',
    channels   TEXT NOT NULL DEFAULT '',
    device_mac TEXT NOT NULL DEFAULT '',
    device_ip  TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    pushed_at  TEXT NOT NULL DEFAULT '',
    extra_json TEXT NOT NULL DEFAULT ''
)
"""


def _ensure_table():
    """Auto-create notifications table if not exists."""
    try:
        from ..db.compat import get_temp_db_connection
        conn = get_temp_db_connection()
        try:
            conn.execute(_NOTIFICATIONS_DDL)
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"Ensure notifications table: {e}")


class NotificationBridge:
    """Bridge between security events and notification delivery.

    Adapted from NetAlertX's NotificationInstance + reporting.py pattern:
      - Events are persisted to DB with status='new'
      - Publishers read 'new' notifications and send via channels
      - After delivery, status is updated to 'processed'
    """

    def __init__(self):
        self._dedup_cache: dict[str, float] = {}
        self._cooldown = _COOLDOWN_SECONDS
        _ensure_table()

    # ── Dedup ─────────────────────────────────────────────────────

    def _is_duplicate(self, key: str) -> bool:
        now = time.time()
        last = self._dedup_cache.get(key, 0)
        if now - last < self._cooldown:
            return True
        self._dedup_cache[key] = now
        if len(self._dedup_cache) > 1000:
            cutoff = now - self._cooldown * 2
            self._dedup_cache = {k: v for k, v in self._dedup_cache.items() if v > cutoff}
        return False

    # ── Core send (NetAlertX: NotificationInstance.create) ────────

    async def _send(self, title: str, message: str, severity: str = "info",
                    section: str = "system", device_info: dict = None,
                    task_type: str = "", extra_data: dict = None,
                    bypass_dedup: bool = False):
        """Persist notification, then publish via channels + WebSocket.
        Returns the guid of the created notification."""
        if not bypass_dedup:
            dedup_key = f"{section}:{title}:{(device_info or {}).get('devMac', '')}"
            if self._is_duplicate(dedup_key):
                logger.debug(f"Notification deduplicated: {title}")
                return None

        guid = str(uuid.uuid4())[:8]
        mac = (device_info or {}).get("devMac", "")
        ip = (device_info or {}).get("devLastIP", "")

        # Build extra_json from task result data
        extra_json = ""
        if extra_data:
            try:
                extra_json = json.dumps({"task_type": task_type, "result": extra_data},
                                        ensure_ascii=False)
            except (TypeError, ValueError):
                extra_json = ""

        # 1. Persist to DB (status='new')
        self._persist_notification(guid, section, title, message, severity, mac, ip, extra_json)

        # 2. Publish via channels (webhook/ntfy)
        channels_sent = []
        try:
            from .notification_service import get_notification_service
            svc = get_notification_service()
            await svc.send(title=title, message=message, severity=severity,
                           device_info=device_info)
            channels_sent = self._get_channels_for_severity(severity)
        except Exception as e:
            logger.warning(f"Notification channels failed: {e}")

        # 3. Mark as processed + record which channels were used
        self._mark_processed(guid, ",".join(channels_sent))

        # 4. Broadcast via WebSocket for real-time frontend
        try:
            from ..main import ws_manager
            await ws_manager.broadcast({
                "type": "notification",
                "guid": guid,
                "section": section,
                "icon": SECTION_ICONS.get(section, "ℹ️"),
                "title": title,
                "message": message,
                "severity": severity,
                "device": device_info,
                "timestamp": datetime.utcnow().isoformat(),
                "channels": channels_sent,
                "has_detail": bool(extra_data),
                "task_type": task_type,
            })
        except Exception:
            pass

        logger.info(f"Notification [{section}] {severity}: {title}")
        return guid

    def _get_channels_for_severity(self, severity: str) -> list[str]:
        """Resolve which channels handle this severity."""
        try:
            from .notification_service import get_notification_service
            svc = get_notification_service()
            channels = set()
            for rule in svc.config.get("rules", []):
                if severity in rule.get("severity", []):
                    channels.update(rule.get("channels", []))
            return list(channels)
        except Exception:
            return []

    # ── DB operations (NetAlertX: NotificationInstance.upsert) ─────

    def _persist_notification(self, guid, section, title, message, severity, mac, ip, extra_json=""):
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                conn.execute("""
                    INSERT INTO cyberclaw_notifications
                        (guid, section, title, message, severity, status, device_mac, device_ip, extra_json)
                    VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?)
                """, (guid, section, title, message, severity, mac, ip, extra_json))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Persist notification failed: {e}")

    def _mark_processed(self, guid: str, channels: str = ""):
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                conn.execute("""
                    UPDATE cyberclaw_notifications
                    SET status='processed', pushed_at=datetime('now'), channels=?
                    WHERE guid=?
                """, (channels, guid))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Mark processed failed: {e}")

    # ── Event handlers (NetAlertX: section-based) ─────────────────

    async def on_device_status_change(self, device: dict, old_status: str, new_status: str):
        name = device.get("devName", device.get("name", "未知设备"))
        ip = device.get("devLastIP", device.get("ip", "未知"))

        if new_status == "attacked":
            await self._send(
                title=f"入侵告警: {name}",
                message=f"设备 {name} ({ip}) 检测到攻击，状态 {old_status} → {new_status}。建议立即隔离。",
                severity="critical", section="security_events", device_info=device,
            )
        elif new_status == "vulnerable":
            await self._send(
                title=f"漏洞告警: {name}",
                message=f"设备 {name} ({ip}) 发现漏洞，状态 {old_status} → {new_status}。",
                severity="warning", section="security_events", device_info=device,
            )
        elif new_status == "isolated":
            await self._send(
                title=f"设备已隔离: {name}",
                message=f"设备 {name} ({ip}) 已被自动隔离。",
                severity="warning", section="security_events", device_info=device,
            )
        elif new_status == "scanning":
            await self._send(
                title=f"扫描检测: {name}",
                message=f"设备 {name} ({ip}) 正在被扫描。",
                severity="info", section="security_events", device_info=device,
            )

    async def on_new_device_found(self, device: dict):
        name = device.get("devName", device.get("name", "未知"))
        ip = device.get("devLastIP", device.get("ip", "未知"))
        mac = device.get("devMac", device.get("mac", "未知"))
        vendor = device.get("devVendor", device.get("vendor", "未知"))

        await self._send(
            title=f"新设备加入: {name}",
            message=f"发现新设备: {name} ({ip})\nMAC: {mac}\n厂商: {vendor}",
            severity="info", section="new_devices", device_info=device,
        )

    async def on_device_down(self, device: dict):
        name = device.get("devName", device.get("name", "未知"))
        ip = device.get("devLastIP", device.get("ip", "未知"))

        await self._send(
            title=f"设备离线: {name}",
            message=f"设备 {name} ({ip}) 已离线。",
            severity="warning", section="down_devices", device_info=device,
        )

    async def on_scheduled_check_result(self, check_name: str, result: dict, issues: int):
        check_labels = {
            "network_scan": "网络扫描",
            "cve_check": "CVE 漏洞检查",
            "baseline_check": "安全基线检查",
            "traffic_analysis": "流量分析",
            "config_audit": "配置审计",
        }
        label = check_labels.get(check_name, check_name)
        severity = "critical" if issues >= 5 else "warning" if issues >= 1 else "info"

        await self._send(
            title=f"安全检查: {label}",
            message=f"{label} 发现 {issues} 个问题，请查看仪表板。",
            severity=severity, section="scheduled_checks",
        )

    async def on_timer_result(self, original_message: str, summary: str):
        """Timer task completed — notify user."""
        await self._send(
            title=f"定时任务完成",
            message=f"任务: {original_message[:100]}\n\n{summary[:300]}",
            severity="info", section="scheduled_checks",
        )

    async def on_intrusion_detected(self, alert: dict):
        src_ip = alert.get("src_ip", "未知")
        dst_ip = alert.get("dest_ip", "未知")
        rule = alert.get("alert", {}).get("signature", "未知规则")

        await self._send(
            title="入侵检测告警",
            message=f"来源: {src_ip} → 目标: {dst_ip}\n规则: {rule}",
            severity="critical", section="security_events",
            device_info={"devLastIP": dst_ip, "src_ip": src_ip},
        )

    async def on_security_event(self, event: dict):
        message = str(event.get("message", event.get("raw", "")))[:200]
        src_ip = event.get("source_ip", event.get("src_ip", "未知"))
        severity = "warning"
        if event.get("severity") in ("critical", "emergency", "alert"):
            severity = "critical"

        await self._send(
            title=f"安全事件: {src_ip}",
            message=message,
            severity=severity, section="security_events",
        )

    # ── Query API (for frontend history) ──────────────────────────

    def get_notifications(self, section: str = None, severity: str = None,
                          search: str = None, status: str = None,
                          limit: int = 50, offset: int = 0) -> list[dict]:
        """Query notifications with filtering and pagination."""
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                query = "SELECT * FROM cyberclaw_notifications WHERE 1=1"
                params = []
                if section:
                    query += " AND section=?"
                    params.append(section)
                if severity:
                    query += " AND severity=?"
                    params.append(severity)
                if status:
                    query += " AND status=?"
                    params.append(status)
                if search:
                    query += " AND (title LIKE ? OR message LIKE ?)"
                    params.extend([f"%{search}%", f"%{search}%"])
                query += " ORDER BY id DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
        except Exception:
            return []

    def get_unread_count(self) -> int:
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cyberclaw_notifications WHERE status='new'"
                ).fetchone()
                return row["cnt"] if row else 0
            finally:
                conn.close()
        except Exception:
            return 0

    def mark_read(self, notification_id: int):
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                conn.execute(
                    "UPDATE cyberclaw_notifications SET status='read' WHERE id=?", (notification_id,)
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

    def mark_all_read(self, section: str = None):
        """Mark all new notifications as read."""
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                if section:
                    conn.execute(
                        "UPDATE cyberclaw_notifications SET status='read' WHERE status='new' AND section=?",
                        (section,),
                    )
                else:
                    conn.execute("UPDATE cyberclaw_notifications SET status='read' WHERE status='new'")
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Mark all read failed: {e}")

    def clear_notifications(self, section: str = None):
        """Delete notifications, optionally by section."""
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                if section:
                    conn.execute("DELETE FROM cyberclaw_notifications WHERE section=?", (section,))
                else:
                    conn.execute("DELETE FROM cyberclaw_notifications")
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Clear notifications failed: {e}")

    def get_notification(self, notification_id: int) -> dict | None:
        """Fetch a single notification by ID, with parsed extra_json."""
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                row = conn.execute(
                    "SELECT * FROM cyberclaw_notifications WHERE id=?", (notification_id,)
                ).fetchone()
                if row:
                    result = dict(row)
                    result["extra"] = self._parse_extra_json(result.get("extra_json", ""))
                    return result
                return None
            finally:
                conn.close()
        except Exception:
            return None

    def get_notification_by_guid(self, guid: str) -> dict | None:
        """Fetch a single notification by GUID, with parsed extra_json."""
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                row = conn.execute(
                    "SELECT * FROM cyberclaw_notifications WHERE guid=?", (guid,)
                ).fetchone()
                if row:
                    result = dict(row)
                    result["extra"] = self._parse_extra_json(result.get("extra_json", ""))
                    return result
                return None
            finally:
                conn.close()
        except Exception:
            return None

    @staticmethod
    def _parse_extra_json(raw: str) -> dict | None:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None


# Singleton
_bridge: NotificationBridge | None = None


def get_notification_bridge() -> NotificationBridge:
    global _bridge
    if _bridge is None:
        _bridge = NotificationBridge()
    return _bridge
