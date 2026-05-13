"""
异步桥接器 — 在 CyberClaw async 服务和持久化层之间桥接
所有 NetAlertX 同步数据库调用通过 run_in_executor 包装为 async
"""
import asyncio
import json
import logging
from typing import Optional

from server.db.compat import get_db, get_temp_db_connection, close_db, load_settings, mylog

logger = logging.getLogger("cyberclaw.db.bridge")


class NXBridge:
    """异步包装持久化数据库操作"""

    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_loop(self):
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.get_event_loop()
        return self._loop

    async def initialize(self):
        """初始化数据库（启动时调用一次）"""
        loop = self._get_loop()
        await loop.run_in_executor(None, self._sync_initialize)

    def _sync_initialize(self):
        from server.db.database import DB
        load_settings()
        db = DB()
        db.open()
        db.initDB()
        db.commitDB()
        mylog("info", "[Bridge] Database initialized")

    async def shutdown(self):
        loop = self._get_loop()
        await loop.run_in_executor(None, close_db)

    # ── 设备操作 ─────────────────────────────────────────────────

    async def get_all_devices(self):
        loop = self._get_loop()
        return await loop.run_in_executor(None, self._sync_get_all_devices)

    def _sync_get_all_devices(self):
        conn = get_temp_db_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM Devices WHERE devIsArchived = 0"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    async def get_device_by_mac(self, mac: str):
        loop = self._get_loop()
        return await loop.run_in_executor(None, lambda m=mac: self._sync_get_device_by_mac(m))

    def _sync_get_device_by_mac(self, mac: str):
        conn = get_temp_db_connection()
        try:
            row = conn.execute(
                "SELECT * FROM Devices WHERE devMac = ?", (mac.lower(),)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    async def get_device_by_ip(self, ip: str):
        loop = self._get_loop()
        return await loop.run_in_executor(None, lambda i=ip: self._sync_get_device_by_ip(i))

    def _sync_get_device_by_ip(self, ip: str):
        conn = get_temp_db_connection()
        try:
            row = conn.execute(
                "SELECT * FROM Devices WHERE devLastIP = ? AND devIsArchived = 0", (ip,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    async def upsert_device(self, mac: str, data: dict, source: str = "CONFIG"):
        loop = self._get_loop()
        return await loop.run_in_executor(
            None, lambda m=mac, d=data, s=source: self._sync_upsert_device(m, d, s)
        )

    def _sync_upsert_device(self, mac: str, data: dict, source: str):
        conn = get_temp_db_connection()
        try:
            mac = mac.lower()
            existing = conn.execute(
                "SELECT devMac FROM Devices WHERE devMac = ?", (mac,)
            ).fetchone()

            if existing:
                # 更新 — 只更新有值的字段
                sets = []
                vals = []
                skip_keys = {"devMac", "devMacSource"}
                for k, v in data.items():
                    if k in skip_keys:
                        continue
                    if v is not None and v != "":
                        sets.append(f'"{k}" = ?')
                        vals.append(v)
                if sets:
                    # 更新字段源
                    source_fields = {
                        "devName": "devNameSource", "devType": "devTypeSource",
                        "devVendor": "devVendorSource", "devLastIP": "devLastIPSource",
                        "devFQDN": "devFQDNSource", "devIcon": "devIconSource",
                    }
                    for field, src_field in source_fields.items():
                        if field in data and data[field]:
                            sets.append(f'"{src_field}" = ?')
                            vals.append(source)
                    vals.append(mac)
                    conn.execute(
                        f'UPDATE Devices SET {", ".join(sets)} WHERE devMac = ?', vals
                    )
            else:
                # 插入新设备
                data.setdefault("devMac", mac)
                data.setdefault("devName", "New Device")
                data.setdefault("devStatus", "secure")
                data.setdefault("devPresentLastScan", 1)
                data.setdefault("devIsNew", 1)
                data.setdefault("devIsArchived", 0)
                data.setdefault("devAlertDown", 1)
                data.setdefault("devFirstConnection", "")
                data.setdefault("devLastConnection", "")

                cols = [f'"{k}"' for k in data.keys()]
                placeholders = ",".join(["?"] * len(data))
                vals = list(data.values())
                conn.execute(
                    f'INSERT OR IGNORE INTO Devices ({", ".join(cols)}) VALUES ({placeholders})', vals
                )
            conn.commit()
        except Exception as e:
            logger.error(f"upsert_device error: {e}")
        finally:
            conn.close()

    async def update_device_status(self, mac: str, status: str):
        loop = self._get_loop()
        return await loop.run_in_executor(
            None, lambda m=mac, s=status: self._sync_update_device_status(m, s)
        )

    def _sync_update_device_status(self, mac: str, status: str):
        conn = get_temp_db_connection()
        try:
            conn.execute(
                'UPDATE Devices SET "devStatus" = ? WHERE devMac = ?',
                (status, mac.lower()),
            )
            conn.commit()
        finally:
            conn.close()

    # ── 安全事件 ─────────────────────────────────────────────────

    async def record_security_event(
        self, source_type: str, severity: str, message: str, **kwargs
    ):
        loop = self._get_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._sync_record_security_event(source_type, severity, message, **kwargs),
        )

    def _sync_record_security_event(self, source_type, severity, message, **kwargs):
        conn = get_temp_db_connection()
        try:
            conn.execute(
                """INSERT INTO security_events
                   (source_type, severity, message, source, target, target_mac, details, fsm_state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_type,
                    severity,
                    message,
                    kwargs.get("source", ""),
                    kwargs.get("target", ""),
                    kwargs.get("target_mac", ""),
                    json.dumps(kwargs.get("details", {})),
                    kwargs.get("fsm_state", ""),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.error(f"record_security_event error: {e}")
        finally:
            conn.close()

    async def get_security_events(self, limit=50, offset=0, severity=None, source_type=None):
        loop = self._get_loop()
        return await loop.run_in_executor(
            None, lambda: self._sync_get_security_events(limit, offset, severity, source_type)
        )

    def _sync_get_security_events(self, limit, offset, severity, source_type):
        conn = get_temp_db_connection()
        try:
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if source_type:
                query += " AND source_type = ?"
                params.append(source_type)
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    async def count_security_events_filtered(self, severity=None, source_type=None):
        """Count security events matching filters (for pagination total)."""
        loop = self._get_loop()
        return await loop.run_in_executor(
            None, lambda: self._sync_count_security_events_filtered(severity, source_type)
        )

    def _sync_count_security_events_filtered(self, severity, source_type):
        conn = get_temp_db_connection()
        try:
            query = "SELECT COUNT(*) as cnt FROM security_events WHERE 1=1"
            params = []
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if source_type:
                query += " AND source_type = ?"
                params.append(source_type)
            row = conn.execute(query, params).fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    # ── 设备事件 ─────────────────────────────────────────────────

    async def record_device_event(self, mac: str, ip: str, event_type: str, details: str = ""):
        loop = self._get_loop()
        return await loop.run_in_executor(
            None, lambda: self._sync_record_device_event(mac, ip, event_type, details)
        )

    def _sync_record_device_event(self, mac, ip, event_type, details):
        conn = get_temp_db_connection()
        try:
            conn.execute(
                """INSERT INTO Events (eveMac, eveIp, eveEventType, eveAdditionalInfo, eveDateTime)
                   VALUES (?, ?, ?, ?, datetime('now'))""",
                (mac.lower(), ip, event_type, details),
            )
            conn.commit()
        except Exception as e:
            logger.error(f"record_device_event error: {e}")
        finally:
            conn.close()

    async def get_events(self, mac: str = None, limit: int = 50):
        loop = self._get_loop()
        return await loop.run_in_executor(None, lambda: self._sync_get_events(mac, limit))

    def _sync_get_events(self, mac, limit):
        conn = get_temp_db_connection()
        try:
            if mac:
                rows = conn.execute(
                    "SELECT * FROM Events WHERE eveMac = ? ORDER BY eveDateTime DESC LIMIT ?",
                    (mac.lower(), limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM Events ORDER BY eveDateTime DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── 统计 ─────────────────────────────────────────────────────

    async def get_device_counts_by_status(self):
        loop = self._get_loop()
        return await loop.run_in_executor(None, self._sync_get_device_counts_by_status)

    def _sync_get_device_counts_by_status(self):
        conn = get_temp_db_connection()
        try:
            rows = conn.execute(
                """SELECT COALESCE(devStatus, 'secure') as status, COUNT(*) as count
                   FROM Devices WHERE devIsArchived = 0 GROUP BY devStatus"""
            ).fetchall()
            return {r["status"]: r["count"] for r in rows}
        finally:
            conn.close()

    async def get_alert_counts_by_hour(self, hours: int = 24):
        loop = self._get_loop()
        return await loop.run_in_executor(None, lambda: self._sync_get_alert_counts_by_hour(hours))

    def _sync_get_alert_counts_by_hour(self, hours):
        conn = get_temp_db_connection()
        try:
            rows = conn.execute(
                """SELECT strftime('%H', timestamp) as hour, severity, COUNT(*) as count
                   FROM security_events
                   WHERE timestamp >= datetime('now', ?)
                   GROUP BY hour, severity ORDER BY hour""",
                (f"-{hours} hours",),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    async def count_security_events(self, hours: int = 24):
        loop = self._get_loop()
        return await loop.run_in_executor(None, lambda: self._sync_count_security_events(hours))

    def _sync_count_security_events(self, hours):
        conn = get_temp_db_connection()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM security_events WHERE timestamp >= datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    # ── 工作流事件 ──────────────────────────────────────────────

    async def record_app_event(self, object_type, event_type, object_guid="", extra_data=None):
        loop = self._get_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._sync_record_app_event(object_type, event_type, object_guid, extra_data),
        )

    def _sync_record_app_event(self, object_type, event_type, object_guid, extra_data):
        import uuid
        conn = get_temp_db_connection()
        try:
            guid = uuid.uuid4().hex[:12]
            extra = json.dumps(extra_data or {})
            conn.execute(
                """INSERT INTO AppEvents
                   (guid, appEventProcessed, objectType, objectGuid, appEventType, extra)
                   VALUES (?, 0, ?, ?, ?, ?)""",
                (guid, object_type, object_guid, event_type, extra),
            )
            conn.commit()
            return guid
        except Exception as e:
            logger.error(f"record_app_event error: {e}")
            return None
        finally:
            conn.close()

    async def process_pending_events(self):
        loop = self._get_loop()
        return await loop.run_in_executor(None, self._sync_process_pending_events)

    def _sync_process_pending_events(self):
        import json as _json
        from pathlib import Path as _Path
        try:
            conn = get_temp_db_connection()
            rows = conn.execute(
                'SELECT * FROM AppEvents WHERE appEventProcessed = 0 ORDER BY dateTimeCreated ASC'
            ).fetchall()
            if not rows:
                conn.close()
                return 0

            wf_path = _Path("config/workflows.json")
            if not wf_path.exists():
                conn.execute('UPDATE AppEvents SET appEventProcessed = 1')
                conn.commit()
                conn.close()
                return len(rows)

            workflows = _json.loads(wf_path.read_text(encoding="utf-8"))
            processed = 0
            for row in rows:
                evt = dict(row)
                for wf in workflows:
                    if wf.get("enabled", "No").lower() != "yes":
                        continue
                    trigger = wf.get("trigger", {})
                    if (trigger.get("object_type") == evt.get("objectType") and
                            trigger.get("event_type") == evt.get("appEventType")):
                        for action in wf.get("actions", []):
                            if action["type"] == "update_field":
                                obj_guid = evt.get("objectGuid", "")
                                if obj_guid:
                                    conn.execute(
                                        f'UPDATE Devices SET "{action["field"]}" = ? WHERE devGUID = ?',
                                        (action["value"], obj_guid),
                                    )
                conn.execute(
                    'UPDATE AppEvents SET appEventProcessed = 1 WHERE "index" = ?',
                    (evt["index"],),
                )
                processed += 1
            conn.commit()
            conn.close()
            return processed
        except Exception as e:
            logger.error(f"process_pending_events error: {e}")
            return 0


# 单例
_bridge: Optional[NXBridge] = None


def get_bridge() -> NXBridge:
    global _bridge
    if _bridge is None:
        _bridge = NXBridge()
    return _bridge
