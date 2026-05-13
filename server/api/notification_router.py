"""通知 API 路由"""
import json
from pathlib import Path

from fastapi import APIRouter

from ..services.notification_service import get_notification_service

router = APIRouter(prefix="/api/notifications", tags=["notifications"])

NOTIFICATIONS_CONFIG = Path("config/notifications.json")


@router.get("/config")
async def get_notification_config():
    if not NOTIFICATIONS_CONFIG.exists():
        return {"channels": {}, "rules": []}
    return json.loads(NOTIFICATIONS_CONFIG.read_text(encoding="utf-8"))


@router.put("/config")
async def update_notification_config(body: dict):
    NOTIFICATIONS_CONFIG.write_text(
        json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    get_notification_service().reload()
    return {"status": "updated"}


@router.post("/test")
async def test_notification(body: dict):
    svc = get_notification_service()
    title = body.get("title", "Test Notification")
    message = body.get("message", "This is a test notification from CyberClaw")
    severity = body.get("severity", "info")
    await svc.send(title, message, severity)
    return {"status": "sent"}


@router.get("/history")
async def get_notification_history(limit: int = 50):
    try:
        from server.db.compat import get_temp_db_connection
        conn = get_temp_db_connection()
        rows = conn.execute(
            "SELECT * FROM notifications ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return {"notifications": [dict(r) for r in rows]}
    except Exception:
        return {"notifications": []}
