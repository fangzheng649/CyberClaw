"""通知 API 路由 — notification management with batch ops and search."""
import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Request

from ..services.notification_service import get_notification_service
from ..services.notification_bridge import get_notification_bridge

router = APIRouter(prefix="/api/notifications", tags=["notifications"])

NOTIFICATIONS_CONFIG = Path(__file__).resolve().parent.parent.parent / "config" / "notifications.json"


@router.get("/config")
async def get_notification_config():
    if not NOTIFICATIONS_CONFIG.exists():
        return {"channels": {}, "rules": []}
    return json.loads(NOTIFICATIONS_CONFIG.read_text(encoding="utf-8"))


@router.put("/config")
async def update_notification_config(body: dict = Body(default={})):
    NOTIFICATIONS_CONFIG.write_text(
        json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    get_notification_service().reload()
    return {"status": "updated"}


@router.post("/test")
async def test_notification(body: dict = Body(default={})):
    """Send a test notification through all configured channels."""
    bridge = get_notification_bridge()
    title = body.get("title", "Test Notification")
    message = body.get("message", "CyberClaw 测试通知")
    severity = body.get("severity", "info")
    await bridge._send(title=title, message=message, severity=severity, section="system")
    return {"status": "sent"}


@router.get("/history")
async def get_notification_history(
    section: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """Get notification history with filtering and pagination."""
    bridge = get_notification_bridge()
    notifications = bridge.get_notifications(
        section=section, severity=severity, search=search, limit=limit, offset=offset
    )
    return {"notifications": notifications}


@router.get("/unread_count")
async def get_unread_count():
    """Get count of unread notifications."""
    bridge = get_notification_bridge()
    return {"count": bridge.get_unread_count()}


@router.post("/{notification_id}/read")
async def mark_notification_read(notification_id: int):
    """Mark a notification as read."""
    bridge = get_notification_bridge()
    bridge.mark_read(notification_id)
    return {"status": "read"}


@router.post("/mark-all-read")
async def mark_all_read(request: Request):
    """Mark all notifications as read, optionally filtered by section."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    section = body.get("section")
    bridge = get_notification_bridge()
    bridge.mark_all_read(section=section)
    return {"status": "updated"}


@router.delete("/history")
async def clear_notifications(request: Request):
    """Delete all notifications, optionally filtered by section."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    section = body.get("section")
    bridge = get_notification_bridge()
    bridge.clear_notifications(section=section)
    return {"status": "cleared"}


@router.get("/by-guid/{guid}")
async def get_notification_by_guid(guid: str):
    """Get full notification detail by GUID (for toast button clicks)."""
    bridge = get_notification_bridge()
    notif = bridge.get_notification_by_guid(guid)
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    bridge.mark_read(notif["id"])
    return notif


@router.get("/{notification_id}")
async def get_notification_detail(notification_id: int):
    """Get full notification detail by ID (for history list clicks)."""
    bridge = get_notification_bridge()
    notif = bridge.get_notification(notification_id)
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    bridge.mark_read(notification_id)
    return notif
