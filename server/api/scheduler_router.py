"""Scheduler API — task CRUD, pause/resume, cron validation."""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from ..services.security_scheduler import get_security_scheduler

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])
logger = logging.getLogger(__name__)


class CreateTaskRequest(BaseModel):
    id: Optional[str] = None
    name: str
    type: str = "custom"
    tool_server: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args: dict = {}
    prompt: Optional[str] = None
    schedule_mode: str = "interval"
    interval_seconds: Optional[int] = None
    cron_expr: Optional[str] = None
    run_at: Optional[str] = None
    enabled: bool = True
    notify_on: list[str] = []


class UpdateTaskRequest(BaseModel):
    name: Optional[str] = None
    schedule_mode: Optional[str] = None
    interval_seconds: Optional[int] = None
    cron_expr: Optional[str] = None
    run_at: Optional[str] = None
    enabled: Optional[bool] = None
    tool_args: Optional[dict] = None
    prompt: Optional[str] = None
    notify_on: Optional[list[str]] = None


# ── Status & listing ──────────────────────────────────────────────

@router.get("/status")
async def scheduler_status():
    scheduler = get_security_scheduler()
    return scheduler.get_status()


@router.get("/tasks")
async def list_tasks():
    scheduler = get_security_scheduler()
    return {"tasks": scheduler.get_active_tasks()}


# ── CRUD ──────────────────────────────────────────────────────────

@router.post("/tasks")
async def create_task(body: CreateTaskRequest):
    scheduler = get_security_scheduler()
    cfg = body.model_dump(exclude_none=True)
    if cfg.get("schedule_mode") == "cron" and cfg.get("cron_expr"):
        result = _validate_cron_expr(cfg["cron_expr"])
        if not result["valid"]:
            return {"error": f"Invalid cron expression: {result['error']}"}
    task = scheduler.create_task(cfg)
    return task.to_dict()


@router.put("/tasks/{task_id}")
async def update_task(task_id: str, body: UpdateTaskRequest):
    scheduler = get_security_scheduler()
    updates = body.model_dump(exclude_none=True)
    if "cron_expr" in updates:
        result = _validate_cron_expr(updates["cron_expr"])
        if not result["valid"]:
            return {"error": f"Invalid cron expression: {result['error']}"}
    task = scheduler.update_task(task_id, updates)
    if not task:
        return {"error": f"Task {task_id} not found"}
    return task.to_dict()


@router.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    scheduler = get_security_scheduler()
    ok = scheduler.delete_task(task_id)
    return {"status": "deleted" if ok else "not_found"}


# ── Pause / Resume ────────────────────────────────────────────────

@router.post("/tasks/{task_id}/pause")
async def pause_task(task_id: str):
    scheduler = get_security_scheduler()
    ok = scheduler.pause_task(task_id)
    return {"status": "paused" if ok else "not_found"}


@router.post("/tasks/{task_id}/resume")
async def resume_task(task_id: str):
    scheduler = get_security_scheduler()
    ok = scheduler.resume_task(task_id)
    return {"status": "resumed" if ok else "not_found"}


# ── Manual trigger ────────────────────────────────────────────────

@router.post("/trigger/{task_id}")
async def trigger_task(task_id: str):
    scheduler = get_security_scheduler()
    result = await scheduler.trigger_check(task_id)
    if not result:
        return {"error": f"Task {task_id} not found"}
    return result


# ── Cron validation ───────────────────────────────────────────────

@router.post("/validate-cron")
async def validate_cron(body: dict):
    expr = body.get("cron_expr", "")
    return _validate_cron_expr(expr)


def _validate_cron_expr(expr: str) -> dict:
    if not expr:
        return {"valid": False, "error": "empty expression"}
    try:
        from croniter import croniter
        now_local = datetime.now().astimezone()
        cron = croniter(expr, now_local)
        next_runs = [cron.get_next(datetime).isoformat() for _ in range(5)]
        return {"valid": True, "next_runs": next_runs}
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ── History & config ──────────────────────────────────────────────

@router.get("/history")
async def scheduler_history(limit: int = 50):
    scheduler = get_security_scheduler()
    return {"history": await scheduler.get_history(limit)}


@router.put("/config")
async def update_config(body: dict):
    scheduler = get_security_scheduler()
    # Update top-level config keys (e.g. "enabled")
    for k, v in body.items():
        if v is not None:
            scheduler._config[k] = v
    scheduler._save_config()
    return {"status": "updated"}
