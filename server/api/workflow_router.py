"""工作流 API 路由"""
import json

from fastapi import APIRouter
from pathlib import Path

from ..services.nx_bridge import get_bridge

router = APIRouter(prefix="/api/workflows", tags=["workflows"])

WORKFLOWS_PATH = Path("config/workflows.json")


@router.get("/")
async def list_workflows():
    if not WORKFLOWS_PATH.exists():
        return {"workflows": []}
    workflows = json.loads(WORKFLOWS_PATH.read_text(encoding="utf-8"))
    return {"workflows": workflows}


@router.post("/")
async def create_workflow(body: dict):
    if not WORKFLOWS_PATH.exists():
        workflows = []
    else:
        workflows = json.loads(WORKFLOWS_PATH.read_text(encoding="utf-8"))

    workflows.append(body)
    WORKFLOWS_PATH.write_text(json.dumps(workflows, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"status": "created", "name": body.get("name")}


@router.put("/{index}")
async def update_workflow(index: int, body: dict):
    if not WORKFLOWS_PATH.exists():
        return {"error": "no workflows file"}
    workflows = json.loads(WORKFLOWS_PATH.read_text(encoding="utf-8"))
    if index < 0 or index >= len(workflows):
        return {"error": "index out of range"}
    workflows[index] = body
    WORKFLOWS_PATH.write_text(json.dumps(workflows, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"status": "updated", "index": index}


@router.delete("/{index}")
async def delete_workflow(index: int):
    if not WORKFLOWS_PATH.exists():
        return {"error": "no workflows file"}
    workflows = json.loads(WORKFLOWS_PATH.read_text(encoding="utf-8"))
    if index < 0 or index >= len(workflows):
        return {"error": "index out of range"}
    removed = workflows.pop(index)
    WORKFLOWS_PATH.write_text(json.dumps(workflows, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"status": "deleted", "name": removed.get("name")}


@router.get("/events")
async def get_workflow_events(limit: int = 50):
    bridge = get_bridge()
    events = await bridge.get_events(limit=limit)
    return {"events": events}


@router.post("/trigger")
async def trigger_workflow_event(body: dict):
    """手动插入一个 AppEvent 并触发工作流处理"""
    bridge = get_bridge()
    await bridge.record_app_event(
        object_type=body.get("object_type", "Devices"),
        event_type=body.get("event_type", "update"),
        object_guid=body.get("object_guid", ""),
        extra_data=body.get("extra_data", {}),
    )
    return {"status": "triggered"}
