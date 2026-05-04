from fastapi import APIRouter

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/events")
async def list_events():
    return {"events": []}


@router.get("/state/{device_id}")
async def device_state(device_id: str):
    return {"device_id": device_id, "state": "secure"}
