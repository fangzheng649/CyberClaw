from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from ..services.nx_bridge import get_bridge
from ..services.topology_service import get_device

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/events")
async def list_events(
    severity: str = Query("", description="Filter by severity"),
    source_type: str = Query("", description="Filter by source_type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    bridge = get_bridge()
    sev = severity or None
    src = source_type or None
    events = await bridge.get_security_events(
        limit=limit, offset=offset, severity=sev, source_type=src,
    )
    total = await bridge.count_security_events_filtered(
        severity=sev, source_type=src,
    )
    return {
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/state/{device_id}")
async def device_state(device_id: str):
    dev = get_device(device_id)
    if not dev:
        return JSONResponse({"error": "not_found", "detail": f"Device {device_id} not found"}, status_code=404)
    return {
        "device_id": device_id,
        "state": dev.status,
        "device": dev.model_dump(),
    }
