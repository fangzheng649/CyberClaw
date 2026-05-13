from fastapi import APIRouter
from fastapi.responses import JSONResponse
from ..services.topology_service import get_topology, get_device

router = APIRouter(prefix="/api", tags=["topology"])


@router.get("/topology")
async def topology():
    return get_topology().model_dump()


@router.get("/topology/devices/{device_id}")
async def device_detail(device_id: str):
    device = get_device(device_id)
    if not device:
        return JSONResponse({"error": "not_found", "detail": f"Device {device_id} not found"}, status_code=404)
    return device.model_dump()
