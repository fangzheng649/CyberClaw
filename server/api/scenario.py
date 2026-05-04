from fastapi import APIRouter
from ..services.scenario_service import ScenarioService

router = APIRouter(prefix="/api/scenario", tags=["scenario"])
scenario_service = ScenarioService()


def set_scenario_service(svc: ScenarioService) -> None:
    global scenario_service
    scenario_service = svc


@router.get("")
async def scenario_list():
    return {"scenarios": [{"id": "mirai", "name": "Mirai Botnet Attack", "steps": 15}]}


@router.get("/status")
async def scenario_status():
    return scenario_service.get_status()


@router.post("/{scenario_id}/start")
async def start_scenario(scenario_id: str):
    await scenario_service.start()
    return {"status": "running", "scenario_id": scenario_id}


@router.post("/{scenario_id}/stop")
async def stop_scenario(scenario_id: str):
    await scenario_service.stop()
    return {"status": "stopped", "scenario_id": scenario_id}


@router.post("/{scenario_id}/reset")
async def reset_scenario(scenario_id: str):
    await scenario_service.stop()
    return {"status": "reset", "scenario_id": scenario_id}
