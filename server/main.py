import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .api.topology import router as topology_router
from .api.security import router as security_router
from .api.scenario import router as scenario_router, set_scenario_service
from .api.chat import router as chat_router
from .services.topology_service import get_topology, DEVICES, LINKS
from .services.scenario_service import ScenarioService
from .websocket.events import ConnectionManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ws_manager = ConnectionManager()
scenario_service = ScenarioService()

topology = get_topology()
scenario_service.set_topology(DEVICES, LINKS)


async def broadcast_event(event_data: dict) -> None:
    await ws_manager.broadcast(event_data)


async def heartbeat_loop():
    """Broadcast heartbeat every 5 seconds."""
    while True:
        await asyncio.sleep(5)
        devices = scenario_service.get_devices()
        if devices:
            stats = {
                "secure": sum(1 for d in devices if d["status"] == "secure"),
                "scanning": sum(1 for d in devices if d["status"] == "scanning"),
                "vulnerable": sum(1 for d in devices if d["status"] == "vulnerable"),
                "attacked": sum(1 for d in devices if d["status"] == "attacked"),
                "isolated": sum(1 for d in devices if d["status"] == "isolated"),
            }
            await ws_manager.broadcast({
                "type": "heartbeat",
                "stats": stats,
                "scenarioRunning": scenario_service.running,
                "step": scenario_service.step,
                "totalSteps": 15,
            })


scenario_service.set_broadcast(broadcast_event)
set_scenario_service(scenario_service)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CyberClaw FastAPI backend starting...")
    hb_task = asyncio.create_task(heartbeat_loop())
    yield
    hb_task.cancel()
    logger.info("CyberClaw FastAPI backend shutting down...")


app = FastAPI(title="CyberClaw API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(topology_router)
app.include_router(security_router)
app.include_router(scenario_router)
app.include_router(chat_router)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        topology = get_topology()
        await ws.send_text(json.dumps({
            "type": "init",
            "devices": topology.model_dump()["devices"],
            "links": [{"from": l.from_, "to": l.to} for l in topology.links],
        }, ensure_ascii=False))

        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "start_scenario":
                await scenario_service.start()
            elif msg.get("action") == "stop_scenario":
                await scenario_service.stop()
            elif msg.get("action") == "reset":
                await scenario_service.stop()
                topology = get_topology()
                await ws.send_text(json.dumps({
                    "type": "init",
                    "devices": topology.model_dump()["devices"],
                    "links": [{"from": l.from_, "to": l.to} for l in topology.links],
                }, ensure_ascii=False))
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
