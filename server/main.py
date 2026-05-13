import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .api.topology import router as topology_router
from .api.security import router as security_router
from .api.scenario import router as scenario_router, set_scenario_service
from .api.chat import router as chat_router
from .api.tools import router as tools_router
from .api.discovery import router as discovery_router
from .services.topology_service import get_topology
from .services.scenario_service import ScenarioService
from .services.tool_broadcast_service import set_broadcast as set_tool_broadcast
from .services.collector_service import get_receiver
from .services.snmp_service import get_snmp_service
from .services.mqtt_service import get_mqtt_service
from .services.suricata_service import get_suricata_service
from .services.scan_service import get_scan_service
from .api.dashboard import router as dashboard_router
from .api.workflow_router import router as workflow_router
from .api.notification_router import router as notification_router
from .services.nx_bridge import get_bridge
from .websocket.events import ConnectionManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ws_manager = ConnectionManager()
scenario_service = ScenarioService()

topology = get_topology()
device_count = len(topology.devices)
scenario_service.set_topology(topology.devices, topology.links)


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
                "totalSteps": device_count,
            })


scenario_service.set_broadcast(broadcast_event)
set_scenario_service(scenario_service)
set_tool_broadcast(broadcast_event)

# Wire collector service broadcast
get_receiver().set_broadcast(broadcast_event)

# Wire SNMP and MQTT service broadcasts
get_snmp_service().set_broadcast(broadcast_event)
get_mqtt_service().set_broadcast(broadcast_event)

# Wire Suricata service broadcast
get_suricata_service().set_broadcast(broadcast_event)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CyberClaw FastAPI backend starting...")
    # 初始化持久化数据库
    try:
        bridge = get_bridge()
        await bridge.initialize()
        logger.info("Database initialized successfully")
        # Seed topology.json 到数据库（仅空库时执行）
        try:
            from .services.db.seed_service import seed_from_config
            await seed_from_config()
        except Exception as e:
            logger.debug(f"Seed skipped: {e}")
    except Exception as e:
        logger.warning(f"Database init failed (continuing without DB): {e}")
    # 可选：自动启动定期网络扫描
    scan_subnet = os.getenv("SCAN_SUBNET", "")
    if scan_subnet:
        scan_interval = int(os.getenv("SCAN_INTERVAL", "300"))
        scan_svc = get_scan_service()
        await scan_svc.start(subnet=scan_subnet, interval=scan_interval)
        logger.info(f"Auto scan started: subnet={scan_subnet}, interval={scan_interval}s")
    hb_task = asyncio.create_task(heartbeat_loop())
    yield
    hb_task.cancel()
    # 停止自动扫描
    try:
        await get_scan_service().stop()
    except Exception:
        pass
    # 关闭数据库
    try:
        await get_bridge().shutdown()
    except Exception:
        pass
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
app.include_router(tools_router)
app.include_router(discovery_router)
app.include_router(dashboard_router)
app.include_router(workflow_router)
app.include_router(notification_router)


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
