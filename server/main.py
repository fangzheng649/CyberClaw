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
from .services.topology_service import get_topology, async_get_topology, is_mock_mode
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
from .api.scheduler_router import router as scheduler_router
from .services.nx_bridge import get_bridge
from .services.security_scheduler import get_security_scheduler
from .websocket.events import ConnectionManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def _detect_and_set_mode(bridge):
    """After initial scan, check if real devices are online.
    If none found → switch to mock mode (re-seed DB with demo devices).
    If devices found → ensure real mode.
    """
    from .services.topology_service import set_mock_mode, is_mock_mode

    # Wait up to 15s for initial scan to complete
    scan_svc = get_scan_service()
    for _ in range(15):
        if scan_svc.get_status().get("stats", {}).get("cycles", 0) > 0:
            break
        await asyncio.sleep(1)

    # Check DB: any REAL (non-mock) device with devPresentLastScan=1?
    try:
        db_devices = await bridge.get_all_devices()
        any_online = any(
            d.get("devPresentLastScan", 0) for d in (db_devices or [])
            if isinstance(d, dict) and d.get("devDiscoveryMethod") != "mock"
        )
    except Exception:
        any_online = False

    if not any_online:
        # No real devices → switch to mock mode
        logger.info("No real devices online — switching to MOCK mode")
        set_mock_mode(True)

        # Re-seed DB with mock devices
        try:
            # Clear existing devices
            from server.db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            conn.execute("DELETE FROM Devices")
            conn.execute("DELETE FROM Events")
            conn.execute("DELETE FROM security_events")
            conn.commit()
            conn.close()

            # Re-seed from mock_topology.json
            from server.services.db.seed_service import seed_from_config
            # Temporarily reset config cache so seed reads mock file
            from server.services import topology_service
            topology_service._config_cache = None
            await seed_from_config()
            topology_service._config_cache = None  # clear again for fresh load
            logger.info("DB re-seeded with mock demo devices")
        except Exception as e:
            logger.warning(f"Mock re-seed failed: {e}")
    else:
        logger.info("Real devices detected online — using REAL mode")
        set_mock_mode(False)

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
                "totalSteps": scenario_service.get_status()["total_steps"],
                "mock_mode": is_mock_mode(),
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
        # 清理上次遗留的非 secure 设备状态（防止演示中断后脏数据残留）
        try:
            reset_count = await bridge.reset_all_device_statuses()
            if reset_count > 0:
                logger.info(f"Startup cleanup: reset {reset_count} devices to 'secure'")
        except Exception as e:
            logger.debug(f"Startup device reset skipped: {e}")
        # One-time cleanup: delete phantom devices where devMac is a
        # topology ID (no colon) or starts with test prefix aa:bb:cc
        try:
            from server.db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                cur1 = conn.execute("DELETE FROM Devices WHERE devMac NOT LIKE '%:%'")
                count1 = cur1.rowcount
                cur2 = conn.execute("DELETE FROM Devices WHERE LOWER(devMac) LIKE 'aa:bb:cc%'")
                count2 = cur2.rowcount
                conn.commit()
                deleted = count1 + count2
                if deleted > 0:
                    logger.info(f"Startup cleanup: removed {deleted} phantom/test devices")
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Phantom device cleanup skipped: {e}")
    except Exception as e:
        logger.warning(f"Database init failed (continuing without DB): {e}")
    # 自动启动定期网络扫描（真实设备环境）
    # 从 topology.json 读取子网，或使用 SCAN_SUBNET 环境变量覆盖
    scan_subnet = os.getenv("SCAN_SUBNET", "")
    if not scan_subnet:
        try:
            _topo_path = Path(__file__).resolve().parent.parent / "config" / "topology.json"
            with open(_topo_path, encoding="utf-8") as f:
                _topo = json.load(f)
            scan_subnet = _topo.get("network", {}).get("subnet", "")
        except Exception:
            pass
    if scan_subnet:
        scan_interval = int(os.getenv("SCAN_INTERVAL", "300"))
        scan_svc = get_scan_service()
        await scan_svc.start(subnet=scan_subnet, interval=scan_interval)
        logger.info(f"Auto scan started: subnet={scan_subnet}, interval={scan_interval}s")
    else:
        logger.warning("SCAN_SUBNET not set and no subnet in topology.json — auto-scan disabled")

    # 检测是否需要切换到 mock 模式
    # 等待初始扫描完成后判断（最多等 15 秒）
    await _detect_and_set_mode(bridge)
    # Mock 模式检测完成后，重新加载拓扑到 scenario_service
    # （模块加载时 get_topology() 在 mock 模式设置之前执行，数据不正确）
    topology = await async_get_topology()
    device_count = len(topology.devices)
    scenario_service.set_topology(topology.devices, topology.links)
    logger.info(f"Scenario topology reloaded: {device_count} devices (mock={is_mock_mode()})")
    hb_task = asyncio.create_task(heartbeat_loop())
    # 启动安全调度器（定时 CVE/基线/流量检查）
    try:
        scheduler = get_security_scheduler()
        await scheduler.start()
        logger.info("Security scheduler started")
    except Exception as e:
        logger.warning(f"Security scheduler start failed: {e}")
    # Mock 模式：启动设备状态模拟器
    if is_mock_mode():
        try:
            from .services.mock_state_service import get_mock_simulator
            sim = get_mock_simulator()
            sim.set_broadcast(broadcast_event)
            await sim.start()
            logger.info("Mock state simulator started")
        except Exception as e:
            logger.warning(f"Mock state simulator start failed: {e}")
    yield
    hb_task.cancel()
    # 停止 Mock 模拟器
    try:
        from .services.mock_state_service import get_mock_simulator
        await get_mock_simulator().stop()
    except Exception:
        pass
    # 停止安全调度器
    try:
        await get_security_scheduler().stop()
    except Exception:
        pass
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


app = FastAPI(title="CyberClaw API", version="0.1.0", lifespan=lifespan, redirect_slashes=False)

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
app.include_router(scheduler_router)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        topology = await async_get_topology()
        await ws.send_text(json.dumps({
            "type": "init",
            "devices": topology.model_dump()["devices"],
            "links": [{"from": l.from_, "to": l.to} for l in topology.links],
            "mock_mode": is_mock_mode(),
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
                topology = await async_get_topology()
                await ws.send_text(json.dumps({
                    "type": "scenario_reset",
                    "devices": topology.model_dump()["devices"],
                    "links": [{"from": l.from_, "to": l.to} for l in topology.links],
                }, ensure_ascii=False))
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
