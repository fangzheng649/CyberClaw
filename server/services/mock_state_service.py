"""Mock 状态模拟器 — 在 Mock 模式下周期性随机变化设备状态，生成合成安全事件。

使 Dashboard 趋势图、设备状态分布等在没有真实数据时也有展示内容。
仅在 is_mock_mode() == True 时运行。
"""
import asyncio
import json
import logging
import random
from datetime import datetime, timedelta

logger = logging.getLogger("cyberclaw.mock_state")

# 目标状态分布比例
_TARGET_RATIOS = {
    "secure": 0.70,
    "scanning": 0.15,
    "vulnerable": 0.10,
    "attacked": 0.03,
    "isolated": 0.02,
}

# 状态转换概率矩阵（当前状态 → 新状态的权重）
_TRANSITION_WEIGHTS = {
    "secure":     {"secure": 75, "scanning": 25},
    "scanning":   {"secure": 30, "scanning": 30, "vulnerable": 40},
    "vulnerable": {"secure": 30, "vulnerable": 30, "attacked": 30, "isolated": 10},
    "attacked":   {"attacked": 50, "isolated": 30, "secure": 20},
    "isolated":   {"isolated": 60, "secure": 40},
}

# 合成事件模板
_EVENT_TEMPLATES = {
    "scanning": [
        ("端口扫描检测", "warning", "检测到异常端口扫描行为 — 来源 {src}"),
        ("服务发现", "info", "SNMP 服务发现请求 — 来源 {src}"),
    ],
    "vulnerable": [
        ("弱密码告警", "warning", "设备 {name} 使用默认凭据"),
        ("固件过旧", "info", "设备 {name} 固件版本存在已知漏洞"),
        ("端口暴露", "warning", "设备 {name} 不安全端口 Telnet(23) 对外开放"),
    ],
    "attacked": [
        ("暴力破解", "critical", "设备 {name} 遭遇暴力破解攻击"),
        ("异常流量", "warning", "设备 {name} 检测到异常出站流量"),
    ],
    "isolated": [
        ("自动隔离", "info", "设备 {name} 已被自动隔离"),
    ],
}


class MockStateSimulator:
    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False
        self._trend_history: list[dict] = []
        self._initialized = False
        self._broadcast_callback = None

    def set_broadcast(self, callback):
        """Set broadcast callback for WebSocket notifications."""
        self._broadcast_callback = callback

    async def start(self):
        if self._running:
            return
        self._running = True
        self._generate_initial_trends()
        # 启动时立即注入初始状态变化，确保 Dashboard 有即时数据
        await self._initial_kick()
        self._task = asyncio.create_task(self._loop())
        logger.info("Mock state simulator started")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("Mock state simulator stopped")

    async def _initial_kick(self):
        """启动时强制改变 3-5 台设备状态并生成事件，确保 Dashboard 即时有数据。"""
        try:
            from .nx_bridge import get_bridge
            bridge = get_bridge()
            devices = await bridge.get_all_devices()
            if not devices:
                return
            candidates = [d for d in devices if isinstance(d, dict) and d.get("devMac")]
            if not candidates:
                return

            # 强制将 3-5 台设备设置为非 secure 状态
            kick_count = random.randint(3, 5)
            targets = random.sample(candidates, min(kick_count, len(candidates)))
            kick_statuses = ["scanning", "scanning", "vulnerable", "vulnerable", "attacked"]

            for dev, status in zip(targets, kick_statuses):
                mac = dev["devMac"]
                name = dev.get("devName", mac)
                await bridge.update_device_status(mac, status)
                await self._generate_event(bridge, dev, status)
                logger.info(f"Mock initial kick: {name} → {status}")

            # 广播初始状态
            if self._broadcast_callback:
                updated = await bridge.get_all_devices()
                stats = {}
                for d in (updated or []):
                    if isinstance(d, dict):
                        s = d.get("devStatus", "secure")
                        stats[s] = stats.get(s, 0) + 1
                await self._broadcast_callback({
                    "type": "mock_state_update",
                    "stats": stats,
                    "devices_count": len(updated or []),
                })
        except Exception as e:
            logger.warning(f"Mock initial kick failed: {e}")

    async def _loop(self):
        """每 15-30 秒随机改变 1-2 台设备状态"""
        try:
            while self._running:
                await asyncio.sleep(random.randint(15, 30))
                await self._simulation_cycle()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Mock state simulator error: {e}")

    async def _simulation_cycle(self):
        """一个模拟周期：随机选取设备进行状态转换"""
        try:
            from .nx_bridge import get_bridge
            bridge = get_bridge()
            devices = await bridge.get_all_devices()
            if not devices:
                return

            # 随机选 1-2 台设备改变状态
            count = random.randint(1, 2)
            candidates = [d for d in devices if isinstance(d, dict) and d.get("devMac")]
            if not candidates:
                return

            changed = False
            for _ in range(min(count, len(candidates))):
                dev = random.choice(candidates)
                current = dev.get("devStatus", "secure")
                new_status = self._pick_next_status(current)

                if new_status != current:
                    mac = dev["devMac"]
                    await bridge.update_device_status(mac, new_status)
                    name = dev.get("devName", mac)
                    logger.debug(f"Mock state: {name} {current} → {new_status}")

                    # Sync scenario_service in-memory state
                    try:
                        from . import scenario_service as _ss
                        _svc = _ss  # module reference
                    except Exception:
                        _svc = None
                    # Update the in-memory device list if available
                    if _svc:
                        try:
                            from server.main import scenario_service
                            for d in scenario_service.get_devices():
                                if d.get("mac") == mac or d.get("id", "").replace("_", "-") == name.lower().replace(" ", "-"):
                                    d["status"] = new_status
                                    break
                        except Exception:
                            pass

                    # 生成合成事件
                    await self._generate_event(bridge, dev, new_status)
                    changed = True

            # Broadcast updated device statuses via WebSocket
            if changed and self._broadcast_callback:
                try:
                    updated_devices = await bridge.get_all_devices()
                    stats = {}
                    for d in (updated_devices or []):
                        if isinstance(d, dict):
                            s = d.get("devStatus", "secure")
                            stats[s] = stats.get(s, 0) + 1
                    await self._broadcast_callback({
                        "type": "mock_state_update",
                        "stats": stats,
                        "devices_count": len(updated_devices or []),
                    })
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Mock simulation cycle error: {e}")

    def _pick_next_status(self, current: str) -> str:
        """基于转换权重随机选择下一个状态"""
        weights = _TRANSITION_WEIGHTS.get(current, _TRANSITION_WEIGHTS["secure"])
        options = list(weights.keys())
        probs = list(weights.values())
        return random.choices(options, weights=probs, k=1)[0]

    async def _generate_event(self, bridge, dev: dict, new_status: str):
        """生成一条合成安全事件"""
        templates = _EVENT_TEMPLATES.get(new_status, [])
        if not templates:
            return

        title, severity, message = random.choice(templates)
        name = dev.get("devName", "")
        src = dev.get("devLastIP", "")
        message = message.format(name=name, src=src)

        try:
            await bridge.record_security_event(
                source_type="mock_simulator",
                severity=severity,
                message=message,
                target=name,
                fsm_state=new_status,
            )
        except Exception as e:
            logger.debug(f"Failed to record mock event: {e}")

    # ── 趋势数据 — 基于 DB security_events 动态聚合 ──────────────

    def _generate_initial_trends(self):
        """生成过去 24 小时的初始趋势基线数据（启动时无事件时使用）"""
        now = datetime.now()
        self._trend_history = []
        for i in range(24):
            hour = (now - timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)
            self._trend_history.append({
                "hour": hour.isoformat(),
                "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
            })

    async def get_simulated_trends(self, hours: int = 24) -> dict:
        """从 DB security_events 聚合真实告警趋势数据。"""
        try:
            from .nx_bridge import get_bridge
            bridge = get_bridge()
            db_trend = await bridge.get_alert_counts_by_hour(hours)
            if db_trend:
                hourly = {}
                for row in db_trend:
                    hour_str = row.get("hour", "")
                    sev = row.get("severity", "info")
                    count = row.get("count", 0)
                    hourly.setdefault(hour_str, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
                    if sev in hourly[hour_str]:
                        hourly[hour_str][sev] = count
                if hourly:
                    return {
                        "labels": list(hourly.keys()),
                        "series": {
                            sev: [h.get(sev, 0) for h in hourly.values()]
                            for sev in ("critical", "high", "medium", "low", "info")
                        },
                    }
        except Exception:
            pass
        # Fallback: return empty trend data
        data = self._trend_history[-hours:]
        return {
            "labels": [d["hour"] for d in data],
            "series": {
                "critical": [d["critical"] for d in data],
                "high": [d["high"] for d in data],
                "medium": [d["medium"] for d in data],
                "low": [d["low"] for d in data],
                "info": [d["info"] for d in data],
            },
        }

    async def get_simulated_device_status_distribution(self) -> dict:
        """从 DB 聚合真实设备状态分布。"""
        try:
            from .nx_bridge import get_bridge
            bridge = get_bridge()
            counts = await bridge.get_device_counts_by_status()
            if counts:
                return counts
        except Exception:
            pass
        return {"secure": 0, "scanning": 0, "vulnerable": 0, "attacked": 0, "isolated": 0}


# 单例
_simulator: MockStateSimulator | None = None


def get_mock_simulator() -> MockStateSimulator:
    global _simulator
    if _simulator is None:
        _simulator = MockStateSimulator()
    return _simulator
