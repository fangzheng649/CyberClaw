"""Mock 模式数据服务 — 提供 Dashboard 趋势数据的 DB 查询。

不生成任何合成事件或随机状态变化。
所有安全事件和设备状态变化完全由 scenario_service（Demo 攻击链）驱动。
"""
import logging

logger = logging.getLogger("cyberclaw.mock_state")


class MockStateService:
    """Mock 模式下的数据查询服务（无自动模拟逻辑）。"""

    def __init__(self):
        self._broadcast_callback = None

    def set_broadcast(self, callback):
        self._broadcast_callback = callback

    async def start(self):
        logger.info("Mock state service started (no auto-simulation)")

    async def stop(self):
        logger.info("Mock state service stopped")

    async def get_simulated_trends(self, hours: int = 24) -> dict:
        """从 DB security_events 聚合告警趋势数据。
        自动检测数据时间跨度：如果所有事件在同一小时内，切换为分钟粒度以显示趋势。
        """
        try:
            from .nx_bridge import get_bridge
            bridge = get_bridge()

            # 先用小时粒度查询
            db_trend = await bridge.get_alert_counts_by_hour(hours)
            if db_trend:
                hourly = {}
                for row in db_trend:
                    hour_str = row.get("hour", "")
                    sev = row.get("severity", "info")
                    count = row.get("count", 0)
                    hourly.setdefault(hour_str, {"critical": 0, "high": 0, "warning": 0, "medium": 0, "low": 0, "info": 0})
                    if sev in hourly[hour_str]:
                        hourly[hour_str][sev] = count

                # 如果所有事件集中在 1-2 个小时桶内，切换为分钟粒度
                if len(hourly) <= 2:
                    db_trend_min = await bridge.get_alert_counts_by_minute(hours * 60)
                    if db_trend_min and len(db_trend_min) > len(db_trend):
                        hourly = {}
                        for row in db_trend_min:
                            bucket = row.get("hour", "")
                            sev = row.get("severity", "info")
                            count = row.get("count", 0)
                            hourly.setdefault(bucket, {"critical": 0, "high": 0, "warning": 0, "medium": 0, "low": 0, "info": 0})
                            if sev in hourly[bucket]:
                                hourly[bucket][sev] = count

                if hourly:
                    return {
                        "labels": list(hourly.keys()),
                        "series": {
                            sev: [h.get(sev, 0) for h in hourly.values()]
                            for sev in ("critical", "high", "warning", "medium", "low", "info")
                        },
                    }
        except Exception:
            pass
        return {"labels": [], "series": {"critical": [], "high": [], "warning": [], "medium": [], "low": [], "info": []}}

    async def get_simulated_device_status_distribution(self) -> dict:
        """从 DB 聚合设备状态分布。"""
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
_service: MockStateService | None = None


def get_mock_simulator() -> MockStateService:
    global _service
    if _service is None:
        _service = MockStateService()
    return _service
