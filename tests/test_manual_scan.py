"""手动网络扫描（快捷键触发）的测试。

需求：扫描改为"手动模式"——系统启动时扫一次，之后不再每 N 秒自动循环；
所有后续扫描由用户在 HUD 按下快捷键，经 trigger_scan() 主动发起。
"""
import asyncio

import pytest

from server.services.scan_service import ScanService


@pytest.fixture(autouse=True)
def _fresh_service():
    """每个用例一个全新 ScanService（避免单例/_scan_lock 跨用例污染）。"""
    svc = ScanService()
    # 单例指纹缓存与本会话无关；这里只测手动触发行为，清空避免互相影响
    svc._fingerprinted = set()
    yield svc


async def test_trigger_scan_runs_one_cycle_and_returns_found(monkeypatch, _fresh_service):
    svc = _fresh_service
    svc._subnet = "192.168.1.0/24"

    seen = []
    scanned = {"found": 3, "devices": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}]}

    async def fake_scan_subnet(subnet):
        seen.append(subnet)
        return scanned

    monkeypatch.setattr(svc, "scan_subnet", fake_scan_subnet)

    res = await svc.trigger_scan()

    assert res["status"] == "ok"
    assert res["found"] == 3
    assert seen == ["192.168.1.0/24"]            # 用配置的子网扫了一次
    assert svc._stats["cycles"] == 1             # 统计已更新


async def test_trigger_scan_without_subnet_returns_error(_fresh_service):
    svc = _fresh_service
    svc._subnet = ""
    res = await svc.trigger_scan()
    assert res["status"] == "error"              # 没配子网时给出明确错误而非抛异常


async def test_start_does_not_loop_only_one_startup_scan(monkeypatch, _fresh_service):
    """start() 在手动模式下只扫一次（启动扫描），不会每 interval 秒循环。"""
    svc = _fresh_service
    count = {"n": 0}

    async def fake_scan_subnet(subnet):
        count["n"] += 1
        return {"found": 0, "devices": []}

    monkeypatch.setattr(svc, "scan_subnet", fake_scan_subnet)

    await svc.start(subnet="10.0.0.0/24", interval=1)  # interval=1：旧行为会每秒循环
    assert svc._subnet == "10.0.0.0/24"

    await asyncio.sleep(0.3)   # 让启动扫描任务跑完
    first = count["n"]
    assert first == 1          # 启动扫了一次

    await asyncio.sleep(2.0)   # 远超 interval=1s：若仍在循环，n 会 >1
    assert count["n"] == 1     # 手动模式：没有循环

    await svc.stop()


async def test_concurrent_trigger_scans_are_serialized(monkeypatch, _fresh_service):
    """重复连按快捷键：_scan_lock 串行化，不会并发跑两份扫描。"""
    svc = _fresh_service
    svc._subnet = "192.168.1.0/24"
    active = {"now": 0, "max": 0}

    async def fake_scan_subnet(subnet):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        await asyncio.sleep(0.1)
        active["now"] -= 1
        return {"found": 0, "devices": []}

    monkeypatch.setattr(svc, "scan_subnet", fake_scan_subnet)

    await asyncio.gather(svc.trigger_scan(), svc.trigger_scan(), svc.trigger_scan())

    assert active["max"] == 1   # 任意时刻只有一份扫描在跑
