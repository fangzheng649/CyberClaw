"""Phase 2 测试 — 扫描管道"""
import pytest


@pytest.mark.asyncio
async def test_process_scan_module_importable():
    """process_scan 模块应可导入"""
    from server.services.process_scan import populate_current_scan, process_scan_results
    assert callable(populate_current_scan)
    assert callable(process_scan_results)


@pytest.mark.asyncio
async def test_populate_current_scan(db_conn):
    """populate_current_scan 应将扫描结果写入 CurrentScan 表"""
    from server.services.process_scan import populate_current_scan

    results = [
        {"ip": "10.0.0.200", "mac": "11:22:33:44:55:66", "vendor": "Test Vendor", "method": "arp_scan"},
        {"ip": "10.0.0.201", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Another Vendor", "method": "nmap_sn"},
    ]
    await populate_current_scan(results, source="TEST")

    rows = db_conn.execute("SELECT * FROM CurrentScan").fetchall()
    assert len(rows) == 2

    # 清理
    db_conn.execute("DELETE FROM CurrentScan")
    db_conn.commit()


@pytest.mark.asyncio
async def test_device_heuristics():
    """设备启发式推断应能识别常见 IoT 设备"""
    from server.db.scan.device_heuristics import guess_device_attributes
    result = guess_device_attributes(
        vendor="Hikvision", mac="44:19:b6:12:34:56", ip="10.0.0.101", name="",
        default_icon="", default_type="",
    )
    assert result is not None


@pytest.mark.asyncio
async def test_scan_schedule_api(client):
    """扫描调度 API 应可用"""
    resp = await client.get("/api/tools/scan-schedule/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "running" in data


@pytest.mark.asyncio
async def test_snmp_discover_topology_api(client):
    """SNMP 拓扑发现 API 端点应存在"""
    resp = await client.post("/api/tools/snmp/discover-topology", json={})
    assert resp.status_code == 200
    data = resp.json()
    # 没有 switch_ip 应返回错误
    assert data.get("status") == "error" or "message" in data
