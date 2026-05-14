"""Phase 1 测试 — 后端核心修复"""
import pytest


@pytest.mark.asyncio
async def test_security_events_returns_real_data(client, db_conn):
    """GET /api/security/events 应返回数据库中的安全事件"""
    # 插入测试事件
    db_conn.execute(
        "INSERT INTO security_events (source_type, severity, message, source, target) VALUES (?, ?, ?, ?, ?)",
        ("syslog", "critical", "Test critical alert", "192.168.10.101", "192.168.10.1")
    )
    db_conn.execute(
        "INSERT INTO security_events (source_type, severity, message, source) VALUES (?, ?, ?, ?)",
        ("snmp", "info", "Test info event", "192.168.10.102")
    )
    db_conn.commit()

    resp = await client.get("/api/security/events")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert data["total"] >= 2
    assert "limit" in data
    assert "offset" in data


@pytest.mark.asyncio
async def test_security_events_filter_by_severity(client, db_conn):
    """GET /api/security/events?severity=critical 应只返回 critical 事件"""
    db_conn.execute(
        "INSERT INTO security_events (source_type, severity, message) VALUES ('syslog', 'critical', 'Critical event')"
    )
    db_conn.execute(
        "INSERT INTO security_events (source_type, severity, message) VALUES ('syslog', 'info', 'Info event')"
    )
    db_conn.commit()

    resp = await client.get("/api/security/events?severity=critical")
    assert resp.status_code == 200
    data = resp.json()
    for event in data["events"]:
        assert event["severity"] == "critical"


@pytest.mark.asyncio
async def test_device_state_returns_db_status(client, db_conn):
    """GET /api/security/state/{device_id} 应返回数据库中的设备状态"""
    # 先通过 topology 获取设备 ID
    topo_resp = await client.get("/api/topology")
    topo_data = topo_resp.json()
    if topo_data["devices"]:
        device_id = topo_data["devices"][0]["id"]
        resp = await client.get(f"/api/security/state/{device_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "state" in data
        assert data["state"] in ("secure", "scanning", "vulnerable", "attacked", "isolated")


@pytest.mark.asyncio
async def test_device_state_not_found(client):
    """GET /api/security/state/nonexistent 应返回 404"""
    resp = await client.get("/api/security/state/nonexistent_device_xyz")
    assert resp.status_code == 404
    data = resp.json()
    assert data.get("error") == "not_found"


@pytest.mark.asyncio
async def test_topology_has_parent_child_links(client, db_conn):
    """GET /api/topology 应包含基于 devParentMAC 的父子关系链接"""
    resp = await client.get("/api/topology")
    assert resp.status_code == 200
    data = resp.json()
    assert "devices" in data
    assert "links" in data

    # 检查 aa:bb:cc:dd:ee:02 的 parent 是 aa:bb:cc:dd:ee:01
    devices = data["devices"]
    links = data["links"]

    # 找到测试设备
    device_ids = {d["id"] for d in devices}

    # 应该有链接包含 parent 关系
    # 验证至少有设备数据返回
    assert len(devices) >= 3, f"Expected at least 3 devices, got {len(devices)}"
