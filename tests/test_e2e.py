"""端到端集成测试 — 全面覆盖前后端交互"""
import pytest


# ── Topology ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_topology_returns_devices_and_links(client):
    """GET /api/topology 应返回设备列表和连接"""
    resp = await client.get("/api/topology")
    assert resp.status_code == 200
    data = resp.json()
    assert "devices" in data and "links" in data
    assert len(data["devices"]) >= 3
    for d in data["devices"]:
        assert "id" in d and "name" in d and "ip" in d and "status" in d


@pytest.mark.asyncio
async def test_topology_device_detail_found(client):
    """GET /api/topology/devices/{id} 应返回设备详情"""
    topo = (await client.get("/api/topology")).json()
    device_id = topo["devices"][0]["id"]
    resp = await client.get(f"/api/topology/devices/{device_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == device_id


@pytest.mark.asyncio
async def test_topology_device_detail_not_found(client):
    """GET /api/topology/devices/nonexistent 应返回 404"""
    resp = await client.get("/api/topology/devices/this_device_does_not_exist")
    assert resp.status_code == 404
    assert resp.json()["error"] == "not_found"


# ── Security ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_security_events_empty(client):
    """GET /api/security/events 空库应返回空列表"""
    resp = await client.get("/api/security/events")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data and "total" in data


@pytest.mark.asyncio
async def test_security_events_with_data(client, db_conn):
    """GET /api/security/events 插入数据后应返回"""
    db_conn.execute(
        "INSERT INTO security_events (source_type, severity, message) VALUES ('test', 'critical', 'Test event')"
    )
    db_conn.commit()
    resp = await client.get("/api/security/events")
    data = resp.json()
    assert data["total"] >= 1
    assert data["events"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_security_device_state_found(client):
    """GET /api/security/state/{id} 应返回设备状态"""
    topo = (await client.get("/api/topology")).json()
    device_id = topo["devices"][0]["id"]
    resp = await client.get(f"/api/security/state/{device_id}")
    assert resp.status_code == 200
    assert resp.json()["state"] in ("secure", "scanning", "vulnerable", "attacked", "isolated")


@pytest.mark.asyncio
async def test_security_device_state_not_found(client):
    """GET /api/security/state/nonexistent 应返回 404"""
    resp = await client.get("/api/security/state/xyz_not_found")
    assert resp.status_code == 404


# ── Scenario ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scenario_list(client):
    """GET /api/scenario 应返回场景列表"""
    resp = await client.get("/api/scenario")
    assert resp.status_code == 200
    assert "scenarios" in resp.json()


@pytest.mark.asyncio
async def test_scenario_status(client):
    """GET /api/scenario/status 应返回运行状态"""
    resp = await client.get("/api/scenario/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "running" in data


# ── Chat ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_chat_status(client):
    """GET /api/chat/status 应返回 LLM 和 MCP 工具信息"""
    resp = await client.get("/api/chat/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "llm_connected" in data
    assert "mcp_tools_loaded" in data
    assert isinstance(data["mcp_tools"], list)


@pytest.mark.asyncio
async def test_chat_send_message(client):
    """POST /api/chat 应正常返回"""
    resp = await client.post("/api/chat", json={"message": "test", "history": []})
    assert resp.status_code == 200
    assert "reply" in resp.json()


@pytest.mark.asyncio
async def test_chat_history(client):
    """GET /api/chat/history 应返回历史列表"""
    resp = await client.get("/api/chat/history")
    assert resp.status_code == 200
    assert "history" in resp.json()


# ── Tools ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.slow
async def test_tools_scan(client):
    """POST /api/tools/scan 应启动扫描任务（后台 MCP 调用可能较慢）"""
    resp = await client.post("/api/tools/scan", json={"target": "127.0.0.1", "scan_type": "network"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "started"


@pytest.mark.asyncio
@pytest.mark.slow
async def test_tools_cve_check(client):
    """POST /api/tools/cve-check 应启动任务"""
    resp = await client.post("/api/tools/cve-check", json={"vendor": "Hikvision", "model": "DS-2CD"})
    assert resp.status_code == 200
    assert "task_id" in resp.json()


@pytest.mark.asyncio
@pytest.mark.slow
async def test_tools_baseline(client):
    """POST /api/tools/baseline 应启动任务"""
    resp = await client.post("/api/tools/baseline", json={"profile": "iot-default", "target": "all"})
    assert resp.status_code == 200
    assert "task_id" in resp.json()


@pytest.mark.asyncio
async def test_tools_isolate_not_found(client):
    """POST /api/tools/isolate 空参数应返回 404"""
    resp = await client.post("/api/tools/isolate", json={})
    assert resp.status_code == 404


@pytest.mark.asyncio
@pytest.mark.slow
async def test_tools_isolate_valid_device(client):
    """POST /api/tools/isolate 有效设备应返回 200（MCP fallback 到 record_only）"""
    resp = await client.post("/api/tools/isolate", json={"device_id": "switch-core", "device_ip": "10.0.0.0"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("task_id") or data.get("status") == "started" or data.get("container")


@pytest.mark.asyncio
@pytest.mark.slow
async def test_tools_restore_valid_device(client):
    """POST /api/tools/restore 有效设备应返回 200"""
    resp = await client.post("/api/tools/restore", json={"device_id": "switch-core", "device_ip": "10.0.0.0"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("task_id") or data.get("status") == "started"


# ── Collector ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collector_status(client):
    """GET /api/tools/collector/status 应返回"""
    resp = await client.get("/api/tools/collector/status")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_collector_events(client):
    """GET /api/tools/collector/events 应返回"""
    resp = await client.get("/api/tools/collector/events?limit=10")
    assert resp.status_code == 200


# ── SNMP ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snmp_status(client):
    """GET /api/tools/snmp/status 应返回"""
    resp = await client.get("/api/tools/snmp/status")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_snmp_discover_no_switch(client):
    """POST /api/tools/snmp/discover-topology 无 switch_ip 应返回错误"""
    resp = await client.post("/api/tools/snmp/discover-topology", json={})
    assert resp.status_code == 200
    assert resp.json().get("status") == "error"


# ── MQTT ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mqtt_status(client):
    """GET /api/tools/mqtt/status 应返回"""
    resp = await client.get("/api/tools/mqtt/status")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mqtt_messages(client):
    """GET /api/tools/mqtt/messages 应返回"""
    resp = await client.get("/api/tools/mqtt/messages?limit=10")
    assert resp.status_code == 200


# ── Scan Schedule ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_schedule_status(client):
    """GET /api/tools/scan-schedule/status 应返回"""
    resp = await client.get("/api/tools/scan-schedule/status")
    assert resp.status_code == 200


# ── Suricata ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_suricata_alerts(client):
    """GET /api/tools/suricata/alerts 应返回"""
    resp = await client.get("/api/tools/suricata/alerts?limit=10")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_suricata_stats(client):
    """GET /api/tools/suricata/stats 应返回"""
    resp = await client.get("/api/tools/suricata/stats")
    assert resp.status_code == 200


# ── Dashboard ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dashboard_devices(client):
    """GET /api/dashboard/db/devices 应返回设备列表"""
    resp = await client.get("/api/dashboard/db/devices")
    assert resp.status_code == 200
    data = resp.json()
    assert "devices" in data


@pytest.mark.asyncio
async def test_dashboard_alerts(client):
    """GET /api/dashboard/alerts 应返回告警列表"""
    resp = await client.get("/api/dashboard/alerts?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts" in data and "total" in data


@pytest.mark.asyncio
async def test_dashboard_trends_alert_count(client):
    """GET /api/dashboard/trends/alert-count 应返回趋势数据"""
    resp = await client.get("/api/dashboard/trends/alert-count?hours=24")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_dashboard_trends_device_status(client):
    """GET /api/dashboard/trends/device-status 应返回状态分布"""
    resp = await client.get("/api/dashboard/trends/device-status")
    assert resp.status_code == 200
    data = resp.json()
    assert "labels" in data and "data" in data


@pytest.mark.asyncio
async def test_dashboard_trends_protocol(client):
    """GET /api/dashboard/trends/protocol-traffic 应返回协议分布"""
    resp = await client.get("/api/dashboard/trends/protocol-traffic")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_dashboard_logs_search(client):
    """GET /api/dashboard/logs/search 应返回搜索结果"""
    resp = await client.get("/api/dashboard/logs/search?limit=10")
    assert resp.status_code == 200
    assert "results" in resp.json()


# ── Workflows ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_workflows_list(client):
    """GET /api/workflows/ 应返回工作流列表"""
    resp = await client.get("/api/workflows/")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_workflows_events(client):
    """GET /api/workflows/events 应返回事件列表"""
    resp = await client.get("/api/workflows/events?limit=10")
    assert resp.status_code == 200


# ── Notifications ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_notifications_config(client):
    """GET /api/notifications/config 应返回配置"""
    resp = await client.get("/api/notifications/config")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_notifications_history(client):
    """GET /api/notifications/history 应返回历史"""
    resp = await client.get("/api/notifications/history?limit=10")
    assert resp.status_code == 200


# ── Discovery ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_discovery_status(client):
    """GET /api/discovery/status 应返回"""
    resp = await client.get("/api/discovery/status")
    assert resp.status_code == 200
