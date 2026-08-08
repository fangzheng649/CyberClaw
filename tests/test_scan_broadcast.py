"""Tests for scan → HUD device broadcast (scan-lag fix).

Root cause being fixed: ``server/services/scan_service.py`` used to try
``from server.services.tool_broadcast_service import get_broadcast_service``
inside ``_process_results`` — a symbol that does not exist — so the
``except Exception: pass`` swallowed the ImportError and scan-discovered
devices never reached the HUD. These tests pin the new behaviour: scan
events are mapped to the WS message types the frontend already handles
(``device_discovered`` / ``device_back_online`` / ``device_offline``),
mirroring the MQTT payload contract (mqtt_service._upsert_esp32_device).
"""
import pytest

from server.services.scan_service import (
    ScanService,
    build_device_ws_message,
)
from server.services.topology_service import _device_id


# ── id derivation must match topology rebuild AND stay unique ─────

def test_device_id_slugifies_meaningful_name():
    # Meaningful names are slugified (historic async_get_topology behaviour).
    assert _device_id("Entrance-Cam", "aa:bb:cc:dd:ee:ff") == "entrance_cam"
    assert _device_id("IPC 01", "aa:bb:cc:dd:ee:ff") == "ipc_01"


def test_device_id_falls_back_to_mac_for_placeholder_names():
    # THE scan-lag collision fix: a placeholder name ("(unknown)" etc.) must NOT
    # become the id — otherwise every unnamed scan-discovered device collides on
    # id "(unknown)" and only one renders on the HUD. Fall back to the MAC.
    for placeholder in ("(unknown)", "unknown", "Unknown", ""):
        assert _device_id(placeholder, "8c:22:d2:41:0b:ca") == "8c22d2410bca"


def test_unnamed_device_broadcast_uses_mac_based_id():
    msg = build_device_ws_message(
        {"type": "New Device", "mac": "8c:22:d2:41:0b:ca", "ip": "192.168.1.11"},
        {"devName": "(unknown)", "devType": "unknown", "devVendor": "Unknown",
         "devLastIP": "192.168.1.11", "devStatus": "secure"},
    )
    assert msg["device"]["id"] == "8c22d2410bca"


def test_two_unnamed_devices_get_distinct_ids():
    cam = build_device_ws_message(
        {"type": "New Device", "mac": "8c:22:d2:41:0b:ca", "ip": "192.168.1.11"},
        {"devName": "(unknown)"},
    )
    switch = build_device_ws_message(
        {"type": "New Device", "mac": "60:a3:e3:61:81:0f", "ip": "192.168.1.1"},
        {"devName": "(unknown)"},
    )
    assert cam["device"]["id"] != switch["device"]["id"]
    assert cam["device"]["id"] == "8c22d2410bca"
    assert switch["device"]["id"] == "60a3e361810f"


# ── pure helper: scan event + device row → WS message ────────────

def test_new_device_maps_to_device_discovered():
    event = {"type": "New Device", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5"}
    device = {
        "devName": "Entrance-Cam", "devType": "camera", "devVendor": "Hikvision",
        "devModel": "DS-2CD", "devLastIP": "10.0.0.5", "devStatus": "secure",
        "devPos": "[1.0, 2.0, 3.0]",
    }
    msg = build_device_ws_message(event, device)

    assert msg["type"] == "device_discovered"
    dev = msg["device"]
    assert dev["mac"] == "aa:bb:cc:dd:ee:ff"
    assert dev["id"] == "entrance_cam"
    assert dev["name"] == "Entrance-Cam"
    assert dev["ip"] == "10.0.0.5"
    assert dev["type"] == "camera"
    assert dev["device_type"] == "camera"  # frontend reads device_type || type
    assert dev["vendor"] == "Hikvision"
    assert dev["status"] == "secure"
    assert dev["pos"] == [1.0, 2.0, 3.0]


def test_reconnected_and_connected_map_to_back_online():
    for etype in ("Down Reconnected", "Connected"):
        msg = build_device_ws_message(
            {"type": etype, "mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.6"},
            {"devName": "Sensor-1", "devType": "sensor", "devStatus": "secure"},
        )
        assert msg["type"] == "device_back_online"
        assert msg["device"]["id"] == "sensor_1"


def test_device_down_maps_to_offline_with_id():
    msg = build_device_ws_message(
        {"type": "Device Down", "mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.6"},
        {"devName": "Sensor-1"},
    )
    assert msg["type"] == "device_offline"
    # offline handler (main.js removeDeviceFromScene) only needs id; keep payload lean
    assert set(msg["device"]) == {"mac", "id", "name", "ip"}
    assert msg["device"]["id"] == "sensor_1"


def test_non_device_events_return_none():
    # IP Changed / info events must not trigger a device-list update on the HUD.
    for etype in ("IP Changed", "", "info"):
        assert build_device_ws_message({"type": etype, "mac": "x"}, None) is None


def test_falls_back_to_mac_when_no_device_row():
    # process_scan normalises MACs to lowercase, so use a realistic lowercase MAC.
    # The fallback id formula is mac.replace(":","") — mirroring async_get_topology
    # exactly (no extra lowercasing), so dedup stays consistent.
    msg = build_device_ws_message(
        {"type": "New Device", "mac": "aa:bb:cc:00:00:01", "ip": "10.0.0.9"}, None,
    )
    assert msg["type"] == "device_discovered"
    dev = msg["device"]
    assert dev["id"] == "aabbcc000001"            # mac.replace(":","") when no name
    assert dev["name"] == "aa:bb:cc:00:00:01"     # name falls back to mac


def test_pos_invalid_falls_back_to_layout():
    # Invalid devPos must now yield a real spread coordinate (pillar 1), not None/[].
    msg = build_device_ws_message(
        {"type": "New Device", "mac": "aa:bb:cc:dd:ee:02", "ip": "10.0.0.2"},
        {"devName": "X", "devPos": "not-json"},
    )
    pos = msg["device"]["pos"]
    assert isinstance(pos, list) and len(pos) == 3


# ── behaviour: ScanService pushes device events to the HUD ───────

async def test_scan_service_broadcasts_device_discovered(monkeypatch):
    svc = ScanService()
    sent = []

    async def fake_broadcast(msg):
        sent.append(msg)

    svc.set_broadcast(fake_broadcast)

    async def fake_resolve(self, mac):
        return {"devName": "New-Cam", "devType": "camera",
                "devStatus": "secure", "devLastIP": "10.0.0.7"}

    monkeypatch.setattr(ScanService, "_resolve_device", fake_resolve)

    await svc._broadcast_device_events(
        [{"type": "New Device", "mac": "aa:bb:cc:dd:ee:10", "ip": "10.0.0.7"}]
    )

    assert len(sent) == 1
    assert sent[0]["type"] == "device_discovered"
    assert sent[0]["device"]["id"] == "new_cam"


async def test_scan_service_no_broadcast_without_callback():
    svc = ScanService()  # no set_broadcast call
    # must not raise even when events are present
    await svc._broadcast_device_events(
        [{"type": "New Device", "mac": "aa:bb:cc:dd:ee:11", "ip": "10.0.0.8"}]
    )
    assert svc._broadcast is None


async def test_scan_service_skips_non_device_events(monkeypatch):
    svc = ScanService()
    sent = []

    async def fake_broadcast(msg):
        sent.append(msg)

    svc.set_broadcast(fake_broadcast)
    await svc._broadcast_device_events(
        [{"type": "IP Changed", "mac": "aa:bb:cc:dd:ee:12", "ip": "10.0.0.9"}]
    )
    assert sent == []


async def test_process_results_broadcasts_device_discovered_on_new_device(monkeypatch):
    """real 模式发现新真实设备 → 增量广播 device_discovered。

    mock/real 改为手动 Shift 切换后，扫描不再自动切模式、不再广播 mode_changed
    重建（real 模式不显示 mock，无重叠）；设备发现只走 device_discovered 增量。
    """
    from server.services import topology_service as ts
    from server.services import scan_service as ss

    ts.set_mock_mode(False)
    svc = ss.ScanService()
    sent = []

    async def fake_broadcast(msg):
        sent.append(msg)

    svc.set_broadcast(fake_broadcast)

    async def fake_populate(results, source="SCAN"):
        pass

    async def fake_process():
        return [{"type": "New Device", "mac": "60:a3:e3:61:81:0f", "ip": "192.168.1.1"}]

    async def fake_enrich(self, events):
        return events

    async def fake_resolve(self, mac):
        return {"devName": "TL-SG2210LPF", "devType": "switch",
                "devStatus": "secure", "devLastIP": "192.168.1.1"}

    monkeypatch.setattr("server.services.process_scan.populate_current_scan", fake_populate)
    monkeypatch.setattr("server.services.process_scan.process_scan_results", fake_process)
    monkeypatch.setattr(ss.ScanService, "_enrich_device_fingerprints", fake_enrich)
    monkeypatch.setattr(ss.ScanService, "_resolve_device", fake_resolve)

    await svc._process_results([{"ip": "192.168.1.1", "mac": "60:a3:e3:61:81:0f"}])

    assert any(m["type"] == "device_discovered" for m in sent), "应增量广播 device_discovered"
    assert all(m["type"] != "mode_changed" for m in sent), "不应再广播 mode_changed(手动 Shift 切换)"
