"""Tests for port-based device fingerprinting (pillar 3: device type ID).

The background scan only does host discovery, so new devices are stuck at
devType="unknown". port_fingerprint.infer_device_type maps open ports (+ MAC
signature) to a type; probe_open_ports gets the open ports (nmap or socket
fallback); scan_service._enrich_device_fingerprints runs the probe BEFORE
broadcasting so the HUD's first device_discovered frame already shows the
right type (zero frontend change — addDeviceToScene dedups by id, so the type
must be right on the first/only frame).
"""
import pytest

from server.services import port_fingerprint
from server.services.scan_service import ScanService


# ── infer_device_type (pure) ─────────────────────────────────────

def test_infer_camera_by_rtsp():
    assert port_fingerprint.infer_device_type([80, 554]) == ("camera", 75)


def test_infer_camera_by_dahua_private_port():
    assert port_fingerprint.infer_device_type([37777])[0] == "camera"


def test_infer_plc_by_ics_ports():
    for p in (502, 102, 4840):
        assert port_fingerprint.infer_device_type([p])[0] == "plc"


def test_infer_gateway_by_mqtt():
    assert port_fingerprint.infer_device_type([1883]) == ("gateway", 70)


def test_infer_switch_by_vendor():
    # Network-gear vendors resolved from the OUI DB → switch (SNMP/161 is UDP,
    # not TCP-probed, so switch ID now comes from the vendor name instead).
    assert port_fingerprint.infer_device_type([], vendor="TP-LINK TECHNOLOGIES CO.,LTD.") == ("switch", 80)
    assert port_fingerprint.infer_device_type([80, 443], vendor="Cisco Systems") == ("switch", 80)


def test_infer_camera_by_vendor():
    # OUI-resolved "Hangzhou Hikvision..." → camera even with only web ports open.
    assert port_fingerprint.infer_device_type([80], vendor="Hangzhou Hikvision Digital Technology") == ("camera", 80)


def test_infer_mac_signature_overrides_ports():
    # Hikvision OUI 44:19:b6 -> camera even though only 22/80 are open.
    assert port_fingerprint.infer_device_type([22, 80], mac="44:19:b6:aa:bb:cc") == ("camera", 90)


def test_infer_unknown_when_no_signal():
    assert port_fingerprint.infer_device_type([12345]) == ("unknown", 0)
    assert port_fingerprint.infer_device_type([]) == ("unknown", 0)


def test_infer_telnet_alone_is_weak():
    # Telnet alone is not a decisive type signal.
    assert port_fingerprint.infer_device_type([23])[1] < 60


# ── probe_open_ports (routing + robustness) ──────────────────────

async def test_probe_uses_nmap_when_available(monkeypatch):
    monkeypatch.setattr(port_fingerprint.shutil, "which", lambda x: "/usr/bin/nmap")

    async def fake_nmap(ip, ports):
        assert ip == "1.2.3.4"
        return [554]
    monkeypatch.setattr(port_fingerprint, "_probe_via_nmap", fake_nmap)

    assert await port_fingerprint.probe_open_ports("1.2.3.4", [554]) == [554]


async def test_probe_socket_fallback_when_no_nmap(monkeypatch):
    monkeypatch.setattr(port_fingerprint.shutil, "which", lambda x: None)

    async def fake_sockets(ip, ports, timeout):
        assert ip == "1.2.3.4"
        return [80]
    monkeypatch.setattr(port_fingerprint, "_probe_via_sockets", fake_sockets)

    assert await port_fingerprint.probe_open_ports("1.2.3.4", [80, 443]) == [80]


async def test_probe_empty_when_no_ip():
    assert await port_fingerprint.probe_open_ports("") == []


async def test_probe_never_raises(monkeypatch):
    def boom(_x):
        raise OSError("nope")
    monkeypatch.setattr(port_fingerprint.shutil, "which", boom)
    assert await port_fingerprint.probe_open_ports("1.2.3.4") == []


# ── scan_service enrichment (fingerprint before broadcast) ───────

class _FakeBridge:
    def __init__(self):
        self.upserts = []
        self._all = []
    async def upsert_device(self, mac, data, source="PORTFP"):
        self.upserts.append((mac, dict(data), source))
    async def get_all_devices(self):
        return self._all


async def test_enrich_fingerprints_new_device(monkeypatch):
    async def fake_fp(ip, mac="", vendor=""):
        return {"type": "camera", "open_ports": [554, 80], "confidence": 75}
    monkeypatch.setattr(port_fingerprint, "fingerprint_device", fake_fp)

    fake_bridge = _FakeBridge()
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: fake_bridge)

    svc = ScanService()
    # aa:bb:cc:dd:ee:77 is NOT in topology.json -> goes through the port probe
    # (the 8c:22:d2 / 60:a3:e3 MACs are presets, covered in test_device_profile.py).
    events = [{"type": "New Device", "mac": "aa:bb:cc:dd:ee:77", "ip": "10.0.0.77"}]
    out = await svc._enrich_device_fingerprints(events)

    assert out is events                       # events list returned unchanged
    assert fake_bridge.upserts                 # a write happened
    mac, data, source = fake_bridge.upserts[0]
    assert mac == "aa:bb:cc:dd:ee:77"
    assert data["devType"] == "camera"
    assert data["devOpenPorts"] == "[554, 80]"
    assert source == "PORTFP"


async def test_enrich_skips_in_mock_mode(monkeypatch):
    called = {"fp": False}

    async def fake_fp(ip, mac="", vendor=""):
        called["fp"] = True
        return {"type": "camera", "open_ports": [554], "confidence": 75}
    monkeypatch.setattr(port_fingerprint, "fingerprint_device", fake_fp)
    monkeypatch.setattr("server.services.scan_service.is_mock_mode", lambda: True)

    fake_bridge = _FakeBridge()
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: fake_bridge)

    svc = ScanService()
    await svc._enrich_device_fingerprints(
        [{"type": "New Device", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.9"}])
    assert called["fp"] is False
    assert fake_bridge.upserts == []


async def test_enrich_does_not_overwrite_with_unknown(monkeypatch):
    # If the probe can't decide a type, only ports are written (devType left alone).
    async def fake_fp(ip, mac="", vendor=""):
        return {"type": "unknown", "open_ports": [], "confidence": 0}
    monkeypatch.setattr(port_fingerprint, "fingerprint_device", fake_fp)

    fake_bridge = _FakeBridge()
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: fake_bridge)

    svc = ScanService()
    await svc._enrich_device_fingerprints(
        [{"type": "New Device", "mac": "aa:bb:cc:dd:ee:99", "ip": "10.0.0.7"}])
    assert len(fake_bridge.upserts) == 1
    assert "devType" not in fake_bridge.upserts[0][1]   # not overwritten
    assert fake_bridge.upserts[0][1]["devOpenPorts"] == "[]"
