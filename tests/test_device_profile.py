"""Tests for known-device profile matching (demo-oriented device identity).

When a device is discovered, its identity (name/type/vendor/model/pos) should
come from topology.json if the MAC (or IP) is a known preset — instant and
authoritative, skipping the slower port-fingerprint probe. topology.json already
holds the demo rig's real devices (e.g. 8c:22:d2:41:0b:ca -> Camera-Entrance,
60:a3:e3:61:81:0f -> TP-LINK switch).
"""
import pytest

from server.services.topology_service import match_device_profile, reset_profile_cache


@pytest.fixture(autouse=True)
def _fresh_profile_cache():
    reset_profile_cache()


def test_match_profile_by_mac():
    p = match_device_profile("8c:22:d2:41:0b:ca", "192.168.1.12")
    assert p is not None
    assert p["name"] == "DS-2CD1023G2-L-02"
    assert p["type"] == "camera"
    assert p["vendor"] == "Hikvision"


def test_match_profile_mac_case_and_separator_insensitive():
    assert match_device_profile("8C:22:D2:41:0B:CA", "").get("type") == "camera"
    assert match_device_profile("8c22d2410bca", "").get("type") == "camera"
    assert match_device_profile("60:A3:E3:61:81:0F", "192.168.1.1").get("type") == "switch"


def test_match_profile_by_ip_when_no_mac():
    # cyberclaw-console has an empty MAC -> match by IP only.
    p = match_device_profile("", "192.168.1.100")
    assert p is not None
    assert p["id"] == "cyberclaw-console"


def test_match_profile_mac_wins_over_conflicting_ip():
    # MAC says camera-2, IP says switch-core -> MAC wins.
    p = match_device_profile("8c:22:d2:41:0b:ca", "192.168.1.1")
    assert p["id"] == "camera-2"


def test_match_profile_no_match():
    assert match_device_profile("aa:bb:cc:dd:ee:77", "10.0.0.77") is None


# ── scan_service enrichment: preset applied, probe skipped ───────

class _FakeBridge:
    def __init__(self, devices=None):
        self.upserts = []
        self._all = devices or []
    async def upsert_device(self, mac, data, source="PROFILE"):
        self.upserts.append((mac, dict(data), source))
    async def get_all_devices(self):
        return self._all


async def test_enrich_backfill_overrides_typed_device_with_preset(monkeypatch):
    from server.services.scan_service import ScanService

    # 60:a3:e3 already typed "Gateway" by the IP heuristic — but topology.json
    # preset says it's the TP-LINK switch. The preset must win on backfill.
    fake_bridge = _FakeBridge(devices=[{
        "devMac": "60:a3:e3:61:81:0f", "devLastIP": "192.168.1.1",
        "devType": "Gateway", "devDiscoveryMethod": "nmap_sn",
    }])
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: fake_bridge)

    svc = ScanService()
    await svc._enrich_device_fingerprints([])   # no new events -> pure backfill

    assert len(fake_bridge.upserts) == 1
    mac, data, source = fake_bridge.upserts[0]
    assert mac == "60:a3:e3:61:81:0f"
    assert data["devName"] == "TL-SG2210LPF"
    assert data["devType"] == "switch"
    assert source == "PROFILE"


async def test_enrich_applies_preset_and_skips_probe(monkeypatch):
    from server.services import port_fingerprint
    from server.services.scan_service import ScanService

    probed = {"called": False}

    async def fake_fp(ip, mac="", vendor=""):
        probed["called"] = True
        return {"type": "camera", "open_ports": [554], "confidence": 75}
    monkeypatch.setattr(port_fingerprint, "fingerprint_device", fake_fp)

    fake_bridge = _FakeBridge()
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: fake_bridge)

    svc = ScanService()
    # 8c:22:d2:41:09:08 @ 192.168.1.11 == camera-1 preset in topology.json
    await svc._enrich_device_fingerprints(
        [{"type": "New Device", "mac": "8c:22:d2:41:09:08", "ip": "192.168.1.11"}])

    assert probed["called"] is False               # preset authoritative -> no probe
    assert len(fake_bridge.upserts) == 1
    mac, data, source = fake_bridge.upserts[0]
    assert mac == "8c:22:d2:41:09:08"
    assert source == "PROFILE"
    assert data["devName"] == "DS-2CD1023G2-L-01"
    assert data["devType"] == "camera"
    assert data["devVendor"] == "Hikvision"
    assert data["devModel"] == "DS-2CD1023G2-L"


async def test_enrich_non_preset_device_falls_back_to_probe(monkeypatch):
    from server.services import port_fingerprint
    from server.services.scan_service import ScanService

    async def fake_fp(ip, mac="", vendor=""):
        return {"type": "plc", "open_ports": [502], "confidence": 70}
    monkeypatch.setattr(port_fingerprint, "fingerprint_device", fake_fp)

    fake_bridge = _FakeBridge()
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: fake_bridge)

    svc = ScanService()
    # aa:bb:cc:dd:ee:77 @ 10.0.0.77 -> not in topology.json -> port fingerprint
    await svc._enrich_device_fingerprints(
        [{"type": "New Device", "mac": "aa:bb:cc:dd:ee:77", "ip": "10.0.0.77"}])

    assert len(fake_bridge.upserts) == 1
    assert fake_bridge.upserts[0][1]["devType"] == "plc"
    assert fake_bridge.upserts[0][2] == "PORTFP"
