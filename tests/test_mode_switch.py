"""Tests for mock→real mode switch on real-device discovery.

Root cause: the switch to real mode only happened at startup or via MQTT/ESP32.
A generic real device discovered by the background scanner never triggered it,
so the HUD kept showing mock demo devices AND the real device landed as
"unknown" (enrichment is skipped in mock mode, and the preset index reads
mock_topology.json in mock mode). Fix: scan_service flips to real when it sees a
New Device event while in mock mode, and set_mock_mode invalidates the
mode-dependent profile cache.
"""
import pytest

from server.services import topology_service as ts
from server.services.scan_service import ScanService


@pytest.fixture(autouse=True)
def _restore_mode():
    saved_mock = ts._mock_mode
    saved_cfg = ts._config_cache
    ts.reset_profile_cache()
    yield
    ts._mock_mode = saved_mock
    ts._config_cache = saved_cfg
    ts.reset_profile_cache()


async def test_switches_to_real_when_new_device_in_mock_mode():
    ts.set_mock_mode(True)
    assert ts.is_mock_mode() is True

    svc = ScanService()
    switched = await svc._maybe_switch_to_real(
        [{"type": "New Device", "mac": "8c:22:d2:41:0b:ca", "ip": "192.168.1.11"}])

    assert switched is True
    assert ts.is_mock_mode() is False


async def test_no_switch_when_already_real_mode():
    ts.set_mock_mode(False)
    svc = ScanService()
    switched = await svc._maybe_switch_to_real(
        [{"type": "New Device", "mac": "x", "ip": "y"}])
    assert switched is False


async def test_no_switch_when_no_new_device_event():
    ts.set_mock_mode(True)
    svc = ScanService()
    switched = await svc._maybe_switch_to_real(
        [{"type": "Device Down", "mac": "x", "ip": "y"}, {"type": "IP Changed", "mac": "z"}])
    assert switched is False
    assert ts.is_mock_mode() is True  # stayed mock


def test_set_mock_mode_invalidates_profile_cache():
    # In REAL mode the preset index is built from topology.json (has 8c:22=d2 camera-1).
    ts.set_mock_mode(False)
    ts.reset_profile_cache()
    assert ts.match_device_profile("8c:22:d2:41:0b:ca", "192.168.1.11") is not None

    # Switching to MOCK must invalidate the cache so the index rebuilds from
    # mock_topology.json (which has no 8c:22:d2) -> no stale real-mode match.
    ts.set_mock_mode(True)
    assert ts.match_device_profile("8c:22:d2:41:0b:ca", "192.168.1.11") is None
