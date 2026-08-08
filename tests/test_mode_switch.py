"""Tests for manual mock/real mode toggle (Shift hotkey / POST /api/mode/toggle).

Mode is now toggled manually — no longer auto-switched on real-device discovery.
These tests pin set_mock_mode flag + profile-cache invalidation (the preset index
is mode-dependent: real reads topology.json, mock reads mock_topology.json).
"""
import pytest

from server.services import topology_service as ts


@pytest.fixture(autouse=True)
def _restore_mode():
    saved_mock = ts._mock_mode
    saved_cfg = ts._config_cache
    ts.reset_profile_cache()
    yield
    ts._mock_mode = saved_mock
    ts._config_cache = saved_cfg
    ts.reset_profile_cache()


def test_set_mock_mode_toggles_flag():
    ts.set_mock_mode(False)
    assert ts.is_mock_mode() is False
    ts.set_mock_mode(True)
    assert ts.is_mock_mode() is True


def test_set_mock_mode_invalidates_profile_cache():
    # REAL mode: topology.json has camera-2 (MAC 8c:22:d2:41:0b:ca)
    ts.set_mock_mode(False)
    ts.reset_profile_cache()
    assert ts.match_device_profile("8c:22:d2:41:0b:ca", "192.168.1.12") is not None
    # MOCK mode: index rebuilds from mock_topology.json (no 8c:22:d2) → no match
    ts.set_mock_mode(True)
    assert ts.match_device_profile("8c:22:d2:41:0b:ca", "192.168.1.12") is None
