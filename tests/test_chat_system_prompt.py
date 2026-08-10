"""System prompt must describe only real, online devices in real mode.

Problem: _build_system_prompt counted ALL DB devices (incl. 18 offline mock
192.168.10.x), so the agent claimed "secure×22" while only 4 real devices
were online — a wrong environmental picture that skewed its analysis.
Fix: in real mode, count only discovery_method != "mock" AND online devices,
mirroring async_get_topology / the HUD.
"""
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))
sys.path.insert(0, str(_PROJECT_ROOT))

from server.api.chat import _real_online_devices


def _row(ip, present, method, status="secure", dtype="camera"):
    return {"devLastIP": ip, "devPresentLastScan": present,
            "devDiscoveryMethod": method, "devStatus": status, "devType": dtype}


def test_real_online_devices_keeps_real_online_only():
    rows = [
        _row("192.168.1.1", 1, "arp_table", "secure", "switch"),
        _row("192.168.1.11", 1, "arp_table", "secure", "camera"),
        _row("192.168.10.101", 0, "mock", "secure", "camera"),   # mock offline
        _row("192.168.10.1", 0, "mock", "secure", "gateway"),    # mock offline
        _row("192.168.1.60", 1, "arp_table", "vulnerable", "nvr"),
    ]
    out = _real_online_devices(rows)
    ips = sorted(d["devLastIP"] for d in out)
    assert ips == ["192.168.1.1", "192.168.1.11", "192.168.1.60"]


def test_real_online_devices_excludes_offline_real_device():
    rows = [_row("192.168.1.12", 0, "arp_table")]   # real but offline now
    assert _real_online_devices(rows) == []


def test_real_online_devices_excludes_mock_even_if_online():
    rows = [_row("192.168.10.5", 1, "mock")]   # mock but present=1 → still excluded
    assert _real_online_devices(rows) == []
