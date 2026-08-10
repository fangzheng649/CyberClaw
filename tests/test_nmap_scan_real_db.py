"""Tests for nmap-scan real-mode DB-backed scanning.

Root cause: in real mode with nmap installed, network_scan ran
`nmap -sT -T3 <entire /24>` (254 hosts × 1000 ports), which always exceeded
the 120s call_tool timeout → both network_scan and iot_fingerprint reported
"执行失败". Fix: real mode reads scan_service's already-discovered live
devices (with devOpenPorts) from the DB instead of blind-scanning the subnet.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))
sys.path.insert(0, str(_PROJECT_ROOT))

# Load the nmap-scan server module (same mechanism as mcp_tool_service).
_spec = importlib.util.spec_from_file_location(
    "nmap_scan_server", _PROJECT_ROOT / "mcp-servers" / "nmap-scan" / "server.py")
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _row(ip, mac, present, ports="[]", method="arp_table",
         vendor="Hikvision", dtype="camera", model="M"):
    return {
        "devLastIP": ip, "devMac": mac, "devPresentLastScan": present,
        "devOpenPorts": ports, "devDiscoveryMethod": method,
        "devVendor": vendor, "devType": dtype, "devModel": model,
    }


# ── _filter_db_devices: pure filtering of raw DB rows ────────────────

def test_filter_keeps_online_real_mac_devices_in_subnet():
    rows = [
        _row("192.168.1.11", "8c:22:d2:41:09:08", 1, "[80, 554, 8000]"),
        _row("192.168.1.1", "60:a3:e3:61:81:0f", 1, "[80]", vendor="TP-LINK", dtype="switch"),
        _row("192.168.10.101", "aa:bb:cc:dd:ee:01", 0, "[80]", method="mock"),  # mock offline
        _row("192.168.1.60", "04:ee:cd:03:2c:46", 0, "[80, 554]"),              # real but offline
    ]
    out = srv._filter_db_devices(rows, "192.168.1.0/24")
    ips = sorted(d["ip"] for d in out)
    assert ips == ["192.168.1.1", "192.168.1.11"]   # online + in-subnet + real MAC only
    cam = next(d for d in out if d["ip"] == "192.168.1.11")
    assert cam["ports"] == [80, 554, 8000]
    assert cam["vendor"] == "Hikvision"


def test_filter_skips_placeholder_macs_and_offline():
    rows = [
        _row("192.168.1.50", "", 1, "[80]"),                   # empty MAC → skip
        _row("192.168.1.51", "switch-core", 1, "[80]"),        # config-id placeholder → skip
        _row("192.168.1.52", "8c:22:d2:41:09:09", 0, "[80]"),  # offline → skip
    ]
    assert srv._filter_db_devices(rows, "192.168.1.0/24") == []


def test_filter_single_ip_target_matches_exact():
    rows = [_row("192.168.1.11", "8c:22:d2:41:09:08", 1, "[80]")]
    assert len(srv._filter_db_devices(rows, "192.168.1.11")) == 1   # exact IP match
    assert srv._filter_db_devices(rows, "192.168.1.99") == []        # different host


def test_filter_parses_port_list_or_json_string():
    rows = [
        _row("192.168.1.11", "8c:22:d2:41:09:08", 1, "[80, 554]"),   # JSON string
        _row("192.168.1.12", "8c:22:d2:41:0b:ca", 1, [80, 8000]),    # already a list
    ]
    out = {d["ip"]: d["ports"] for d in srv._filter_db_devices(rows, "192.168.1.0/24")}
    assert out["192.168.1.11"] == [80, 554]
    assert out["192.168.1.12"] == [80, 8000]


# ── _db_devices_to_scan_result: normalized devices → ScanResult ──────

def test_db_devices_to_scan_result_builds_hosts_with_open_ports():
    devices = [
        {"ip": "192.168.1.11", "mac": "8c:22:d2:41:09:08", "vendor": "Hikvision",
         "type": "camera", "model": "DS-2CD", "ports": [80, 554]},
    ]
    result = srv._db_devices_to_scan_result(devices, "192.168.1.0/24", "nmap -sT")
    assert len(result.hosts) == 1
    h = result.hosts[0]
    assert h.ip == "192.168.1.11"
    assert h.mac == "8c:22:d2:41:09:08"
    assert h.vendor == "Hikvision"
    assert h.state == "up"
    open_ports = [p.port for p in h.ports if p.state == srv.PortState.OPEN]
    assert open_ports == [80, 554]


# ── _known_device_ips: topology-based IP resolution (nmap fallback) ───

def test_known_device_ips_resolves_subnet_to_configured_ips(monkeypatch):
    monkeypatch.setattr(srv, "_load_mock_devices", lambda: [
        {"ip": "192.168.1.1"}, {"ip": "192.168.1.11"}, {"ip": "10.0.0.5"},
    ])
    ips = srv._known_device_ips("192.168.1.0/24")
    assert sorted(ips) == ["192.168.1.1", "192.168.1.11"]


def test_known_device_ips_empty_for_unrelated_subnet(monkeypatch):
    monkeypatch.setattr(srv, "_load_mock_devices", lambda: [{"ip": "192.168.1.1"}])
    assert srv._known_device_ips("10.0.0.0/24") == []


# ── integration: _exec_scan uses DB in real mode (no nmap, no timeout) ─

async def test_exec_scan_real_mode_uses_db_not_nmap(monkeypatch):
    monkeypatch.setattr(srv, "_is_mock_mode", lambda: False)   # real mode
    async def fake_load(_target):
        return [{"ip": "192.168.1.11", "mac": "8c:22:d2:41:09:08",
                 "vendor": "Hikvision", "type": "camera", "model": "x", "ports": [80, 554]}]
    monkeypatch.setattr(srv, "_load_real_devices_from_db", fake_load)
    # Guard: must never fall back to nmap when DB has devices.
    def boom(*a, **kw):
        raise AssertionError("should not run nmap when DB has devices")
    monkeypatch.setattr(srv, "_run_nmap", boom)

    result = await srv._exec_scan("192.168.1.0/24", None, "connect", "normal", 300)
    assert len(result.hosts) == 1
    assert result.hosts[0].ip == "192.168.1.11"


# ── device type passthrough (problem 3: accurate device types) ───────

def test_db_devices_to_scan_result_carries_device_type():
    devices = [{"ip": "192.168.1.60", "mac": "04:ee:cd:03:2c:46", "vendor": "Hikvision",
                "type": "nvr", "model": "DS-7108N", "ports": [80, 554]}]
    result = srv._db_devices_to_scan_result(devices, "192.168.1.0/24", "nmap -sT")
    assert result.hosts[0].device_type == "nvr"


def test_host_summary_returns_type():
    h = srv.HostResult(ip="192.168.1.1", device_type="switch", vendor="TP-LINK")
    s = srv._host_summary(h)
    assert s["type"] == "switch"


def test_fingerprint_uses_db_device_type_for_nvr():
    """NVR opens 554 (port heuristic would say camera) but DB devType=nvr wins."""
    scan = srv.ScanResult(hosts=[srv.HostResult(
        ip="192.168.1.60", mac="04:ee:cd:03:2c:46", vendor="Hikvision",
        device_type="nvr",
        ports=[srv.PortResult(port=554, state=srv.PortState.OPEN)])])
    devs = srv._fingerprint_iot(scan)
    nvr = next(d for d in devs if d["ip"] == "192.168.1.60")
    assert nvr["type"] == "nvr"


def test_fingerprint_falls_back_to_port_heuristic_without_db_type():
    """No device_type → port heuristic still works (554 → camera)."""
    scan = srv.ScanResult(hosts=[srv.HostResult(
        ip="10.0.0.5", mac="aa:bb:cc:00:00:05", vendor="",
        ports=[srv.PortResult(port=554, state=srv.PortState.OPEN)])])
    devs = srv._fingerprint_iot(scan)
    cam = next(d for d in devs if d["ip"] == "10.0.0.5")
    assert cam["type"] == "camera"
