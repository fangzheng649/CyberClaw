import pytest
from cyberclaw_core.security_models import SecurityState, DeviceInfo, SecurityEvent


def test_security_state_enum():
    assert SecurityState.SECURE == "secure"
    assert SecurityState.SCANNING == "scanning"
    assert SecurityState.VULNERABLE == "vulnerable"
    assert SecurityState.ATTACKED == "attacked"
    assert SecurityState.ISOLATED == "isolated"


def test_device_info_creation():
    dev = DeviceInfo(
        id="camera-1", name="Camera-1", type="camera",
        ip="10.0.0.101", mac="AA:BB:CC:01:01:01",
        status=SecurityState.SECURE,
    )
    assert dev.id == "camera-1"
    assert dev.vendor is None


def test_device_info_with_vendor():
    dev = DeviceInfo(
        id="camera-1", name="Camera-1", type="camera",
        ip="10.0.0.101", mac="AA:BB:CC:01:01:01",
        status=SecurityState.SECURE, vendor="Hikvision", model="DS-2CD2142",
    )
    assert dev.vendor == "Hikvision"
    assert dev.model == "DS-2CD2142"


def test_security_event_creation():
    evt = SecurityEvent(
        type="port_scan", severity="warning",
        message="Camera-1 open Telnet port",
        target="camera-1",
    )
    assert evt.type == "port_scan"
    assert evt.severity == "warning"


def test_security_event_defaults():
    evt = SecurityEvent(type="scan_started", message="Scanning")
    assert evt.severity == "info"
    assert evt.target is None
    assert evt.source is None
