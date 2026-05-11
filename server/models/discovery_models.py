from pydantic import BaseModel


class DiscoveredDevice(BaseModel):
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    open_ports: list[int] = []
    discovery_method: str = "unknown"


class DiscoveryResult(BaseModel):
    scan_time: str
    subnet: str
    methods: list[str]
    found: int
    devices: list[DiscoveredDevice]
    duration_ms: int
    error: str | None = None
