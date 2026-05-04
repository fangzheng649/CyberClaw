from enum import StrEnum
from pydantic import BaseModel


class SecurityState(StrEnum):
    SECURE = "secure"
    SCANNING = "scanning"
    VULNERABLE = "vulnerable"
    ATTACKED = "attacked"
    ISOLATED = "isolated"


class DeviceInfo(BaseModel):
    id: str
    name: str
    type: str
    ip: str
    mac: str
    status: SecurityState = SecurityState.SECURE
    vendor: str | None = None
    model: str | None = None
    pos: list[float] | None = None


class SecurityEvent(BaseModel):
    type: str
    message: str
    severity: str = "info"
    target: str | None = None
    source: str | None = None
    details: dict | None = None
