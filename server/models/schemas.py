from pydantic import BaseModel


class DeviceResponse(BaseModel):
    id: str
    name: str
    type: str
    ip: str
    mac: str
    status: str
    vendor: str | None = None
    model: str | None = None
    pos: list[float] | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    last_seen: str | None = None
    uptime: int | None = None
    discovery_method: str | None = None
    protocols: list[str] | None = None
    vlan_id: int | None = None
    location: str | None = None
    notes: str | None = None


class LinkResponse(BaseModel):
    from_: str
    to: str

    class Config:
        populate_by_name = True


class TopologyResponse(BaseModel):
    devices: list[DeviceResponse]
    links: list[LinkResponse]


class SecurityEventResponse(BaseModel):
    type: str
    message: str
    severity: str = "info"
    target: str | None = None
    source: str | None = None
    details: dict | None = None
    step: int | None = None


class ScenarioStatusResponse(BaseModel):
    running: bool
    step: int
    total_steps: int


class AnalysisStep(BaseModel):
    tool: str
    summary: str
    detail: str | None = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []


class ChatResponse(BaseModel):
    reply: str
    message_type: str = "reply"
    steps: list[AnalysisStep] = []
