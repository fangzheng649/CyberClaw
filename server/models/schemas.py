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


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str
    message_type: str = "reply"
