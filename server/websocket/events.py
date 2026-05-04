import json
import logging
from fastapi import WebSocket


logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, data: dict) -> None:
        msg = json.dumps(data, ensure_ascii=False)
        for ws in self.connections[:]:
            try:
                await ws.send_text(msg)
            except Exception:
                self.disconnect(ws)
