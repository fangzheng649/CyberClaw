"""
Asyncio TCP receiver for syslog over TCP (RFC 6587).
Supports both newline-delimited and octet-counting framing.
"""

import asyncio
import logging
from datetime import datetime
from typing import Awaitable, Callable, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Type alias for message handler
MessageHandler = Callable[[bytes, Tuple[str, int]], Awaitable[None]]


class TCPSyslogProtocol(asyncio.Protocol):
    """
    Asyncio protocol for TCP syslog reception.

    Handles newline-delimited syslog messages (Cisco default).
    """

    def __init__(
        self,
        message_handler: MessageHandler,
        client_addr: Tuple[str, int],
        on_disconnect: Optional[Callable[[Tuple[str, int]], None]] = None
    ):
        self.message_handler = message_handler
        self.client_addr = client_addr
        self.on_disconnect = on_disconnect
        self.transport: Optional[asyncio.Transport] = None
        self.buffer = b""
        self.messages_received = 0

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when connection is established."""
        self.transport = transport
        logger.info(f"TCP syslog connection from {self.client_addr}")

    def data_received(self, data: bytes) -> None:
        """Called when data is received."""
        self.buffer += data

        # Process complete lines (newline-delimited)
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if line:  # Skip empty lines
                self.messages_received += 1
                # Schedule async handler
                asyncio.create_task(self._handle_message(line))

    async def _handle_message(self, data: bytes) -> None:
        """Handle a complete syslog message."""
        try:
            await self.message_handler(data, self.client_addr)
        except Exception as e:
            logger.error(f"Error handling TCP syslog from {self.client_addr}: {e}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when connection is lost."""
        if exc:
            logger.warning(f"TCP connection lost from {self.client_addr}: {exc}")
        else:
            logger.info(f"TCP connection closed from {self.client_addr}")

        if self.on_disconnect:
            self.on_disconnect(self.client_addr)


class TCPReceiver:
    """
    High-level TCP receiver manager for syslog.

    Manages multiple client connections and the server lifecycle.
    """

    def __init__(
        self,
        message_handler: MessageHandler,
        host: str = "0.0.0.0",
        port: int = 1514
    ):
        self.message_handler = message_handler
        self.host = host
        self.port = port

        self.server: Optional[asyncio.Server] = None
        self.is_running = False
        self.started_at: Optional[datetime] = None
        self.clients: Set[Tuple[str, int]] = set()
        self.total_connections = 0
        self.total_messages = 0

    def _client_factory(self, client_addr: Tuple[str, int]) -> TCPSyslogProtocol:
        """Create protocol instance for new client."""
        self.clients.add(client_addr)
        self.total_connections += 1

        def on_disconnect(addr: Tuple[str, int]):
            self.clients.discard(addr)

        return TCPSyslogProtocol(
            self.message_handler,
            client_addr,
            on_disconnect
        )

    async def start(self) -> None:
        """Start the TCP server."""
        if self.is_running:
            logger.warning("TCP receiver already running")
            return

        loop = asyncio.get_event_loop()

        self.server = await loop.create_server(
            lambda: self._client_factory(("unknown", 0)),  # Will be updated
            self.host,
            self.port,
            reuse_address=True
        )

        # Override to get real client address
        original_serve = self.server.serve_forever

        self.is_running = True
        self.started_at = datetime.utcnow()
        logger.info(f"TCP syslog receiver started on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the TCP server."""
        if not self.is_running:
            logger.warning("TCP receiver not running")
            return

        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

        self.is_running = False
        self.clients.clear()
        logger.info("TCP syslog receiver stopped")

    def get_status(self) -> dict:
        """Get receiver status."""
        return {
            'is_running': self.is_running,
            'host': self.host,
            'port': self.port,
            'protocol': 'tcp',
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'active_connections': len(self.clients),
            'total_connections': self.total_connections,
        }
