"""
Asyncio UDP receiver base pattern.
Based on research.md specification for asyncio.DatagramProtocol.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional, Tuple

logger = logging.getLogger(__name__)

# Type alias for message handler
MessageHandler = Callable[[bytes, Tuple[str, int]], Awaitable[None]]


class UDPReceiverProtocol(asyncio.DatagramProtocol):
    """
    Asyncio datagram protocol for UDP message reception.

    Handles incoming UDP packets and dispatches them to a message handler.
    """

    def __init__(
        self,
        message_handler: MessageHandler,
        on_error: Optional[Callable[[Exception, Tuple[str, int]], None]] = None
    ):
        """
        Initialize the protocol.

        Args:
            message_handler: Async function to handle received messages
            on_error: Optional callback for error handling
        """
        self.message_handler = message_handler
        self.on_error = on_error
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.packets_received = 0
        self.bytes_received = 0
        self.errors = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Called when the transport is ready."""
        self.transport = transport
        logger.info(f"UDP receiver started on {transport.get_extra_info('sockname')}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Called when a datagram is received.

        Args:
            data: The received data
            addr: Tuple of (host, port)
        """
        self.packets_received += 1
        self.bytes_received += len(data)

        # Schedule async handler
        asyncio.create_task(self._handle_message(data, addr))

    async def _handle_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle message with error catching."""
        try:
            await self.message_handler(data, addr)
        except Exception as e:
            self.errors += 1
            logger.error(f"Error handling message from {addr}: {e}")
            if self.on_error:
                self.on_error(e, addr)

    def error_received(self, exc: Exception) -> None:
        """Called when an error is received."""
        self.errors += 1
        logger.error(f"UDP receiver error: {exc}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost."""
        if exc:
            logger.error(f"UDP connection lost: {exc}")
        else:
            logger.info("UDP receiver stopped")

    def get_stats(self) -> dict:
        """Get receiver statistics."""
        return {
            'packets_received': self.packets_received,
            'bytes_received': self.bytes_received,
            'errors': self.errors
        }


class UDPReceiver:
    """
    High-level UDP receiver manager.

    Manages the lifecycle of a UDP receiver with start/stop functionality.
    """

    def __init__(
        self,
        message_handler: MessageHandler,
        host: str = "0.0.0.0",
        port: int = 514,
        on_error: Optional[Callable[[Exception, Tuple[str, int]], None]] = None
    ):
        """
        Initialize the UDP receiver.

        Args:
            message_handler: Async function to handle received messages
            host: Address to bind to (default: all interfaces)
            port: Port to listen on
            on_error: Optional error callback
        """
        self.message_handler = message_handler
        self.host = host
        self.port = port
        self.on_error = on_error

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[UDPReceiverProtocol] = None
        self.is_running = False
        self.started_at: Optional[datetime] = None

    async def start(self) -> None:
        """Start the UDP receiver."""
        if self.is_running:
            logger.warning("UDP receiver already running")
            return

        loop = asyncio.get_event_loop()

        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: UDPReceiverProtocol(self.message_handler, self.on_error),
            local_addr=(self.host, self.port)
        )

        self.is_running = True
        self.started_at = datetime.utcnow()
        logger.info(f"UDP receiver started on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the UDP receiver."""
        if not self.is_running:
            logger.warning("UDP receiver not running")
            return

        if self.transport:
            self.transport.close()
            self.transport = None

        self.protocol = None
        self.is_running = False
        logger.info("UDP receiver stopped")

    def get_status(self) -> dict:
        """Get receiver status."""
        status = {
            'is_running': self.is_running,
            'host': self.host,
            'port': self.port,
            'started_at': self.started_at.isoformat() if self.started_at else None,
        }

        if self.protocol:
            status.update(self.protocol.get_stats())

        return status


async def create_udp_receiver(
    message_handler: MessageHandler,
    host: str = "0.0.0.0",
    port: int = 514,
    auto_start: bool = True
) -> UDPReceiver:
    """
    Factory function to create and optionally start a UDP receiver.

    Args:
        message_handler: Async function to handle messages
        host: Bind address
        port: Listen port
        auto_start: Whether to start immediately

    Returns:
        Configured UDPReceiver instance
    """
    receiver = UDPReceiver(message_handler, host, port)
    if auto_start:
        await receiver.start()
    return receiver
