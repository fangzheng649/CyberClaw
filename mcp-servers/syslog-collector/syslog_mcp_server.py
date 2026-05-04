"""
Syslog MCP Server - Receives and queries syslog messages.
Implements FR-001 through FR-005 and FR-017 through FR-022.
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .models import (
    SyslogMessage, SyslogQueryFilter, ReceiverStatus,
    SeverityCountsResponse, SEVERITY_NAMES, TimeRange
)
from .syslog_parser import parse_syslog
from .message_store import MessageStore
from .udp_receiver import UDPReceiver
from .tcp_receiver import TCPReceiver
from .rate_limiter import RateLimiter
from .gait_logger import GAITLogger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', '514'))
SYSLOG_BIND_ADDRESS = os.getenv('SYSLOG_BIND_ADDRESS', '0.0.0.0')
SYSLOG_RETENTION_HOURS = int(os.getenv('SYSLOG_RETENTION_HOURS', '24'))
SYSLOG_RATE_LIMIT = float(os.getenv('SYSLOG_RATE_LIMIT', '1000'))
SYSLOG_DEDUP_WINDOW = int(os.getenv('SYSLOG_DEDUP_WINDOW', '5'))

# Create MCP server
app = Server("syslog-mcp")

# Global state
message_store: Optional[MessageStore[SyslogMessage]] = None
udp_receiver: Optional[UDPReceiver] = None
tcp_receiver: Optional[TCPReceiver] = None
rate_limiter: Optional[RateLimiter] = None
gait_logger: Optional[GAITLogger] = None
receiver_status: ReceiverStatus = ReceiverStatus(
    port=SYSLOG_PORT,
    bind_address=SYSLOG_BIND_ADDRESS
)
receiver_protocol: str = "udp"  # Track which protocol is active


async def handle_syslog_message(data: bytes, addr: Tuple[str, int]) -> None:
    """Handle incoming syslog message."""
    global receiver_status

    source_ip, source_port = addr

    # Rate limiting
    if rate_limiter and not rate_limiter.allow():
        receiver_status.rate_limited_count += 1
        return

    try:
        # Parse the message
        msg = parse_syslog(data, source_ip, source_port)

        # Store with deduplication
        if message_store:
            stored = message_store.add(
                msg,
                hash_fields=['source_ip', 'facility', 'severity', 'message']
            )

            if stored:
                receiver_status.messages_received += 1
                receiver_status.last_message_time = datetime.utcnow()

                # GAIT audit logging
                if gait_logger:
                    gait_logger.log_syslog_received(
                        source_ip=source_ip,
                        message_id=msg.id,
                        severity=msg.severity,
                        facility=msg.facility,
                        message_preview=msg.message[:100]
                    )

                logger.debug(f"Stored syslog from {source_ip}: {msg.severity_name} - {msg.message[:50]}")
            else:
                receiver_status.messages_deduplicated += 1

    except Exception as e:
        receiver_status.errors += 1
        logger.error(f"Error processing syslog from {addr}: {e}")


@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available syslog tools."""
    return [
        Tool(
            name="syslog_start_receiver",
            description="Start the syslog receiver to listen for messages (UDP or TCP)",
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "Port to listen on",
                        "default": 514
                    },
                    "bind_address": {
                        "type": "string",
                        "description": "Address to bind to",
                        "default": "0.0.0.0"
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["udp", "tcp"],
                        "description": "Transport protocol (udp or tcp). Use tcp with ngrok tunnels.",
                        "default": "udp"
                    }
                }
            }
        ),
        Tool(
            name="syslog_stop_receiver",
            description="Stop the syslog receiver",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="syslog_get_status",
            description="Get syslog receiver status including message counts and uptime",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="syslog_query",
            description="Query syslog messages by time, severity, facility, hostname, or content",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "format": "date-time"},
                    "end_time": {"type": "string", "format": "date-time"},
                    "severity_min": {"type": "integer", "minimum": 0, "maximum": 7},
                    "severity_max": {"type": "integer", "minimum": 0, "maximum": 7},
                    "facility": {"type": "integer", "minimum": 0, "maximum": 23},
                    "hostname": {"type": "string"},
                    "source_ip": {"type": "string"},
                    "message_contains": {"type": "string"},
                    "limit": {"type": "integer", "default": 100, "maximum": 1000},
                    "offset": {"type": "integer", "default": 0}
                }
            }
        ),
        Tool(
            name="syslog_get_message",
            description="Get full details of a specific syslog message",
            inputSchema={
                "type": "object",
                "properties": {
                    "message_id": {"type": "string", "description": "UUID of the message"}
                },
                "required": ["message_id"]
            }
        ),
        Tool(
            name="syslog_get_severity_counts",
            description="Get count of messages by severity level for a time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "format": "date-time"},
                    "end_time": {"type": "string", "format": "date-time"}
                }
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls."""
    global udp_receiver, message_store, rate_limiter, gait_logger, receiver_status

    try:
        if name == "syslog_start_receiver":
            return await handle_start_receiver(arguments)
        elif name == "syslog_stop_receiver":
            return await handle_stop_receiver()
        elif name == "syslog_get_status":
            return await handle_get_status()
        elif name == "syslog_query":
            return await handle_query(arguments)
        elif name == "syslog_get_message":
            return await handle_get_message(arguments)
        elif name == "syslog_get_severity_counts":
            return await handle_severity_counts(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"Error in tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def handle_start_receiver(arguments: Dict[str, Any]) -> List[TextContent]:
    """Start the syslog receiver (UDP or TCP)."""
    global udp_receiver, tcp_receiver, message_store, rate_limiter, gait_logger, receiver_status, receiver_protocol

    # Check if already running
    if (udp_receiver and udp_receiver.is_running) or (tcp_receiver and tcp_receiver.is_running):
        return [TextContent(type="text", text="Syslog receiver is already running")]

    port = arguments.get('port', SYSLOG_PORT)
    bind_address = arguments.get('bind_address', SYSLOG_BIND_ADDRESS)
    protocol = arguments.get('protocol', 'udp').lower()

    if protocol not in ('udp', 'tcp'):
        return [TextContent(type="text", text=f"Invalid protocol: {protocol}. Use 'udp' or 'tcp'")]

    # Initialize components
    message_store = MessageStore[SyslogMessage](
        retention_hours=SYSLOG_RETENTION_HOURS,
        dedup_window_sec=SYSLOG_DEDUP_WINDOW
    )
    rate_limiter = RateLimiter(rate=SYSLOG_RATE_LIMIT, burst=int(SYSLOG_RATE_LIMIT * 5))
    gait_logger = GAITLogger(service_name='syslog-mcp')

    # Create and start receiver based on protocol
    if protocol == 'udp':
        udp_receiver = UDPReceiver(
            message_handler=handle_syslog_message,
            host=bind_address,
            port=port
        )
        await udp_receiver.start()
    else:  # tcp
        tcp_receiver = TCPReceiver(
            message_handler=handle_syslog_message,
            host=bind_address,
            port=port
        )
        await tcp_receiver.start()

    receiver_protocol = protocol

    # Update status
    receiver_status = ReceiverStatus(
        port=port,
        bind_address=bind_address,
        is_running=True,
        started_at=datetime.utcnow()
    )

    # Log to GAIT
    gait_logger.log_receiver_started(port, bind_address)

    return [TextContent(
        type="text",
        text=f"Syslog receiver started on {bind_address}:{port} ({protocol.upper()})"
    )]


async def handle_stop_receiver() -> List[TextContent]:
    """Stop the syslog receiver (UDP or TCP)."""
    global udp_receiver, tcp_receiver, receiver_status, receiver_protocol

    # Check which receiver is running
    is_udp_running = udp_receiver and udp_receiver.is_running
    is_tcp_running = tcp_receiver and tcp_receiver.is_running

    if not is_udp_running and not is_tcp_running:
        return [TextContent(type="text", text="Syslog receiver is not running")]

    # Stop the appropriate receiver
    if is_udp_running:
        await udp_receiver.stop()
    if is_tcp_running:
        await tcp_receiver.stop()

    # Log to GAIT
    if gait_logger:
        gait_logger.log_receiver_stopped(receiver_status.port, receiver_status.messages_received)

    receiver_status.is_running = False

    return [TextContent(type="text", text=f"Syslog receiver stopped ({receiver_protocol.upper()})")]


async def handle_get_status() -> List[TextContent]:
    """Get current receiver status."""
    import json

    status_dict = receiver_status.to_dict()

    # Add store stats
    if message_store:
        status_dict['store_stats'] = message_store.get_stats()

    # Add rate limiter stats
    if rate_limiter:
        status_dict['rate_limiter'] = rate_limiter.get_stats()

    return [TextContent(type="text", text=json.dumps(status_dict, indent=2))]


async def handle_query(arguments: Dict[str, Any]) -> List[TextContent]:
    """Query syslog messages."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    # Build filter function
    def message_filter(msg: SyslogMessage) -> bool:
        if arguments.get('severity_min') is not None:
            if msg.severity > arguments['severity_min']:
                return False
        if arguments.get('severity_max') is not None:
            if msg.severity < arguments['severity_max']:
                return False
        if arguments.get('facility') is not None:
            if msg.facility != arguments['facility']:
                return False
        if arguments.get('hostname'):
            if msg.hostname != arguments['hostname']:
                return False
        if arguments.get('source_ip'):
            if msg.source_ip != arguments['source_ip']:
                return False
        if arguments.get('message_contains'):
            if arguments['message_contains'].lower() not in msg.message.lower():
                return False
        return True

    # Parse time range
    start_time = None
    end_time = None
    if arguments.get('start_time'):
        start_time = datetime.fromisoformat(arguments['start_time'].replace('Z', '+00:00'))
    if arguments.get('end_time'):
        end_time = datetime.fromisoformat(arguments['end_time'].replace('Z', '+00:00'))

    # Query
    total, messages = message_store.query(
        filter_func=message_filter,
        start_time=start_time,
        end_time=end_time,
        limit=arguments.get('limit', 100),
        offset=arguments.get('offset', 0)
    )

    result = {
        'total': total,
        'returned': len(messages),
        'messages': [msg.to_display_dict() for msg in messages]
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_get_message(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get a specific message by ID."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    message_id = arguments.get('message_id')
    if not message_id:
        return [TextContent(type="text", text="message_id is required")]

    msg = message_store.get(message_id)
    if not msg:
        return [TextContent(type="text", text=f"Message not found: {message_id}")]

    return [TextContent(type="text", text=json.dumps(msg.model_dump(mode='json'), indent=2))]


async def handle_severity_counts(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get message counts by severity."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    # Parse time range
    start_time = None
    end_time = None
    if arguments.get('start_time'):
        start_time = datetime.fromisoformat(arguments['start_time'].replace('Z', '+00:00'))
    if arguments.get('end_time'):
        end_time = datetime.fromisoformat(arguments['end_time'].replace('Z', '+00:00'))

    # Count by severity
    counts = {}
    for sev_value, sev_name in SEVERITY_NAMES.items():
        def make_filter(severity):
            def filter_func(msg):
                if start_time and msg.received_at < start_time:
                    return False
                if end_time and msg.received_at > end_time:
                    return False
                return msg.severity == severity
            return filter_func

        counts[sev_name] = message_store.count(make_filter(sev_value))

    result = {
        'time_range': {
            'start': start_time.isoformat() if start_time else None,
            'end': end_time.isoformat() if end_time else None
        },
        'counts': counts,
        'total': sum(counts.values())
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
