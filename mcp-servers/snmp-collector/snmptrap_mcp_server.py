"""
SNMP Trap MCP Server - Receives and queries SNMP traps.
Implements FR-006 through FR-011 and FR-017 through FR-022.
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
    SNMPTrap, TrapQueryFilter, ReceiverStatus,
    SNMPVersion, STANDARD_TRAPS
)
from .trap_parser import parse_trap
from .message_store import MessageStore
from .udp_receiver import UDPReceiver
from .rate_limiter import RateLimiter
from .gait_logger import GAITLogger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
SNMPTRAP_PORT = int(os.getenv('SNMPTRAP_PORT', '162'))
SNMPTRAP_BIND_ADDRESS = os.getenv('SNMPTRAP_BIND_ADDRESS', '0.0.0.0')
SNMPTRAP_RETENTION_HOURS = int(os.getenv('SNMPTRAP_RETENTION_HOURS', '24'))
SNMPTRAP_RATE_LIMIT = float(os.getenv('SNMPTRAP_RATE_LIMIT', '1000'))
SNMPTRAP_DEDUP_WINDOW = int(os.getenv('SNMPTRAP_DEDUP_WINDOW', '5'))

# Create MCP server
app = Server("snmptrap-mcp")

# Global state
message_store: Optional[MessageStore[SNMPTrap]] = None
udp_receiver: Optional[UDPReceiver] = None
rate_limiter: Optional[RateLimiter] = None
gait_logger: Optional[GAITLogger] = None
receiver_status: ReceiverStatus = ReceiverStatus(
    port=SNMPTRAP_PORT,
    bind_address=SNMPTRAP_BIND_ADDRESS
)


async def handle_trap_message(data: bytes, addr: Tuple[str, int]) -> None:
    """Handle incoming SNMP trap."""
    global receiver_status

    source_ip, source_port = addr

    # Rate limiting
    if rate_limiter and not rate_limiter.allow():
        receiver_status.rate_limited_count += 1
        return

    try:
        # Parse the trap
        trap = parse_trap(data, source_ip, source_port)

        # Store with deduplication
        if message_store:
            stored = message_store.add(
                trap,
                hash_fields=['source_ip', 'trap_oid', 'version']
            )

            if stored:
                receiver_status.traps_received += 1
                receiver_status.last_trap_time = datetime.utcnow()

                # Update version counters
                if trap.version == SNMPVersion.V1:
                    receiver_status.v1_traps += 1
                elif trap.version == SNMPVersion.V2C:
                    receiver_status.v2c_traps += 1
                elif trap.version == SNMPVersion.V3:
                    receiver_status.v3_traps += 1

                # GAIT audit logging
                if gait_logger:
                    gait_logger.log_trap_received(
                        source_ip=source_ip,
                        trap_id=trap.id,
                        trap_oid=trap.trap_oid,
                        version=trap.version,
                        trap_type=trap.trap_type
                    )

                logger.debug(f"Stored trap from {source_ip}: {trap.trap_type} ({trap.version})")
            else:
                receiver_status.traps_deduplicated += 1

    except Exception as e:
        receiver_status.errors += 1
        logger.error(f"Error processing trap from {addr}: {e}")


@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available SNMP trap tools."""
    return [
        Tool(
            name="snmptrap_start_receiver",
            description="Start the SNMP trap receiver to listen for UDP messages",
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "UDP port to listen on",
                        "default": 162
                    },
                    "bind_address": {
                        "type": "string",
                        "description": "Address to bind to",
                        "default": "0.0.0.0"
                    }
                }
            }
        ),
        Tool(
            name="snmptrap_stop_receiver",
            description="Stop the SNMP trap receiver",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="snmptrap_get_status",
            description="Get SNMP trap receiver status including trap counts and uptime",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="snmptrap_query",
            description="Query SNMP traps by time, source, version, OID, or community",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "format": "date-time"},
                    "end_time": {"type": "string", "format": "date-time"},
                    "source_ip": {"type": "string"},
                    "version": {"type": "string", "enum": ["v1", "v2c", "v3"]},
                    "trap_oid": {"type": "string"},
                    "trap_oid_prefix": {"type": "string", "description": "Match OIDs starting with this prefix"},
                    "limit": {"type": "integer", "default": 100, "maximum": 1000},
                    "offset": {"type": "integer", "default": 0}
                }
            }
        ),
        Tool(
            name="snmptrap_get_trap",
            description="Get full details of a specific SNMP trap including all varbinds",
            inputSchema={
                "type": "object",
                "properties": {
                    "trap_id": {"type": "string", "description": "UUID of the trap"}
                },
                "required": ["trap_id"]
            }
        ),
        Tool(
            name="snmptrap_get_counts",
            description="Get trap counts grouped by type and source for a time range",
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
        if name == "snmptrap_start_receiver":
            return await handle_start_receiver(arguments)
        elif name == "snmptrap_stop_receiver":
            return await handle_stop_receiver()
        elif name == "snmptrap_get_status":
            return await handle_get_status()
        elif name == "snmptrap_query":
            return await handle_query(arguments)
        elif name == "snmptrap_get_trap":
            return await handle_get_trap(arguments)
        elif name == "snmptrap_get_counts":
            return await handle_get_counts(arguments)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"Error in tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def handle_start_receiver(arguments: Dict[str, Any]) -> List[TextContent]:
    """Start the SNMP trap UDP receiver."""
    global udp_receiver, message_store, rate_limiter, gait_logger, receiver_status

    if udp_receiver and udp_receiver.is_running:
        return [TextContent(type="text", text="SNMP trap receiver is already running")]

    port = arguments.get('port', SNMPTRAP_PORT)
    bind_address = arguments.get('bind_address', SNMPTRAP_BIND_ADDRESS)

    # Initialize components
    message_store = MessageStore[SNMPTrap](
        retention_hours=SNMPTRAP_RETENTION_HOURS,
        dedup_window_sec=SNMPTRAP_DEDUP_WINDOW
    )
    rate_limiter = RateLimiter(rate=SNMPTRAP_RATE_LIMIT, burst=int(SNMPTRAP_RATE_LIMIT * 5))
    gait_logger = GAITLogger(service_name='snmptrap-mcp')

    # Create and start receiver
    udp_receiver = UDPReceiver(
        message_handler=handle_trap_message,
        host=bind_address,
        port=port
    )
    await udp_receiver.start()

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
        text=f"SNMP trap receiver started on {bind_address}:{port}"
    )]


async def handle_stop_receiver() -> List[TextContent]:
    """Stop the SNMP trap UDP receiver."""
    global udp_receiver, receiver_status

    if not udp_receiver or not udp_receiver.is_running:
        return [TextContent(type="text", text="SNMP trap receiver is not running")]

    await udp_receiver.stop()

    # Log to GAIT
    if gait_logger:
        gait_logger.log_receiver_stopped(receiver_status.port, receiver_status.traps_received)

    receiver_status.is_running = False

    return [TextContent(type="text", text="SNMP trap receiver stopped")]


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
    """Query SNMP traps."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    # Build filter function
    def trap_filter(trap: SNMPTrap) -> bool:
        if arguments.get('source_ip'):
            if trap.source_ip != arguments['source_ip']:
                return False
        if arguments.get('version'):
            if trap.version != arguments['version']:
                return False
        if arguments.get('trap_oid'):
            if trap.trap_oid != arguments['trap_oid']:
                return False
        if arguments.get('trap_oid_prefix'):
            if not trap.trap_oid.startswith(arguments['trap_oid_prefix']):
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
    total, traps = message_store.query(
        filter_func=trap_filter,
        start_time=start_time,
        end_time=end_time,
        limit=arguments.get('limit', 100),
        offset=arguments.get('offset', 0)
    )

    result = {
        'total': total,
        'returned': len(traps),
        'traps': [trap.to_display_dict() for trap in traps]
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_get_trap(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get a specific trap by ID."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    trap_id = arguments.get('trap_id')
    if not trap_id:
        return [TextContent(type="text", text="trap_id is required")]

    trap = message_store.get(trap_id)
    if not trap:
        return [TextContent(type="text", text=f"Trap not found: {trap_id}")]

    # Include full varbinds in response
    result = trap.model_dump(mode='json', exclude={'raw_data'})
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_get_counts(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get trap counts by type and source."""
    import json
    from collections import defaultdict

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    # Parse time range
    start_time = None
    end_time = None
    if arguments.get('start_time'):
        start_time = datetime.fromisoformat(arguments['start_time'].replace('Z', '+00:00'))
    if arguments.get('end_time'):
        end_time = datetime.fromisoformat(arguments['end_time'].replace('Z', '+00:00'))

    # Count traps
    by_type = defaultdict(int)
    by_source = defaultdict(int)
    total = 0

    def time_filter(trap: SNMPTrap) -> bool:
        if start_time and trap.received_at < start_time:
            return False
        if end_time and trap.received_at > end_time:
            return False
        return True

    for msg_id, (ts, trap) in message_store.messages.items():
        if time_filter(trap):
            by_type[trap.trap_type] += 1
            by_source[trap.source_ip] += 1
            total += 1

    # Format type counts with OIDs
    type_counts = []
    for trap_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
        # Find the OID for this type
        oid = None
        for o, name in STANDARD_TRAPS.items():
            if name == trap_type:
                oid = o
                break
        type_counts.append({
            'trap_type': trap_type,
            'trap_oid': oid,
            'count': count
        })

    result = {
        'time_range': {
            'start': start_time.isoformat() if start_time else None,
            'end': end_time.isoformat() if end_time else None
        },
        'by_type': type_counts,
        'by_source': dict(sorted(by_source.items(), key=lambda x: -x[1])),
        'total': total
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
