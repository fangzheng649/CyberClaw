"""
IPFIX/NetFlow MCP Server - Receives and queries flow records.
Implements FR-012 through FR-016 and FR-017 through FR-022.
"""

import asyncio
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .models import (
    FlowRecord, FlowTemplate, FlowQueryFilter, ReceiverStatus,
    TopTalkersEntry, PROTOCOL_NAMES
)
from .flow_parser import parse_flow_packet, get_template_cache
from .message_store import MessageStore
from .udp_receiver import UDPReceiver
from .rate_limiter import RateLimiter
from .gait_logger import GAITLogger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
IPFIX_PORT = int(os.getenv('IPFIX_PORT', '2055'))
IPFIX_BIND_ADDRESS = os.getenv('IPFIX_BIND_ADDRESS', '0.0.0.0')
IPFIX_RETENTION_HOURS = int(os.getenv('IPFIX_RETENTION_HOURS', '24'))
IPFIX_RATE_LIMIT = float(os.getenv('IPFIX_RATE_LIMIT', '10000'))  # Higher for flows
IPFIX_DEDUP_WINDOW = int(os.getenv('IPFIX_DEDUP_WINDOW', '5'))

# Create MCP server
app = Server("ipfix-mcp")

# Global state
message_store: Optional[MessageStore[FlowRecord]] = None
udp_receiver: Optional[UDPReceiver] = None
rate_limiter: Optional[RateLimiter] = None
gait_logger: Optional[GAITLogger] = None
receiver_status: ReceiverStatus = ReceiverStatus(
    port=IPFIX_PORT,
    bind_address=IPFIX_BIND_ADDRESS
)


async def handle_flow_packet(data: bytes, addr: Tuple[str, int]) -> None:
    """Handle incoming flow packet."""
    global receiver_status

    exporter_ip, exporter_port = addr
    receiver_status.packets_received += 1

    # Rate limiting
    if rate_limiter and not rate_limiter.allow():
        receiver_status.rate_limited_count += 1
        return

    try:
        # Parse the packet (may contain multiple flows)
        flows, new_templates = parse_flow_packet(data, exporter_ip, exporter_port)

        # Track new templates
        for template in new_templates:
            receiver_status.templates_received += 1
            if gait_logger:
                gait_logger.log_template_received(
                    exporter_ip=exporter_ip,
                    template_id=template.template_id,
                    field_count=template.field_count
                )

        # Update template count
        receiver_status.active_templates = get_template_cache().count()

        # Store each flow
        for flow in flows:
            if message_store:
                stored = message_store.add(
                    flow,
                    hash_fields=['exporter_ip', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
                )

                if stored:
                    receiver_status.flows_received += 1
                    receiver_status.last_flow_time = datetime.utcnow()

                    # Update version counters
                    if flow.version == 5:
                        receiver_status.netflow_v5_flows += 1
                    elif flow.version == 9:
                        receiver_status.netflow_v9_flows += 1
                    elif flow.version == 10:
                        receiver_status.ipfix_flows += 1

                    # GAIT audit logging (sample - don't log every flow)
                    if gait_logger and receiver_status.flows_received % 100 == 0:
                        gait_logger.log_flow_received(
                            exporter_ip=exporter_ip,
                            flow_id=flow.id,
                            src_ip=flow.src_ip or '',
                            dst_ip=flow.dst_ip or '',
                            protocol=flow.protocol or 0,
                            bytes_count=flow.bytes
                        )

                    logger.debug(f"Stored flow: {flow.flow_tuple}")
                else:
                    receiver_status.flows_deduplicated += 1

    except Exception as e:
        receiver_status.errors += 1
        logger.error(f"Error processing flow packet from {addr}: {e}")


@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available IPFIX/NetFlow tools."""
    return [
        Tool(
            name="ipfix_start_receiver",
            description="Start the IPFIX/NetFlow receiver to listen for UDP flow exports",
            inputSchema={
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "UDP port to listen on",
                        "default": 2055
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
            name="ipfix_stop_receiver",
            description="Stop the IPFIX/NetFlow receiver",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="ipfix_get_status",
            description="Get IPFIX/NetFlow receiver status including flow counts and template info",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="ipfix_query_flows",
            description="Query flow records by time, IPs, ports, protocol, or exporter",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "format": "date-time"},
                    "end_time": {"type": "string", "format": "date-time"},
                    "exporter_ip": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "dst_ip": {"type": "string"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "protocol": {"type": "integer", "description": "IP protocol number (6=TCP, 17=UDP)"},
                    "version": {"type": "integer", "description": "NetFlow version (5, 9) or IPFIX (10)"},
                    "min_bytes": {"type": "integer", "description": "Minimum byte count filter"},
                    "limit": {"type": "integer", "default": 100, "maximum": 1000},
                    "offset": {"type": "integer", "default": 0}
                }
            }
        ),
        Tool(
            name="ipfix_get_flow",
            description="Get full details of a specific flow record",
            inputSchema={
                "type": "object",
                "properties": {
                    "flow_id": {"type": "string", "description": "UUID of the flow"}
                },
                "required": ["flow_id"]
            }
        ),
        Tool(
            name="ipfix_top_talkers",
            description="Get top talkers (by bytes/packets) for a time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "format": "date-time"},
                    "end_time": {"type": "string", "format": "date-time"},
                    "limit": {"type": "integer", "default": 10, "description": "Number of top entries"}
                }
            }
        ),
        Tool(
            name="ipfix_get_templates",
            description="List cached IPFIX/NetFlow v9 templates",
            inputSchema={"type": "object", "properties": {}}
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls."""
    global udp_receiver, message_store, rate_limiter, gait_logger, receiver_status

    try:
        if name == "ipfix_start_receiver":
            return await handle_start_receiver(arguments)
        elif name == "ipfix_stop_receiver":
            return await handle_stop_receiver()
        elif name == "ipfix_get_status":
            return await handle_get_status()
        elif name == "ipfix_query_flows":
            return await handle_query_flows(arguments)
        elif name == "ipfix_get_flow":
            return await handle_get_flow(arguments)
        elif name == "ipfix_top_talkers":
            return await handle_top_talkers(arguments)
        elif name == "ipfix_get_templates":
            return await handle_get_templates()
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"Error in tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def handle_start_receiver(arguments: Dict[str, Any]) -> List[TextContent]:
    """Start the IPFIX/NetFlow UDP receiver."""
    global udp_receiver, message_store, rate_limiter, gait_logger, receiver_status

    if udp_receiver and udp_receiver.is_running:
        return [TextContent(type="text", text="IPFIX/NetFlow receiver is already running")]

    port = arguments.get('port', IPFIX_PORT)
    bind_address = arguments.get('bind_address', IPFIX_BIND_ADDRESS)

    # Initialize components
    message_store = MessageStore[FlowRecord](
        retention_hours=IPFIX_RETENTION_HOURS,
        dedup_window_sec=IPFIX_DEDUP_WINDOW,
        max_messages=500000  # Higher limit for flows
    )
    rate_limiter = RateLimiter(rate=IPFIX_RATE_LIMIT, burst=int(IPFIX_RATE_LIMIT * 5))
    gait_logger = GAITLogger(service_name='ipfix-mcp')

    # Create and start receiver
    udp_receiver = UDPReceiver(
        message_handler=handle_flow_packet,
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
        text=f"IPFIX/NetFlow receiver started on {bind_address}:{port}"
    )]


async def handle_stop_receiver() -> List[TextContent]:
    """Stop the IPFIX/NetFlow UDP receiver."""
    global udp_receiver, receiver_status

    if not udp_receiver or not udp_receiver.is_running:
        return [TextContent(type="text", text="IPFIX/NetFlow receiver is not running")]

    await udp_receiver.stop()

    # Log to GAIT
    if gait_logger:
        gait_logger.log_receiver_stopped(receiver_status.port, receiver_status.flows_received)

    receiver_status.is_running = False

    return [TextContent(type="text", text="IPFIX/NetFlow receiver stopped")]


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


async def handle_query_flows(arguments: Dict[str, Any]) -> List[TextContent]:
    """Query flow records."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    # Build filter function
    def flow_filter(flow: FlowRecord) -> bool:
        if arguments.get('exporter_ip'):
            if flow.exporter_ip != arguments['exporter_ip']:
                return False
        if arguments.get('src_ip'):
            if flow.src_ip != arguments['src_ip']:
                return False
        if arguments.get('dst_ip'):
            if flow.dst_ip != arguments['dst_ip']:
                return False
        if arguments.get('src_port'):
            if flow.src_port != arguments['src_port']:
                return False
        if arguments.get('dst_port'):
            if flow.dst_port != arguments['dst_port']:
                return False
        if arguments.get('protocol'):
            if flow.protocol != arguments['protocol']:
                return False
        if arguments.get('version'):
            if flow.version != arguments['version']:
                return False
        if arguments.get('min_bytes'):
            if flow.bytes is None or flow.bytes < arguments['min_bytes']:
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
    total, flows = message_store.query(
        filter_func=flow_filter,
        start_time=start_time,
        end_time=end_time,
        limit=arguments.get('limit', 100),
        offset=arguments.get('offset', 0)
    )

    result = {
        'total': total,
        'returned': len(flows),
        'flows': [flow.to_display_dict() for flow in flows]
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_get_flow(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get a specific flow by ID."""
    import json

    if not message_store:
        return [TextContent(type="text", text="Receiver not started")]

    flow_id = arguments.get('flow_id')
    if not flow_id:
        return [TextContent(type="text", text="flow_id is required")]

    flow = message_store.get(flow_id)
    if not flow:
        return [TextContent(type="text", text=f"Flow not found: {flow_id}")]

    result = flow.model_dump(mode='json', exclude={'raw_data'})
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_top_talkers(arguments: Dict[str, Any]) -> List[TextContent]:
    """Get top talkers by bytes."""
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

    limit = arguments.get('limit', 10)

    # Aggregate flows
    by_src: Dict[str, Dict[str, int]] = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'flows': 0})
    by_dst: Dict[str, Dict[str, int]] = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'flows': 0})
    by_proto: Dict[str, int] = defaultdict(int)
    total_bytes = 0
    total_flows = 0

    def time_filter(flow: FlowRecord) -> bool:
        if start_time and flow.received_at < start_time:
            return False
        if end_time and flow.received_at > end_time:
            return False
        return True

    for msg_id, (ts, flow) in message_store.messages.items():
        if time_filter(flow):
            total_flows += 1

            if flow.src_ip:
                by_src[flow.src_ip]['bytes'] += flow.bytes or 0
                by_src[flow.src_ip]['packets'] += flow.packets or 0
                by_src[flow.src_ip]['flows'] += 1

            if flow.dst_ip:
                by_dst[flow.dst_ip]['bytes'] += flow.bytes or 0
                by_dst[flow.dst_ip]['packets'] += flow.packets or 0
                by_dst[flow.dst_ip]['flows'] += 1

            if flow.protocol:
                proto_name = PROTOCOL_NAMES.get(flow.protocol, f"proto-{flow.protocol}")
                by_proto[proto_name] += flow.bytes or 0

            total_bytes += flow.bytes or 0

    # Sort and limit
    top_src = sorted(by_src.items(), key=lambda x: x[1]['bytes'], reverse=True)[:limit]
    top_dst = sorted(by_dst.items(), key=lambda x: x[1]['bytes'], reverse=True)[:limit]

    result = {
        'time_range': {
            'start': start_time.isoformat() if start_time else None,
            'end': end_time.isoformat() if end_time else None
        },
        'by_source': [
            {'ip': ip, 'bytes': stats['bytes'], 'packets': stats['packets'], 'flows': stats['flows']}
            for ip, stats in top_src
        ],
        'by_destination': [
            {'ip': ip, 'bytes': stats['bytes'], 'packets': stats['packets'], 'flows': stats['flows']}
            for ip, stats in top_dst
        ],
        'by_protocol': dict(sorted(by_proto.items(), key=lambda x: x[1], reverse=True)),
        'total_bytes': total_bytes,
        'total_flows': total_flows
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def handle_get_templates() -> List[TextContent]:
    """List cached templates."""
    import json

    cache = get_template_cache()
    templates = cache.get_all()

    result = {
        'count': len(templates),
        'templates': [
            {
                'template_id': t.template_id,
                'exporter_ip': t.exporter_ip,
                'field_count': t.field_count,
                'received_at': t.received_at.isoformat(),
                'last_used': t.last_used.isoformat()
            }
            for t in templates
        ]
    }

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
