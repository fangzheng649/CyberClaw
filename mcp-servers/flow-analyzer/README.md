# IPFIX/NetFlow MCP Server

An MCP server that receives and queries IPFIX and NetFlow flow records over UDP.

## Features

- **UDP Receiver**: Listens on configurable port (default: 2055) for flow exports
- **NetFlow v5 Support**: Fixed-format legacy NetFlow parsing
- **NetFlow v9 Support**: Template-based flow parsing with automatic template caching
- **IPFIX Support**: RFC 7011 compliant flow parsing (version 10)
- **Template Caching**: Automatic template management with 30-minute expiration
- **In-Memory Storage**: Configurable retention period with automatic cleanup
- **Deduplication**: Hash-based duplicate detection within configurable time window
- **Rate Limiting**: Token bucket algorithm to handle high flow volumes
- **Query Interface**: Filter flows by IPs, ports, protocol, exporter, or time
- **Top Talkers**: Identify highest bandwidth consumers
- **GAIT Logging**: Audit trail for received flows (sampled)

## Installation

```bash
cd mcp-servers/ipfix-mcp
pip install -r requirements.txt
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `IPFIX_PORT` | `2055` | UDP port to listen on |
| `IPFIX_BIND_ADDRESS` | `0.0.0.0` | Address to bind to |
| `IPFIX_RETENTION_HOURS` | `24` | How long to retain flows |
| `IPFIX_RATE_LIMIT` | `10000` | Flows per second limit |
| `IPFIX_DEDUP_WINDOW` | `5` | Deduplication window in seconds |

## Running

### Standalone

```bash
python -m ipfix_mcp_server
```

### With Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "ipfix-mcp": {
      "command": "python",
      "args": ["-m", "ipfix_mcp_server"],
      "cwd": "/path/to/mcp-servers/ipfix-mcp",
      "env": {
        "IPFIX_PORT": "9995"
      }
    }
  }
}
```

## MCP Tools

### ipfix_start_receiver

Start the IPFIX/NetFlow UDP receiver.

**Parameters:**
- `port` (optional): UDP port to listen on (default: 2055)
- `bind_address` (optional): Address to bind to (default: 0.0.0.0)

### ipfix_stop_receiver

Stop the flow receiver.

**Parameters:** None

### ipfix_get_status

Get receiver status including flow counts, version breakdown, and template info.

**Returns:**
```json
{
  "receiver_type": "ipfix",
  "port": 2055,
  "is_running": true,
  "flows_received": 12345,
  "packets_received": 456,
  "by_version": {
    "netflow_v5": 1000,
    "netflow_v9": 5000,
    "ipfix": 6345
  },
  "templates": {
    "received": 12,
    "active": 8
  }
}
```

### ipfix_query_flows

Query flow records with filters.

**Parameters:**
- `start_time` (optional): ISO 8601 datetime
- `end_time` (optional): ISO 8601 datetime
- `exporter_ip` (optional): Exporter IP address
- `src_ip` (optional): Source IP address
- `dst_ip` (optional): Destination IP address
- `src_port` (optional): Source port
- `dst_port` (optional): Destination port
- `protocol` (optional): IP protocol number (6=TCP, 17=UDP)
- `version` (optional): Flow version (5, 9, 10)
- `min_bytes` (optional): Minimum byte count filter
- `limit` (optional): Max results (default: 100, max: 1000)
- `offset` (optional): Pagination offset

**Example:**
```json
{
  "protocol": 6,
  "min_bytes": 1000000,
  "limit": 50
}
```

### ipfix_get_flow

Get full details of a specific flow by ID.

**Parameters:**
- `flow_id` (required): UUID of the flow

### ipfix_top_talkers

Get top bandwidth consumers grouped by source, destination, and protocol.

**Parameters:**
- `start_time` (optional): ISO 8601 datetime
- `end_time` (optional): ISO 8601 datetime
- `limit` (optional): Number of top entries (default: 10)

**Returns:**
```json
{
  "by_source": [
    {"ip": "192.168.1.100", "bytes": 5000000, "packets": 3500, "flows": 45}
  ],
  "by_destination": [
    {"ip": "10.0.0.50", "bytes": 4500000, "packets": 3000, "flows": 40}
  ],
  "by_protocol": {
    "TCP": 8000000,
    "UDP": 1500000
  },
  "total_bytes": 9500000,
  "total_flows": 85
}
```

### ipfix_get_templates

List cached IPFIX/NetFlow v9 templates.

**Returns:**
```json
{
  "count": 3,
  "templates": [
    {
      "template_id": 256,
      "exporter_ip": "192.168.1.1",
      "field_count": 15,
      "received_at": "2024-03-28T10:00:00",
      "last_used": "2024-03-28T10:05:00"
    }
  ]
}
```

## Protocol Numbers

| Number | Name | Description |
|--------|------|-------------|
| 1 | ICMP | Internet Control Message Protocol |
| 6 | TCP | Transmission Control Protocol |
| 17 | UDP | User Datagram Protocol |
| 47 | GRE | Generic Routing Encapsulation |
| 50 | ESP | Encapsulating Security Payload |
| 58 | ICMPv6 | ICMP for IPv6 |

## Testing with Cisco Devices

Configure your Cisco Catalyst 9300 for Flexible NetFlow with IPFIX export:

```
! Define flow record
flow record NETCLAW-RECORD
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 match ipv4 protocol
 collect counter bytes
 collect counter packets

! Define exporter
flow exporter NETCLAW-EXPORTER
 destination 10.0.0.1
 transport udp 2055
 export-protocol ipfix
 template data timeout 300

! Define monitor
flow monitor NETCLAW-MONITOR
 record NETCLAW-RECORD
 exporter NETCLAW-EXPORTER

! Apply to interface
interface GigabitEthernet1/0/1
 ip flow monitor NETCLAW-MONITOR input
 ip flow monitor NETCLAW-MONITOR output
```

## Remote Testing with UDP Tunnels

Since ngrok doesn't support UDP, use alternatives:

- **Pinggy**: `ssh -R 0:localhost:2055 a.pinggy.io`
- **Tailscale**: Peer-to-peer mesh VPN
- **LocalXpose**: UDP tunnel support available

## Sending Test Flows

Using `softflowd` to generate test flows:

```bash
# Generate flows from captured traffic
softflowd -i eth0 -n localhost:2055 -v 9
```

## License

Part of the NetClaw project.
