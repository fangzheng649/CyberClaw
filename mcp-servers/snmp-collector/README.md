# SNMP Trap MCP Server

An MCP server that receives and queries SNMP traps over UDP, supporting SNMPv1, SNMPv2c, and SNMPv3.

## Features

- **UDP Receiver**: Listens on configurable port (default: 162) for SNMP traps
- **SNMPv1 Support**: Legacy trap format with enterprise OID and generic/specific trap types
- **SNMPv2c Support**: TRAP-PDU parsing with community string authentication
- **SNMPv3 Support**: USM-based authentication (requires configuration)
- **In-Memory Storage**: Configurable retention period with automatic cleanup
- **Deduplication**: Hash-based duplicate detection within configurable time window
- **Rate Limiting**: Token bucket algorithm to prevent overload
- **Query Interface**: Filter traps by time, source, version, or OID
- **GAIT Logging**: Audit trail for all received traps

## Installation

```bash
cd mcp-servers/snmptrap-mcp
pip install -r requirements.txt
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SNMPTRAP_PORT` | `162` | UDP port to listen on |
| `SNMPTRAP_BIND_ADDRESS` | `0.0.0.0` | Address to bind to |
| `SNMPTRAP_RETENTION_HOURS` | `24` | How long to retain traps |
| `SNMPTRAP_RATE_LIMIT` | `1000` | Traps per second limit |
| `SNMPTRAP_DEDUP_WINDOW` | `5` | Deduplication window in seconds |

## Running

### Standalone

```bash
python -m snmptrap_mcp_server
```

### With Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "snmptrap-mcp": {
      "command": "python",
      "args": ["-m", "snmptrap_mcp_server"],
      "cwd": "/path/to/mcp-servers/snmptrap-mcp",
      "env": {
        "SNMPTRAP_PORT": "10162"
      }
    }
  }
}
```

## MCP Tools

### snmptrap_start_receiver

Start the SNMP trap UDP receiver.

**Parameters:**
- `port` (optional): UDP port to listen on (default: 162)
- `bind_address` (optional): Address to bind to (default: 0.0.0.0)

**Example:**
```json
{"port": 10162, "bind_address": "0.0.0.0"}
```

### snmptrap_stop_receiver

Stop the SNMP trap receiver.

**Parameters:** None

### snmptrap_get_status

Get receiver status including trap counts and version breakdown.

**Returns:**
```json
{
  "receiver_type": "snmptrap",
  "port": 162,
  "is_running": true,
  "traps_received": 456,
  "traps_deduplicated": 12,
  "by_version": {
    "v1": 23,
    "v2c": 421,
    "v3": 12
  }
}
```

### snmptrap_query

Query SNMP traps with filters.

**Parameters:**
- `start_time` (optional): ISO 8601 datetime
- `end_time` (optional): ISO 8601 datetime
- `source_ip` (optional): Source IP address
- `version` (optional): SNMP version ("v1", "v2c", "v3")
- `trap_oid` (optional): Exact trap OID match
- `trap_oid_prefix` (optional): Match OIDs starting with this prefix
- `limit` (optional): Max results (default: 100, max: 1000)
- `offset` (optional): Pagination offset

**Example:**
```json
{
  "version": "v2c",
  "trap_oid_prefix": "1.3.6.1.6.3.1.1.5",
  "limit": 50
}
```

### snmptrap_get_trap

Get full details of a specific trap by ID, including all variable bindings.

**Parameters:**
- `trap_id` (required): UUID of the trap

### snmptrap_get_counts

Get trap counts grouped by type and source.

**Parameters:**
- `start_time` (optional): ISO 8601 datetime
- `end_time` (optional): ISO 8601 datetime

**Returns:**
```json
{
  "time_range": {"start": null, "end": null},
  "by_type": [
    {"trap_type": "linkDown", "trap_oid": "1.3.6.1.6.3.1.1.5.3", "count": 45},
    {"trap_type": "linkUp", "trap_oid": "1.3.6.1.6.3.1.1.5.4", "count": 42}
  ],
  "by_source": {
    "192.168.1.1": 50,
    "192.168.1.2": 37
  },
  "total": 87
}
```

## Standard Trap OIDs

| OID | Name | Description |
|-----|------|-------------|
| 1.3.6.1.6.3.1.1.5.1 | coldStart | Agent reinitializing |
| 1.3.6.1.6.3.1.1.5.2 | warmStart | Agent reinitializing (config unchanged) |
| 1.3.6.1.6.3.1.1.5.3 | linkDown | Interface went down |
| 1.3.6.1.6.3.1.1.5.4 | linkUp | Interface came up |
| 1.3.6.1.6.3.1.1.5.5 | authenticationFailure | SNMP auth failed |

## Testing with Cisco Devices

Configure your Cisco Catalyst 9300 to send SNMP traps:

### SNMPv2c

```
snmp-server community public RO
snmp-server enable traps
snmp-server host 10.0.0.1 version 2c public
```

### SNMPv3

```
snmp-server group NETCLAW v3 priv
snmp-server user netclaw NETCLAW v3 auth sha AuthPass priv aes 128 PrivPass
snmp-server host 10.0.0.1 version 3 priv netclaw
snmp-server enable traps
```

## Remote Testing with UDP Tunnels

Since ngrok doesn't support UDP, use alternatives:

- **Pinggy**: `ssh -R 0:localhost:162 a.pinggy.io`
- **Tailscale**: Peer-to-peer mesh VPN
- **LocalXpose**: UDP tunnel support available

## Sending Test Traps

Using `snmptrap` command (from net-snmp):

```bash
# SNMPv2c linkDown trap
snmptrap -v 2c -c public localhost:162 '' 1.3.6.1.6.3.1.1.5.3 \
    1.3.6.1.2.1.2.2.1.1.1 i 1 \
    1.3.6.1.2.1.2.2.1.2.1 s "GigabitEthernet1/0/1"
```

## License

Part of the NetClaw project.
