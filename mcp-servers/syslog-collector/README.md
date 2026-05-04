# Syslog MCP Server

An MCP server that receives and queries syslog messages over UDP, supporting both RFC 5424 and RFC 3164 formats.

## Features

- **UDP Receiver**: Listens on configurable port (default: 514) for syslog messages
- **RFC 5424 Support**: Full parsing of modern syslog format including structured data
- **RFC 3164 Support**: Fallback parsing for BSD-style and Cisco-style syslog
- **In-Memory Storage**: Configurable retention period with automatic cleanup
- **Deduplication**: Hash-based duplicate detection within configurable time window
- **Rate Limiting**: Token bucket algorithm to prevent overload
- **Query Interface**: Filter messages by time, severity, facility, hostname, or content
- **GAIT Logging**: Audit trail for all received messages

## Installation

```bash
cd mcp-servers/syslog-mcp
pip install -r requirements.txt
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_PORT` | `514` | UDP port to listen on |
| `SYSLOG_BIND_ADDRESS` | `0.0.0.0` | Address to bind to |
| `SYSLOG_RETENTION_HOURS` | `24` | How long to retain messages |
| `SYSLOG_RATE_LIMIT` | `1000` | Messages per second limit |
| `SYSLOG_DEDUP_WINDOW` | `5` | Deduplication window in seconds |

## Running

### Standalone

```bash
python -m syslog_mcp_server
```

### With Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "syslog-mcp": {
      "command": "python",
      "args": ["-m", "syslog_mcp_server"],
      "cwd": "/path/to/mcp-servers/syslog-mcp",
      "env": {
        "SYSLOG_PORT": "10514"
      }
    }
  }
}
```

## MCP Tools

### syslog_start_receiver

Start the syslog UDP receiver.

**Parameters:**
- `port` (optional): UDP port to listen on (default: 514)
- `bind_address` (optional): Address to bind to (default: 0.0.0.0)

**Example:**
```json
{"port": 10514, "bind_address": "0.0.0.0"}
```

### syslog_stop_receiver

Stop the syslog receiver.

**Parameters:** None

### syslog_get_status

Get receiver status including message counts and uptime.

**Returns:**
```json
{
  "receiver_type": "syslog",
  "port": 514,
  "is_running": true,
  "messages_received": 1234,
  "messages_deduplicated": 56,
  "errors": 0,
  "rate_limited_count": 0
}
```

### syslog_query

Query syslog messages with filters.

**Parameters:**
- `start_time` (optional): ISO 8601 datetime
- `end_time` (optional): ISO 8601 datetime
- `severity_min` (optional): Minimum severity (0=Emergency, 7=Debug)
- `severity_max` (optional): Maximum severity
- `facility` (optional): Facility code (0-23)
- `hostname` (optional): Exact hostname match
- `source_ip` (optional): Source IP address
- `message_contains` (optional): Substring search (case-insensitive)
- `limit` (optional): Max results (default: 100, max: 1000)
- `offset` (optional): Pagination offset

**Example:**
```json
{
  "severity_max": 3,
  "message_contains": "interface",
  "limit": 50
}
```

### syslog_get_message

Get full details of a specific message by ID.

**Parameters:**
- `message_id` (required): UUID of the message

### syslog_get_severity_counts

Get message counts grouped by severity level.

**Parameters:**
- `start_time` (optional): ISO 8601 datetime
- `end_time` (optional): ISO 8601 datetime

**Returns:**
```json
{
  "time_range": {"start": null, "end": null},
  "counts": {
    "EMERGENCY": 0,
    "ALERT": 0,
    "CRITICAL": 2,
    "ERROR": 15,
    "WARNING": 45,
    "NOTICE": 123,
    "INFO": 500,
    "DEBUG": 0
  },
  "total": 685
}
```

## Severity Levels

| Code | Name | Description |
|------|------|-------------|
| 0 | EMERGENCY | System is unusable |
| 1 | ALERT | Action must be taken immediately |
| 2 | CRITICAL | Critical conditions |
| 3 | ERROR | Error conditions |
| 4 | WARNING | Warning conditions |
| 5 | NOTICE | Normal but significant |
| 6 | INFO | Informational |
| 7 | DEBUG | Debug-level messages |

## Facility Codes

| Code | Name | Code | Name |
|------|------|------|------|
| 0 | KERN | 12 | NTP |
| 1 | USER | 13 | AUDIT |
| 2 | MAIL | 14 | ALERT |
| 3 | DAEMON | 15 | CLOCK |
| 4 | AUTH | 16 | LOCAL0 |
| 5 | SYSLOG | 17 | LOCAL1 |
| 6 | LPR | 18 | LOCAL2 |
| 7 | NEWS | 19 | LOCAL3 |
| 8 | UUCP | 20 | LOCAL4 |
| 9 | CRON | 21 | LOCAL5 |
| 10 | AUTHPRIV | 22 | LOCAL6 |
| 11 | FTP | 23 | LOCAL7 |

## Testing with Cisco Devices

Configure your Cisco Catalyst 9300 to send syslog:

```
logging host 10.0.0.1 transport udp port 514
logging trap informational
logging source-interface Loopback0
```

## Remote Testing with UDP Tunnels

Since ngrok doesn't support UDP, use alternatives:

- **Pinggy**: `ssh -R 0:localhost:514 a.pinggy.io`
- **Tailscale**: Peer-to-peer mesh VPN
- **LocalXpose**: UDP tunnel support available

## License

Part of the NetClaw project.
