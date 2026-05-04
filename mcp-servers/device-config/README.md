# gNMI Streaming Telemetry MCP Server

A FastMCP server providing gNMI (gRPC Network Management Interface) operations as MCP tools for NetClaw. Supports multi-vendor devices (Cisco IOS-XR, Juniper, Arista, Nokia SR OS) through OpenConfig and vendor-native YANG models.

## Tools (10)

| # | Tool | Description | Safety |
|---|------|-------------|--------|
| 1 | `gnmi_get` | Retrieve device state/config via gNMI Get using YANG paths | Read-only |
| 2 | `gnmi_set` | Apply config changes via gNMI Set (ITSM-gated) | Write — requires ServiceNow CR |
| 3 | `gnmi_subscribe` | Create streaming telemetry subscription | Read-only |
| 4 | `gnmi_unsubscribe` | Cancel an active subscription | N/A |
| 5 | `gnmi_get_subscriptions` | List all active subscriptions | Read-only |
| 6 | `gnmi_get_subscription_updates` | Get latest updates from a subscription | Read-only |
| 7 | `gnmi_capabilities` | Retrieve YANG models and encodings from device | Read-only |
| 8 | `gnmi_browse_yang_paths` | Browse YANG paths under a module | Read-only |
| 9 | `gnmi_compare_with_cli` | Compare gNMI state vs CLI state (pyATS) | Read-only |
| 10 | `gnmi_list_targets` | List configured target devices | Read-only |

## Transport

**stdio** — FastMCP over standard input/output (JSON-RPC).

## Vendor Support

| Vendor | Default Port | Default Encoding | ON_CHANGE |
|--------|-------------|-------------------|-----------|
| Cisco IOS-XR | 57400 | JSON_IETF | Yes |
| Juniper | 32767 | JSON_IETF | Yes |
| Arista | 6030 | JSON | Yes |
| Nokia SR OS | 57400 | JSON_IETF | Yes |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GNMI_TARGETS` | Yes | JSON array of target device definitions |
| `GNMI_TLS_CA_CERT` | No | Global CA certificate path |
| `GNMI_TLS_CLIENT_CERT` | No | Global client certificate (mTLS) |
| `GNMI_TLS_CLIENT_KEY` | No | Global client private key (mTLS) |
| `GNMI_TLS_SKIP_VERIFY` | No | Skip TLS verification (lab mode only) |
| `GNMI_DEFAULT_PORT` | No | Override default gNMI port |
| `GNMI_MAX_RESPONSE_SIZE` | No | Response truncation threshold in bytes (default 1MB) |
| `GNMI_MAX_SUBSCRIPTIONS` | No | Max concurrent subscriptions (default 50) |

### GNMI_TARGETS Format

```json
[
  {
    "name": "router1",
    "host": "10.1.1.1",
    "port": 57400,
    "username": "admin",
    "password": "changeme",
    "vendor": "cisco-iosxr",
    "tls_ca_cert": "/certs/ca.pem"
  },
  {
    "name": "switch1",
    "host": "10.1.2.1",
    "port": 6030,
    "username": "admin",
    "password": "changeme",
    "vendor": "arista",
    "tls_skip_verify": true
  }
]
```

## Installation

```bash
cd mcp-servers/gnmi-mcp
pip install -r requirements.txt
```

## Usage

```bash
# Run directly (stdio transport)
python gnmi_mcp_server.py

# Docker
docker build -t gnmi-mcp .
docker run --env-file .env gnmi-mcp
```

## Security

- TLS is mandatory for all device connections
- mTLS is supported when client cert/key are provided
- `tls_skip_verify` is for lab environments only
- gNMI Set requires an approved ServiceNow Change Request (ITSM gate)
- Credentials are never logged or included in error messages
- All operations are logged to the GAIT audit trail

## Dependencies

- fastmcp (MCP framework)
- grpcio / grpcio-tools (gRPC transport)
- pygnmi (gNMI client)
- protobuf (protocol buffers)
- cryptography (TLS handling)
- pydantic (data models)
