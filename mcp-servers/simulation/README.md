# GNS3 MCP Server

MCP server for managing GNS3 network lab environments. Provides natural language control over GNS3 projects, nodes, links, packet captures, and snapshots.

## Features

- **Project Lifecycle**: Create, open, close, delete, clone, export/import GNS3 projects
- **Node Operations**: Add nodes from templates, start/stop/suspend/reload, access consoles
- **Link Management**: Create and delete links between node interfaces, isolate nodes
- **Packet Capture**: Start/stop captures on links, retrieve PCAP data
- **Snapshot Management**: Create, restore, and delete project snapshots

## Prerequisites

- GNS3 Server 2.2.0+ with REST API v3 enabled
- Python 3.10+
- Valid GNS3 user credentials

## Installation

```bash
# Navigate to the server directory
cd mcp-servers/gns3-mcp-server

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your GNS3 server details
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GNS3_URL` | Yes | - | GNS3 server URL (e.g., `http://localhost:3080`) |
| `GNS3_USER` | Yes | - | Username for authentication |
| `GNS3_PASSWORD` | Yes | - | Password for authentication |
| `GNS3_VERIFY_SSL` | No | `true` | Verify SSL certificates |
| `GNS3_TOKEN_TTL` | No | `3000` | Token cache TTL in seconds |

## Usage

### As MCP Server (stdio transport)

```bash
python3 -u gns3_mcp_server.py
```

### Register in OpenClaw

Add to `config/openclaw.json`:

```json
{
  "mcpServers": {
    "gns3": {
      "command": "python3",
      "args": ["-u", "mcp-servers/gns3-mcp-server/gns3_mcp_server.py"],
      "env": {
        "GNS3_URL": "${GNS3_URL}",
        "GNS3_USER": "${GNS3_USER}",
        "GNS3_PASSWORD": "${GNS3_PASSWORD}"
      }
    }
  }
}
```

## Available Tools

### Project Lifecycle (9 tools)
- `gns3_list_projects` - List all GNS3 projects
- `gns3_create_project` - Create a new project
- `gns3_get_project` - Get project details
- `gns3_open_project` - Open a closed project
- `gns3_close_project` - Close an opened project
- `gns3_delete_project` - Delete a project
- `gns3_clone_project` - Clone an existing project
- `gns3_export_project` - Export project as archive
- `gns3_import_project` - Import project from archive

### Node Operations (8 tools)
- `gns3_list_nodes` - List nodes in a project
- `gns3_create_node` - Create node from template
- `gns3_start_node` - Start a node
- `gns3_stop_node` - Stop a node
- `gns3_suspend_node` - Suspend a node
- `gns3_reload_node` - Reload a node
- `gns3_bulk_node_action` - Apply action to all nodes
- `gns3_get_node_console` - Get console connection info

### Link Management (4 tools)
- `gns3_list_links` - List links in a project
- `gns3_create_link` - Create link between nodes
- `gns3_delete_link` - Delete a link
- `gns3_isolate_node` - Isolate/unisolate a node

### Packet Capture (3 tools)
- `gns3_start_capture` - Start packet capture on link
- `gns3_stop_capture` - Stop packet capture
- `gns3_get_capture` - Get capture file info

### Snapshot Operations (4 tools)
- `gns3_list_snapshots` - List project snapshots
- `gns3_create_snapshot` - Create a snapshot
- `gns3_restore_snapshot` - Restore to snapshot
- `gns3_delete_snapshot` - Delete a snapshot

### Utility Tools (2 tools)
- `gns3_list_templates` - List available node templates
- `gns3_list_computes` - List compute servers

## Example Commands

```
"List all my GNS3 labs"
"Create a new GNS3 lab called routing-test"
"Add a Cisco IOSv router to routing-test"
"Connect router1 eth0 to switch1 eth0"
"Start all nodes in routing-test"
"Start capturing traffic on the link between router1 and router2"
"Create a snapshot called baseline for routing-test"
```

## Error Codes

| Code | Description |
|------|-------------|
| `GNS3_NOT_FOUND` | Resource not found |
| `GNS3_CONFLICT` | Resource conflict (locked, exists) |
| `GNS3_VALIDATION` | Invalid parameters |
| `GNS3_FORBIDDEN` | Insufficient privileges |
| `GNS3_AUTH_FAILED` | Authentication failed |
| `GNS3_SERVER_ERROR` | GNS3 server error |
| `GNS3_UNREACHABLE` | Server unreachable |

## Related Skills

- `gns3-project-lifecycle` - Project management operations
- `gns3-node-operations` - Node lifecycle and console access
- `gns3-link-management` - Topology building
- `gns3-packet-capture` - Traffic capture and analysis
- `gns3-snapshot-ops` - State management

## License

Part of the NetClaw project.
