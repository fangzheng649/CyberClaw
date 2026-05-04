#!/usr/bin/env python3
"""
GNS3 MCP Server - Network lab management via Model Context Protocol.

Provides tools for managing GNS3 projects, nodes, links, packet captures,
and snapshots through natural language commands.
"""

import json
import os
import sys
import time
import logging
import re
from functools import wraps
from typing import Optional, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging to stderr (stdout reserved for MCP protocol)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("gns3-mcp")

# Import FastMCP and httpx
try:
    from fastmcp import FastMCP
    import httpx
except ImportError as e:
    logger.error(f"Missing required dependency: {e}")
    logger.error("Install with: pip install fastmcp httpx python-dotenv")
    sys.exit(1)

# =============================================================================
# Configuration
# =============================================================================

GNS3_URL = os.getenv("GNS3_URL", "http://localhost:3080")
GNS3_USER = os.getenv("GNS3_USER", "")
GNS3_PASSWORD = os.getenv("GNS3_PASSWORD", "")
GNS3_VERIFY_SSL = os.getenv("GNS3_VERIFY_SSL", "true").lower() == "true"
GNS3_TOKEN_TTL = int(os.getenv("GNS3_TOKEN_TTL", "3000"))  # 50 minutes default

# =============================================================================
# GNS3 Client with Authentication
# =============================================================================

class GNS3Client:
    """HTTP client for GNS3 REST API v3 with token caching."""

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True, token_ttl: int = 3000):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token_ttl = token_ttl
        self._token: Optional[str] = None
        self._token_expires: float = 0
        self._client = httpx.Client(verify=verify_ssl, timeout=30.0)

    def _authenticate(self) -> str:
        """Authenticate and cache bearer token."""
        if self._token and time.time() < self._token_expires:
            return self._token

        logger.info("Authenticating with GNS3 server...")
        response = self._client.post(
            f"{self.base_url}/v3/access/users/authenticate",
            json={"username": self.username, "password": self.password}
        )

        if response.status_code != 200:
            raise GNS3Error("GNS3_AUTH_FAILED", "Authentication failed", response.status_code)

        data = response.json()
        self._token = data.get("access_token")
        self._token_expires = time.time() + self.token_ttl
        logger.info("Authentication successful, token cached")
        return self._token

    def _headers(self) -> dict:
        """Get headers with bearer token."""
        token = self._authenticate()
        return {"Authorization": f"Bearer {token}"}

    def request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Make authenticated request to GNS3 API."""
        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault("headers", {}).update(self._headers())

        try:
            response = self._client.request(method, url, **kwargs)
            return response
        except httpx.ConnectError:
            raise GNS3Error("GNS3_UNREACHABLE", f"Cannot connect to GNS3 server at {self.base_url}", 503)
        except httpx.TimeoutException:
            raise GNS3Error("GNS3_UNREACHABLE", "Request to GNS3 server timed out", 503)

    def get(self, endpoint: str, **kwargs) -> httpx.Response:
        return self.request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs) -> httpx.Response:
        return self.request("POST", endpoint, **kwargs)

    def put(self, endpoint: str, **kwargs) -> httpx.Response:
        return self.request("PUT", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", endpoint, **kwargs)


# =============================================================================
# Error Handling
# =============================================================================

class GNS3Error(Exception):
    """GNS3 API error with structured response."""

    def __init__(self, error_code: str, message: str, status_code: int = 500):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        super().__init__(message)

    def to_dict(self) -> dict:
        return {
            "success": False,
            "error": self.message,
            "error_code": self.error_code,
            "status_code": self.status_code
        }


def handle_gns3_response(response: httpx.Response, success_codes: list = None) -> dict:
    """Convert GNS3 API response to structured format."""
    success_codes = success_codes or [200, 201, 204]

    if response.status_code in success_codes:
        if response.status_code == 204 or not response.content:
            return {"success": True}
        return response.json()

    # Map HTTP status to GNS3 error codes
    error_map = {
        400: "GNS3_VALIDATION",
        401: "GNS3_AUTH_FAILED",
        403: "GNS3_FORBIDDEN",
        404: "GNS3_NOT_FOUND",
        409: "GNS3_CONFLICT",
        422: "GNS3_VALIDATION",
        500: "GNS3_SERVER_ERROR",
        503: "GNS3_UNREACHABLE"
    }

    error_code = error_map.get(response.status_code, "GNS3_SERVER_ERROR")

    try:
        error_detail = response.json()
        message = error_detail.get("message", error_detail.get("detail", str(error_detail)))
    except Exception:
        message = response.text or f"HTTP {response.status_code}"

    raise GNS3Error(error_code, message, response.status_code)


def success_response(data: Any = None, message: str = None, count: int = None) -> str:
    """Create standardized success response."""
    result = {"success": True}
    if data is not None:
        result["data"] = data
    if message:
        result["message"] = message
    if count is not None:
        result["count"] = count
    return json.dumps(result, indent=2)


def error_response(error: Exception) -> str:
    """Create standardized error response."""
    if isinstance(error, GNS3Error):
        return json.dumps(error.to_dict(), indent=2)
    return json.dumps({
        "success": False,
        "error": str(error),
        "error_code": "GNS3_SERVER_ERROR",
        "status_code": 500
    }, indent=2)


# =============================================================================
# GAIT Audit Logging Decorator
# =============================================================================

def with_gait_logging(operation: str):
    """Decorator to log operations to GAIT audit trail."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"GAIT: Starting {operation}")
            try:
                result = func(*args, **kwargs)
                logger.info(f"GAIT: Completed {operation} successfully")
                return result
            except Exception as e:
                logger.error(f"GAIT: Failed {operation}: {str(e)}")
                raise
        return wrapper
    return decorator


# =============================================================================
# Name-to-UUID Resolution Helpers
# =============================================================================

def resolve_project_id(client: GNS3Client, project_identifier: str) -> str:
    """Resolve project name or ID to UUID."""
    # If it looks like a UUID, use it directly
    if _is_uuid(project_identifier):
        return project_identifier

    # Otherwise, search by name
    response = client.get("/v3/projects")
    projects = handle_gns3_response(response)

    for project in projects:
        if project.get("name", "").lower() == project_identifier.lower():
            return project["project_id"]

    raise GNS3Error("GNS3_NOT_FOUND", f"Project not found: {project_identifier}", 404)


def resolve_node_id(client: GNS3Client, project_id: str, node_identifier: str) -> str:
    """Resolve node name or ID to UUID."""
    if _is_uuid(node_identifier):
        return node_identifier

    response = client.get(f"/v3/projects/{project_id}/nodes")
    nodes = handle_gns3_response(response)

    for node in nodes:
        if node.get("name", "").lower() == node_identifier.lower():
            return node["node_id"]

    raise GNS3Error("GNS3_NOT_FOUND", f"Node not found: {node_identifier}", 404)


def resolve_snapshot_id(client: GNS3Client, project_id: str, snapshot_identifier: str) -> str:
    """Resolve snapshot name or ID to UUID."""
    if _is_uuid(snapshot_identifier):
        return snapshot_identifier

    response = client.get(f"/v3/projects/{project_id}/snapshots")
    snapshots = handle_gns3_response(response)

    for snapshot in snapshots:
        if snapshot.get("name", "").lower() == snapshot_identifier.lower():
            return snapshot["snapshot_id"]

    raise GNS3Error("GNS3_NOT_FOUND", f"Snapshot not found: {snapshot_identifier}", 404)


def resolve_template_id(client: GNS3Client, template_identifier: str) -> tuple:
    """Resolve template name or ID to (UUID, name). Supports fuzzy matching."""
    if _is_uuid(template_identifier):
        response = client.get(f"/v3/templates/{template_identifier}")
        template = handle_gns3_response(response)
        return template["template_id"], template["name"]

    response = client.get("/v3/templates")
    templates = handle_gns3_response(response)

    # Exact match first
    for template in templates:
        if template.get("name", "").lower() == template_identifier.lower():
            return template["template_id"], template["name"]

    # Fuzzy match (contains)
    search_lower = template_identifier.lower()
    for template in templates:
        if search_lower in template.get("name", "").lower():
            return template["template_id"], template["name"]

    raise GNS3Error("GNS3_NOT_FOUND", f"Template not found: {template_identifier}", 404)


def _is_uuid(s: str) -> bool:
    """Check if string looks like a UUID."""
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    return bool(uuid_pattern.match(s))


# =============================================================================
# Interface Name Parsing
# =============================================================================

def parse_interface(interface_str: str) -> tuple:
    """
    Parse interface string to (adapter_number, port_number).

    Supports formats:
    - eth0, eth1, ... -> (0, 0), (0, 1), ...
    - Ethernet0, Ethernet1 -> (0, 0), (0, 1)
    - Gi0/0, Gi0/1 -> (0, 0), (0, 1)
    - GigabitEthernet0/0 -> (0, 0)
    - e0, e1 -> (0, 0), (0, 1)
    - 0/0, 0/1 -> (0, 0), (0, 1)
    """
    iface = interface_str.strip().lower()

    # Pattern: eth0, e0, ethernet0
    match = re.match(r'^(?:eth|e|ethernet)(\d+)$', iface)
    if match:
        return 0, int(match.group(1))

    # Pattern: Gi0/0, GigabitEthernet0/0
    match = re.match(r'^(?:gi|gigabitethernet|fa|fastethernet|te|tengigabitethernet)(\d+)/(\d+)$', iface)
    if match:
        return int(match.group(1)), int(match.group(2))

    # Pattern: 0/0
    match = re.match(r'^(\d+)/(\d+)$', iface)
    if match:
        return int(match.group(1)), int(match.group(2))

    # Pattern: port0, p0
    match = re.match(r'^(?:port|p)(\d+)$', iface)
    if match:
        return 0, int(match.group(1))

    raise GNS3Error("GNS3_VALIDATION", f"Cannot parse interface: {interface_str}", 422)


# =============================================================================
# Initialize FastMCP and Client
# =============================================================================

mcp = FastMCP("GNS3 MCP Server")
client: Optional[GNS3Client] = None


def get_client() -> GNS3Client:
    """Get or create GNS3 client."""
    global client
    if client is None:
        if not GNS3_USER or not GNS3_PASSWORD:
            raise GNS3Error("GNS3_AUTH_FAILED", "GNS3_USER and GNS3_PASSWORD environment variables required", 401)
        client = GNS3Client(GNS3_URL, GNS3_USER, GNS3_PASSWORD, GNS3_VERIFY_SSL, GNS3_TOKEN_TTL)
    return client


# =============================================================================
# Utility Tools (T011, T012)
# =============================================================================

@mcp.tool()
@with_gait_logging("gns3_list_templates")
def gns3_list_templates() -> str:
    """List available node templates on the GNS3 server."""
    try:
        c = get_client()
        response = c.get("/v3/templates")
        templates = handle_gns3_response(response)

        result = []
        for t in templates:
            result.append({
                "template_id": t.get("template_id"),
                "name": t.get("name"),
                "template_type": t.get("template_type"),
                "category": t.get("category"),
                "builtin": t.get("builtin", False)
            })

        return success_response(result, f"Found {len(result)} templates", len(result))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_list_computes")
def gns3_list_computes() -> str:
    """List available compute servers."""
    try:
        c = get_client()
        response = c.get("/v3/computes")
        computes = handle_gns3_response(response)

        result = []
        for comp in computes:
            result.append({
                "compute_id": comp.get("compute_id"),
                "name": comp.get("name"),
                "host": comp.get("host"),
                "port": comp.get("port"),
                "protocol": comp.get("protocol"),
                "connected": comp.get("connected", False),
                "cpu_usage_percent": comp.get("cpu_usage_percent"),
                "memory_usage_percent": comp.get("memory_usage_percent")
            })

        return success_response(result, f"Found {len(result)} compute servers", len(result))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


# =============================================================================
# Project Lifecycle Tools (US1: T013-T021)
# =============================================================================

@mcp.tool()
@with_gait_logging("gns3_list_projects")
def gns3_list_projects() -> str:
    """List all GNS3 projects on the server."""
    try:
        c = get_client()
        response = c.get("/v3/projects")
        projects = handle_gns3_response(response)

        result = []
        for p in projects:
            result.append({
                "project_id": p.get("project_id"),
                "name": p.get("name"),
                "status": p.get("status"),
                "path": p.get("path"),
                "auto_open": p.get("auto_open", False),
                "created_at": p.get("created_at")
            })

        return success_response(result, f"Found {len(result)} projects", len(result))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_create_project")
def gns3_create_project(
    name: str,
    auto_open: bool = False,
    auto_close: bool = False,
    auto_start: bool = False
) -> str:
    """
    Create a new GNS3 project.

    Args:
        name: Project name (must be unique)
        auto_open: Open project on server start (default: false)
        auto_close: Close project when unused (default: false)
        auto_start: Start nodes when project is opened (default: false)
    """
    try:
        c = get_client()
        payload = {
            "name": name,
            "auto_open": auto_open,
            "auto_close": auto_close,
            "auto_start": auto_start
        }

        response = c.post("/v3/projects", json=payload)
        project = handle_gns3_response(response, [200, 201])

        result = {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "status": project.get("status"),
            "path": project.get("path")
        }

        return success_response(result, f"Project '{name}' created successfully")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_get_project")
def gns3_get_project(project_id: str) -> str:
    """
    Get details of a specific project.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.get(f"/v3/projects/{pid}")
        project = handle_gns3_response(response)

        result = {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "status": project.get("status"),
            "path": project.get("path"),
            "scene_width": project.get("scene_width"),
            "scene_height": project.get("scene_height"),
            "zoom": project.get("zoom"),
            "auto_open": project.get("auto_open"),
            "auto_close": project.get("auto_close"),
            "auto_start": project.get("auto_start")
        }

        return success_response(result)
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_open_project")
def gns3_open_project(project_id: str) -> str:
    """
    Open a closed project.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.post(f"/v3/projects/{pid}/open")
        project = handle_gns3_response(response)

        result = {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "status": project.get("status")
        }

        return success_response(result, f"Project '{project.get('name')}' opened")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_close_project")
def gns3_close_project(project_id: str) -> str:
    """
    Close an opened project and release resources.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.post(f"/v3/projects/{pid}/close")
        project = handle_gns3_response(response)

        result = {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "status": project.get("status")
        }

        return success_response(result, f"Project '{project.get('name')}' closed")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_delete_project")
def gns3_delete_project(project_id: str) -> str:
    """
    Delete a project and all its resources.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        # Get project name first for message
        response = c.get(f"/v3/projects/{pid}")
        project = handle_gns3_response(response)
        name = project.get("name", pid)

        response = c.delete(f"/v3/projects/{pid}")
        handle_gns3_response(response, [200, 204])

        return success_response(message=f"Project '{name}' deleted")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_clone_project")
def gns3_clone_project(
    project_id: str,
    new_name: str,
    reset_mac_addresses: bool = True
) -> str:
    """
    Create a copy of an existing project.

    Args:
        project_id: Source project UUID or name
        new_name: Name for the cloned project
        reset_mac_addresses: Generate new MAC addresses (default: true)
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        payload = {
            "name": new_name,
            "reset_mac_addresses": reset_mac_addresses
        }

        response = c.post(f"/v3/projects/{pid}/duplicate", json=payload)
        project = handle_gns3_response(response, [200, 201])

        result = {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "status": project.get("status")
        }

        return success_response(result, f"Project cloned as '{new_name}'")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_export_project")
def gns3_export_project(
    project_id: str,
    include_snapshots: bool = True,
    include_images: bool = False,
    compression: str = "zip"
) -> str:
    """
    Export a project as a portable archive.

    Args:
        project_id: Project UUID or name
        include_snapshots: Include snapshots in export (default: true)
        include_images: Include disk images (default: false)
        compression: Compression type: none, zip, gzip (default: zip)
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        params = {
            "include_snapshots": include_snapshots,
            "include_images": include_images,
            "compression": compression
        }

        response = c.get(f"/v3/projects/{pid}/export", params=params)

        if response.status_code == 200:
            # The response is the file content, get info from headers
            content_length = response.headers.get("content-length", "unknown")
            result = {
                "export_path": f"GNS3 export stream (size: {content_length} bytes)",
                "file_size": int(content_length) if content_length.isdigit() else 0
            }
            return success_response(result, f"Project export ready ({content_length} bytes)")
        else:
            handle_gns3_response(response)
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_import_project")
def gns3_import_project(file_path: str, name: str = None) -> str:
    """
    Import a project from an archive.

    Args:
        file_path: Path to project archive file
        name: Override project name (optional)
    """
    try:
        c = get_client()

        # Read the file
        with open(file_path, "rb") as f:
            file_content = f.read()

        params = {}
        if name:
            params["name"] = name

        response = c.post(
            "/v3/projects/import",
            params=params,
            content=file_content,
            headers={"Content-Type": "application/octet-stream"}
        )
        project = handle_gns3_response(response, [200, 201])

        result = {
            "project_id": project.get("project_id"),
            "name": project.get("name"),
            "status": project.get("status")
        }

        return success_response(result, f"Project '{project.get('name')}' imported")
    except FileNotFoundError:
        return error_response(GNS3Error("GNS3_NOT_FOUND", f"File not found: {file_path}", 404))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


# =============================================================================
# Node Operations Tools (US2: T023-T030)
# =============================================================================

@mcp.tool()
@with_gait_logging("gns3_list_nodes")
def gns3_list_nodes(project_id: str) -> str:
    """
    List all nodes in a project.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.get(f"/v3/projects/{pid}/nodes")
        nodes = handle_gns3_response(response)

        result = []
        for n in nodes:
            result.append({
                "node_id": n.get("node_id"),
                "name": n.get("name"),
                "node_type": n.get("node_type"),
                "status": n.get("status"),
                "console": n.get("console"),
                "console_type": n.get("console_type"),
                "console_host": n.get("console_host")
            })

        return success_response(result, f"Found {len(result)} nodes", len(result))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_create_node")
def gns3_create_node(
    project_id: str,
    template: str,
    name: str = None,
    x: int = 0,
    y: int = 0,
    compute_id: str = "local"
) -> str:
    """
    Create a node from a template.

    Args:
        project_id: Project UUID or name
        template: Template name or ID (fuzzy match supported)
        name: Node name (auto-generated if not provided)
        x: Canvas X position (default: 0)
        y: Canvas Y position (default: 0)
        compute_id: Target compute server (default: "local")
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        template_id, template_name = resolve_template_id(c, template)

        payload = {
            "x": x,
            "y": y,
            "compute_id": compute_id
        }
        if name:
            payload["name"] = name

        response = c.post(f"/v3/projects/{pid}/templates/{template_id}", json=payload)
        node = handle_gns3_response(response, [200, 201])

        result = {
            "node_id": node.get("node_id"),
            "name": node.get("name"),
            "node_type": node.get("node_type"),
            "status": node.get("status"),
            "console": node.get("console"),
            "console_type": node.get("console_type"),
            "ports": node.get("ports", [])
        }

        return success_response(result, f"Node '{node.get('name')}' created from template '{template_name}'")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_start_node")
def gns3_start_node(project_id: str, node_id: str) -> str:
    """
    Start a node (power on).

    Args:
        project_id: Project UUID or name
        node_id: Node UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid = resolve_node_id(c, pid, node_id)

        response = c.post(f"/v3/projects/{pid}/nodes/{nid}/start")
        handle_gns3_response(response, [200, 204])

        # Get updated node status
        response = c.get(f"/v3/projects/{pid}/nodes/{nid}")
        node = handle_gns3_response(response)

        result = {
            "node_id": node.get("node_id"),
            "name": node.get("name"),
            "status": node.get("status")
        }

        return success_response(result, f"Node '{node.get('name')}' started")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_stop_node")
def gns3_stop_node(project_id: str, node_id: str) -> str:
    """
    Stop a node (power off).

    Args:
        project_id: Project UUID or name
        node_id: Node UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid = resolve_node_id(c, pid, node_id)

        response = c.post(f"/v3/projects/{pid}/nodes/{nid}/stop")
        handle_gns3_response(response, [200, 204])

        # Get updated node status
        response = c.get(f"/v3/projects/{pid}/nodes/{nid}")
        node = handle_gns3_response(response)

        result = {
            "node_id": node.get("node_id"),
            "name": node.get("name"),
            "status": node.get("status")
        }

        return success_response(result, f"Node '{node.get('name')}' stopped")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_suspend_node")
def gns3_suspend_node(project_id: str, node_id: str) -> str:
    """
    Suspend a node (save state).

    Args:
        project_id: Project UUID or name
        node_id: Node UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid = resolve_node_id(c, pid, node_id)

        response = c.post(f"/v3/projects/{pid}/nodes/{nid}/suspend")
        handle_gns3_response(response, [200, 204])

        # Get updated node status
        response = c.get(f"/v3/projects/{pid}/nodes/{nid}")
        node = handle_gns3_response(response)

        result = {
            "node_id": node.get("node_id"),
            "name": node.get("name"),
            "status": node.get("status")
        }

        return success_response(result, f"Node '{node.get('name')}' suspended")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_reload_node")
def gns3_reload_node(project_id: str, node_id: str) -> str:
    """
    Reload a node (restart).

    Args:
        project_id: Project UUID or name
        node_id: Node UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid = resolve_node_id(c, pid, node_id)

        response = c.post(f"/v3/projects/{pid}/nodes/{nid}/reload")
        handle_gns3_response(response, [200, 204])

        # Get updated node status
        response = c.get(f"/v3/projects/{pid}/nodes/{nid}")
        node = handle_gns3_response(response)

        result = {
            "node_id": node.get("node_id"),
            "name": node.get("name"),
            "status": node.get("status")
        }

        return success_response(result, f"Node '{node.get('name')}' reloaded")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_bulk_node_action")
def gns3_bulk_node_action(project_id: str, action: str) -> str:
    """
    Perform an action on all nodes in a project.

    Args:
        project_id: Project UUID or name
        action: Action to perform: start, stop, suspend, reload
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        valid_actions = ["start", "stop", "suspend", "reload"]
        if action.lower() not in valid_actions:
            raise GNS3Error("GNS3_VALIDATION", f"Invalid action: {action}. Must be one of: {', '.join(valid_actions)}", 422)

        response = c.post(f"/v3/projects/{pid}/nodes/{action.lower()}")
        handle_gns3_response(response, [200, 204])

        # Count nodes
        response = c.get(f"/v3/projects/{pid}/nodes")
        nodes = handle_gns3_response(response)

        result = {
            "affected_nodes": len(nodes),
            "action": action
        }

        return success_response(result, f"Action '{action}' applied to {len(nodes)} nodes")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_get_node_console")
def gns3_get_node_console(project_id: str, node_id: str) -> str:
    """
    Get console connection information for a node.

    Args:
        project_id: Project UUID or name
        node_id: Node UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid = resolve_node_id(c, pid, node_id)

        response = c.get(f"/v3/projects/{pid}/nodes/{nid}")
        node = handle_gns3_response(response)

        console_host = node.get("console_host", "localhost")
        console_port = node.get("console")
        console_type = node.get("console_type", "telnet")

        if console_type == "telnet":
            connection_string = f"telnet {console_host} {console_port}"
        elif console_type == "vnc":
            connection_string = f"vnc://{console_host}:{console_port}"
        elif console_type in ("http", "https"):
            connection_string = f"{console_type}://{console_host}:{console_port}"
        else:
            connection_string = f"{console_type}:{console_host}:{console_port}"

        result = {
            "node_id": node.get("node_id"),
            "node_name": node.get("name"),
            "console": console_port,
            "console_type": console_type,
            "console_host": console_host,
            "connection_string": connection_string
        }

        return success_response(result, f"Console: {connection_string}")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


# =============================================================================
# Link Management Tools (US3: T032-T036)
# =============================================================================

@mcp.tool()
@with_gait_logging("gns3_list_links")
def gns3_list_links(project_id: str) -> str:
    """
    List all links in a project.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        # Get links
        response = c.get(f"/v3/projects/{pid}/links")
        links = handle_gns3_response(response)

        # Get nodes for name resolution
        response = c.get(f"/v3/projects/{pid}/nodes")
        nodes = handle_gns3_response(response)
        node_map = {n["node_id"]: n["name"] for n in nodes}

        result = []
        for link in links:
            link_nodes = []
            for node_info in link.get("nodes", []):
                node_id = node_info.get("node_id")
                link_nodes.append({
                    "node_id": node_id,
                    "node_name": node_map.get(node_id, "unknown"),
                    "adapter_number": node_info.get("adapter_number"),
                    "port_number": node_info.get("port_number")
                })

            result.append({
                "link_id": link.get("link_id"),
                "nodes": link_nodes,
                "suspend": link.get("suspend", False),
                "capturing": link.get("capturing", False)
            })

        return success_response(result, f"Found {len(result)} links", len(result))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_create_link")
def gns3_create_link(
    project_id: str,
    node1: str,
    port1: str,
    node2: str,
    port2: str
) -> str:
    """
    Create a link between two node interfaces.

    Args:
        project_id: Project UUID or name
        node1: First node UUID or name
        port1: First node interface (e.g., "eth0", "Gi0/0")
        node2: Second node UUID or name
        port2: Second node interface
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid1 = resolve_node_id(c, pid, node1)
        nid2 = resolve_node_id(c, pid, node2)

        adapter1, portnum1 = parse_interface(port1)
        adapter2, portnum2 = parse_interface(port2)

        payload = {
            "nodes": [
                {
                    "node_id": nid1,
                    "adapter_number": adapter1,
                    "port_number": portnum1
                },
                {
                    "node_id": nid2,
                    "adapter_number": adapter2,
                    "port_number": portnum2
                }
            ]
        }

        response = c.post(f"/v3/projects/{pid}/links", json=payload)
        link = handle_gns3_response(response, [200, 201])

        result = {
            "link_id": link.get("link_id"),
            "nodes": link.get("nodes", [])
        }

        return success_response(result, f"Link created between {node1}:{port1} and {node2}:{port2}")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_delete_link")
def gns3_delete_link(project_id: str, link_id: str) -> str:
    """
    Delete a link between nodes.

    Args:
        project_id: Project UUID or name
        link_id: Link UUID
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.delete(f"/v3/projects/{pid}/links/{link_id}")
        handle_gns3_response(response, [200, 204])

        return success_response(message="Link deleted")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_isolate_node")
def gns3_isolate_node(project_id: str, node_id: str, isolate: bool) -> str:
    """
    Disable or enable all links to a node (isolate without deleting).

    Args:
        project_id: Project UUID or name
        node_id: Node UUID or name
        isolate: true = isolate (disable links), false = unisolate (enable links)
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        nid = resolve_node_id(c, pid, node_id)

        if isolate:
            response = c.post(f"/v3/projects/{pid}/nodes/{nid}/isolate")
        else:
            response = c.post(f"/v3/projects/{pid}/nodes/{nid}/unisolate")

        handle_gns3_response(response, [200, 204])

        # Count affected links
        response = c.get(f"/v3/projects/{pid}/nodes/{nid}/links")
        links = handle_gns3_response(response)

        # Get node name
        response = c.get(f"/v3/projects/{pid}/nodes/{nid}")
        node = handle_gns3_response(response)

        result = {
            "node_id": nid,
            "node_name": node.get("name"),
            "isolated": isolate,
            "affected_links": len(links)
        }

        action = "isolated" if isolate else "unisolated"
        return success_response(result, f"Node '{node.get('name')}' {action}")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


# =============================================================================
# Packet Capture Tools (US4: T038-T040)
# =============================================================================

@mcp.tool()
@with_gait_logging("gns3_start_capture")
def gns3_start_capture(
    project_id: str,
    link_id: str,
    capture_file_name: str = None
) -> str:
    """
    Start packet capture on a link.

    Args:
        project_id: Project UUID or name
        link_id: Link UUID
        capture_file_name: Custom PCAP filename (optional)
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        payload = {}
        if capture_file_name:
            payload["capture_file_name"] = capture_file_name

        response = c.post(f"/v3/projects/{pid}/links/{link_id}/capture/start", json=payload)
        link = handle_gns3_response(response)

        result = {
            "link_id": link_id,
            "capturing": True,
            "capture_file_name": link.get("capture_file_name"),
            "capture_file_path": link.get("capture_file_path")
        }

        return success_response(result, "Capture started on link")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_stop_capture")
def gns3_stop_capture(project_id: str, link_id: str) -> str:
    """
    Stop packet capture on a link.

    Args:
        project_id: Project UUID or name
        link_id: Link UUID
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.post(f"/v3/projects/{pid}/links/{link_id}/capture/stop")
        handle_gns3_response(response, [200, 204])

        # Get link info for capture path
        response = c.get(f"/v3/projects/{pid}/links/{link_id}")
        link = handle_gns3_response(response)

        result = {
            "link_id": link_id,
            "capturing": False,
            "capture_file_path": link.get("capture_file_path")
        }

        return success_response(result, f"Capture stopped. PCAP available at: {link.get('capture_file_path')}")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_get_capture")
def gns3_get_capture(project_id: str, link_id: str) -> str:
    """
    Get capture file path or stream info for a link.

    Args:
        project_id: Project UUID or name
        link_id: Link UUID
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.get(f"/v3/projects/{pid}/links/{link_id}")
        link = handle_gns3_response(response)

        result = {
            "link_id": link_id,
            "capturing": link.get("capturing", False),
            "capture_file_path": link.get("capture_file_path")
        }

        if link.get("capturing"):
            result["stream_url"] = f"{GNS3_URL}/v3/projects/{pid}/links/{link_id}/capture/stream"

        return success_response(result, "Capture info retrieved")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


# =============================================================================
# Snapshot Operations Tools (US5: T042-T045)
# =============================================================================

@mcp.tool()
@with_gait_logging("gns3_list_snapshots")
def gns3_list_snapshots(project_id: str) -> str:
    """
    List all snapshots for a project.

    Args:
        project_id: Project UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        response = c.get(f"/v3/projects/{pid}/snapshots")
        snapshots = handle_gns3_response(response)

        result = []
        for s in snapshots:
            result.append({
                "snapshot_id": s.get("snapshot_id"),
                "name": s.get("name"),
                "created_at": s.get("created_at")
            })

        return success_response(result, f"Found {len(result)} snapshots", len(result))
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_create_snapshot")
def gns3_create_snapshot(project_id: str, name: str) -> str:
    """
    Create a snapshot of the current project state.

    Args:
        project_id: Project UUID or name
        name: Snapshot name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)

        payload = {"name": name}

        response = c.post(f"/v3/projects/{pid}/snapshots", json=payload)
        snapshot = handle_gns3_response(response, [200, 201])

        result = {
            "snapshot_id": snapshot.get("snapshot_id"),
            "name": snapshot.get("name"),
            "created_at": snapshot.get("created_at")
        }

        return success_response(result, f"Snapshot '{name}' created")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_restore_snapshot")
def gns3_restore_snapshot(project_id: str, snapshot_id: str) -> str:
    """
    Restore a project to a previous snapshot state.

    Args:
        project_id: Project UUID or name
        snapshot_id: Snapshot UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        sid = resolve_snapshot_id(c, pid, snapshot_id)

        # Get snapshot name first
        response = c.get(f"/v3/projects/{pid}/snapshots")
        snapshots = handle_gns3_response(response)
        snapshot_name = snapshot_id
        for s in snapshots:
            if s.get("snapshot_id") == sid:
                snapshot_name = s.get("name", sid)
                break

        response = c.post(f"/v3/projects/{pid}/snapshots/{sid}/restore")
        handle_gns3_response(response)

        result = {
            "snapshot_id": sid,
            "snapshot_name": snapshot_name,
            "project_id": pid
        }

        return success_response(result, f"Project restored to snapshot '{snapshot_name}'")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


@mcp.tool()
@with_gait_logging("gns3_delete_snapshot")
def gns3_delete_snapshot(project_id: str, snapshot_id: str) -> str:
    """
    Delete a snapshot.

    Args:
        project_id: Project UUID or name
        snapshot_id: Snapshot UUID or name
    """
    try:
        c = get_client()
        pid = resolve_project_id(c, project_id)
        sid = resolve_snapshot_id(c, pid, snapshot_id)

        # Get snapshot name first
        response = c.get(f"/v3/projects/{pid}/snapshots")
        snapshots = handle_gns3_response(response)
        snapshot_name = snapshot_id
        for s in snapshots:
            if s.get("snapshot_id") == sid:
                snapshot_name = s.get("name", sid)
                break

        response = c.delete(f"/v3/projects/{pid}/snapshots/{sid}")
        handle_gns3_response(response, [200, 204])

        return success_response(message=f"Snapshot '{snapshot_name}' deleted")
    except GNS3Error as e:
        return error_response(e)
    except Exception as e:
        return error_response(e)


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    logger.info(f"Starting GNS3 MCP Server (connecting to {GNS3_URL})")
    mcp.run()
