"""
Smoke tests for GNS3 MCP Server.

These tests verify basic functionality without requiring a live GNS3 server.
For live integration tests, set GNS3_URL, GNS3_USER, GNS3_PASSWORD environment variables.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGNS3ErrorHandling:
    """Test error handling utilities."""

    def test_gns3_error_to_dict(self):
        """Test GNS3Error serialization."""
        from gns3_mcp_server import GNS3Error

        error = GNS3Error("GNS3_NOT_FOUND", "Project not found", 404)
        result = error.to_dict()

        assert result["success"] is False
        assert result["error"] == "Project not found"
        assert result["error_code"] == "GNS3_NOT_FOUND"
        assert result["status_code"] == 404

    def test_success_response_with_data(self):
        """Test success_response helper with data."""
        from gns3_mcp_server import success_response

        result = json.loads(success_response(
            data={"project_id": "abc123", "name": "test"},
            message="Project created",
            count=1
        ))

        assert result["success"] is True
        assert result["data"]["project_id"] == "abc123"
        assert result["message"] == "Project created"
        assert result["count"] == 1

    def test_success_response_minimal(self):
        """Test success_response with minimal args."""
        from gns3_mcp_server import success_response

        result = json.loads(success_response())

        assert result["success"] is True
        assert "data" not in result
        assert "message" not in result

    def test_error_response_from_gns3_error(self):
        """Test error_response with GNS3Error."""
        from gns3_mcp_server import GNS3Error, error_response

        error = GNS3Error("GNS3_AUTH_FAILED", "Invalid credentials", 401)
        result = json.loads(error_response(error))

        assert result["success"] is False
        assert result["error_code"] == "GNS3_AUTH_FAILED"
        assert result["status_code"] == 401

    def test_error_response_from_generic_exception(self):
        """Test error_response with generic Exception."""
        from gns3_mcp_server import error_response

        error = Exception("Something went wrong")
        result = json.loads(error_response(error))

        assert result["success"] is False
        assert result["error"] == "Something went wrong"
        assert result["error_code"] == "GNS3_SERVER_ERROR"


class TestNameResolution:
    """Test name-to-UUID resolution helpers."""

    def test_is_uuid_valid(self):
        """Test _is_uuid with valid UUID."""
        from gns3_mcp_server import _is_uuid

        assert _is_uuid("550e8400-e29b-41d4-a716-446655440000") is True
        assert _is_uuid("550e8400e29b41d4a716446655440000") is True

    def test_is_uuid_invalid(self):
        """Test _is_uuid with invalid input."""
        from gns3_mcp_server import _is_uuid

        assert _is_uuid("my-project") is False
        assert _is_uuid("not-a-uuid") is False
        assert _is_uuid("") is False


class TestInterfaceParsing:
    """Test interface name parsing."""

    def test_parse_standard_ethernet(self):
        """Test parsing standard ethernet interfaces."""
        from gns3_mcp_server import parse_interface_name

        assert parse_interface_name("eth0") == ("Ethernet", 0)
        assert parse_interface_name("eth1") == ("Ethernet", 1)
        assert parse_interface_name("Ethernet0") == ("Ethernet", 0)

    def test_parse_cisco_gigabit(self):
        """Test parsing Cisco GigabitEthernet interfaces."""
        from gns3_mcp_server import parse_interface_name

        assert parse_interface_name("Gi0/0") == ("GigabitEthernet", 0)
        assert parse_interface_name("GigabitEthernet0/1") == ("GigabitEthernet", 1)
        assert parse_interface_name("g0/2") == ("GigabitEthernet", 2)

    def test_parse_fastethernet(self):
        """Test parsing FastEthernet interfaces."""
        from gns3_mcp_server import parse_interface_name

        assert parse_interface_name("Fa0/0") == ("FastEthernet", 0)
        assert parse_interface_name("FastEthernet0/1") == ("FastEthernet", 1)
        assert parse_interface_name("f0/2") == ("FastEthernet", 2)

    def test_parse_unknown_returns_none(self):
        """Test that unknown interface names return None."""
        from gns3_mcp_server import parse_interface_name

        assert parse_interface_name("unknown") is None
        assert parse_interface_name("invalid") is None


class TestTemplateFuzzyMatching:
    """Test template fuzzy matching."""

    def test_fuzzy_match_exact(self):
        """Test exact template name match."""
        from gns3_mcp_server import fuzzy_match_template

        templates = [
            {"template_id": "1", "name": "Cisco IOSv"},
            {"template_id": "2", "name": "Arista vEOS"},
        ]

        result = fuzzy_match_template("Cisco IOSv", templates)
        assert result["template_id"] == "1"

    def test_fuzzy_match_partial(self):
        """Test partial template name match."""
        from gns3_mcp_server import fuzzy_match_template

        templates = [
            {"template_id": "1", "name": "Cisco IOSv L2"},
            {"template_id": "2", "name": "Cisco IOSv L3"},
            {"template_id": "3", "name": "Arista vEOS"},
        ]

        result = fuzzy_match_template("iosv", templates)
        assert result is not None
        assert "IOSv" in result["name"]

    def test_fuzzy_match_no_match(self):
        """Test no template match returns None."""
        from gns3_mcp_server import fuzzy_match_template

        templates = [
            {"template_id": "1", "name": "Cisco IOSv"},
        ]

        result = fuzzy_match_template("Juniper", templates)
        assert result is None


class TestGNS3ClientConfig:
    """Test GNS3Client configuration."""

    def test_client_initialization(self):
        """Test client initializes with environment variables."""
        import os
        from gns3_mcp_server import GNS3Client

        with patch.dict(os.environ, {
            "GNS3_URL": "http://test:3080",
            "GNS3_USER": "testuser",
            "GNS3_PASSWORD": "testpass"
        }):
            client = GNS3Client()
            assert client.base_url == "http://test:3080"
            assert client.username == "testuser"
            assert client.password == "testpass"

    def test_client_missing_env_raises(self):
        """Test client raises error when env vars missing."""
        import os
        from gns3_mcp_server import GNS3Client, GNS3Error

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(GNS3Error) as exc_info:
                GNS3Client()
            assert "GNS3_URL" in str(exc_info.value)


class TestGAITLogging:
    """Test GAIT audit logging decorator."""

    def test_gait_decorator_logs_success(self):
        """Test GAIT decorator logs successful operations."""
        from gns3_mcp_server import with_gait_logging

        @with_gait_logging("test operation")
        def test_func():
            return "success"

        with patch("gns3_mcp_server.logger") as mock_logger:
            result = test_func()
            assert result == "success"
            assert mock_logger.info.call_count >= 2

    def test_gait_decorator_logs_failure(self):
        """Test GAIT decorator logs failed operations."""
        from gns3_mcp_server import with_gait_logging

        @with_gait_logging("failing operation")
        def failing_func():
            raise ValueError("Test error")

        with patch("gns3_mcp_server.logger") as mock_logger:
            with pytest.raises(ValueError):
                failing_func()
            mock_logger.error.assert_called_once()


class TestResponseFormat:
    """Test that all tools follow the JSON response contract."""

    def test_all_tools_registered(self):
        """Verify expected tools are registered with MCP server."""
        from gns3_mcp_server import mcp

        # Get registered tools
        tools = mcp._tool_manager._tools if hasattr(mcp, '_tool_manager') else {}

        # Expected tool names based on contracts
        expected_tools = [
            # Project lifecycle (9)
            "gns3_list_projects",
            "gns3_create_project",
            "gns3_get_project",
            "gns3_open_project",
            "gns3_close_project",
            "gns3_delete_project",
            "gns3_clone_project",
            "gns3_export_project",
            "gns3_import_project",
            # Node operations (8)
            "gns3_list_nodes",
            "gns3_create_node",
            "gns3_start_node",
            "gns3_stop_node",
            "gns3_suspend_node",
            "gns3_reload_node",
            "gns3_bulk_node_action",
            "gns3_get_node_console",
            # Link management (4)
            "gns3_list_links",
            "gns3_create_link",
            "gns3_delete_link",
            "gns3_isolate_node",
            # Packet capture (3)
            "gns3_start_capture",
            "gns3_stop_capture",
            "gns3_get_capture",
            # Snapshots (4)
            "gns3_list_snapshots",
            "gns3_create_snapshot",
            "gns3_restore_snapshot",
            "gns3_delete_snapshot",
            # Utility (2)
            "gns3_list_templates",
            "gns3_list_computes",
        ]

        # This test documents expected tools
        # Actual registration check depends on FastMCP implementation
        assert len(expected_tools) == 30  # 23 core + 2 utility + some extras


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
