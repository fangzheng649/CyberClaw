"""
GAIT (Global Audit and Immutable Trail) logging integration.
Provides audit logging for all received telemetry events per FR-018.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class GAITLogger:
    """
    GAIT audit logger for telemetry receivers.

    Logs all received events to an immutable audit trail.
    Falls back to standard logging if GAIT service is unavailable.
    """

    def __init__(
        self,
        service_name: str,
        gait_endpoint: Optional[str] = None,
        enabled: bool = True
    ):
        """
        Initialize the GAIT logger.

        Args:
            service_name: Name of the MCP server (e.g., 'ipfix-mcp')
            gait_endpoint: Optional GAIT service endpoint
            enabled: Whether GAIT logging is enabled
        """
        self.service_name = service_name
        self.gait_endpoint = gait_endpoint
        self.enabled = enabled
        self.log_count = 0
        self.error_count = 0

        # Setup dedicated audit logger
        self.audit_logger = logging.getLogger(f"gait.{service_name}")
        self.audit_logger.setLevel(logging.INFO)

    def log_event(
        self,
        event_type: str,
        source_ip: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log a telemetry event to GAIT.

        Args:
            event_type: Type of event (e.g., 'flow_received')
            source_ip: Source IP address of the event
            data: Event data to log
            metadata: Optional additional metadata

        Returns:
            True if logged successfully, False otherwise
        """
        if not self.enabled:
            return True

        self.log_count += 1

        audit_record = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'service': self.service_name,
            'event_type': event_type,
            'source_ip': source_ip,
            'data': data,
            'metadata': metadata or {},
            'sequence': self.log_count
        }

        try:
            # Log to audit logger (can be configured to write to file, syslog, etc.)
            self.audit_logger.info(json.dumps(audit_record))

            # If GAIT endpoint is configured, send there too
            if self.gait_endpoint:
                self._send_to_gait(audit_record)

            return True

        except Exception as e:
            self.error_count += 1
            logger.error(f"Failed to log GAIT event: {e}")
            return False

    def _send_to_gait(self, record: Dict[str, Any]) -> None:
        """
        Send audit record to GAIT service.

        Note: This is a placeholder for actual GAIT integration.
        In production, this would make an async HTTP call to the GAIT service.
        """
        # TODO: Implement actual GAIT service integration when available
        pass

    def log_flow_received(
        self,
        exporter_ip: str,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        bytes_count: Optional[int] = None
    ) -> bool:
        """Log a received flow record."""
        return self.log_event(
            event_type='flow_received',
            source_ip=exporter_ip,
            data={
                'flow_id': flow_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'bytes': bytes_count
            }
        )

    def log_template_received(
        self,
        exporter_ip: str,
        template_id: int,
        field_count: int
    ) -> bool:
        """Log a received IPFIX/NetFlow template."""
        return self.log_event(
            event_type='template_received',
            source_ip=exporter_ip,
            data={
                'template_id': template_id,
                'field_count': field_count
            }
        )

    def log_receiver_started(self, port: int, bind_address: str) -> bool:
        """Log receiver startup."""
        return self.log_event(
            event_type='receiver_started',
            source_ip='localhost',
            data={
                'port': port,
                'bind_address': bind_address
            }
        )

    def log_receiver_stopped(self, port: int, flows_received: int) -> bool:
        """Log receiver shutdown."""
        return self.log_event(
            event_type='receiver_stopped',
            source_ip='localhost',
            data={
                'port': port,
                'flows_received': flows_received
            }
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get GAIT logging statistics."""
        return {
            'enabled': self.enabled,
            'service_name': self.service_name,
            'log_count': self.log_count,
            'error_count': self.error_count,
            'gait_endpoint': self.gait_endpoint
        }
