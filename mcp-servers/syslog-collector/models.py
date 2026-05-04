"""
Pydantic models for the Syslog MCP Server.
Based on data-model.md specification.
"""

from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class SyslogFacility(IntEnum):
    """Syslog facility codes (0-23) per RFC 5424."""
    KERN = 0        # Kernel messages
    USER = 1        # User-level messages
    MAIL = 2        # Mail system
    DAEMON = 3      # System daemons
    AUTH = 4        # Security/authorization
    SYSLOG = 5      # Syslog internal
    LPR = 6         # Line printer
    NEWS = 7        # Network news
    UUCP = 8        # UUCP subsystem
    CRON = 9        # Clock daemon
    AUTHPRIV = 10   # Security/authorization (private)
    FTP = 11        # FTP daemon
    NTP = 12        # NTP subsystem
    AUDIT = 13      # Log audit
    ALERT = 14      # Log alert
    CLOCK = 15      # Clock daemon (note 2)
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(IntEnum):
    """Syslog severity levels (0-7, lower = more severe) per RFC 5424."""
    EMERGENCY = 0   # System is unusable
    ALERT = 1       # Action must be taken immediately
    CRITICAL = 2    # Critical conditions
    ERROR = 3       # Error conditions
    WARNING = 4     # Warning conditions
    NOTICE = 5      # Normal but significant
    INFO = 6        # Informational
    DEBUG = 7       # Debug-level messages


FACILITY_NAMES = {
    0: "KERN", 1: "USER", 2: "MAIL", 3: "DAEMON",
    4: "AUTH", 5: "SYSLOG", 6: "LPR", 7: "NEWS",
    8: "UUCP", 9: "CRON", 10: "AUTHPRIV", 11: "FTP",
    12: "NTP", 13: "AUDIT", 14: "ALERT", 15: "CLOCK",
    16: "LOCAL0", 17: "LOCAL1", 18: "LOCAL2", 19: "LOCAL3",
    20: "LOCAL4", 21: "LOCAL5", 22: "LOCAL6", 23: "LOCAL7"
}

SEVERITY_NAMES = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}


class StructuredDataElement(BaseModel):
    """RFC 5424 Structured Data Element."""
    sd_id: str = Field(..., description="Structured Data ID")
    params: Dict[str, str] = Field(default_factory=dict, description="SD parameters")


class SyslogMessage(BaseModel):
    """
    Parsed syslog message (FR-001 through FR-005).
    Supports both RFC 5424 and RFC 3164 formats.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique message ID")
    received_at: datetime = Field(default_factory=datetime.utcnow, description="When NetClaw received it")
    source_ip: str = Field(..., description="Source device IP")
    source_port: int = Field(..., description="Source UDP port")

    # RFC 5424 fields
    version: Optional[int] = Field(None, description="Protocol version (1 for RFC 5424)")
    facility: int = Field(..., ge=0, le=23, description="Facility code (0-23)")
    severity: int = Field(..., ge=0, le=7, description="Severity level (0-7)")
    timestamp: Optional[datetime] = Field(None, description="Message timestamp from device")
    hostname: Optional[str] = Field(None, description="Originating hostname")
    app_name: Optional[str] = Field(None, description="Application name")
    process_id: Optional[str] = Field(None, description="Process ID")
    message_id: Optional[str] = Field(None, description="Message identifier")
    structured_data: List[StructuredDataElement] = Field(
        default_factory=list,
        description="RFC 5424 Structured Data elements"
    )
    message: str = Field(..., description="Message content")

    # Metadata
    rfc_format: str = Field(default="5424", description="'5424' or '3164'")
    raw_message: Optional[str] = Field(None, description="Original unparsed message")
    parse_errors: List[str] = Field(default_factory=list, description="Any parsing warnings")

    @property
    def priority(self) -> int:
        """Calculate PRI value: facility * 8 + severity."""
        return self.facility * 8 + self.severity

    @property
    def facility_name(self) -> str:
        """Get human-readable facility name."""
        return FACILITY_NAMES.get(self.facility, f"UNKNOWN({self.facility})")

    @property
    def severity_name(self) -> str:
        """Get human-readable severity name."""
        return SEVERITY_NAMES.get(self.severity, f"UNKNOWN({self.severity})")

    def to_display_dict(self) -> Dict[str, Any]:
        """Convert to display-friendly dictionary."""
        return {
            'id': self.id,
            'received_at': self.received_at.isoformat() if self.received_at else None,
            'source_ip': self.source_ip,
            'severity': self.severity,
            'severity_name': self.severity_name,
            'facility': self.facility,
            'facility_name': self.facility_name,
            'hostname': self.hostname,
            'app_name': self.app_name,
            'message': self.message,
            'rfc_format': self.rfc_format
        }


class TimeRange(BaseModel):
    """Time range filter for queries."""
    start: Optional[datetime] = None
    end: Optional[datetime] = None


class SyslogQueryFilter(BaseModel):
    """Syslog-specific query filters."""
    time_range: Optional[TimeRange] = None
    source_ip: Optional[str] = None
    severity_min: Optional[int] = Field(None, ge=0, le=7, description="Minimum severity (0=Emergency, 7=Debug)")
    severity_max: Optional[int] = Field(None, ge=0, le=7, description="Maximum severity")
    facility: Optional[int] = Field(None, ge=0, le=23, description="Facility code")
    hostname: Optional[str] = None
    app_name: Optional[str] = None
    message_contains: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ReceiverStatus(BaseModel):
    """Operational status of the syslog receiver (FR-019)."""
    receiver_type: str = Field(default="syslog", description="Type of receiver")
    port: int = Field(..., description="UDP port")
    bind_address: str = Field(default="0.0.0.0", description="Bind address")
    is_running: bool = Field(default=False, description="Whether receiver is active")
    started_at: Optional[datetime] = Field(None, description="When receiver started")
    messages_received: int = Field(default=0, description="Total messages received")
    messages_deduplicated: int = Field(default=0, description="Messages discarded as duplicates")
    errors: int = Field(default=0, description="Total errors")
    last_message_time: Optional[datetime] = Field(None, description="Time of last message")
    rate_limited_count: int = Field(default=0, description="Messages dropped due to rate limiting")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            'receiver_type': self.receiver_type,
            'port': self.port,
            'bind_address': self.bind_address,
            'is_running': self.is_running,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'messages_received': self.messages_received,
            'messages_deduplicated': self.messages_deduplicated,
            'errors': self.errors,
            'last_message_time': self.last_message_time.isoformat() if self.last_message_time else None,
            'rate_limited_count': self.rate_limited_count
        }


class SeverityCount(BaseModel):
    """Count of messages by severity level."""
    severity: int
    severity_name: str
    count: int


class SeverityCountsResponse(BaseModel):
    """Response for severity counts query."""
    time_range: Optional[TimeRange] = None
    counts: Dict[str, int] = Field(default_factory=dict)
    total: int = 0
