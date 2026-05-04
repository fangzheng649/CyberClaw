"""
Pydantic models for the IPFIX/NetFlow MCP Server.
Based on data-model.md specification and FR-012 through FR-016.
"""

from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class FlowVersion(IntEnum):
    """NetFlow/IPFIX version enumeration."""
    NETFLOW_V1 = 1
    NETFLOW_V5 = 5
    NETFLOW_V9 = 9
    IPFIX = 10  # IPFIX uses version 10


class Protocol(IntEnum):
    """IP protocol numbers (common ones)."""
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50
    AH = 51
    ICMPV6 = 58
    SCTP = 132


PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    132: "SCTP"
}


# Standard IPFIX Information Elements (RFC 7011)
INFORMATION_ELEMENTS = {
    1: "octetDeltaCount",
    2: "packetDeltaCount",
    4: "protocolIdentifier",
    5: "ipClassOfService",
    6: "tcpControlBits",
    7: "sourceTransportPort",
    8: "sourceIPv4Address",
    10: "ingressInterface",
    11: "destinationTransportPort",
    12: "destinationIPv4Address",
    14: "egressInterface",
    15: "ipNextHopIPv4Address",
    16: "bgpSourceAsNumber",
    17: "bgpDestinationAsNumber",
    21: "flowEndSysUpTime",
    22: "flowStartSysUpTime",
    27: "sourceIPv6Address",
    28: "destinationIPv6Address",
    136: "flowEndReason",
    152: "flowStartMilliseconds",
    153: "flowEndMilliseconds",
}


class FlowTemplate(BaseModel):
    """IPFIX/NetFlow v9 template definition."""
    template_id: int = Field(..., description="Template ID (256+)")
    exporter_ip: str = Field(..., description="IP of the exporter that sent this template")
    field_count: int = Field(..., description="Number of fields in template")
    fields: List[Dict[str, Any]] = Field(default_factory=list, description="Template field definitions")
    received_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


class FlowRecord(BaseModel):
    """
    Parsed flow record (FR-012 through FR-016).
    Supports NetFlow v5, v9, and IPFIX formats.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique flow ID")
    received_at: datetime = Field(default_factory=datetime.utcnow, description="When NetClaw received it")
    exporter_ip: str = Field(..., description="Exporter device IP")
    exporter_port: int = Field(..., description="Exporter UDP port")

    # Flow version
    version: int = Field(..., description="NetFlow version (1, 5, 9) or IPFIX (10)")

    # Core flow fields (RFC 7011 Information Elements)
    src_ip: Optional[str] = Field(None, description="Source IP address (IE 8/27)")
    dst_ip: Optional[str] = Field(None, description="Destination IP address (IE 12/28)")
    src_port: Optional[int] = Field(None, description="Source port (IE 7)")
    dst_port: Optional[int] = Field(None, description="Destination port (IE 11)")
    protocol: Optional[int] = Field(None, description="IP protocol (IE 4)")

    # Counters
    bytes: Optional[int] = Field(None, description="Byte count (IE 1)")
    packets: Optional[int] = Field(None, description="Packet count (IE 2)")

    # Interfaces
    input_interface: Optional[int] = Field(None, description="Ingress interface index (IE 10)")
    output_interface: Optional[int] = Field(None, description="Egress interface index (IE 14)")

    # Timing
    flow_start: Optional[datetime] = Field(None, description="Flow start time")
    flow_end: Optional[datetime] = Field(None, description="Flow end time")
    duration_ms: Optional[int] = Field(None, description="Flow duration in milliseconds")

    # BGP/Routing
    src_as: Optional[int] = Field(None, description="Source AS number (IE 16)")
    dst_as: Optional[int] = Field(None, description="Destination AS number (IE 17)")
    next_hop: Optional[str] = Field(None, description="Next hop IP (IE 15)")

    # QoS
    tos: Optional[int] = Field(None, description="Type of Service / DSCP (IE 5)")
    tcp_flags: Optional[int] = Field(None, description="TCP control flags (IE 6)")

    # Template reference (for v9/IPFIX)
    template_id: Optional[int] = Field(None, description="Template ID used for decoding")

    # Additional fields (key-value for extensibility)
    extra_fields: Dict[str, Any] = Field(default_factory=dict, description="Additional decoded fields")

    # Metadata
    raw_data: Optional[bytes] = Field(None, description="Raw flow data", exclude=True)
    parse_errors: List[str] = Field(default_factory=list, description="Any parsing warnings")

    class Config:
        use_enum_values = True

    @property
    def protocol_name(self) -> str:
        """Get human-readable protocol name."""
        if self.protocol is None:
            return "unknown"
        return PROTOCOL_NAMES.get(self.protocol, f"proto-{self.protocol}")

    @property
    def version_name(self) -> str:
        """Get human-readable version name."""
        if self.version == 10:
            return "IPFIX"
        return f"NetFlow v{self.version}"

    @property
    def flow_tuple(self) -> str:
        """Get 5-tuple representation of the flow."""
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol_name})"

    def to_display_dict(self) -> Dict[str, Any]:
        """Convert to display-friendly dictionary."""
        return {
            'id': self.id,
            'received_at': self.received_at.isoformat() if self.received_at else None,
            'exporter_ip': self.exporter_ip,
            'version': self.version_name,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol_name,
            'bytes': self.bytes,
            'packets': self.packets,
            'duration_ms': self.duration_ms
        }


class FlowQueryFilter(BaseModel):
    """Flow record query filters."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    exporter_ip: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    version: Optional[int] = None
    min_bytes: Optional[int] = Field(None, description="Minimum byte count")
    min_packets: Optional[int] = Field(None, description="Minimum packet count")
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ReceiverStatus(BaseModel):
    """Operational status of the IPFIX/NetFlow receiver."""
    receiver_type: str = Field(default="ipfix", description="Type of receiver")
    port: int = Field(..., description="UDP port")
    bind_address: str = Field(default="0.0.0.0", description="Bind address")
    is_running: bool = Field(default=False, description="Whether receiver is active")
    started_at: Optional[datetime] = Field(None, description="When receiver started")
    flows_received: int = Field(default=0, description="Total flow records received")
    flows_deduplicated: int = Field(default=0, description="Flows discarded as duplicates")
    packets_received: int = Field(default=0, description="Total UDP packets received")
    errors: int = Field(default=0, description="Total errors")
    last_flow_time: Optional[datetime] = Field(None, description="Time of last flow")
    rate_limited_count: int = Field(default=0, description="Flows dropped due to rate limiting")

    # Version-specific counters
    netflow_v5_flows: int = Field(default=0, description="NetFlow v5 flows")
    netflow_v9_flows: int = Field(default=0, description="NetFlow v9 flows")
    ipfix_flows: int = Field(default=0, description="IPFIX flows")

    # Template stats
    templates_received: int = Field(default=0, description="Templates received")
    active_templates: int = Field(default=0, description="Currently cached templates")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            'receiver_type': self.receiver_type,
            'port': self.port,
            'bind_address': self.bind_address,
            'is_running': self.is_running,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'flows_received': self.flows_received,
            'flows_deduplicated': self.flows_deduplicated,
            'packets_received': self.packets_received,
            'errors': self.errors,
            'last_flow_time': self.last_flow_time.isoformat() if self.last_flow_time else None,
            'rate_limited_count': self.rate_limited_count,
            'by_version': {
                'netflow_v5': self.netflow_v5_flows,
                'netflow_v9': self.netflow_v9_flows,
                'ipfix': self.ipfix_flows
            },
            'templates': {
                'received': self.templates_received,
                'active': self.active_templates
            }
        }


class TopTalkersEntry(BaseModel):
    """Entry in top talkers list."""
    ip: str
    bytes: int
    packets: int
    flows: int


class TopTalkersResponse(BaseModel):
    """Response for top talkers query."""
    time_range: Optional[Dict[str, Optional[str]]] = None
    by_source: List[TopTalkersEntry] = Field(default_factory=list)
    by_destination: List[TopTalkersEntry] = Field(default_factory=list)
    by_protocol: Dict[str, int] = Field(default_factory=dict)
    total_bytes: int = 0
    total_flows: int = 0
