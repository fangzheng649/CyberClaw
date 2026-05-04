"""
Pydantic models for the SNMP Trap MCP Server.
Based on data-model.md specification and FR-006 through FR-011.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class SNMPVersion(str, Enum):
    """SNMP version enumeration."""
    V1 = "v1"
    V2C = "v2c"
    V3 = "v3"


class SNMPv3SecurityLevel(str, Enum):
    """SNMPv3 USM security levels."""
    NO_AUTH_NO_PRIV = "noAuthNoPriv"
    AUTH_NO_PRIV = "authNoPriv"
    AUTH_PRIV = "authPriv"


class SNMPv3AuthProtocol(str, Enum):
    """SNMPv3 authentication protocols."""
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"


class SNMPv3PrivProtocol(str, Enum):
    """SNMPv3 privacy protocols."""
    DES = "DES"
    TDES = "3DES"  # Triple-DES
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"


# Standard SNMP trap OIDs (RFC 3418)
STANDARD_TRAPS = {
    '1.3.6.1.6.3.1.1.5.1': 'coldStart',
    '1.3.6.1.6.3.1.1.5.2': 'warmStart',
    '1.3.6.1.6.3.1.1.5.3': 'linkDown',
    '1.3.6.1.6.3.1.1.5.4': 'linkUp',
    '1.3.6.1.6.3.1.1.5.5': 'authenticationFailure',
    '1.3.6.1.6.3.1.1.5.6': 'egpNeighborLoss',
}

# Generic trap types for SNMPv1
GENERIC_TRAP_TYPES = {
    0: 'coldStart',
    1: 'warmStart',
    2: 'linkDown',
    3: 'linkUp',
    4: 'authenticationFailure',
    5: 'egpNeighborLoss',
    6: 'enterpriseSpecific',
}


class VarBind(BaseModel):
    """SNMP variable binding (OID-value pair)."""
    oid: str = Field(..., description="Object Identifier")
    oid_name: Optional[str] = Field(None, description="Human-readable OID name if resolved")
    value: Any = Field(..., description="Value associated with the OID")
    value_type: str = Field(default="unknown", description="Value type (integer, string, etc.)")


class SNMPTrap(BaseModel):
    """
    Parsed SNMP trap (FR-006 through FR-011).
    Supports SNMPv1, SNMPv2c, and SNMPv3 formats.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique trap ID")
    received_at: datetime = Field(default_factory=datetime.utcnow, description="When NetClaw received it")
    source_ip: str = Field(..., description="Source device IP")
    source_port: int = Field(..., description="Source UDP port")

    # SNMP version info
    version: SNMPVersion = Field(..., description="SNMP version (v1, v2c, v3)")
    community: Optional[str] = Field(None, description="SNMPv1/v2c community string")

    # SNMPv3 specific
    security_level: Optional[SNMPv3SecurityLevel] = Field(None, description="SNMPv3 security level")
    security_name: Optional[str] = Field(None, description="SNMPv3 security name (user)")
    context_name: Optional[str] = Field(None, description="SNMPv3 context name")
    context_engine_id: Optional[str] = Field(None, description="SNMPv3 context engine ID")

    # Trap identification
    trap_oid: str = Field(..., description="Trap OID (snmpTrapOID.0 for v2c/v3)")
    trap_name: Optional[str] = Field(None, description="Human-readable trap name")

    # SNMPv1 specific fields
    enterprise_oid: Optional[str] = Field(None, description="SNMPv1 enterprise OID")
    agent_addr: Optional[str] = Field(None, description="SNMPv1 agent address")
    generic_trap: Optional[int] = Field(None, description="SNMPv1 generic trap type (0-6)")
    specific_trap: Optional[int] = Field(None, description="SNMPv1 specific trap code")

    # Timing
    uptime: Optional[int] = Field(None, description="sysUpTime in hundredths of seconds")
    timestamp: Optional[datetime] = Field(None, description="Timestamp from trap if available")

    # Variable bindings
    varbinds: List[VarBind] = Field(default_factory=list, description="Variable bindings")

    # Metadata
    raw_data: Optional[bytes] = Field(None, description="Raw trap data", exclude=True)
    parse_errors: List[str] = Field(default_factory=list, description="Any parsing warnings")

    class Config:
        use_enum_values = True

    @property
    def trap_type(self) -> str:
        """Get human-readable trap type."""
        if self.trap_name:
            return self.trap_name
        if self.trap_oid in STANDARD_TRAPS:
            return STANDARD_TRAPS[self.trap_oid]
        if self.generic_trap is not None and self.generic_trap in GENERIC_TRAP_TYPES:
            return GENERIC_TRAP_TYPES[self.generic_trap]
        return 'unknown'

    @property
    def is_standard_trap(self) -> bool:
        """Check if this is a standard trap (coldStart, linkDown, etc.)."""
        return self.trap_oid in STANDARD_TRAPS or (
            self.generic_trap is not None and self.generic_trap < 6
        )

    def to_display_dict(self) -> Dict[str, Any]:
        """Convert to display-friendly dictionary."""
        return {
            'id': self.id,
            'received_at': self.received_at.isoformat() if self.received_at else None,
            'source_ip': self.source_ip,
            'version': self.version,
            'trap_oid': self.trap_oid,
            'trap_type': self.trap_type,
            'uptime': self.uptime,
            'varbind_count': len(self.varbinds),
            'community': '***' if self.community else None,  # Mask community string
            'security_name': self.security_name,
        }

    def get_varbind(self, oid: str) -> Optional[VarBind]:
        """Get a specific variable binding by OID."""
        for vb in self.varbinds:
            if vb.oid == oid:
                return vb
        return None


class TrapQueryFilter(BaseModel):
    """SNMP trap query filters."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source_ip: Optional[str] = None
    version: Optional[SNMPVersion] = None
    trap_oid: Optional[str] = None
    trap_oid_prefix: Optional[str] = Field(None, description="Match traps with OID starting with this")
    community: Optional[str] = None
    security_name: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ReceiverStatus(BaseModel):
    """Operational status of the SNMP trap receiver."""
    receiver_type: str = Field(default="snmptrap", description="Type of receiver")
    port: int = Field(..., description="UDP port")
    bind_address: str = Field(default="0.0.0.0", description="Bind address")
    is_running: bool = Field(default=False, description="Whether receiver is active")
    started_at: Optional[datetime] = Field(None, description="When receiver started")
    traps_received: int = Field(default=0, description="Total traps received")
    traps_deduplicated: int = Field(default=0, description="Traps discarded as duplicates")
    errors: int = Field(default=0, description="Total errors")
    last_trap_time: Optional[datetime] = Field(None, description="Time of last trap")
    rate_limited_count: int = Field(default=0, description="Traps dropped due to rate limiting")

    # Version-specific counters
    v1_traps: int = Field(default=0, description="SNMPv1 traps received")
    v2c_traps: int = Field(default=0, description="SNMPv2c traps received")
    v3_traps: int = Field(default=0, description="SNMPv3 traps received")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            'receiver_type': self.receiver_type,
            'port': self.port,
            'bind_address': self.bind_address,
            'is_running': self.is_running,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'traps_received': self.traps_received,
            'traps_deduplicated': self.traps_deduplicated,
            'errors': self.errors,
            'last_trap_time': self.last_trap_time.isoformat() if self.last_trap_time else None,
            'rate_limited_count': self.rate_limited_count,
            'by_version': {
                'v1': self.v1_traps,
                'v2c': self.v2c_traps,
                'v3': self.v3_traps
            }
        }


class TrapTypeCount(BaseModel):
    """Count of traps by type."""
    trap_oid: str
    trap_name: Optional[str]
    count: int


class TrapCountsResponse(BaseModel):
    """Response for trap counts query."""
    time_range: Optional[Dict[str, Optional[str]]] = None
    by_type: List[TrapTypeCount] = Field(default_factory=list)
    by_source: Dict[str, int] = Field(default_factory=dict)
    total: int = 0


class SNMPv3User(BaseModel):
    """SNMPv3 USM user configuration."""
    user_name: str = Field(..., description="USM user name")
    auth_protocol: Optional[SNMPv3AuthProtocol] = Field(None, description="Authentication protocol")
    auth_key: Optional[str] = Field(None, description="Authentication key/passphrase")
    priv_protocol: Optional[SNMPv3PrivProtocol] = Field(None, description="Privacy protocol")
    priv_key: Optional[str] = Field(None, description="Privacy key/passphrase")

    @property
    def security_level(self) -> SNMPv3SecurityLevel:
        """Determine security level from configured protocols."""
        if self.auth_protocol and self.priv_protocol:
            return SNMPv3SecurityLevel.AUTH_PRIV
        elif self.auth_protocol:
            return SNMPv3SecurityLevel.AUTH_NO_PRIV
        else:
            return SNMPv3SecurityLevel.NO_AUTH_NO_PRIV
