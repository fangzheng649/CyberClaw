"""
SNMP Trap parser using PySNMP.
Based on research.md specification using pysnmp 7.1.x.
"""

import logging
from datetime import datetime
from typing import Any, List, Optional, Tuple

from .models import (
    SNMPTrap, VarBind, SNMPVersion, SNMPv3SecurityLevel,
    STANDARD_TRAPS, GENERIC_TRAP_TYPES
)

logger = logging.getLogger(__name__)

# Try to import pysnmp
try:
    from pysnmp.hlapi.v3arch.asyncio import (
        ObjectIdentity, ObjectType
    )
    from pysnmp.proto import rfc1902, rfc1905
    from pysnmp.proto.api import v1, v2c
    from pysnmp.smi import builder, compiler, view
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False
    logger.warning("pysnmp not installed, SNMP trap parsing will be limited")


# Standard SNMP OIDs
SNMP_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0'  # snmpTrapOID.0
SYS_UPTIME_OID = '1.3.6.1.2.1.1.3.0'     # sysUpTime.0


def oid_to_string(oid: Any) -> str:
    """Convert various OID representations to string."""
    if isinstance(oid, str):
        return oid
    if hasattr(oid, 'prettyPrint'):
        return oid.prettyPrint()
    return str(oid)


def value_to_python(value: Any) -> Tuple[Any, str]:
    """
    Convert SNMP value to Python type.

    Returns:
        Tuple of (python_value, type_name)
    """
    if value is None:
        return None, 'null'

    type_name = type(value).__name__

    # Handle pysnmp types if available
    if HAS_PYSNMP:
        if hasattr(value, 'prettyPrint'):
            # Check specific types
            if hasattr(rfc1902, 'Integer32') and isinstance(value, rfc1902.Integer32):
                return int(value), 'integer'
            elif hasattr(rfc1902, 'OctetString') and isinstance(value, rfc1902.OctetString):
                try:
                    return value.prettyPrint(), 'string'
                except:
                    return bytes(value).hex(), 'hex-string'
            elif hasattr(rfc1902, 'ObjectIdentifier') and isinstance(value, rfc1902.ObjectIdentifier):
                return value.prettyPrint(), 'oid'
            elif hasattr(rfc1902, 'IpAddress') and isinstance(value, rfc1902.IpAddress):
                return value.prettyPrint(), 'ip-address'
            elif hasattr(rfc1902, 'Counter32') and isinstance(value, rfc1902.Counter32):
                return int(value), 'counter32'
            elif hasattr(rfc1902, 'Counter64') and isinstance(value, rfc1902.Counter64):
                return int(value), 'counter64'
            elif hasattr(rfc1902, 'Gauge32') and isinstance(value, rfc1902.Gauge32):
                return int(value), 'gauge32'
            elif hasattr(rfc1902, 'TimeTicks') and isinstance(value, rfc1902.TimeTicks):
                return int(value), 'timeticks'
            else:
                return value.prettyPrint(), type_name.lower()

    # Fallback for basic types
    if isinstance(value, (int, float)):
        return value, 'number'
    elif isinstance(value, bytes):
        try:
            return value.decode('utf-8'), 'string'
        except:
            return value.hex(), 'hex-string'
    elif isinstance(value, str):
        return value, 'string'

    return str(value), type_name.lower()


def parse_varbinds(varbind_list: List[Any]) -> List[VarBind]:
    """Parse a list of variable bindings."""
    result = []

    for vb in varbind_list:
        try:
            if hasattr(vb, '__iter__') and len(vb) == 2:
                oid, value = vb
            elif hasattr(vb, 'getName') and hasattr(vb, 'getVal'):
                oid = vb.getName()
                value = vb.getVal()
            else:
                continue

            oid_str = oid_to_string(oid)
            py_value, value_type = value_to_python(value)

            # Try to get human-readable name
            oid_name = None
            if oid_str in STANDARD_TRAPS:
                oid_name = STANDARD_TRAPS[oid_str]

            result.append(VarBind(
                oid=oid_str,
                oid_name=oid_name,
                value=py_value,
                value_type=value_type
            ))

        except Exception as e:
            logger.debug(f"Error parsing varbind: {e}")
            continue

    return result


def parse_snmpv1_trap(
    data: bytes,
    source_ip: str,
    source_port: int
) -> Optional[SNMPTrap]:
    """
    Parse SNMPv1 trap.

    Args:
        data: Raw trap data
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SNMPTrap if successful, None if parsing fails
    """
    if not HAS_PYSNMP:
        return _parse_basic_trap(data, source_ip, source_port, SNMPVersion.V1)

    try:
        from pysnmp.proto.api import v1, decodeMessageVersion
        from pysnmp.proto import rfc1157

        # Decode the message
        msg = rfc1157.Message()
        msg.decodeData(data)

        pdu = msg.getComponentByPosition(2)

        # Extract fields
        enterprise = oid_to_string(pdu.getComponentByPosition(0))
        agent_addr = pdu.getComponentByPosition(1).prettyPrint()
        generic_trap = int(pdu.getComponentByPosition(2))
        specific_trap = int(pdu.getComponentByPosition(3))
        timestamp = int(pdu.getComponentByPosition(4))

        # Get community
        community = msg.getComponentByPosition(1).prettyPrint()

        # Determine trap OID
        if generic_trap < 6:
            trap_oid = f'1.3.6.1.6.3.1.1.5.{generic_trap + 1}'
            trap_name = GENERIC_TRAP_TYPES.get(generic_trap)
        else:
            trap_oid = f'{enterprise}.0.{specific_trap}'
            trap_name = None

        # Parse varbinds
        varbind_list = pdu.getComponentByPosition(5)
        varbinds = parse_varbinds(varbind_list)

        return SNMPTrap(
            source_ip=source_ip,
            source_port=source_port,
            version=SNMPVersion.V1,
            community=community,
            trap_oid=trap_oid,
            trap_name=trap_name,
            enterprise_oid=enterprise,
            agent_addr=agent_addr,
            generic_trap=generic_trap,
            specific_trap=specific_trap,
            uptime=timestamp,
            varbinds=varbinds,
            raw_data=data
        )

    except Exception as e:
        logger.debug(f"SNMPv1 parsing failed: {e}")
        return None


def parse_snmpv2c_trap(
    data: bytes,
    source_ip: str,
    source_port: int
) -> Optional[SNMPTrap]:
    """
    Parse SNMPv2c trap (TRAP-PDU or INFORM-PDU).

    Args:
        data: Raw trap data
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SNMPTrap if successful, None if parsing fails
    """
    if not HAS_PYSNMP:
        return _parse_basic_trap(data, source_ip, source_port, SNMPVersion.V2C)

    try:
        from pysnmp.proto.api import v2c
        from pysnmp.proto import rfc1902, rfc1905, rfc3411

        # Decode the message
        msg, _ = v2c.apiMessage.prepareReceiveMessage(data)

        # Get community
        community = v2c.apiMessage.getCommunity(msg).prettyPrint()

        # Get PDU
        pdu = v2c.apiMessage.getPDU(msg)

        # Parse varbinds
        varbinds = []
        trap_oid = None
        trap_name = None
        uptime = None

        for oid, val in v2c.apiPDU.getVarBinds(pdu):
            oid_str = oid.prettyPrint()

            # Check for snmpTrapOID.0
            if oid_str == SNMP_TRAP_OID:
                trap_oid = val.prettyPrint()
                trap_name = STANDARD_TRAPS.get(trap_oid)
                continue

            # Check for sysUpTime.0
            if oid_str == SYS_UPTIME_OID:
                uptime = int(val)
                continue

            py_value, value_type = value_to_python(val)
            varbinds.append(VarBind(
                oid=oid_str,
                value=py_value,
                value_type=value_type
            ))

        if not trap_oid:
            trap_oid = 'unknown'

        return SNMPTrap(
            source_ip=source_ip,
            source_port=source_port,
            version=SNMPVersion.V2C,
            community=community,
            trap_oid=trap_oid,
            trap_name=trap_name,
            uptime=uptime,
            varbinds=varbinds,
            raw_data=data
        )

    except Exception as e:
        logger.debug(f"SNMPv2c parsing failed: {e}")
        return None


def parse_snmpv3_trap(
    data: bytes,
    source_ip: str,
    source_port: int
) -> Optional[SNMPTrap]:
    """
    Parse SNMPv3 trap.

    Note: Full SNMPv3 parsing requires USM user configuration.
    This provides basic parsing without authentication verification.

    Args:
        data: Raw trap data
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SNMPTrap if successful, None if parsing fails
    """
    if not HAS_PYSNMP:
        return _parse_basic_trap(data, source_ip, source_port, SNMPVersion.V3)

    try:
        from pysnmp.proto import rfc3412, rfc3414

        # Note: Full v3 parsing requires engine/user setup
        # This is a simplified version that extracts what we can

        # For now, return a basic trap indicating v3
        return SNMPTrap(
            source_ip=source_ip,
            source_port=source_port,
            version=SNMPVersion.V3,
            trap_oid='snmpv3-trap',
            trap_name='SNMPv3 Trap (requires USM configuration for full parsing)',
            raw_data=data,
            parse_errors=['SNMPv3 trap requires USM configuration for full parsing']
        )

    except Exception as e:
        logger.debug(f"SNMPv3 parsing failed: {e}")
        return None


def _parse_basic_trap(
    data: bytes,
    source_ip: str,
    source_port: int,
    version: SNMPVersion
) -> SNMPTrap:
    """Basic trap parsing when pysnmp is not available."""
    return SNMPTrap(
        source_ip=source_ip,
        source_port=source_port,
        version=version,
        trap_oid='unknown',
        raw_data=data,
        parse_errors=['pysnmp not available, could not fully parse trap']
    )


def detect_snmp_version(data: bytes) -> Optional[SNMPVersion]:
    """
    Detect SNMP version from raw data.

    Args:
        data: Raw SNMP message data

    Returns:
        SNMPVersion if detected, None otherwise
    """
    if len(data) < 5:
        return None

    try:
        # SNMP messages start with a SEQUENCE tag (0x30)
        if data[0] != 0x30:
            return None

        # Find the version field (after length bytes)
        idx = 1
        # Skip length byte(s)
        if data[idx] & 0x80:
            idx += (data[idx] & 0x7f) + 1
        else:
            idx += 1

        # Version is INTEGER (0x02)
        if data[idx] != 0x02:
            return None
        idx += 1

        # Length of version (usually 1)
        length = data[idx]
        idx += 1

        # Version value
        version = data[idx]

        if version == 0:
            return SNMPVersion.V1
        elif version == 1:
            return SNMPVersion.V2C
        elif version == 3:
            return SNMPVersion.V3

    except (IndexError, ValueError):
        pass

    return None


def parse_trap(
    data: bytes,
    source_ip: str,
    source_port: int
) -> SNMPTrap:
    """
    Auto-detect and parse SNMP trap.

    Args:
        data: Raw trap data
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SNMPTrap (may have parse_errors if partially parsed)
    """
    # Detect version
    version = detect_snmp_version(data)

    if version == SNMPVersion.V1:
        result = parse_snmpv1_trap(data, source_ip, source_port)
        if result:
            return result

    elif version == SNMPVersion.V2C:
        result = parse_snmpv2c_trap(data, source_ip, source_port)
        if result:
            return result

    elif version == SNMPVersion.V3:
        result = parse_snmpv3_trap(data, source_ip, source_port)
        if result:
            return result

    # Try all parsers as fallback
    for parser, ver in [
        (parse_snmpv2c_trap, SNMPVersion.V2C),
        (parse_snmpv1_trap, SNMPVersion.V1),
        (parse_snmpv3_trap, SNMPVersion.V3)
    ]:
        try:
            result = parser(data, source_ip, source_port)
            if result:
                return result
        except:
            continue

    # Complete fallback
    return SNMPTrap(
        source_ip=source_ip,
        source_port=source_port,
        version=version or SNMPVersion.V2C,
        trap_oid='unknown',
        raw_data=data,
        parse_errors=['Could not parse SNMP trap']
    )
