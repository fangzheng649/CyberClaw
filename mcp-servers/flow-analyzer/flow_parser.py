"""
IPFIX/NetFlow parser using the netflow library.
Based on research.md specification using netflow PyPI package.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    FlowRecord, FlowTemplate, FlowVersion,
    INFORMATION_ELEMENTS, PROTOCOL_NAMES
)

logger = logging.getLogger(__name__)

# Try to import netflow library
try:
    import netflow
    HAS_NETFLOW = True
except ImportError:
    HAS_NETFLOW = False
    logger.warning("netflow library not installed, flow parsing will be limited")


class TemplateCache:
    """
    Cache for IPFIX/NetFlow v9 templates.

    Templates are keyed by (exporter_ip, template_id) and expire after 30 minutes.
    """

    def __init__(self, expire_minutes: int = 30):
        """
        Initialize template cache.

        Args:
            expire_minutes: Minutes until templates expire (Cisco default: 30)
        """
        self.templates: Dict[Tuple[str, int], FlowTemplate] = {}
        self.expire_seconds = expire_minutes * 60

    def add(self, exporter_ip: str, template_id: int, fields: List[Dict[str, Any]]) -> FlowTemplate:
        """Add or update a template."""
        key = (exporter_ip, template_id)

        template = FlowTemplate(
            template_id=template_id,
            exporter_ip=exporter_ip,
            field_count=len(fields),
            fields=fields,
            received_at=datetime.utcnow(),
            last_used=datetime.utcnow()
        )

        self.templates[key] = template
        return template

    def get(self, exporter_ip: str, template_id: int) -> Optional[FlowTemplate]:
        """Get a template from cache."""
        key = (exporter_ip, template_id)
        template = self.templates.get(key)

        if template:
            # Check expiration
            age = (datetime.utcnow() - template.received_at).total_seconds()
            if age > self.expire_seconds:
                del self.templates[key]
                return None

            # Update last used
            template.last_used = datetime.utcnow()

        return template

    def cleanup(self) -> int:
        """Remove expired templates. Returns count of removed templates."""
        now = datetime.utcnow()
        expired = []

        for key, template in self.templates.items():
            age = (now - template.received_at).total_seconds()
            if age > self.expire_seconds:
                expired.append(key)

        for key in expired:
            del self.templates[key]

        return len(expired)

    def count(self) -> int:
        """Get number of cached templates."""
        return len(self.templates)

    def get_all(self) -> List[FlowTemplate]:
        """Get all cached templates."""
        return list(self.templates.values())


# Global template cache
template_cache = TemplateCache()


def detect_flow_version(data: bytes) -> Optional[int]:
    """
    Detect NetFlow/IPFIX version from packet header.

    Args:
        data: Raw packet data

    Returns:
        Version number (1, 5, 9, 10) or None if unknown
    """
    if len(data) < 2:
        return None

    # Version is in the first 2 bytes (big-endian)
    version = int.from_bytes(data[0:2], byteorder='big')

    if version in (1, 5, 9, 10):
        return version

    return None


def parse_netflow_v5(
    data: bytes,
    exporter_ip: str,
    exporter_port: int
) -> List[FlowRecord]:
    """
    Parse NetFlow v5 packet.

    NetFlow v5 has a fixed format with 24-byte header and 48-byte records.
    """
    if len(data) < 24:
        return []

    records = []

    try:
        # Parse header
        version = int.from_bytes(data[0:2], 'big')
        count = int.from_bytes(data[2:4], 'big')
        sys_uptime = int.from_bytes(data[4:8], 'big')
        unix_secs = int.from_bytes(data[8:12], 'big')
        unix_nsecs = int.from_bytes(data[12:16], 'big')

        # Each v5 record is 48 bytes
        offset = 24
        for i in range(count):
            if offset + 48 > len(data):
                break

            record_data = data[offset:offset + 48]

            # Parse record fields
            src_ip = '.'.join(str(b) for b in record_data[0:4])
            dst_ip = '.'.join(str(b) for b in record_data[4:8])
            next_hop = '.'.join(str(b) for b in record_data[8:12])
            input_if = int.from_bytes(record_data[12:14], 'big')
            output_if = int.from_bytes(record_data[14:16], 'big')
            packets = int.from_bytes(record_data[16:20], 'big')
            bytes_count = int.from_bytes(record_data[20:24], 'big')
            first = int.from_bytes(record_data[24:28], 'big')
            last = int.from_bytes(record_data[28:32], 'big')
            src_port = int.from_bytes(record_data[32:34], 'big')
            dst_port = int.from_bytes(record_data[34:36], 'big')
            tcp_flags = record_data[37]
            protocol = record_data[38]
            tos = record_data[39]
            src_as = int.from_bytes(record_data[40:42], 'big')
            dst_as = int.from_bytes(record_data[42:44], 'big')

            # Calculate duration
            duration_ms = (last - first) if last >= first else 0

            flow = FlowRecord(
                exporter_ip=exporter_ip,
                exporter_port=exporter_port,
                version=5,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                bytes=bytes_count,
                packets=packets,
                input_interface=input_if,
                output_interface=output_if,
                duration_ms=duration_ms,
                src_as=src_as if src_as else None,
                dst_as=dst_as if dst_as else None,
                next_hop=next_hop if next_hop != '0.0.0.0' else None,
                tos=tos,
                tcp_flags=tcp_flags
            )
            records.append(flow)

            offset += 48

    except Exception as e:
        logger.error(f"Error parsing NetFlow v5: {e}")

    return records


def parse_with_netflow_lib(
    data: bytes,
    exporter_ip: str,
    exporter_port: int
) -> Tuple[List[FlowRecord], List[FlowTemplate]]:
    """
    Parse IPFIX/NetFlow v9 using the netflow library.

    Args:
        data: Raw packet data
        exporter_ip: Exporter IP address
        exporter_port: Exporter port

    Returns:
        Tuple of (flow_records, new_templates)
    """
    records = []
    new_templates = []

    if not HAS_NETFLOW:
        return records, new_templates

    try:
        # Get cached templates for this exporter
        cached_templates = {}
        for tmpl in template_cache.get_all():
            if tmpl.exporter_ip == exporter_ip:
                cached_templates[tmpl.template_id] = tmpl.fields

        # Parse packet with templates
        packet = netflow.parse_packet(data, cached_templates)

        # Check for new templates
        if hasattr(packet, 'templates') and packet.templates:
            for tid, fields in packet.templates.items():
                template = template_cache.add(exporter_ip, tid, fields)
                new_templates.append(template)

        # Parse flows
        if hasattr(packet, 'flows'):
            for flow_data in packet.flows:
                flow = _convert_netflow_record(
                    flow_data,
                    exporter_ip,
                    exporter_port,
                    packet.header.version if hasattr(packet, 'header') else 9
                )
                if flow:
                    records.append(flow)

    except Exception as e:
        logger.debug(f"netflow library parsing failed: {e}")

    return records, new_templates


def _convert_netflow_record(
    flow_data: Dict[str, Any],
    exporter_ip: str,
    exporter_port: int,
    version: int
) -> Optional[FlowRecord]:
    """Convert netflow library output to FlowRecord."""
    try:
        # Map common field names
        src_ip = flow_data.get('IPV4_SRC_ADDR') or flow_data.get('sourceIPv4Address')
        dst_ip = flow_data.get('IPV4_DST_ADDR') or flow_data.get('destinationIPv4Address')

        # IPv6 fallback
        if not src_ip:
            src_ip = flow_data.get('IPV6_SRC_ADDR') or flow_data.get('sourceIPv6Address')
        if not dst_ip:
            dst_ip = flow_data.get('IPV6_DST_ADDR') or flow_data.get('destinationIPv6Address')

        src_port = flow_data.get('L4_SRC_PORT') or flow_data.get('sourceTransportPort')
        dst_port = flow_data.get('L4_DST_PORT') or flow_data.get('destinationTransportPort')
        protocol = flow_data.get('PROTOCOL') or flow_data.get('protocolIdentifier')

        bytes_count = flow_data.get('IN_BYTES') or flow_data.get('octetDeltaCount')
        packets = flow_data.get('IN_PKTS') or flow_data.get('packetDeltaCount')

        input_if = flow_data.get('INPUT_SNMP') or flow_data.get('ingressInterface')
        output_if = flow_data.get('OUTPUT_SNMP') or flow_data.get('egressInterface')

        # Collect extra fields
        extra_fields = {}
        standard_keys = {
            'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'IPV6_SRC_ADDR', 'IPV6_DST_ADDR',
            'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL', 'IN_BYTES', 'IN_PKTS',
            'INPUT_SNMP', 'OUTPUT_SNMP', 'sourceIPv4Address', 'destinationIPv4Address',
            'sourceTransportPort', 'destinationTransportPort', 'protocolIdentifier',
            'octetDeltaCount', 'packetDeltaCount', 'ingressInterface', 'egressInterface'
        }
        for key, value in flow_data.items():
            if key not in standard_keys and value is not None:
                extra_fields[key] = value

        return FlowRecord(
            exporter_ip=exporter_ip,
            exporter_port=exporter_port,
            version=version,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=int(src_port) if src_port else None,
            dst_port=int(dst_port) if dst_port else None,
            protocol=int(protocol) if protocol else None,
            bytes=int(bytes_count) if bytes_count else None,
            packets=int(packets) if packets else None,
            input_interface=int(input_if) if input_if else None,
            output_interface=int(output_if) if output_if else None,
            extra_fields=extra_fields
        )

    except Exception as e:
        logger.debug(f"Error converting flow record: {e}")
        return None


def parse_flow_packet(
    data: bytes,
    exporter_ip: str,
    exporter_port: int
) -> Tuple[List[FlowRecord], List[FlowTemplate]]:
    """
    Auto-detect and parse NetFlow/IPFIX packet.

    Args:
        data: Raw packet data
        exporter_ip: Exporter IP address
        exporter_port: Exporter port

    Returns:
        Tuple of (flow_records, new_templates)
    """
    version = detect_flow_version(data)

    if version == 5:
        # NetFlow v5 - fixed format
        records = parse_netflow_v5(data, exporter_ip, exporter_port)
        return records, []

    elif version in (9, 10):
        # NetFlow v9 or IPFIX - template-based
        return parse_with_netflow_lib(data, exporter_ip, exporter_port)

    else:
        # Unknown version - try netflow library
        if HAS_NETFLOW:
            return parse_with_netflow_lib(data, exporter_ip, exporter_port)

        # Fallback: return empty with error
        return [], []


def get_template_cache() -> TemplateCache:
    """Get the global template cache."""
    return template_cache
