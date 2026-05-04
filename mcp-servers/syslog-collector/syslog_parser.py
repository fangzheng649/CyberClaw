"""
Syslog message parser supporting RFC 5424 and RFC 3164 formats.
Based on research.md specification using syslog-rfc5424-parser with fallback.
"""

import re
import logging
from datetime import datetime
from typing import Optional, Tuple, List, Dict
from .models import SyslogMessage, StructuredDataElement

logger = logging.getLogger(__name__)

# Try to import the RFC 5424 parser
try:
    from syslog_rfc5424_parser import SyslogMessage as RFC5424Message
    from syslog_rfc5424_parser import ParseError
    HAS_RFC5424_PARSER = True
except ImportError:
    HAS_RFC5424_PARSER = False
    logger.warning("syslog-rfc5424-parser not installed, using built-in parser")


# RFC 3164 regex pattern
# Format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
RFC3164_PATTERN = re.compile(
    r'^<(\d{1,3})>'  # PRI
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp (e.g., "Mar 28 12:34:56")
    r'(\S+)\s+'  # Hostname
    r'(\S+?)(?:\[(\d+)\])?:\s*'  # Tag and optional PID
    r'(.*)$',  # Message
    re.DOTALL
)

# Simpler RFC 3164 pattern for Cisco-style messages
CISCO_SYSLOG_PATTERN = re.compile(
    r'^<(\d{1,3})>'  # PRI
    r'(?:(\d+):\s+)?'  # Optional sequence number
    r'(?:\*?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*:\s+)?'  # Optional timestamp
    r'(.*)$',  # Rest is the message
    re.DOTALL
)

# RFC 5424 detection pattern
RFC5424_PATTERN = re.compile(r'^<\d{1,3}>1\s')


def parse_priority(pri: int) -> Tuple[int, int]:
    """
    Parse PRI value into facility and severity.

    Args:
        pri: Priority value (0-191)

    Returns:
        Tuple of (facility, severity)
    """
    facility = pri >> 3  # pri // 8
    severity = pri & 0x07  # pri % 8
    return facility, severity


def parse_rfc3164_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse RFC 3164 timestamp (no year).

    Args:
        ts_str: Timestamp string like "Mar 28 12:34:56"

    Returns:
        datetime object (assumes current year)
    """
    try:
        # Add current year
        current_year = datetime.utcnow().year
        full_ts = f"{ts_str} {current_year}"
        return datetime.strptime(full_ts, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def parse_rfc5424(
    raw_message: str,
    source_ip: str,
    source_port: int
) -> Optional[SyslogMessage]:
    """
    Parse RFC 5424 formatted syslog message.

    Args:
        raw_message: Raw syslog message string
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SyslogMessage if successful, None if parsing fails
    """
    if not HAS_RFC5424_PARSER:
        return _parse_rfc5424_builtin(raw_message, source_ip, source_port)

    try:
        parsed = RFC5424Message.parse(raw_message)

        # Extract structured data
        structured_data = []
        if parsed.sd:
            for sd_id, params in parsed.sd.items():
                structured_data.append(StructuredDataElement(
                    sd_id=sd_id,
                    params=params if isinstance(params, dict) else {}
                ))

        return SyslogMessage(
            source_ip=source_ip,
            source_port=source_port,
            version=1,
            facility=parsed.facility,
            severity=parsed.severity,
            timestamp=parsed.timestamp,
            hostname=parsed.hostname,
            app_name=parsed.appname,
            process_id=parsed.procid,
            message_id=parsed.msgid,
            structured_data=structured_data,
            message=parsed.msg or "",
            rfc_format="5424",
            raw_message=raw_message
        )
    except Exception as e:
        logger.debug(f"RFC 5424 parsing failed: {e}")
        return None


def _parse_rfc5424_builtin(
    raw_message: str,
    source_ip: str,
    source_port: int
) -> Optional[SyslogMessage]:
    """
    Built-in RFC 5424 parser (fallback when library not available).
    """
    # Basic RFC 5424 pattern
    pattern = re.compile(
        r'^<(\d{1,3})>1\s+'  # PRI and VERSION
        r'(\S+)\s+'  # TIMESTAMP
        r'(\S+)\s+'  # HOSTNAME
        r'(\S+)\s+'  # APP-NAME
        r'(\S+)\s+'  # PROCID
        r'(\S+)\s+'  # MSGID
        r'(\[.*?\]|-)\s*'  # STRUCTURED-DATA
        r'(.*)$',  # MSG
        re.DOTALL
    )

    match = pattern.match(raw_message)
    if not match:
        return None

    try:
        pri = int(match.group(1))
        facility, severity = parse_priority(pri)

        # Parse timestamp
        ts_str = match.group(2)
        timestamp = None
        if ts_str != '-':
            try:
                timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except ValueError:
                pass

        return SyslogMessage(
            source_ip=source_ip,
            source_port=source_port,
            version=1,
            facility=facility,
            severity=severity,
            timestamp=timestamp,
            hostname=match.group(3) if match.group(3) != '-' else None,
            app_name=match.group(4) if match.group(4) != '-' else None,
            process_id=match.group(5) if match.group(5) != '-' else None,
            message_id=match.group(6) if match.group(6) != '-' else None,
            structured_data=[],  # TODO: Parse SD
            message=match.group(8),
            rfc_format="5424",
            raw_message=raw_message
        )
    except Exception as e:
        logger.debug(f"Built-in RFC 5424 parsing failed: {e}")
        return None


def parse_rfc3164(
    raw_message: str,
    source_ip: str,
    source_port: int
) -> Optional[SyslogMessage]:
    """
    Parse RFC 3164 (BSD) formatted syslog message.

    Args:
        raw_message: Raw syslog message string
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SyslogMessage if successful, None if parsing fails
    """
    # Try standard RFC 3164 pattern first
    match = RFC3164_PATTERN.match(raw_message)
    if match:
        try:
            pri = int(match.group(1))
            facility, severity = parse_priority(pri)
            timestamp = parse_rfc3164_timestamp(match.group(2))

            return SyslogMessage(
                source_ip=source_ip,
                source_port=source_port,
                facility=facility,
                severity=severity,
                timestamp=timestamp,
                hostname=match.group(3),
                app_name=match.group(4),
                process_id=match.group(5),
                message=match.group(6),
                rfc_format="3164",
                raw_message=raw_message
            )
        except Exception as e:
            logger.debug(f"RFC 3164 standard parsing failed: {e}")

    # Try Cisco-style pattern
    match = CISCO_SYSLOG_PATTERN.match(raw_message)
    if match:
        try:
            pri = int(match.group(1))
            facility, severity = parse_priority(pri)

            ts_str = match.group(3)
            timestamp = None
            if ts_str:
                timestamp = parse_rfc3164_timestamp(ts_str.split('.')[0])  # Remove fractional seconds

            return SyslogMessage(
                source_ip=source_ip,
                source_port=source_port,
                facility=facility,
                severity=severity,
                timestamp=timestamp,
                hostname=source_ip,  # Use source IP as hostname
                message=match.group(4),
                rfc_format="3164",
                raw_message=raw_message,
                parse_errors=["Parsed as Cisco-style syslog"]
            )
        except Exception as e:
            logger.debug(f"Cisco-style parsing failed: {e}")

    return None


def parse_syslog(
    raw_message: str,
    source_ip: str,
    source_port: int
) -> SyslogMessage:
    """
    Auto-detect and parse syslog message (RFC 5424 or RFC 3164).

    Args:
        raw_message: Raw syslog message bytes or string
        source_ip: Source IP address
        source_port: Source port

    Returns:
        SyslogMessage (may have parse_errors if partially parsed)
    """
    # Handle bytes
    if isinstance(raw_message, bytes):
        try:
            raw_message = raw_message.decode('utf-8')
        except UnicodeDecodeError:
            raw_message = raw_message.decode('latin-1')

    raw_message = raw_message.strip()

    # Check if RFC 5424 format (starts with <PRI>1)
    if RFC5424_PATTERN.match(raw_message):
        result = parse_rfc5424(raw_message, source_ip, source_port)
        if result:
            return result

    # Try RFC 3164 format
    result = parse_rfc3164(raw_message, source_ip, source_port)
    if result:
        return result

    # Fallback: extract just the PRI if present
    pri_match = re.match(r'^<(\d{1,3})>(.*)', raw_message, re.DOTALL)
    if pri_match:
        pri = int(pri_match.group(1))
        facility, severity = parse_priority(pri)
        return SyslogMessage(
            source_ip=source_ip,
            source_port=source_port,
            facility=facility,
            severity=severity,
            message=pri_match.group(2),
            hostname=source_ip,
            rfc_format="unknown",
            raw_message=raw_message,
            parse_errors=["Could not fully parse message, extracted PRI only"]
        )

    # Complete fallback
    return SyslogMessage(
        source_ip=source_ip,
        source_port=source_port,
        facility=1,  # USER
        severity=6,  # INFO
        message=raw_message,
        hostname=source_ip,
        rfc_format="unknown",
        raw_message=raw_message,
        parse_errors=["Could not parse message, stored as-is"]
    )
