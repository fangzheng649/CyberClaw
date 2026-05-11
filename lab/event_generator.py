"""CyberClaw Event Generator — test harness for syslog collector.

Sends realistic IoT security events via UDP syslog to the collector.
This is a TEST TOOL, not fake data — it generates standardized test inputs
that flow through the real collector pipeline.

Usage:
  python lab/event_generator.py                    # send a burst of events
  python lab/event_generator.py --loop --interval 5  # continuous mode
  python lab/event_generator.py --port 8514         # custom port
"""
import argparse
import json
import random
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Syslog RFC5424 format ─────────────────────────────────────────

def format_syslog(facility: int, severity: int, hostname: str, msg: str) -> bytes:
    pri = facility * 8 + severity
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return f"<{pri}>1 {timestamp} {hostname} - - - {msg}".encode("utf-8")


# ── Test event templates ──────────────────────────────────────────
# These represent realistic IoT security scenarios for lab testing.

SECURITY_EVENTS = [
    # ── Brute force login attempts ────────────────────────────────
    {
        "facility": 1, "severity": 4,  # user/warning
        "hostname": "10.0.0.11",
        "message": "Login failed for user 'admin' from 10.0.1.100 via Telnet (attempt 1/20)",
    },
    {
        "facility": 1, "severity": 2,  # user/critical
        "hostname": "10.0.0.11",
        "message": "Login successful for user 'admin' from 10.0.1.100 via Telnet after 8 attempts",
    },
    {
        "facility": 1, "severity": 4,
        "hostname": "10.0.0.12",
        "message": "Login failed for user 'root' from 10.0.1.100 via Telnet (attempt 3/20)",
    },
    # ── Port scanning detected ────────────────────────────────────
    {
        "facility": 0, "severity": 4,  # kernel/warning
        "hostname": "10.0.0.1",
        "message": "SYN flood detected from 10.0.1.100 targeting 10.0.0.0/24 port range 1-1024",
    },
    {
        "facility": 0, "severity": 3,  # kernel/error
        "hostname": "10.0.0.1",
        "message": "Port scan detected: 10.0.1.100 scanned 10.0.0.11 ports 23,80,554,8080 in 2.3s",
    },
    # ── Configuration changes ─────────────────────────────────────
    {
        "facility": 10, "severity": 5,  # security-auth/notice
        "hostname": "10.0.0.11",
        "message": "Configuration changed: firmware update initiated from 10.0.1.100",
    },
    {
        "facility": 10, "severity": 2,
        "hostname": "10.0.0.13",
        "message": "New user 'backdoor' created with admin privileges by unknown source",
    },
    # ── Anomalous network behavior ────────────────────────────────
    {
        "facility": 0, "severity": 3,
        "hostname": "10.0.0.11",
        "message": "Outbound connection from IoT device to external IP 185.220.101.34:4443 (suspicious)",
    },
    {
        "facility": 0, "severity": 2,
        "hostname": "10.0.0.11",
        "message": "Lateral scan: device attempting SSH to 10.0.0.12, 10.0.0.13, 10.0.0.14",
    },
    # ── Service disruptions ───────────────────────────────────────
    {
        "facility": 1, "severity": 3,
        "hostname": "10.0.0.21",
        "message": "Temperature sensor reading anomaly: 999.9°C (possible sensor compromise)",
    },
    {
        "facility": 1, "severity": 4,
        "hostname": "10.0.0.50",
        "message": "MQTT broker: unusual publish rate from 10.0.0.11 (500 msg/s, normal: 5 msg/s)",
    },
    # ── Normal operational events (for contrast) ──────────────────
    {
        "facility": 1, "severity": 6,  # user/info
        "hostname": "10.0.0.22",
        "message": "Pressure reading normal: 101.3 kPa",
    },
    {
        "facility": 1, "severity": 6,
        "hostname": "10.0.0.31",
        "message": "SmartPlug power state: ON, consumption 45W",
    },
    {
        "facility": 16, "severity": 6,  # local-use0/info
        "hostname": "10.0.0.0",
        "message": "Network topology stable: 11 devices online, 0 alerts",
    },
    # ── Malware indicators ────────────────────────────────────────
    {
        "facility": 0, "severity": 1,  # kernel/alert
        "hostname": "10.0.0.11",
        "message": "CRITICAL: Mirai-like process detected — binary /tmp/.mirai executing C2 callbacks to 185.220.101.34",
    },
    {
        "facility": 0, "severity": 1,
        "hostname": "10.0.0.12",
        "message": "CRITICAL: Known malware signature detected in outbound traffic — Mirai DDoS bot participation",
    },
]

SEVERITY_NAMES = {0: "emergency", 1: "alert", 2: "critical", 3: "error",
                  4: "warning", 5: "notice", 6: "info", 7: "debug"}

_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent / "config" / "topology.json"


def load_device_ips() -> dict[str, str]:
    """Load device IP→name mapping from topology config."""
    try:
        with open(_TOPOLOGY_PATH, encoding="utf-8") as f:
            config = json.load(f)
        return {d["ip"]: d["name"] for d in config["devices"]}
    except Exception:
        return {}


def send_syslog_events(host: str, port: int, events: list[dict] | None = None):
    """Send syslog events via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    events = events or SECURITY_EVENTS

    sent = 0
    for evt in events:
        data = format_syslog(evt["facility"], evt["severity"], evt["hostname"], evt["message"])
        try:
            sock.sendto(data, (host, port))
            sev_name = SEVERITY_NAMES.get(evt["severity"], "?")
            print(f"  [{sev_name:>9}] {evt['hostname']}: {evt['message'][:80]}")
            sent += 1
        except Exception as e:
            print(f"  [ERROR] Failed to send to {host}:{port}: {e}")
            break
        time.sleep(0.05)  # slight delay to avoid overwhelming receiver

    sock.close()
    return sent


def main():
    parser = argparse.ArgumentParser(description="CyberClaw test event generator")
    parser.add_argument("--host", default="127.0.0.1", help="Syslog collector host")
    parser.add_argument("--port", type=int, default=8514, help="Syslog collector port (default: 8514)")
    parser.add_argument("--loop", action="store_true", help="Continuous mode")
    parser.add_argument("--interval", type=int, default=10, help="Seconds between bursts (default: 10)")
    parser.add_argument("--random", action="store_true", help="Shuffle event order")
    args = parser.parse_args()

    print(f"CyberClaw Event Generator → {args.host}:{args.port}")
    print(f"Mode: {'continuous' if args.loop else 'single burst'}")
    print(f"Events per burst: {len(SECURITY_EVENTS)}")
    print()

    burst = 0
    while True:
        burst += 1
        events = list(SECURITY_EVENTS)
        if args.random:
            random.shuffle(events)

        print(f"--- Burst #{burst} ({len(events)} events) @ {datetime.now().strftime('%H:%M:%S')} ---")
        sent = send_syslog_events(args.host, args.port, events)
        print(f"  Sent: {sent}/{len(events)} events\n")

        if not args.loop:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
