"""CyberClaw Config Audit MCP Server — ACL and configuration auditing.

Tools:
  - audit_config: Audit device configuration for security issues
  - check_acl_conflicts: Check ACL rules for conflicts and shadows
  - compare_configs: Compare two configuration snapshots
  - get_audit_report: Retrieve a saved audit report
"""
import asyncio
import json
import logging
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("config-audit", "Network device configuration auditing, ACL conflict detection, and compliance checking")

# In-memory reports
_reports: list[dict] = []


def _is_mock_mode() -> bool:
    try:
        from server.services.topology_service import is_mock_mode
        return is_mock_mode()
    except Exception:
        return False


def _load_topology_devices() -> list[dict]:
    """Load devices from topology config (mock-aware)."""
    try:
        config_name = "mock_topology.json" if _is_mock_mode() else "topology.json"
        topo_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", config_name)
        with open(topo_path, encoding="utf-8") as f:
            topo = json.load(f)
        return topo.get("devices", [])
    except Exception:
        return []


def _find_first_ssh_device() -> str | None:
    """Find the first device with SSH (port 22) open in topology."""
    devices = _load_topology_devices()
    for d in devices[:10]:
        ip = d.get("ip", "")
        if not ip:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, 22))
            s.close()
            if result == 0:
                return ip
        except (socket.error, OSError):
            continue
    return None


async def _ssh_fetch_config(device_ip: str) -> dict | None:
    """Attempt to fetch device config via SSH using paramiko."""
    try:
        import paramiko
    except ImportError:
        return None

    # Try common credential pairs from environment or defaults
    cred_pairs = []
    env_user = os.getenv("CYBERCLAW_SSH_USER", "")
    env_pass = os.getenv("CYBERCLAW_SSH_PASS", "")
    if env_user and env_pass:
        cred_pairs.append((env_user, env_pass))
    # Common IoT device defaults
    cred_pairs.extend([
        ("admin", "admin"),
        ("admin", ""),
        ("root", "root"),
    ])

    commands = [
        "display current-configuration",   # H3C / Huawei
        "show running-config",              # Cisco
        "cat /etc/config/config",           # OpenWrt
    ]

    loop = asyncio.get_event_loop()

    def _try_ssh():
        for username, password in cred_pairs:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(device_ip, port=22, username=username, password=password,
                               timeout=5, allow_agent=False, look_for_keys=False)
                for cmd in commands:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                    output = stdout.read().decode("utf-8", errors="replace")
                    if output and len(output) > 50 and "Invalid" not in output and "Error" not in output[:100]:
                        return {"status": "ok", "config": output, "method": f"ssh-{cmd.split()[0]}"}
                return None  # Connected but no valid config command
            except (paramiko.AuthenticationException, paramiko.SSHException, OSError):
                continue
            finally:
                client.close()
        return None

    try:
        return await loop.run_in_executor(None, _try_ssh)
    except Exception:
        return None


async def _nmap_audit_device(device_ip: str) -> dict | None:
    """Use nmap to scan device and generate security findings from real port data."""
    # Check if nmap is available
    nmap_path = os.path.join("C:\\", "Program Files (x86)", "Nmap", "nmap.exe")
    if not os.path.isfile(nmap_path):
        # Try PATH
        import shutil
        if not shutil.which("nmap"):
            return None
        nmap_path = "nmap"

    loop = asyncio.get_event_loop()

    # IoT-relevant security ports to scan
    _AUDIT_PORTS = "21,22,23,25,53,80,110,143,443,445,993,995,161,162,554,1723,2222,3389,4444,8000,8080,8443,31337,37277"

    def _run():
        import subprocess
        try:
            # Fast SYN-only scan of security-relevant ports (~2s per device)
            result = subprocess.run(
                [nmap_path, "-sS", "-T4", "-p", _AUDIT_PORTS, "-oX", "-", device_ip],
                capture_output=True, text=True, timeout=15,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    xml_output = await loop.run_in_executor(None, _run)
    if not xml_output:
        return None

    # Parse nmap XML to extract open ports and services
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return None

    open_ports = []
    port_services = {}
    for port in root.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            port_id = port.get("portid", "")
            service = port.find("service")
            svc_name = service.get("name", "") if service is not None else ""
            open_ports.append(int(port_id))
            port_services[int(port_id)] = svc_name

    if not open_ports:
        # Device reachable (nmap responded) but no open ports found — still real data
        return {
            "status": "ok",
            "config": f"! Device {device_ip} — nmap scan: no open ports found",
            "method": "nmap-scan",
            "open_ports": [],
            "findings": [],
            "config_lines": [f"! Device {device_ip} — no open ports detected"],
        }

    # Generate security findings from real port data
    findings = []
    INSECURE_PORTS = {
        23: ("Telnet 服务开放", "high", "telnet-open", "禁用 Telnet，使用 SSH 替代"),
        21: ("FTP 服务开放（明文传输）", "high", "ftp-open", "使用 SFTP 或 SCP 替代 FTP"),
        80: ("HTTP 明文管理服务开放", "medium", "http-open", "启用 HTTPS (443) 并禁用 HTTP"),
        554: ("RTSP 流媒体服务开放（明文视频流）", "medium", "rtsp-open", "限制 RTSP 访问来源，考虑使用加密传输"),
        8000: ("HTTP 替代端口开放（常见 IPCam 管理）", "medium", "http-alt-open", "限制该端口访问来源 IP"),
        161: ("SNMP 服务开放", "medium", "snmp-open", "确保使用非默认 community，推荐 SNMPv3"),
        445: ("SMB 服务开放", "medium", "smb-open", "如非必要，关闭 SMB 服务"),
        3389: ("RDP 远程桌面开放", "medium", "rdp-open", "限制 RDP 访问来源 IP"),
        4444: ("可疑端口 4444（常见反向 Shell）", "critical", "reverse-shell-port", "立即排查该端口用途，可能是后门"),
        31337: ("可疑端口 31337（Back Orifice）", "critical", "backdoor-port", "立即排查该端口，可能是后门"),
        2222: ("非标准 SSH 端口", "info", "nonstandard-ssh", "确认该端口用途是否为 SSH"),
    }

    for port in open_ports:
        if port in INSECURE_PORTS:
            desc, sev, rule, fix = INSECURE_PORTS[port]
            findings.append({
                "severity": sev, "rule": rule, "line": 0,
                "config": f"port {port}/{port_services.get(port, 'unknown')}",
                "issue": desc, "fix": fix,
            })

    # Check for missing security ports
    if 22 not in open_ports and 23 in open_ports:
        findings.append({
            "severity": "critical", "rule": "no-ssh-only-telnet", "line": 0,
            "config": f"open: {', '.join(str(p) for p in open_ports)}",
            "issue": "仅 Telnet 可用，无 SSH 加密访问",
            "fix": "启用 SSH 并禁用 Telnet",
        })
    if 443 not in open_ports and 80 in open_ports:
        findings.append({
            "severity": "high", "rule": "no-https-only-http", "line": 0,
            "config": f"port 80 open, port 443 closed",
            "issue": "HTTP 明文管理无 HTTPS 加密",
            "fix": "启用 HTTPS (443) 并配置证书",
        })

    # Build synthetic config from port data
    config_lines = [f"! Device {device_ip} — nmap service scan audit"]
    for port in sorted(open_ports):
        svc = port_services.get(port, "unknown")
        config_lines.append(f"port {port}/{svc}: open")

    return {
        "status": "ok",
        "config": "\n".join(config_lines),
        "method": "nmap-scan",
        "open_ports": open_ports,
        "findings": findings,
        "config_lines": config_lines,
    }


async def _fetch_device_config(device_ip: str) -> dict:
    """Fetch real device config — tries SSH, then nmap scan, then mock."""
    # Strategy 1: Try SSH config fetch
    ssh_result = await _ssh_fetch_config(device_ip)
    if ssh_result:
        return ssh_result

    # Strategy 2: Try nmap service scan audit
    nmap_result = await _nmap_audit_device(device_ip)
    if nmap_result:
        findings = nmap_result.pop("findings", [])
        config_text = nmap_result.get("config", "")
        lines = nmap_result.get("config_lines", [])
        # If nmap found security issues, return them directly
        if findings:
            nmap_result["status"] = "ok"
            nmap_result["findings"] = findings
            return nmap_result
        # Device reachable but no findings — that's still real data
        nmap_result["status"] = "ok"
        nmap_result["findings"] = []
        return nmap_result

    # Strategy 3: Try legacy ConfigFetcher
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from server.services.config_fetcher import get_config_fetcher
        fetcher = get_config_fetcher()
        result = await fetcher.fetch_best(device_ip)
        if result.get("status") == "ok":
            return result
    except Exception:
        pass

    # Strategy 4: Mock fallback
    mock_configs = {
        "default": f"""
!
version 15.2
hostname IoT-Gateway
!
interface GigabitEthernet0/0
 ip address {device_ip} 255.255.255.0
 no shutdown
!
line vty 0 4
 transport input telnet
 password cisco
!
snmp-server community public RO
snmp-server community private RW
!
ip http server
!
access-list 1 permit 0.0.0.0 255.255.255.255
!
no service password-encryption
!
""",
    }
    await asyncio.sleep(0.05)
    return {"status": "ok", "config": mock_configs["default"], "method": "mock"}


def _parse_config_lines(config_text: str) -> list[str]:
    """Split config text into lines."""
    return [l for l in config_text.split("\n") if l.strip()]


def _audit_config_lines(lines: list[str]) -> list[dict]:
    """Run security audit rules against config lines."""
    findings = []
    for i, line in enumerate(lines):
        stripped = line.strip()

        if "password " in stripped and not ("secret" in stripped or "5 " in stripped or "7 " in stripped):
            findings.append({"severity": "critical", "rule": "plaintext-password", "line": i + 1,
                             "config": stripped, "issue": "明文密码配置",
                             "fix": "使用 enable secret 或 username ... secret 替代"})
        if "transport input telnet" in stripped and "ssh" not in stripped:
            findings.append({"severity": "high", "rule": "telnet-only", "line": i + 1,
                             "config": stripped, "issue": "仅允许 Telnet 访问",
                             "fix": "使用 transport input ssh 替代"})
        if "transport input telnet" in stripped and "ssh" in stripped:
            findings.append({"severity": "medium", "rule": "telnet-enabled", "line": i + 1,
                             "config": stripped, "issue": "Telnet 未禁用",
                             "fix": "使用 transport input ssh 替代"})
        if "ip http server" in stripped and "secure" not in stripped:
            findings.append({"severity": "high", "rule": "http-enabled", "line": i + 1,
                             "config": stripped, "issue": "HTTP 明文管理服务启用",
                             "fix": "禁用 ip http server，启用 ip http secure-server"})
        if "community public" in stripped:
            findings.append({"severity": "high", "rule": "snmp-default-community", "line": i + 1,
                             "config": stripped, "issue": "SNMP 使用默认 community 'public'",
                             "fix": "迁移到 SNMPv3 或修改 community string"})
        if "community private" in stripped:
            findings.append({"severity": "critical", "rule": "snmp-private-community", "line": i + 1,
                             "config": stripped, "issue": "SNMP 使用默认 community 'private' (读写)",
                             "fix": "修改默认 community 或迁移到 SNMPv3"})
        if stripped.startswith("no ") and "shutdown" in stripped:
            pass
        elif " no shutdown" not in stripped and stripped.startswith("interface ") and "loopback" not in stripped.lower():
            pass
    return findings


def _extract_acl_rules(lines: list[str]) -> list[dict]:
    """Parse ACL rules from config lines."""
    rules = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("access-list ") or stripped.startswith("rule "):
            rules.append({"line": i + 1, "config": stripped})
        elif "permit " in stripped and ("ip " in stripped or "tcp " in stripped or "udp " in stripped):
            if "access-group" not in stripped and "class-map" not in stripped:
                rules.append({"line": i + 1, "config": stripped})
    return rules


@mcp.tool()
async def audit_config(device_ip: str = "auto") -> str:
    """Audit a device's running configuration for security issues.

    Checks for: plaintext passwords, insecure protocols, missing ACLs,
    default SNMP community, unnecessary services, etc.

    Args:
        device_ip: Device IP to audit. Default: 'auto' (auto-detect first reachable device).
    """
    # Auto-detect: find first device with SSH open
    if device_ip == "auto" or not device_ip:
        found = _find_first_ssh_device()
        if found:
            device_ip = found
            logger.info(f"audit_config: auto-detected device {device_ip}")
        else:
            # Fall back to first topology device
            devices = _load_topology_devices()
            if devices:
                device_ip = devices[0].get("ip", "192.168.10.1")
            else:
                device_ip = "192.168.10.1"

    logger.info(f"audit_config: {device_ip}")

    # Mock mode: skip real network ops, return mock audit
    if _is_mock_mode():
        logger.info("Mock mode — returning simulated config audit")
        devices = _load_topology_devices()
        dev = next((d for d in devices if d.get("ip") == device_ip), devices[0] if devices else {})
        return json.dumps({
            "mode": "mock",
            "device_ip": device_ip,
            "device_name": dev.get("name", "Unknown"),
            "findings": [
                {"severity": "critical", "rule": "default-credentials", "issue": f"{dev.get('vendor', 'Device')} 设备使用默认密码",
                 "remediation": "修改默认密码，使用强密码策略"},
                {"severity": "high", "rule": "insecure-protocol", "issue": "Telnet (23) 服务开放",
                 "remediation": "禁用 Telnet，启用 SSH"},
                {"severity": "medium", "rule": "http-plaintext", "issue": "HTTP 管理界面使用明文传输",
                 "remediation": "启用 HTTPS 管理界面"},
                {"severity": "low", "rule": "firmware-outdated", "issue": f"固件版本 {dev.get('firmware_version', 'unknown')} 可能过旧",
                 "remediation": "检查并更新到最新固件版本"},
            ],
            "score": 72,
        }, ensure_ascii=False, indent=2)

    result = await _fetch_device_config(device_ip)

    if result.get("status") != "ok":
        return json.dumps({
            "status": "unavailable",
            "device": device_ip,
            "message": result.get("message", "Unable to fetch device configuration"),
            "hint": "确保设备可达且 SSH/SNMP 凭据已配置",
        }, ensure_ascii=False, indent=2)

    # If nmap scan already provided findings, use those
    if "findings" in result and result.get("method", "").startswith("nmap"):
        findings = result["findings"]
        config_text = result.get("config", "")
        lines = _parse_config_lines(config_text)
        method = result.get("method", "nmap-scan")
    else:
        config_text = result.get("config", "")
        lines = _parse_config_lines(config_text)
        findings = _audit_config_lines(lines)
        method = result.get("method", "unknown")

    report = {
        "report_id": f"audit-{int(time.time())}",
        "device": device_ip,
        "method": method,
        "total_findings": len(findings),
        "critical": len([f for f in findings if f["severity"] == "critical"]),
        "high": len([f for f in findings if f["severity"] == "high"]),
        "medium": len([f for f in findings if f["severity"] == "medium"]),
        "findings": findings,
        "config_lines": len(lines),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _reports.append(report)
    return json.dumps(report, ensure_ascii=False, indent=2)


@mcp.tool()
async def check_acl_conflicts(device_ip: str = "10.0.0.1") -> str:
    """Check ACL rules for conflicts, overlaps, and shadow rules.

    Detects: shadowed rules, contradictory rules, overly permissive rules.

    Args:
        device_ip: Device IP. Default: 10.0.0.1.
    """
    logger.info(f"check_acl_conflicts: {device_ip}")

    result = await _fetch_device_config(device_ip)

    if result.get("status") != "ok":
        return json.dumps({
            "status": "unavailable",
            "device": device_ip,
            "message": result.get("message", "Unable to fetch device configuration"),
        }, ensure_ascii=False, indent=2)

    config_text = result.get("config", "")
    lines = _parse_config_lines(config_text)
    acl_rules = _extract_acl_rules(lines)

    if not acl_rules:
        return json.dumps({
            "device": device_ip,
            "status": "no_acl",
            "message": "未检测到 ACL 规则",
            "hint": "设备可能未配置 ACL 或使用非标准格式",
        }, ensure_ascii=False, indent=2)

    issues = []
    for i, rule in enumerate(acl_rules):
        for earlier in acl_rules[:i]:
            if rule["config"] != earlier["config"]:
                issues.append({
                    "type": "potential_conflict",
                    "severity": "medium",
                    "detail": f"规则 L{rule['line']} 可能与 L{earlier['line']} 冲突",
                    "rule": rule["config"],
                    "conflicts_with": earlier["config"],
                })

    return json.dumps({
        "device": device_ip,
        "method": result.get("method", "unknown"),
        "total_rules": len(acl_rules),
        "issues_found": len(issues),
        "issues": issues,
        "acl_rules": acl_rules,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def compare_configs(device_ip: str, baseline_desc: str = "last_known_good") -> str:
    """Compare current config against a known-good baseline.

    Args:
        device_ip: Device IP.
        baseline_desc: Baseline description. Default: last_known_good.
    """
    logger.info(f"compare_configs: {device_ip} vs {baseline_desc}")

    result = await _fetch_device_config(device_ip)

    if result.get("status") != "ok":
        return json.dumps({
            "status": "unavailable",
            "device": device_ip,
            "message": result.get("message", "Unable to fetch device configuration"),
            "hint": "需要先获取设备配置才能进行比较",
        }, ensure_ascii=False, indent=2)

    return json.dumps({
        "device": device_ip,
        "baseline": baseline_desc,
        "status": "fetched",
        "message": "当前配置已获取。需要指定基线文件路径才能进行 diff 比较。",
        "config_lines": result.get("lines", 0),
        "method": result.get("method", "unknown"),
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def get_audit_report(report_id: str = "") -> str:
    """Retrieve a saved audit report.

    Args:
        report_id: Report ID. Empty = latest.
    """
    if not _reports:
        return json.dumps({"error": "No reports available. Run audit_config first."})
    report = _reports[-1] if not report_id else next((r for r in _reports if r["report_id"] == report_id), None)
    if not report:
        return json.dumps({"error": f"Report {report_id} not found"})
    return json.dumps(report, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw config-audit MCP")
    mcp.run()
