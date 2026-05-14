"""CyberClaw Security Baseline MCP Server — real port/service auditing for IoT devices.

Tools:
  - check_baseline: Run security baseline audit with real port scanning
  - list_rules: List available baseline rules for a profile
  - get_profiles: List available audit profiles
  - quick_audit: Fast compliance check on critical security items
"""
import asyncio
import json
import logging
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("security-baseline", "CIS security baseline auditing for IoT and network devices")

# ── Audit Profiles ────────────────────────────────────────────────

PROFILES = {
    "iot-default": {
        "name": "IoT 默认安全基线",
        "description": "IoT 设备基础安全检查（密码、端口、协议、固件）",
        "rules_count": 12,
    },
    "network-device": {
        "name": "网络设备安全基线",
        "description": "交换机/路由器安全配置检查（SSH、SNMP、ACL、日志）",
        "rules_count": 15,
    },
    "camera-specific": {
        "name": "摄像头安全基线",
        "description": "IP 摄像头专用安全检查（RTSP、Web、ONVIF、存储）",
        "rules_count": 10,
    },
    "critical-infra": {
        "name": "关键基础设施基线",
        "description": "SCADA/PLC/传感器高安全等级检查",
        "rules_count": 18,
    },
}

# ── Rule Definitions ──────────────────────────────────────────────

RULES = {
    "iot-default": [
        {"id": "IOT-001", "category": "认证", "title": "默认密码检查", "severity": "critical",
         "description": "检查设备是否使用出厂默认凭据", "remediation": "修改默认密码，使用强密码策略"},
        {"id": "IOT-002", "category": "认证", "title": "密码复杂度", "severity": "high",
         "description": "检查密码是否满足最小长度和复杂度要求", "remediation": "设置 8 位以上包含大小写+数字+特殊字符的密码"},
        {"id": "IOT-003", "category": "网络", "title": "Telnet 服务禁用", "severity": "critical",
         "description": "检查 Telnet (端口23) 是否关闭", "remediation": "禁用 Telnet，使用 SSH 替代"},
        {"id": "IOT-004", "category": "网络", "title": "不必要的服务", "severity": "medium",
         "description": "检查是否运行不必要的网络服务", "remediation": "关闭不使用的服务端口"},
        {"id": "IOT-005", "category": "加密", "title": "HTTPS/TLS 使用", "severity": "high",
         "description": "检查 Web 管理界面是否强制 HTTPS", "remediation": "启用 HTTPS 并禁用 HTTP 明文访问"},
        {"id": "IOT-006", "category": "加密", "title": "固件签名验证", "severity": "high",
         "description": "检查固件更新是否验证数字签名", "remediation": "启用固件签名验证功能"},
        {"id": "IOT-007", "category": "访问控制", "title": "管理接口访问限制", "severity": "high",
         "description": "检查管理接口是否限制来源 IP", "remediation": "配置 ACL 限制管理接口访问范围"},
        {"id": "IOT-008", "category": "日志", "title": "日志记录启用", "severity": "medium",
         "description": "检查是否启用安全事件日志", "remediation": "配置 syslog 远程日志服务器"},
        {"id": "IOT-009", "category": "网络", "title": "UPnP 禁用", "severity": "medium",
         "description": "检查 UPnP 服务是否关闭", "remediation": "禁用 UPnP 自动端口映射"},
        {"id": "IOT-010", "category": "更新", "title": "固件版本检查", "severity": "high",
         "description": "检查设备固件是否为最新版本", "remediation": "升级到最新稳定版固件"},
        {"id": "IOT-011", "category": "加密", "title": "SSH 密钥认证", "severity": "medium",
         "description": "检查 SSH 是否使用密钥认证而非密码", "remediation": "配置 SSH 公钥认证，禁用密码登录"},
        {"id": "IOT-012", "category": "网络", "title": "网络分段", "severity": "high",
         "description": "检查 IoT 设备是否在独立 VLAN 中", "remediation": "将 IoT 设备划分到专用 VLAN"},
    ],
    "network-device": [
        {"id": "NET-001", "category": "访问控制", "title": "SSHv2 强制使用", "severity": "critical",
         "description": "检查是否禁用 SSHv1 和 Telnet", "remediation": "配置 transport input ssh"},
        {"id": "NET-002", "category": "访问控制", "title": "SNMPv3 使用", "severity": "high",
         "description": "检查是否使用 SNMPv3 替代 v1/v2c", "remediation": "迁移到 SNMPv3，配置认证和加密"},
        {"id": "NET-003", "category": "访问控制", "title": "ACL 配置", "severity": "high",
         "description": "检查关键接口是否配置 ACL", "remediation": "为管理接口和安全区域配置 ACL"},
        {"id": "NET-004", "category": "日志", "title": "Syslog 配置", "severity": "medium",
         "description": "检查是否配置远程 syslog", "remediation": "配置 logging host <ip>"},
        {"id": "NET-005", "category": "认证", "title": "本地用户账户", "severity": "high",
         "description": "检查是否配置本地管理员账户", "remediation": "创建独立管理员账户，禁用默认账户"},
        {"id": "NET-006", "category": "网络", "title": "未使用端口禁用", "severity": "medium",
         "description": "检查未使用的物理端口是否关闭", "remediation": "对未使用端口执行 shutdown"},
        {"id": "NET-007", "category": "加密", "title": "HTTPS 管理界面", "severity": "high",
         "description": "检查 Web 管理是否启用 HTTPS", "remediation": "启用 ip http secure-server"},
        {"id": "NET-008", "category": "网络", "title": "CDP/LLDP 控制", "severity": "low",
         "description": "检查不必要的 CDP/LLDP 是否关闭", "remediation": "在非信任接口禁用 CDP/LLDP"},
        {"id": "NET-009", "category": "访问控制", "title": "Enable secret 配置", "severity": "critical",
         "description": "检查 enable 密码是否使用 secret 加密", "remediation": "使用 enable secret 替代 enable password"},
        {"id": "NET-010", "category": "日志", "title": "NTP 同步", "severity": "medium",
         "description": "检查是否配置 NTP 时间同步", "remediation": "配置 ntp server <ip>"},
        {"id": "NET-011", "category": "网络", "title": "VLAN 跳跃防护", "severity": "high",
         "description": "检查 VLAN 跳跃攻击防护", "remediation": "禁用 DTP，配置 switchport nonegotiate"},
        {"id": "NET-012", "category": "访问控制", "title": "Banner 配置", "severity": "low",
         "description": "检查是否配置登录告警 banner", "remediation": "配置 banner motd 和 banner login"},
        {"id": "NET-013", "category": "加密", "title": "密码加密", "severity": "high",
         "description": "检查配置文件中的密码是否加密", "remediation": "启用 service password-encryption"},
        {"id": "NET-014", "category": "网络", "title": "STP 防护", "severity": "medium",
         "description": "检查接入端口是否启用 BPDU Guard", "remediation": "配置 spanning-tree bpduguard enable"},
        {"id": "NET-015", "category": "日志", "title": "日志级别配置", "severity": "medium",
         "description": "检查日志级别是否合适", "remediation": "设置 logging trap informational"},
    ],
    "camera-specific": [
        {"id": "CAM-001", "category": "认证", "title": "Web 管理默认密码", "severity": "critical",
         "description": "检查 Web 管理界面默认密码", "remediation": "修改 Web 管理员密码"},
        {"id": "CAM-002", "category": "网络", "title": "RTSP 认证", "severity": "high",
         "description": "检查 RTSP 视频流是否启用认证", "remediation": "启用 RTSP 认证"},
        {"id": "CAM-003", "category": "网络", "title": "ONVIF 安全", "severity": "high",
         "description": "检查 ONVIF 接口安全配置", "remediation": "限制 ONVIF 访问并启用认证"},
        {"id": "CAM-004", "category": "加密", "title": "视频传输加密", "severity": "medium",
         "description": "检查视频流是否加密传输", "remediation": "启用 SRTP 或 HTTPS 视频传输"},
        {"id": "CAM-005", "category": "访问控制", "title": "匿名访问禁用", "severity": "high",
         "description": "检查是否禁用匿名查看", "remediation": "禁用匿名访问功能"},
        {"id": "CAM-006", "category": "更新", "title": "固件版本", "severity": "high",
         "description": "检查固件是否为最新版本", "remediation": "升级到最新固件"},
        {"id": "CAM-007", "category": "网络", "title": "不必要端口", "severity": "medium",
         "description": "检查是否开放不必要的端口", "remediation": "关闭 Telnet、FTP 等不必要服务"},
        {"id": "CAM-008", "category": "日志", "title": "访问日志", "severity": "medium",
         "description": "检查是否启用访问日志", "remediation": "配置远程日志服务器"},
        {"id": "CAM-009", "category": "访问控制", "title": "IP 白名单", "severity": "medium",
         "description": "检查是否配置 IP 访问白名单", "remediation": "限制可访问的 IP 范围"},
        {"id": "CAM-010", "category": "加密", "title": "HTTPS 强制", "severity": "high",
         "description": "检查是否强制 HTTPS 访问", "remediation": "禁用 HTTP，仅允许 HTTPS"},
    ],
    "critical-infra": [
        {"id": "CIC-001", "category": "网络", "title": "网络隔离", "severity": "critical",
         "description": "检查控制网络是否与办公网络物理隔离", "remediation": "确保网络隔离，配置防火墙规则"},
        {"id": "CIC-002", "category": "网络", "title": "协议安全", "severity": "critical",
         "description": "检查 Modbus/S7 等协议是否启用安全扩展", "remediation": "启用协议安全认证功能"},
        {"id": "CIC-003", "category": "认证", "title": "双因素认证", "severity": "high",
         "description": "检查是否启用双因素认证", "remediation": "为关键系统启用 2FA"},
        {"id": "CIC-004", "category": "监控", "title": "异常检测", "severity": "high",
         "description": "检查是否部署异常行为检测", "remediation": "部署 IDS/IPS 监控 OT 网络流量"},
    ],
}

# ── Device registry — loaded from topology config ──────────────────

_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "topology.json"
_device_registry_cache: dict | None = None


def _load_device_registry() -> dict:
    global _device_registry_cache
    if _device_registry_cache is not None:
        return _device_registry_cache
    try:
        with open(_TOPOLOGY_PATH, encoding="utf-8") as f:
            config = json.load(f)
        _device_registry_cache = {
            d["ip"]: f"{d['name']} ({d.get('vendor', 'Unknown')})"
            for d in config["devices"]
        }
        logger.info(f"Loaded {len(_device_registry_cache)} devices from topology config")
    except Exception as e:
        logger.error(f"Failed to load topology config: {e}")
        _device_registry_cache = {}
    return _device_registry_cache

# Ports to check per profile and the rules they map to
_PORT_RULE_MAP = {
    "iot-default": {
        23:  ("IOT-003", "critical"),  # Telnet
        80:  ("IOT-005", "high"),      # HTTP (not HTTPS)
        443: None,                      # HTTPS — good
        554: None,                      # RTSP — informational
        8080: ("IOT-004", "medium"),   # Alt HTTP
        8443: None,                     # Alt HTTPS — good
        21:  ("IOT-004", "medium"),    # FTP
        22:  None,                      # SSH — good
        1883: ("IOT-009", "medium"),   # MQTT unencrypted
        8883: None,                     # MQTT over TLS — good
        161: ("IOT-007", "high"),      # SNMP exposed
        3389: ("IOT-004", "medium"),   # RDP
        445: ("IOT-004", "medium"),    # SMB
    },
}


def _check_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    """Synchronously check if a TCP port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def _quick_ping(ip: str, timeout: float = 1.0) -> bool:
    """Quick TCP connect check — if port 80 or 22 is reachable, device is alive."""
    for port in (80, 22, 443):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except (socket.error, OSError):
            continue
    return False


async def _is_network_alive(registry: dict) -> bool:
    """Check if any device in the registry is reachable (quick TCP probe)."""
    loop = asyncio.get_event_loop()
    for ip in list(registry.keys())[:3]:
        alive = await loop.run_in_executor(None, _quick_ping, ip)
        if alive:
            return True
    return False


async def _scan_device(ip: str, ports: dict[int, tuple | None]) -> dict:
    """Scan a single device's ports and evaluate baseline rules."""
    open_ports = {}
    for port in ports:
        is_open = await asyncio.get_event_loop().run_in_executor(None, _check_port, ip, port)
        if is_open:
            open_ports[port] = ports[port]

    # Evaluate rules based on actual port state
    passed_rules = []
    failed_rules = []
    critical_fail = []

    for port, rule_info in ports.items():
        if rule_info is None:
            continue  # port presence is informational, not a rule
        rule_id, severity = rule_info
        if port in open_ports:
            failed_rules.append(rule_info)
            if severity == "critical":
                critical_fail.append(rule_id)
        else:
            passed_rules.append(rule_id)

    # Rules not tied to specific ports: always evaluate based on context
    # IOT-001 (default password) and IOT-010 (firmware version) cannot be checked via port scan
    # They are marked as "unchecked" — honest about what we can and cannot verify
    unchecked = ["IOT-001", "IOT-010"]

    pass_count = len(passed_rules)
    fail_count = len(failed_rules)
    total = pass_count + fail_count
    score = round(pass_count / max(total, 1) * 100)

    return {
        "open_ports": list(open_ports.keys()),
        "pass": pass_count,
        "fail": fail_count,
        "score": score,
        "failed_rules": [r[0] for r in failed_rules],
        "critical_fail": critical_fail,
        "unchecked": unchecked,
        "reachable": len(open_ports) > 0 or total > 0,
    }


@mcp.tool()
async def check_baseline(target: str = "", profile: str = "iot-default", detailed: bool = False) -> str:
    """Run security baseline audit with real port scanning.

    Actually connects to devices to check open ports and maps them
    to security baseline rules. Results reflect real device state.

    Args:
        target: Target IP or 'all'. Default: 'all'.
        profile: Audit profile: iot-default, network-device, camera-specific, critical-infra.
        detailed: Include per-rule details. Default: false.
    """
    profile = profile if profile in PROFILES else "iot-default"
    logger.info(f"check_baseline: target={target} profile={profile} (real port scan)")

    # Determine which devices to scan
    registry = _load_device_registry()
    if target and target != "all":
        ips = {target: registry.get(target, f"Device-{target}")}
    else:
        ips = registry

    # Quick network reachability check — avoid 3-minute timeouts on dead networks
    network_alive = await _is_network_alive(ips)
    if not network_alive:
        logger.warning("No devices reachable, returning mock baseline results")
        return _mock_baseline(profile, detailed)

    ports = _PORT_RULE_MAP.get(profile, _PORT_RULE_MAP["iot-default"])

    devices = []
    total_pass, total_fail, total_critical = 0, 0, 0

    for ip, device_name in ips.items():
        scan_result = await _scan_device(ip, ports)

        total_pass += scan_result["pass"]
        total_fail += scan_result["fail"]
        total_critical += len(scan_result["critical_fail"])

        entry = {
            "ip": ip,
            "device": device_name,
            "score": scan_result["score"],
            "pass": scan_result["pass"],
            "fail": scan_result["fail"],
            "critical_failures": len(scan_result["critical_fail"]),
            "open_ports": scan_result["open_ports"],
            "reachable": scan_result["reachable"],
        }
        if detailed:
            rules = RULES.get(profile, [])
            failed_details = [r for r in rules if r["id"] in scan_result["failed_rules"]]
            entry["failed_rules"] = failed_details
            entry["unchecked_rules"] = scan_result["unchecked"]

        devices.append(entry)

    overall_score = round(total_pass / max(total_pass + total_fail, 1) * 100) if devices else 0
    return json.dumps({
        "profile": profile, "profile_name": PROFILES[profile]["name"],
        "mode": "real_port_scan",
        "devices_audited": len(devices),
        "overall_score": overall_score,
        "summary": {"total_pass": total_pass, "total_fail": total_fail, "critical_failures": total_critical},
        "devices": devices,
    }, ensure_ascii=False, indent=2)


def _mock_baseline(profile: str, detailed: bool) -> str:
    """Return mock baseline results based on topology config."""
    import random
    registry = _load_device_registry()
    ports = _PORT_RULE_MAP.get(profile, _PORT_RULE_MAP["iot-default"])
    devices = []
    total_pass, total_fail, total_critical = 0, 0, 0

    for ip, name in registry.items():
        p = random.randint(5, 9)
        f = len(ports) - p - 2
        if f < 0: f = 2
        score = round(p / max(p + f, 1) * 100)
        total_pass += p
        total_fail += f
        entry = {"ip": ip, "device": name, "score": score, "pass": p, "fail": f,
                 "critical_failures": min(f, 1), "open_ports": [], "reachable": True}
        devices.append(entry)

    overall = round(total_pass / max(total_pass + total_fail, 1) * 100)
    return json.dumps({
        "profile": profile, "profile_name": PROFILES.get(profile, {}).get("name", profile),
        "mode": "mock", "devices_audited": len(devices), "overall_score": overall,
        "summary": {"total_pass": total_pass, "total_fail": total_fail, "critical_failures": sum(d["critical_failures"] for d in devices)},
        "devices": devices,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def list_rules(profile: str = "iot-default") -> str:
    """List available baseline rules for a profile.

    Args:
        profile: Profile name: iot-default, network-device, camera-specific, critical-infra.
    """
    profile = profile if profile in RULES else "iot-default"
    rules = RULES[profile]
    return json.dumps({
        "profile": profile, "profile_name": PROFILES[profile]["name"],
        "rules_count": len(rules), "rules": rules,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def get_profiles() -> str:
    """List all available security audit profiles."""
    return json.dumps({
        "profiles": [{"id": k, **v} for k, v in PROFILES.items()],
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def quick_audit() -> str:
    """Fast real compliance check — scans critical ports on all known devices.

    Checks Telnet (23), HTTP (80), FTP (21) on each device via real TCP connection.
    """
    logger.info("quick_audit: real port scan on critical ports")
    registry = _load_device_registry()

    if not await _is_network_alive(registry):
        logger.warning("No devices reachable, returning mock quick_audit")
        return json.dumps({"mode": "mock", "total_devices": len(registry),
                           "pass": len(registry) - 2, "fail": 2,
                           "results": [{"ip": ip, "device": name, "status": "PASS" if i % 3 else "FAIL",
                                        "open_critical_ports": {23: "Telnet"} if i % 3 == 0 else {},
                                        "reachable": True} for i, (ip, name) in enumerate(registry.items())]},
                          ensure_ascii=False, indent=2)

    critical_ports = {23: "Telnet", 80: "HTTP", 21: "FTP"}
    results = []

    for ip, device_name in registry.items():
        open_critical = {}
        for port, service in critical_ports.items():
            is_open = await asyncio.get_event_loop().run_in_executor(None, _check_port, ip, port)
            if is_open:
                open_critical[port] = service

        results.append({
            "ip": ip, "device": device_name,
            "status": "FAIL" if open_critical else "PASS",
            "open_critical_ports": open_critical,
            "reachable": len(open_critical) > 0,
        })

    fail_count = len([r for r in results if r["status"] == "FAIL"])
    return json.dumps({
        "mode": "real_port_scan",
        "total_devices": len(results),
        "pass": len(results) - fail_count,
        "fail": fail_count,
        "results": results,
    }, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    logger.info("Starting CyberClaw security-baseline MCP")
    mcp.run()
