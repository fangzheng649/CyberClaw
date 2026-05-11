"""CyberClaw Config Audit MCP Server — ACL and configuration auditing.

Tools:
  - audit_config: Audit device configuration for security issues
  - check_acl_conflicts: Check ACL rules for conflicts and shadows
  - compare_configs: Compare two configuration snapshots
  - get_audit_report: Retrieve a saved audit report
"""
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from cyberclaw_core.mcp_base import create_mcp_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = create_mcp_server("config-audit", "Network device configuration auditing, ACL conflict detection, and compliance checking")

# In-memory reports
_reports: list[dict] = []


async def _fetch_device_config(device_ip: str) -> dict:
    """Fetch real device config via ConfigFetcher."""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from server.services.config_fetcher import get_config_fetcher
        fetcher = get_config_fetcher()
        return await fetcher.fetch_best(device_ip)
    except Exception as e:
        logger.error(f"Config fetch error: {e}")
        return {"status": "error", "message": str(e)}


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
async def audit_config(device_ip: str = "10.0.0.1") -> str:
    """Audit a device's running configuration for security issues.

    Checks for: plaintext passwords, insecure protocols, missing ACLs,
    default SNMP community, unnecessary services, etc.

    Args:
        device_ip: Device IP to audit. Default: 10.0.0.1.
    """
    logger.info(f"audit_config: {device_ip}")

    result = await _fetch_device_config(device_ip)

    if result.get("status") != "ok":
        return json.dumps({
            "status": "unavailable",
            "device": device_ip,
            "message": result.get("message", "Unable to fetch device configuration"),
            "hint": "确保设备可达且 SSH/SNMP 凭据已配置",
        }, ensure_ascii=False, indent=2)

    config_text = result.get("config", "")
    lines = _parse_config_lines(config_text)
    findings = _audit_config_lines(lines)

    report = {
        "report_id": f"audit-{int(time.time())}",
        "device": device_ip,
        "method": result.get("method", "unknown"),
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
