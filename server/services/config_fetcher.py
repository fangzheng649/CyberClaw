"""Configuration fetcher for CyberClaw — retrieves device configs via SSH/SNMP/HTTP.

Supports:
  - SSH (netmiko): Huawei `display current-configuration`, Cisco `show running-config`
  - SNMP (pysnmp): Basic device info via standard OIDs
  - HTTP: Web API for devices with management interfaces
"""
import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_COMMAND_MAP = {
    "huawei": "display current-configuration",
    "cisco_ios": "show running-config",
    "hp_comware": "display current-configuration",
}


class ConfigFetcher:

    async def fetch_via_ssh(self, ip: str, device_type: str = "huawei",
                            username: str | None = None,
                            password: str | None = None) -> dict:
        """Fetch device configuration via SSH (netmiko)."""
        try:
            from netmiko import ConnectHandler
        except ImportError:
            return {"status": "unavailable", "message": "netmiko not installed"}

        username = username or os.getenv("SWITCH_SSH_USER", "admin")
        password = password or os.getenv("SWITCH_SSH_PASS", "")
        command = _COMMAND_MAP.get(device_type, "display current-configuration")

        try:
            conn = ConnectHandler(
                device_type=device_type,
                host=ip,
                username=username,
                password=password,
                timeout=15,
            )
            output = conn.send_command(command)
            conn.disconnect()

            if not output or "Error" in output[:100]:
                return {"status": "error", "message": "Empty or error response from device"}

            return {
                "status": "ok",
                "config": output,
                "device_type": device_type,
                "lines": output.count("\n") + 1,
            }
        except Exception as e:
            logger.debug(f"SSH config fetch error for {ip}: {e}")
            return {"status": "error", "message": str(e)}

    async def fetch_via_snmp(self, ip: str, community: str = "public") -> dict:
        """Fetch basic device info via SNMP."""
        try:
            from server.services.snmp_service import get_snmp_service
        except ImportError:
            return {"status": "unavailable", "message": "SNMP service not available"}

        svc = get_snmp_service()
        return await svc.get_device_info(ip, community)

    async def fetch_via_http(self, ip: str, username: str | None = None,
                             password: str | None = None,
                             endpoint: str = "/api/config") -> dict:
        """Fetch device config via HTTP API."""
        try:
            import httpx
        except ImportError:
            return {"status": "unavailable", "message": "httpx not installed"}

        url = f"http://{ip}{endpoint}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if username:
                    resp = await client.get(url, auth=(username, password or ""))
                else:
                    resp = await client.get(url)

                if resp.status_code == 200:
                    return {
                        "status": "ok",
                        "config": resp.text,
                        "content_type": resp.headers.get("content-type", ""),
                    }
                else:
                    return {
                        "status": "error",
                        "message": f"HTTP {resp.status_code}",
                    }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def fetch_best(self, ip: str, protocols: list[str] | None = None) -> dict:
        """Try multiple methods to fetch device config, returning the first success."""
        if not protocols:
            protocols = ["ssh", "snmp", "http"]

        for method in protocols:
            if method == "ssh":
                result = await self.fetch_via_ssh(ip)
            elif method == "snmp":
                result = await self.fetch_via_snmp(ip)
            elif method == "http":
                result = await self.fetch_via_http(ip)
            else:
                continue

            if result.get("status") == "ok":
                result["method"] = method
                return result

        return {"status": "unavailable", "message": "All fetch methods failed or unavailable"}


_service: Optional[ConfigFetcher] = None


def get_config_fetcher() -> ConfigFetcher:
    global _service
    if _service is None:
        _service = ConfigFetcher()
    return _service
