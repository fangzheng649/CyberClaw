"""持续网络扫描服务 — 调用 ARP/Nmap 发现网络设备"""
import asyncio
import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IEEE OUI MAC-vendor database
# ---------------------------------------------------------------------------
_OUI_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "ieee-oui.txt"
_oui_cache: dict[str, str] | None = None


def _lookup_vendor_oui(mac: str) -> str:
    """通过 IEEE OUI 数据库查询 MAC 厂商"""
    global _oui_cache
    if _oui_cache is None:
        _oui_cache = {}
        try:
            with open(_OUI_PATH, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        _oui_cache[parts[0].lower()] = parts[1].strip()
        except FileNotFoundError:
            pass
    prefix = mac.replace(":", "").lower()[:6]
    return _oui_cache.get(prefix, "")


# ---------------------------------------------------------------------------
# MAC address normalisation — lowercase, colon-separated
# ---------------------------------------------------------------------------
def _normalize_mac(raw_mac: str) -> str:
    mac = raw_mac.lower().replace("-", ":")
    if len(mac) == 12 and ":" not in mac:
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


class ScanService:
    def __init__(self):
        self._running = False
        self._task = None
        self._stats = {"cycles": 0, "devices_found": 0, "last_scan": ""}

    async def start(self, subnet: str = "192.168.1.0/24", interval: int = 300):
        if self._running:
            return {"status": "already_running"}
        self._running = True
        self._task = asyncio.create_task(self._loop(subnet, interval))
        return {"status": "started", "subnet": subnet, "interval": interval}

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        return {"status": "stopped"}

    def get_status(self):
        return {
            "running": self._running,
            "stats": self._stats,
        }

    async def _loop(self, subnet: str, interval: int):
        while self._running:
            try:
                result = await self.scan_subnet(subnet)
                self._stats["cycles"] += 1
                self._stats["devices_found"] = result.get("found", 0)
                from datetime import datetime
                self._stats["last_scan"] = datetime.now().isoformat()
            except Exception as e:
                logger.error(f"Scan cycle error: {e}")
            await asyncio.sleep(interval)

    async def scan_subnet(self, subnet: str) -> dict:
        """执行一次 ARP + ICMP 扫描"""
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._sync_scan, subnet)
        await self._process_results(results)
        return {"found": len(results), "devices": results}

    def _sync_scan(self, subnet: str) -> list[dict]:
        """同步执行网络扫描（在线程池中运行）"""
        results = []

        # ARP 扫描
        try:
            output = subprocess.check_output(
                ["arp-scan", subnet],
                universal_newlines=True,
                timeout=60,
                stderr=subprocess.STDOUT,
            )
            pattern = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.+)"
            )
            for m in pattern.finditer(output):
                mac = _normalize_mac(m.group(2))
                vendor = m.group(3).strip()
                if not vendor:
                    vendor = _lookup_vendor_oui(mac)
                results.append({
                    "ip": m.group(1),
                    "mac": mac,
                    "vendor": vendor,
                    "method": "arp_scan",
                    "scanSourcePlugin": "ARPSCAN",
                })
        except FileNotFoundError:
            logger.debug("arp-scan not available")
        except subprocess.TimeoutExpired:
            logger.warning("arp-scan timeout")
        except Exception as e:
            logger.debug(f"arp-scan error: {e}")

        # ICMP ping 扫描（nmap -sn）
        if not results:
            try:
                output = subprocess.check_output(
                    ["nmap", "-sn", "-n", subnet],
                    universal_newlines=True,
                    timeout=120,
                    stderr=subprocess.STDOUT,
                )
                ip_pattern = re.compile(
                    r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)"
                )
                mac_pattern = re.compile(
                    r"MAC Address: ([0-9A-Fa-f:]{17}) \((.+?)\)"
                )
                current_ip = None
                for line in output.splitlines():
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                    mac_match = mac_pattern.search(line)
                    if mac_match and current_ip:
                        mac = _normalize_mac(mac_match.group(1))
                        vendor = mac_match.group(2)
                        if not vendor:
                            vendor = _lookup_vendor_oui(mac)
                        results.append({
                            "ip": current_ip,
                            "mac": mac,
                            "vendor": vendor,
                            "method": "nmap_sn",
                            "scanSourcePlugin": "NMAPSN",
                        })
                        current_ip = None
            except FileNotFoundError:
                logger.debug("nmap not available")
            except Exception as e:
                logger.debug(f"nmap scan error: {e}")

        return results

    async def _process_results(self, results: list[dict]):
        """将扫描结果送入处理管道"""
        if not results:
            return

        from server.services.process_scan import populate_current_scan, process_scan_results

        # Stage 0: Write scan results to CurrentScan temp table
        await populate_current_scan(results, source="SCAN")

        # Stages 1-6: Full pipeline (new devices, updates, presence, events, cleanup)
        events = await process_scan_results()

        if events:
            logger.info(f"Scan pipeline produced {len(events)} events")
            # Broadcast events via WebSocket if available
            try:
                from server.services.tool_broadcast_service import get_broadcast_service
                bs = get_broadcast_service()
                for evt in events:
                    await bs.broadcast_event("scan_event", evt)
            except Exception:
                pass


# 单例
_service: ScanService | None = None


def get_scan_service() -> ScanService:
    global _service
    if _service is None:
        _service = ScanService()
    return _service
