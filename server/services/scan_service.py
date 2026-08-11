"""持续网络扫描服务 — 调用 ARP/Nmap 发现网络设备"""
import asyncio
import ipaddress
import json
import logging
import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .topology_service import _device_id, _resolved_pos, is_mock_mode, match_device_profile
from server.db.compat import NULL_EQUIVALENTS

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


# Vendor strings that mean "we don't actually know the vendor" — treat as
# no-vendor and fall back to the OUI DB. Lower-cased NULL_EQUIVALENTS so we
# catch "Unknown"/"unknown"/"(unknown)"/"UNKNOWN"/"" uniformly. This fixes the
# bug where nmap's literal "Unknown" (truthy) skipped the OUI fallback.
_NULL_VENDOR = {str(x).strip().lower() for x in NULL_EQUIVALENTS if str(x).strip()}

# Same source but keeps "" — used to decide whether a stored devType is
# "unknown-ish" (incl. empty) and worth a fingerprint backfill.
_NULL_TYPE = {str(x).strip().lower() for x in NULL_EQUIVALENTS}

# Max devices port-fingerprinted per scan cycle (bounds latency + nmap subprocesses).
_FP_CAP = 8


def _resolve_vendor(raw: str, mac: str) -> str:
    """Return a trustworthy vendor string.

    A real vendor is kept as-is. A null-equivalent value (empty / Unknown /
    (unknown) / ...) falls back to the IEEE OUI DB. Returns '' when neither
    source knows the vendor (honest empty — never the "Unknown" placeholder),
    which process_scan then treats as overwritable on the next real scan.
    """
    s = str(raw).strip() if raw is not None else ""
    if s and s.lower() not in _NULL_VENDOR:
        return s
    return _lookup_vendor_oui(mac)


# ---------------------------------------------------------------------------
# MAC address normalisation — lowercase, colon-separated
# ---------------------------------------------------------------------------
def _normalize_mac(raw_mac: str) -> str:
    mac = raw_mac.lower().replace("-", ":")
    if len(mac) == 12 and ":" not in mac:
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


# ---------------------------------------------------------------------------
# ARP-table discovery — reliable on Windows without admin / arp-scan / nmap
# ---------------------------------------------------------------------------
# `arp -a` line: "<ip>   <mac [-: separated]>   <type>". MAC must be 6 hex
# octets with consistent separators; we then keep only entries whose IP is in
# the target network and whose first octet is even (drops broadcast ff-.. and
# multicast 01-.. / 33-..).
_ARP_LINE_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+\S+"
)


def _parse_arp_output(text: str, network: ipaddress.IPv4Network) -> list[tuple[str, str]]:
    """Parse `arp -a` output → [(ip, mac)] for entries inside ``network``.

    Excludes broadcast/multicast (first MAC octet odd) and entries on other
    interfaces/subnets.
    """
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = _ARP_LINE_RE.search(line)
        if not m:
            continue
        ip_str, mac_raw = m.group(1), m.group(2)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip not in network:
            continue
        if int(mac_raw.split(":" if ":" in mac_raw else "-")[0], 16) % 2 == 1:
            # multicast / broadcast MAC — skip
            continue
        out.append((str(ip), _normalize_mac(mac_raw)))
    return out


def _arp_table_scan(subnet: str) -> list[dict]:
    """Discover devices via the OS ARP table (Windows-friendly, no admin).

    1) Parallel ICMP ping-sweep across the subnet to populate the ARP cache.
    2) Read ``arp -a`` and parse IP→MAC.
    3) Resolve vendor via the IEEE OUI DB.

    This is the reliable path on Windows where ``arp-scan`` is not installed
    and ``nmap -sn`` both times out (>120s on a /24) and misses ICMP-only hosts
    such as IP cameras that drop nmap's TCP probes.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return []

    is_windows = platform.system() == "Windows"

    def _ping(ip: str):
        try:
            cmd = ["ping", "-n", "1", "-w", "400", ip] if is_windows \
                else ["ping", "-c", "1", "-W", "1", ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=3)
        except Exception:
            pass

    try:
        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(_ping, [str(h) for h in network.hosts()]))
    except Exception as e:
        logger.debug(f"ARP-table ping-sweep error: {e}")

    try:
        text = subprocess.check_output(["arp", "-a"], universal_newlines=True,
                                       timeout=10, errors="replace")
    except Exception as e:
        logger.debug(f"arp -a failed: {e}")
        return []

    return [{
        "ip": ip,
        "mac": mac,
        "vendor": _resolve_vendor("", mac),
        "method": "arp_table",
        "scanSourcePlugin": "ARPTABLE",
    } for ip, mac in _parse_arp_output(text, network)]


# ---------------------------------------------------------------------------
# Scan event → HUD WS message mapping
# ---------------------------------------------------------------------------
# process_scan emits events keyed by eveEventType ("New Device", "Device Down",
# "Down Reconnected", "Connected", "IP Changed", ...). The device-list-changing
# ones are mapped here to the WS message types the frontend already handles —
# the SAME contract as the MQTT discovery path (mqtt_service._upsert_esp32_device)
# so no frontend change is needed to make scan-discovered devices appear.
_EVENT_TO_WS = {
    "New Device": "device_discovered",
    "Down Reconnected": "device_back_online",
    "Connected": "device_back_online",
    "Device Down": "device_offline",
}


def _parse_pos(pos_raw) -> list | None:
    """Parse devPos (JSON string / list / None) → list, else None."""
    if pos_raw is None:
        return None
    if isinstance(pos_raw, (list, tuple)):
        return list(pos_raw)
    try:
        parsed = json.loads(pos_raw)
        return list(parsed) if isinstance(parsed, (list, tuple)) else None
    except (ValueError, TypeError):
        return None


def build_device_ws_message(event: dict, device: dict | None) -> dict | None:
    """Map one process_scan device event + DB device row → a HUD WS message.

    Returns None for events that must not trigger a device-list update.
    Payload mirrors the MQTT device_discovered contract so the frontend's
    existing device_discovered / device_back_online / device_offline handlers
    render scan results without any frontend change.
    """
    ws_type = _EVENT_TO_WS.get(event.get("type", ""))
    if not ws_type:
        return None

    mac = event.get("mac", "")
    dev = device or {}
    name = dev.get("devName") or mac
    dev_id = _device_id(dev.get("devName", ""), mac)
    ip = event.get("ip") or dev.get("devLastIP", "")

    if ws_type == "device_offline":
        # removeDeviceFromScene only needs id; keep the offline payload lean
        return {"type": "device_offline",
                "device": {"mac": mac, "id": dev_id, "name": name, "ip": ip}}

    return {"type": ws_type, "device": {
        "mac": mac,
        "id": dev_id,
        "name": name,
        "ip": ip,
        "type": dev.get("devType", "unknown"),
        "device_type": dev.get("devType", "unknown"),
        "vendor": dev.get("devVendor", ""),
        "model": dev.get("devModel", ""),
        "pos": _resolved_pos(dev.get("devPos"), mac),
        "status": dev.get("devStatus", "secure"),
    }}


class ScanService:
    def __init__(self):
        self._running = False
        self._task = None
        self._subnet = ""           # configured scan subnet (set on start)
        self._interval = 300        # retained for status/logging; NOT used for looping in manual mode
        self._scan_lock = asyncio.Lock()  # serialize startup scan vs manual triggers vs re-presses
        self._stats = {"cycles": 0, "devices_found": 0, "last_scan": ""}
        self._broadcast = None  # ws broadcast callback (wired in main.py)
        self._fingerprinted: set[str] = set()  # macs already port-fingerprinted this session

    def set_broadcast(self, cb):
        """Wire the WebSocket broadcast callback (same pattern as the other
        collector services). Scan-detected device changes are pushed here."""
        self._broadcast = cb

    async def start(self, subnet: str = "192.168.1.0/24", interval: int = 300):
        """启动扫描服务（手动模式）。

        启动时执行一次扫描；之后不再每 N 秒自动循环——所有后续扫描由用户在
        HUD 按下快捷键、经 ``trigger_scan()`` 主动发起。``interval`` 仅作记录，
        不再用于循环。
        """
        if self._running:
            return {"status": "already_running"}
        self._running = True
        self._subnet = subnet
        self._interval = interval
        self._task = asyncio.create_task(self._startup_scan())
        return {"status": "started", "subnet": subnet, "mode": "manual"}

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

    async def _startup_scan(self):
        """启动时的一次性扫描（不循环）。"""
        try:
            await self._run_one_cycle(reason="startup")
        except Exception as e:
            logger.error(f"Startup scan error: {e}")

    async def _run_one_cycle(self, reason: str = "manual") -> dict:
        """执行一次完整扫描并刷新统计。

        ``_scan_lock`` 串行化，避免启动扫描与手动触发（或重复连按快捷键）并发
        跑两份 arp/nmap 子进程。scan_subnet → _process_results 会把设备变更事件
        经 device_discovered / device_offline / device_back_online 推送到 HUD。
        """
        async with self._scan_lock:
            result = await self.scan_subnet(self._subnet)
            self._stats["cycles"] += 1
            self._stats["devices_found"] = result.get("found", 0)
            from datetime import datetime
            self._stats["last_scan"] = datetime.now().isoformat()
            logger.info(f"Scan complete ({reason}): found {result.get('found', 0)} devices on {self._subnet}")
            return result

    async def trigger_scan(self) -> dict:
        """用户快捷键手动触发一次网络扫描。

        扫描结果经 ``_process_results`` 处理后，通过 ``_broadcast_device_events``
        推送 device_discovered / device_offline / device_back_online，实时刷新 HUD
        的设备列表与拓扑。返回扫描到的设备数与原始结果。
        """
        if not self._subnet:
            return {"status": "error", "message": "scan subnet not configured"}
        result = await self._run_one_cycle(reason="manual")
        return {"status": "ok", "found": result.get("found", 0),
                "devices": result.get("devices", [])}

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
                vendor = _resolve_vendor(m.group(3).strip(), mac)
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

        # ARP 表扫描（Windows/跨平台主路径）：并行 ICMP ping-sweep 填充 ARP 缓存后
        # 读 arp -a。本机 arp-scan 未装、nmap -sn 既超时(208s>120s)又漏摄像头，
        # 此法最可靠 —— ping 能通的设备其 MAC 都会在 ARP 表里。
        if not results:
            results = _arp_table_scan(subnet)

        # NOTE: 不再用 nmap -sn 兜底。本机实测 nmap -sn 扫 /24 要 ~208s（timeout=120 必
        # 超时）、还会漏掉 ICMP-only 的摄像头；更糟的是当 arp_table 因断网返回 [] 时，
        # nmap 兜底会去扫一个无响应网段 ~120s 才超时 → trigger_scan 挂起，用户按 S 后迟迟
        # 看不到"发现 N 台"。arp_table（ping-sweep + arp -a）覆盖 Windows、arp-scan 覆盖
        # Linux；空结果即"确实没设备"，交给 _process_results 据此把真实设备标记离线。
        return results

    async def _process_results(self, results: list[dict]):
        """将扫描结果送入处理管道。

        即使 results 为空也必须跑：populate_current_scan([]) 会清空 CurrentScan，
        process_scan_results 的 presence 阶段据此把本次未扫到的真实设备标记为离线
        (Device Down) → 广播 device_offline，让断网时 HUD 能反映设备失联。
        """
        from server.services.process_scan import populate_current_scan, process_scan_results

        # Stage 0: Write scan results to CurrentScan temp table
        await populate_current_scan(results, source="SCAN")

        # Stages 1-6: Full pipeline (new devices, updates, presence, events, cleanup)
        events = await process_scan_results()

        if events:
            logger.info(f"Scan pipeline produced {len(events)} events")
            # Fingerprint/preset new+unknown devices BEFORE broadcasting, so the HUD's
            # first frame already shows the right type (frontend dedups by id).
            events = await self._enrich_device_fingerprints(events)
            # mock/real 由用户手动 Shift 切换，扫描不再自动切模式。real 模式不显示 mock
            # (async_get_topology 过滤 mock)，故设备发现只需增量广播 device_discovered /
            # device_offline / device_back_online，不会与 mock 设备重叠。
            await self._broadcast_device_events(events)

    async def _resolve_device(self, mac: str) -> dict | None:
        """Look up a device row by MAC for broadcast enrichment (best-effort)."""
        if not mac:
            return None
        try:
            from .nx_bridge import get_bridge
            return await get_bridge().get_device_by_mac(mac)
        except Exception:
            return None

    async def _enrich_device_fingerprints(self, events: list[dict]) -> list[dict]:
        """Port-fingerprint new + backfill devices BEFORE broadcast (pillar 3).

        For each New Device event (and a few still-unknown existing devices),
        probe common IoT ports and write the inferred devType + devOpenPorts
        back to the DB so the first device_discovered frame carries the right
        type. Best-effort: never raises, returns the events list unchanged.
        Skipped entirely in mock mode (protects the demo layout/devices).
        """
        try:
            if is_mock_mode():
                return events
            from .port_fingerprint import fingerprint_device
            from .nx_bridge import get_bridge
            bridge = get_bridge()

            # Gather candidate (mac, ip) pairs: new devices first, then backfill
            # devices still typed "unknown".
            candidates: dict[str, str] = {}  # mac -> ip (insertion-ordered, deduped)
            for evt in events:
                if evt.get("type") == "New Device":
                    mac, ip = evt.get("mac", ""), evt.get("ip", "")
                    # New Device 总是进入候选：create_new_groups 新建的设备 devName="(unknown)"，
                    # 必须识别。不受 _fingerprinted 限制——否则同一 MAC 重新发现后 enrichment
                    # 被跳过，devName/id 漂移，前端按 id 去重/渲染错乱。
                    if mac and ip:
                        candidates.setdefault(mac, ip)
            try:
                all_devs = await bridge.get_all_devices()
            except Exception:
                all_devs = []
            for d in all_devs or []:
                if not isinstance(d, dict):
                    continue
                if d.get("devDiscoveryMethod") in ("mock", "mqtt"):
                    continue
                mac, ip = d.get("devMac", ""), d.get("devLastIP", "")
                if not mac or not ip or mac in candidates or mac in self._fingerprinted:
                    continue
                # Backfill devices that are still "unknown" OR have a known-device
                # preset (the preset is authoritative for known devices, so it
                # overrides e.g. a weak IP-heuristic "Gateway" with the real profile).
                if (str(d.get("devType", "")).strip().lower() in _NULL_TYPE
                        or match_device_profile(mac, ip) is not None):
                    candidates.setdefault(mac, ip)

            # Classify each candidate: a known-device preset (authoritative,
            # instant, no probe) vs a port-fingerprint probe.
            presets: list[tuple[str, dict]] = []
            probe_targets: dict[str, str] = {}
            for mac, ip in candidates.items():
                profile = match_device_profile(mac, ip)
                if profile:
                    presets.append((mac, profile))
                elif len(probe_targets) < _FP_CAP and mac not in self._fingerprinted:
                    probe_targets[mac] = ip

            # 1. Apply known-device presets from topology.json (demo identity).
            for mac, profile in presets:
                try:
                    await bridge.upsert_device(mac, {
                        "devName": profile.get("name", ""),
                        "devType": profile.get("type", "unknown"),
                        "devVendor": profile.get("vendor", ""),
                        "devModel": profile.get("model", ""),
                        "devPos": json.dumps(profile.get("pos", [])),
                        "devOpenPorts": json.dumps(profile.get("expected_ports", [])),
                        "devIcon": profile.get("type", ""),
                        "devProtocols": json.dumps(profile.get("protocols", [])),
                        "devOsGuess": profile.get("os_guess", ""),
                        "devSwitchPort": profile.get("switch_port") or "",
                        "devGroup": profile.get("role", ""),
                        "devNotes": profile.get("notes", ""),
                    }, source="PROFILE")
                    self._fingerprinted.add(mac)
                except Exception as e:
                    logger.debug(f"preset upsert failed for {mac}: {e}")

            # 2. Port-fingerprint the remaining (unknown, non-preset) devices.
            sem = asyncio.Semaphore(6)  # bound concurrent port probes (nmap/socket)

            async def _one(m, ip):
                async with sem:
                    try:
                        r = await asyncio.wait_for(fingerprint_device(ip, mac=m), timeout=8)
                    except Exception as e:
                        logger.debug(f"fingerprint failed for {m}@{ip}: {e}")
                        return m, None
                # Mark done only when the probe completed (incl. an "unknown"
                # verdict); a transient failure (None) stays retryable next cycle.
                if r is not None:
                    self._fingerprinted.add(m)
                return m, r

            done = await asyncio.gather(*[_one(m, ip) for m, ip in probe_targets.items()])
            for mac, r in done:
                if not r:
                    continue
                data = {"devOpenPorts": json.dumps(r.get("open_ports", []))}
                # Only set devType when the probe reached a decision; never overwrite
                # a good existing type with "unknown".
                if r.get("type") and r["type"] != "unknown":
                    data["devType"] = r["type"]
                try:
                    await bridge.upsert_device(mac, data, source="PORTFP")
                except Exception as e:
                    logger.debug(f"upsert fingerprint failed for {mac}: {e}")
        except Exception as e:
            logger.debug(f"_enrich_device_fingerprints failed: {e}")
        return events

    async def _broadcast_device_events(self, events: list[dict]) -> None:
        """Map scan pipeline events to HUD device WS messages and push them.

        No-op when no broadcast callback is wired. Silently skips events that
        don't change the device list.
        """
        if not events or not self._broadcast:
            return
        for evt in events:
            if evt.get("type") not in _EVENT_TO_WS:
                continue
            mac = evt.get("mac", "")
            device = await self._resolve_device(mac)
            msg = build_device_ws_message(evt, device)
            if msg:
                try:
                    await self._broadcast(msg)
                except Exception as e:
                    logger.debug(f"broadcast device event failed: {e}")
                # 也写 security_events —— 让 chat 事件界面/HUD alert timeline 都能从 DB
                # 看到设备状态变更（发现/离线/恢复在线），不只 WS 实时推送。
                try:
                    from .nx_bridge import get_bridge
                    d = msg.get("device") or {}
                    ip = d.get("ip") or ""
                    name = d.get("name") or ip
                    ws_type = msg.get("type", "")
                    if ws_type == "device_offline":
                        sev, m = "warning", f"设备离线: {name} ({ip}) 失去连接"
                    elif ws_type == "device_back_online":
                        sev, m = "info", f"设备恢复: {name} ({ip}) 重新在线"
                    else:  # device_discovered
                        sev, m = "info", f"设备发现: {name} ({ip}) 上线"
                    await get_bridge().record_security_event(
                        source_type="device_status", severity=sev, message=m,
                        target=ip, source="scan_service")
                except Exception as e:
                    logger.debug(f"record_security_event(device_status) failed: {e}")


# 单例
_service: ScanService | None = None


def get_scan_service() -> ScanService:
    global _service
    if _service is None:
        _service = ScanService()
    return _service
