import asyncio
import logging

logger = logging.getLogger("cyberclaw.scenario")

# ── 预设演示剧本 ──────────────────────────────────────────────────
# DEMO_SCRIPT 是用于演示和测试的固定攻击脚本。
# 在 "demo" 模式下按预设时间线播放；在 "live" 模式下从
# security_events 表实时读取真实事件。
DEMO_SCRIPT = [
    # ── Phase 1: 初始态势 ────────────────────────────────────────────
    {"delay": 3000, "event": {"type": "system_ready", "message": "智能园区视频监控系统已上线 — 19 台设备、18 条链路就绪"}},
    # ── Phase 2: 侦察 — 外部攻击者穿透防火墙扫描 ────────────────────
    {"delay": 5000, "event": {"type": "scan_started", "source": "10.0.1.100", "message": "防火墙检测到来自 10.0.1.100 的大规模端口扫描行为，目标为视频监控设备", "details": {"targets": ["cam_entrance", "cam_parking", "cam_lobby", "cam_elevator", "cam_corridor", "cam_server_room", "cam_rooftop", "nvr_main"]}}},
    {"delay": 3000, "event": {"type": "port_scan", "source": "10.0.1.100", "target": "cam_entrance", "severity": "warning", "message": "IPC-Entrance-PTZ (192.168.10.101) 开放 Telnet 端口 (23)", "details": {"port": 23, "service": "Telnet"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "10.0.1.100", "target": "cam_parking", "severity": "warning", "message": "IPC-Parking (192.168.10.102) 开放 HTTP 管理端口 (80)", "details": {"port": 80, "service": "Hikvision HTTP"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "10.0.1.100", "target": "cam_lobby", "severity": "warning", "message": "IPC-Lobby-Dome (192.168.10.103) 开放 Dahua 管理端口 (37777)", "details": {"port": 37777, "service": "Dahua Manager"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "10.0.1.100", "target": "cam_server_room", "severity": "warning", "message": "IPC-ServerRoom (192.168.10.106) 开放 Telnet 端口 (23)", "details": {"port": 23, "service": "Telnet"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "10.0.1.100", "target": "nvr_main", "severity": "warning", "message": "NVR-DS-9632N (192.168.10.10) 开放 RTSP 端口 (554)", "details": {"port": 554, "service": "RTSP"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "10.0.1.100", "target": "access_ctrl_main", "severity": "warning", "message": "AccessCtrl-Main (192.168.10.110) 开放 ISAPI 端口 (80)", "details": {"port": 80, "service": "Hikvision ISAPI"}}},
    # ── Phase 3: 漏洞发现 ───────────────────────────────────────────
    {"delay": 3500, "event": {"type": "vulnerability_found", "target": "cam_entrance", "severity": "critical", "message": "IPC-Entrance-PTZ (Hikvision DS-2DE4425IW) 存在命令注入漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8, "firmware": "V5.7.16"}}},
    {"delay": 2500, "event": {"type": "vulnerability_found", "target": "cam_parking", "severity": "critical", "message": "IPC-Parking (Hikvision DS-2CD2T86FWD) 存在未授权访问漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8, "firmware": "V5.7.12"}}},
    {"delay": 2500, "event": {"type": "vulnerability_found", "target": "cam_server_room", "severity": "critical", "message": "IPC-ServerRoom (Hikvision DS-2CD2142FWD) 存在命令注入漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8, "firmware": "V5.6.22"}}},
    {"delay": 2500, "event": {"type": "vulnerability_found", "target": "cam_lobby", "severity": "critical", "message": "IPC-Lobby-Dome (Dahua IPC-HDBW5442E) 存在身份认证绕过漏洞 CVE-2021-33044 (CVSS 9.8)", "details": {"cve": "CVE-2021-33044", "cvss": 9.8, "firmware": "V2.820.0000"}}},
    {"delay": 2500, "event": {"type": "vulnerability_found", "target": "cam_corridor", "severity": "critical", "message": "IPC-Corridor-B2 (Dahua IPC-HFW2831E) 存在身份认证绕过漏洞 CVE-2021-33044 (CVSS 9.8)", "details": {"cve": "CVE-2021-33044", "cvss": 9.8, "firmware": "V2.800.0000"}}},
    {"delay": 2500, "event": {"type": "vulnerability_found", "target": "nvr_main", "severity": "critical", "message": "NVR-DS-9632N 存在弱密码 — admin/12345 (默认凭据未更改)", "details": {"cve": "CWE-521", "cvss": 9.1, "firmware": "V4.1.60"}}},
    # ── Phase 4: 暴力破解 ───────────────────────────────────────────
    {"delay": 4000, "event": {"type": "bruteforce", "source": "10.0.1.100", "target": "cam_entrance", "severity": "critical", "message": "IPC-Entrance-PTZ 遭遇 Telnet 暴力破解 — 使用默认凭据 admin/12345 成功", "details": {"attempts": 12, "success": True, "protocol": "Telnet"}}},
    # ── Phase 5: 首台设备感染 ────────────────────────────────────────
    {"delay": 3000, "event": {"type": "attack_detected", "source": "10.0.1.100", "target": "cam_entrance", "severity": "critical", "message": "IPC-Entrance-PTZ 已被 Mirai 僵尸网络感染 — 检测到恶意进程 /tmp/.mirai", "details": {"malware": "Mirai", "method": "Telnet brute-force"}}},
    # ── Phase 6: 横向扩散 ───────────────────────────────────────────
    {"delay": 4500, "event": {"type": "lateral_movement", "source": "cam_entrance", "target": "cam_parking", "severity": "critical", "message": "Mirai 从 IPC-Entrance 横向扩散至 IPC-Parking (利用同品牌 Hikvision CVE-2021-36260)"}},
    {"delay": 3000, "event": {"type": "attack_detected", "source": "cam_entrance", "target": "cam_parking", "severity": "critical", "message": "IPC-Parking 已被感染 — Mirai 利用 Hikvision 命令注入植入恶意载荷", "details": {"malware": "Mirai"}}},
    {"delay": 3500, "event": {"type": "lateral_movement", "source": "cam_entrance", "target": "cam_lobby", "severity": "critical", "message": "Mirai 从 IPC-Entrance 横向扩散至 IPC-Lobby-Dome (利用 Dahua CVE-2021-33044)"}},
    {"delay": 2500, "event": {"type": "attack_detected", "source": "cam_entrance", "target": "cam_lobby", "severity": "critical", "message": "IPC-Lobby-Dome 已被感染 — Mirai 利用 Dahua 认证绕过植入恶意载荷", "details": {"malware": "Mirai"}}},
    {"delay": 3000, "event": {"type": "lateral_movement", "source": "cam_lobby", "target": "cam_corridor", "severity": "critical", "message": "Mirai 从 IPC-Lobby 横向扩散至 IPC-Corridor-B2 (同品牌 Dahua 漏洞)"}},
    {"delay": 3000, "event": {"type": "lateral_movement", "source": "cam_entrance", "target": "nvr_main", "severity": "critical", "message": "Mirai 从 IPC-Entrance 横向扩散至 NVR-DS-9632N (共享摄像头密码)"}},
    {"delay": 2500, "event": {"type": "attack_detected", "source": "cam_entrance", "target": "nvr_main", "severity": "critical", "message": "NVR-DS-9632N 已被感染 — 攻击者获得全网录像控制权", "details": {"malware": "Mirai"}}},
    # ── Phase 7: C2 通信检测 ────────────────────────────────────────
    {"delay": 3000, "event": {"type": "c2_detected", "source": "cam_entrance", "severity": "critical", "message": "检测到 C2 回连: IPC-Entrance → 185.220.101.34:443 (Tor 出口节点)", "details": {"c2_server": "185.220.101.34:443", "protocol": "HTTPS"}}},
    {"delay": 2500, "event": {"type": "c2_detected", "source": "nvr_main", "severity": "critical", "message": "检测到 DDoS 参与行为: NVR → 239.255.0.1 (组播 C2 指令，6 台受控设备参与)", "details": {"c2_server": "239.255.0.1:48101", "type": "DDoS_participation"}}},
    # ── Phase 8: CyberAgent 分析 ────────────────────────────────────
    {"delay": 4000, "event": {"type": "analysis_complete", "severity": "critical", "message": "CyberAgent 分析完成: Mirai 僵尸网络感染 — 6 台设备受控（含 NVR），置信度 96%", "details": {"threat": "Mirai Botnet", "confidence": 96, "infected": ["cam_entrance", "cam_parking", "cam_lobby", "cam_corridor", "cam_server_room", "nvr_main"]}}},
    # ── Phase 9: 自动隔离响应 ───────────────────────────────────────
    # 不再写死隔离事件 — 由 AutoResponseService 事件驱动引擎响应
    # analysis_complete 事件触发：策略评估 → 置信度 96% ≥ 阈值 → 真实隔离 6 台设备。
    # 引擎在 _run() 处理 analysis_complete 时生成 response_decision +
    # device_isolated 事件（含真实 isolation_service 调用与 action_id 审计）。
    # ── Phase 10: 收尾 ──────────────────────────────────────────────
    {"delay": 3000, "event": {"type": "threat_resolved", "severity": "info", "message": "威胁已清除 — Mirai 攻击时间线报告已生成。建议：更新 Hikvision/Dahua 固件、修改默认密码、部署网络分段", "details": {"isolated": ["cam_entrance", "cam_parking", "cam_lobby", "cam_corridor", "cam_server_room", "nvr_main"]}}},
]

EVENT_STATUS_MAP = {
    "scan_started": ("details.targets", "scanning"),
    "port_scan": ("target", "vulnerable"),
    "vulnerability_found": ("target", "vulnerable"),
    "bruteforce": ("target", "attacked"),
    "attack_detected": ("target", "attacked"),
    "lateral_movement": ("target", "attacked"),
    "c2_detected": ("source", "attacked"),
    "device_isolated": ("target", "isolated"),
    "analysis_complete": ("_noop", "secure"),
    "isolation_request": ("_noop", "secure"),
}


class ScenarioService:
    def __init__(self):
        self.running = False
        self.step = 0
        self.mode: str = "demo"  # "demo" or "live"
        self._task: asyncio.Task | None = None
        self._broadcast_callback = None
        self._devices: list[dict] = []
        self._links: list[dict] = []
        self._last_seen_event_id: int = 0

    def set_broadcast(self, callback):
        self._broadcast_callback = callback

    def set_topology(self, devices, links):
        self._devices = [d.model_dump() for d in devices]
        self._links = [{"from": l.from_, "to": l.to} for l in links]

    def get_status(self) -> dict:
        return {"running": self.running, "step": self.step, "total_steps": len(DEMO_SCRIPT), "mode": self.mode}

    async def _reset_devices(self, reset_db: bool = False):
        """Reset all devices to 'secure'. If reset_db, also clear DB statuses."""
        for d in self._devices:
            d["status"] = "secure"
        if reset_db:
            try:
                from .nx_bridge import get_bridge
                bridge = get_bridge()
                for d in self._devices:
                    mac = d.get("mac", "")
                    if mac:
                        await bridge.update_device_status(mac, "secure")
            except Exception:
                pass

    def _update_device_status(self, event: dict) -> None:
        evt_type = event.get("type", "")
        if evt_type not in EVENT_STATUS_MAP:
            if evt_type == "threat_resolved":
                for dev_id in event.get("details", {}).get("isolated", []):
                    dev = next((d for d in self._devices if d["id"] == dev_id), None)
                    if dev:
                        dev["status"] = "isolated"
            return
        field, new_status = EVENT_STATUS_MAP[evt_type]
        if field == "_noop":
            return
        if field == "details.targets":
            for dev_id in event.get("details", {}).get("targets", []):
                dev = next((d for d in self._devices if d["id"] == dev_id), None)
                if dev:
                    dev["status"] = new_status
        else:
            dev_id = event.get(field)
            if dev_id:
                dev = next((d for d in self._devices if d["id"] == dev_id), None)
                if dev and dev["status"] != "attacked":
                    dev["status"] = new_status
        # Lateral movement: also mark source as attacked
        if evt_type == "lateral_movement":
            src_id = event.get("source")
            if src_id:
                src_dev = next((d for d in self._devices if d["id"] == src_id), None)
                if src_dev:
                    src_dev["status"] = "attacked"

    async def start(self, mode: str = "demo") -> None:
        if self.running:
            return
        self.mode = mode if mode in ("demo", "live") else "demo"
        self.running = True
        self.step = 0
        await self._reset_devices(reset_db=True)
        if self._broadcast_callback:
            await self._broadcast_callback({"type": "scenario_start", "devices": self._devices, "links": self._links, "mode": self.mode})
        if self.mode == "live":
            self._task = asyncio.create_task(self._run_live())
        else:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
        self.running = False
        self.step = 0
        await self._reset_devices(reset_db=True)
        if self._broadcast_callback:
            await self._broadcast_callback({"type": "scenario_stop", "devices": self._devices, "links": self._links})

    async def _run(self) -> None:
        try:
            for i, script_step in enumerate(DEMO_SCRIPT):
                await asyncio.sleep(script_step["delay"] / 1000)
                self.step = i + 1
                evt = script_step["event"]
                self._update_device_status(evt)
                if self._broadcast_callback:
                    await self._broadcast_callback({**evt, "step": self.step, "devices": self._devices})
                # Persist scenario event to database
                try:
                    from .nx_bridge import get_bridge
                    severity = "critical" if evt.get("severity") == "critical" else "warning"
                    await get_bridge().record_security_event(
                        "scenario", severity, evt.get("message", ""),
                        source=evt.get("source", ""), target=evt.get("target", ""),
                        fsm_state=evt.get("type", ""))
                    # Update device FSM in DB
                    for dev in self._devices:
                        if dev.get("status") != "secure":
                            await get_bridge().update_device_status(
                                dev.get("mac", ""), dev.get("status", "secure"))
                except Exception:
                    pass
                # Event-driven auto-response: engine evaluates policy on each event.
                # On analysis_complete it auto-isolates the infected devices for real
                # (real isolation_service call + action_id audit). Awaits completion so
                # the demo's threat_resolved step fires only after isolation finishes.
                try:
                    from .auto_response_service import get_auto_response_service
                    await get_auto_response_service().handle_event(evt, devices=self._devices)
                except Exception as e:
                    logger.warning(f"Auto-response handler error: {e}")
            if self._broadcast_callback:
                await self._broadcast_callback({"type": "scenario_complete", "devices": self._devices})
            # Auto-reset devices to secure after demo completes
            await asyncio.sleep(3)
            await self._reset_devices(reset_db=True)
            if self._broadcast_callback:
                await self._broadcast_callback({"type": "scenario_reset", "devices": self._devices})
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False

    async def _run_live(self) -> None:
        """Live mode: poll security_events table every 2 seconds for new real events."""
        try:
            from .nx_bridge import get_bridge
            bridge = get_bridge()

            # Determine starting point: find the max event id already present
            recent = await bridge.get_security_events(limit=1)
            if recent:
                self._last_seen_event_id = recent[0].get("id", 0) if recent[0].get("id") else 0

            # Also load real devices from DB
            db_devices = await bridge.get_all_devices()
            if db_devices:
                self._devices = db_devices
                if self._broadcast_callback:
                    await self._broadcast_callback({"type": "scenario_start", "devices": self._devices, "links": self._links, "mode": "live"})

            # Severity → FSM state mapping
            SEV_TO_FSM = {
                "critical": "attacked",
                "high": "attacked",
                "warning": "vulnerable",
                "medium": "vulnerable",
                "low": "scanning",
                "info": "secure",
            }

            while self.running:
                await asyncio.sleep(2)

                # Fetch events from the last 5 seconds
                events = await bridge.get_security_events(limit=50)
                new_events = [
                    e for e in events
                    if e.get("id", 0) > self._last_seen_event_id
                ]

                if not new_events:
                    continue

                for evt in new_events:
                    self.step += 1
                    fsm_state = evt.get("fsm_state", "")
                    severity = evt.get("severity", "info")
                    target = evt.get("target", "") or evt.get("target_mac", "")
                    source = evt.get("source", "")
                    message = evt.get("message", "")

                    # Determine new FSM state for target device
                    new_status = SEV_TO_FSM.get(severity, "scanning")
                    if fsm_state:
                        new_status = fsm_state

                    # Update device status by target name/MAC/IP
                    if target:
                        for dev in self._devices:
                            dev_id = dev.get("id") or dev.get("devMAC") or dev.get("devName") or ""
                            dev_ip = dev.get("devLastIP") or dev.get("ip") or ""
                            dev_mac = dev.get("devMAC") or dev.get("mac") or ""
                            if target in (dev_id, dev_ip, dev_mac, dev.get("devName", "")):
                                # Don't downgrade from attacked
                                if dev.get("status") != "attacked":
                                    dev["status"] = new_status
                                # Persist to DB
                                try:
                                    await bridge.update_device_status(dev_mac, dev.get("status", "secure"))
                                except Exception:
                                    pass
                                break

                    # Broadcast to WebSocket clients
                    broadcast_evt = {
                        "type": fsm_state or severity,
                        "source": source,
                        "target": target,
                        "severity": severity,
                        "message": message,
                        "step": self.step,
                        "devices": self._devices,
                    }
                    if self._broadcast_callback:
                        await self._broadcast_callback(broadcast_evt)

                # Update cursor
                self._last_seen_event_id = max(e.get("id", 0) for e in new_events)

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error(f"Live scenario error: {exc}")
        finally:
            self.running = False

    def get_devices(self) -> list[dict]:
        return self._devices
