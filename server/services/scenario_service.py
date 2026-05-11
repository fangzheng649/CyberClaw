import asyncio


MIRAI_SCRIPT = [
    {"delay": 3000, "event": {"type": "system_ready", "message": "IoT 网络安全监控已上线"}},
    {"delay": 5000, "event": {"type": "scan_started", "source": "kali", "message": "检测到来自 10.0.1.100 的端口扫描行为", "details": {"targets": ["camera-1","camera-2","camera-3","camera-4","plug-1","plug-2"]}}},
    {"delay": 6000, "event": {"type": "port_scan", "source": "kali", "target": "camera-1", "severity": "warning", "message": "Camera-1 开放 Telnet 端口 (23)", "details": {"port": 23, "service": "Telnet"}}},
    {"delay": 2000, "event": {"type": "port_scan", "source": "kali", "target": "camera-2", "severity": "warning", "message": "Camera-2 开放 Telnet 端口 (23)", "details": {"port": 23, "service": "Telnet"}}},
    {"delay": 2000, "event": {"type": "vulnerability_found", "target": "camera-1", "severity": "critical", "message": "Camera-1 发现严重漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8}}},
    {"delay": 3000, "event": {"type": "vulnerability_found", "target": "camera-2", "severity": "critical", "message": "Camera-2 发现严重漏洞 CVE-2021-36260 (CVSS 9.8)", "details": {"cve": "CVE-2021-36260", "cvss": 9.8}}},
    {"delay": 4000, "event": {"type": "bruteforce", "source": "kali", "target": "camera-1", "severity": "critical", "message": "Camera-1 遭遇暴力破解 — 12次尝试后成功", "details": {"attempts": 12, "success": True}}},
    {"delay": 3000, "event": {"type": "attack_detected", "source": "kali", "target": "camera-1", "severity": "critical", "message": "Camera-1 已被 Mirai 僵尸网络感染", "details": {"malware": "Mirai"}}},
    {"delay": 4000, "event": {"type": "lateral_movement", "source": "camera-1", "target": "camera-2", "severity": "critical", "message": "Mirai 从 Camera-1 横向扩散至 Camera-2"}},
    {"delay": 3000, "event": {"type": "c2_detected", "source": "camera-1", "severity": "critical", "message": "检测到 C2 回连: 185.220.101.34", "details": {"c2_server": "185.220.101.34:443"}}},
    {"delay": 3000, "event": {"type": "analysis_complete", "severity": "critical", "message": "CyberAgent 分析完成: Mirai 僵尸网络感染，置信度 94%", "details": {"threat": "Mirai Botnet", "confidence": 94}}},
    {"delay": 4000, "event": {"type": "isolation_request", "severity": "warning", "message": "建议隔离 Camera-1/2", "details": {"targets": ["camera-1", "camera-2"]}}},
    {"delay": 4000, "event": {"type": "device_isolated", "target": "camera-1", "severity": "info", "message": "Camera-1 已隔离"}},
    {"delay": 2000, "event": {"type": "device_isolated", "target": "camera-2", "severity": "info", "message": "Camera-2 已隔离"}},
    {"delay": 3000, "event": {"type": "threat_resolved", "severity": "info", "message": "威胁已清除，攻击时间线报告已生成", "details": {"isolated": ["camera-1", "camera-2"]}}},
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
}


class ScenarioService:
    def __init__(self):
        self.running = False
        self.step = 0
        self._task: asyncio.Task | None = None
        self._broadcast_callback = None
        self._devices: list[dict] = []
        self._links: list[dict] = []

    def set_broadcast(self, callback):
        self._broadcast_callback = callback

    def set_topology(self, devices, links):
        self._devices = [d.model_dump() for d in devices]
        self._links = [{"from": l.from_, "to": l.to} for l in links]

    def get_status(self) -> dict:
        return {"running": self.running, "step": self.step, "total_steps": len(MIRAI_SCRIPT)}

    def _reset_devices(self):
        for d in self._devices:
            d["status"] = "secure"

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

    async def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.step = 0
        self._reset_devices()
        if self._broadcast_callback:
            await self._broadcast_callback({"type": "scenario_start", "devices": self._devices, "links": self._links})
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
        self.running = False
        self.step = 0
        self._reset_devices()
        if self._broadcast_callback:
            await self._broadcast_callback({"type": "scenario_stop", "devices": self._devices})

    async def _run(self) -> None:
        try:
            for i, script_step in enumerate(MIRAI_SCRIPT):
                await asyncio.sleep(script_step["delay"] / 1000)
                self.step = i + 1
                evt = script_step["event"]
                self._update_device_status(evt)
                if self._broadcast_callback:
                    await self._broadcast_callback({**evt, "step": self.step, "devices": self._devices})
            if self._broadcast_callback:
                await self._broadcast_callback({"type": "scenario_complete", "devices": self._devices})
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False

    def get_devices(self) -> list[dict]:
        return self._devices
