"""CyberClaw VM 实验场隔离执行器 —— SSH 到 Ubuntu VM 断/恢复设备 tap 口。

实验场每台虚拟设备占一个 TAP 口桥接在 br0 上（tap↔MAC↔IP 静态映射），
`sudo ip link set tapN down` 即把设备从实验内网断开 —— 语义等效于物理场景
的交换机端口关闭。凭证复用 SURICATA_SSH_*（同一台 VM）。
"""
import asyncio
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_VM_LAB_CONFIG = Path(__file__).resolve().parent.parent.parent / "config" / "vm_lab.json"


def _load_registry() -> dict:
    """ip → registry entry（含 tap 编号）。"""
    try:
        cfg = json.loads(_VM_LAB_CONFIG.read_text(encoding="utf-8"))
        prefix = cfg.get("internal_prefix", "192.168.1.")
        return {f"{prefix}{n}": d for n, d in (cfg.get("devices") or {}).items()}
    except Exception:
        return {}


def vm_device_tap(device_ip: str) -> int | None:
    """设备 IP → tap 编号（不在实验场注册表返回 None）。"""
    entry = _load_registry().get(device_ip)
    if entry and entry.get("tap") is not None:
        return int(entry["tap"])
    return None


def _ssh_run(cmd: str) -> tuple[bool, str]:
    """同步 SSH 执行（在线程池中调用）。返回 (成功, 输出)。"""
    import paramiko
    pw = ""
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("SURICATA_SSH_PASS="):
                pw = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(os.getenv("SURICATA_SSH_HOST", "192.168.24.130"),
                       port=int(os.getenv("SURICATA_SSH_PORT", "22")),
                       username=os.getenv("SURICATA_SSH_USER", "fz"),
                       password=pw or os.getenv("SURICATA_SSH_PASS", ""),
                       timeout=8, allow_agent=False, look_for_keys=False)
        _, out, err = client.exec_command(cmd, timeout=10)
        output = out.read().decode("utf-8", "replace").strip()
        error = err.read().decode("utf-8", "replace").strip()
        rc = out.channel.recv_exit_status()
        return (rc == 0, output or error)
    finally:
        try:
            client.close()
        except Exception:
            pass


def _tap_state(tap: int) -> str:
    ok, out = _ssh_run(f"ip link show tap{tap}")
    if not ok:
        return "unknown"
    return "DOWN" if "DOWN" in out else "UP"


async def vm_isolate(device_ip: str) -> dict:
    """断开设备的 tap 口（等效拔网线）。"""
    tap = vm_device_tap(device_ip)
    if tap is None:
        return {"status": "unsupported", "message": f"{device_ip} 不在 VM 实验场注册表"}
    try:
        ok, out = await asyncio.to_thread(_ssh_run, f"sudo ip link set tap{tap} down")
        state = await asyncio.to_thread(_tap_state, tap)
        if ok and state == "DOWN":
            logger.info(f"[vm_isolator] tap{tap} DOWN → {device_ip} 已从实验内网断开")
            return {"status": "isolated", "method": "vm_tap", "tap": tap, "state": state}
        return {"status": "error", "method": "vm_tap", "tap": tap,
                "message": f"tap{tap} 操作失败({out[:100]})"}
    except Exception as e:
        return {"status": "error", "method": "vm_tap", "message": str(e)}


async def vm_restore(device_ip: str) -> dict:
    """恢复设备的 tap 口。"""
    tap = vm_device_tap(device_ip)
    if tap is None:
        return {"status": "unsupported", "message": f"{device_ip} 不在 VM 实验场注册表"}
    try:
        ok, out = await asyncio.to_thread(_ssh_run, f"sudo ip link set tap{tap} up")
        state = await asyncio.to_thread(_tap_state, tap)
        if ok:
            logger.info(f"[vm_isolator] tap{tap} UP → {device_ip} 已恢复接入")
            return {"status": "restored", "method": "vm_tap", "tap": tap, "state": state}
        return {"status": "error", "method": "vm_tap", "tap": tap,
                "message": f"tap{tap} 操作失败({out[:100]})"}
    except Exception as e:
        return {"status": "error", "method": "vm_tap", "message": str(e)}
