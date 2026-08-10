"""Security Scheduler — cron-aware periodic task execution.

Supports three scheduling modes:
  - interval: fixed interval (seconds), backward compatible
  - cron: standard 5-field cron expressions (via croniter)
  - once: one-shot at a specific datetime

Tasks persist to config/scheduler.json and survive restarts.
"""
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from croniter import croniter

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "scheduler.json"

# ── Legacy defaults (auto-migrated on first load) ────────────────────

LEGACY_CHECKS = {
    "network_scan": {
        "tool_server": "nmap-scan", "tool_name": "host_discovery",
        "tool_args": {}, "interval_seconds": 90,
        "notify_on": ["new_device", "device_down"],
    },
    "cve_check": {
        "tool_server": "cve-intel", "tool_name": "check_device_vulns",
        "tool_args": {"vendor": "Hikvision", "min_severity": "HIGH"},
        "interval_seconds": 3600,
        "notify_on": ["new_vulnerability"],
    },
    "baseline_check": {
        "tool_server": "security-baseline", "tool_name": "check_baseline",
        "tool_args": {"detailed": True}, "interval_seconds": 1800,
        "notify_on": ["score_drop"],
    },
    "traffic_analysis": {
        "tool_server": "traffic-analyzer", "tool_name": "extract_ioc",
        "tool_args": {}, "interval_seconds": 600,
        "notify_on": ["ioc_found"],
    },
    "config_audit": {
        "tool_server": "config-audit", "tool_name": "audit_config",
        "tool_args": {}, "interval_seconds": 3600,
        "notify_on": ["misconfiguration"],
    },
}


# ── ScheduledTask ────────────────────────────────────────────────────

class ScheduledTask:
    """A single schedulable task with cron/interval/once support."""

    def __init__(self, config: dict):
        self.id: str = config.get("id", uuid.uuid4().hex[:8])
        self.name: str = config.get("name", self.id)
        self.type: str = config.get("type", "preset")  # preset / custom / timer
        self.tool_server: str = config.get("tool_server", "")
        self.tool_name: str = config.get("tool_name", "")
        self.tool_args: dict = config.get("tool_args", {})
        self.prompt: str = config.get("prompt", "")

        # Schedule config
        self.schedule_mode: str = config.get("schedule_mode", "interval")
        self.interval_seconds: int = config.get("interval_seconds", 600)
        self.cron_expr: str | None = config.get("cron_expr")
        self.run_at: str | None = config.get("run_at")

        # Flags
        self.enabled: bool = config.get("enabled", True)
        self.paused: bool = config.get("paused", False)
        self.notify_on: list[str] = config.get("notify_on", [])

        # Runtime state
        self.last_run: float = config.get("last_run_ts", 0)
        self.last_result: dict | None = None
        self.last_status: str = "never_run"
        self.run_count: int = config.get("run_count", 0)
        self.error_count: int = 0
        self._async_task: asyncio.Task | None = None

    # ── Next-run calculation ──────────────────────────────────────

    def calculate_next_run(self) -> datetime | None:
        now_local = datetime.now().astimezone()
        now_utc = datetime.now(timezone.utc)
        if self.schedule_mode == "interval":
            base = self.last_run if self.last_run else time.time()
            return datetime.fromtimestamp(base, tz=timezone.utc) + timedelta(
                seconds=self.interval_seconds
            )
        elif self.schedule_mode == "cron" and self.cron_expr:
            try:
                # Interpret cron in local timezone so "0 9 * * *" = local 9am
                return croniter(self.cron_expr, now_local).get_next(datetime)
            except (ValueError, KeyError):
                return None
        elif self.schedule_mode == "once" and self.run_at:
            try:
                t = datetime.fromisoformat(self.run_at)
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                return t if t > now_utc else None
            except (ValueError, TypeError):
                return None
        return None

    def seconds_until_next(self) -> float | None:
        nxt = self.calculate_next_run()
        if nxt is None:
            return None
        now = datetime.now(timezone.utc)
        if nxt.tzinfo is None:
            nxt = nxt.replace(tzinfo=timezone.utc)
        delta = (nxt - now).total_seconds()
        return max(delta, 0)

    # ── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        nxt = self.calculate_next_run()
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "tool": f"{self.tool_server}/{self.tool_name}" if self.tool_server else "",
            "schedule_mode": self.schedule_mode,
            "interval_seconds": self.interval_seconds,
            "cron_expr": self.cron_expr,
            "run_at": self.run_at,
            "enabled": self.enabled,
            "paused": self.paused,
            "status": self._runtime_status(),
            "last_run": (
                datetime.fromtimestamp(self.last_run, tz=timezone.utc).isoformat()
                if self.last_run else None
            ),
            "next_run": nxt.isoformat() if nxt else None,
            "next_run_in": round(self.seconds_until_next() or 0),
            "run_count": self.run_count,
            "error_count": self.error_count,
            "last_status": self.last_status,
        }

    def to_config(self) -> dict:
        return {
            "id": self.id, "name": self.name, "type": self.type,
            "tool_server": self.tool_server, "tool_name": self.tool_name,
            "tool_args": self.tool_args, "prompt": self.prompt,
            "schedule_mode": self.schedule_mode,
            "interval_seconds": self.interval_seconds,
            "cron_expr": self.cron_expr, "run_at": self.run_at,
            "enabled": self.enabled, "paused": self.paused,
            "notify_on": self.notify_on,
            "last_run_ts": self.last_run, "run_count": self.run_count,
        }

    def _runtime_status(self) -> str:
        if not self.enabled:
            return "stopped"
        if self.paused:
            return "paused"
        return "running"

    # ── Execution ─────────────────────────────────────────────────

    async def execute(self) -> dict:
        try:
            if self.tool_server and self.tool_name:
                from .mcp_tool_service import call_tool, _load_subnet
                args = dict(self.tool_args)
                if args.get("target") == "auto":
                    args["target"] = _load_subnet()
                result = await call_tool(self.tool_server, self.tool_name, **args)
            elif self.prompt:
                from .mcp_tool_service import execute_intent
                results = await execute_intent(self.prompt)
                result = {"prompt_results": results}
            else:
                result = {"error": "no tool or prompt configured"}

            self.last_run = time.time()
            self.last_result = result
            self.run_count += 1
            is_error = isinstance(result, dict) and "error" in result
            self.last_status = "error" if is_error else "success"
            if is_error:
                self.error_count += 1
            return result
        except Exception as e:
            self.last_run = time.time()
            self.last_status = "error"
            self.error_count += 1
            self.last_result = {"error": str(e)}
            return {"error": str(e)}


# ── SecurityScheduler ────────────────────────────────────────────────

class SecurityScheduler:
    """Cron-aware task scheduler with dynamic CRUD and persistence."""

    def __init__(self):
        self._running = False
        self._tasks: dict[str, ScheduledTask] = {}
        self._async_tasks: dict[str, asyncio.Task] = {}
        self._config: dict = {}

    # ── Config I/O ────────────────────────────────────────────────

    def _load_config(self) -> dict:
        if CONFIG_PATH.exists():
            try:
                return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, Exception):
                pass
        return {"enabled": True, "tasks": []}

    def _save_config(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tasks_cfg = [t.to_config() for t in self._tasks.values() if t.type != "timer"]
        payload = {"enabled": self._config.get("enabled", True), "tasks": tasks_cfg}
        CONFIG_PATH.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _migrate_legacy_config(self):
        """Convert old 'checks' dict format to new 'tasks' array."""
        if "checks" not in self._config:
            return
        if self._config.get("tasks"):
            return
        checks = self._config.pop("checks")
        tasks = []
        for name, cfg in checks.items():
            tasks.append({
                "id": name,
                "name": {
                    "network_scan": "网络扫描", "cve_check": "CVE 漏洞检查",
                    "baseline_check": "安全基线检查", "traffic_analysis": "流量分析",
                    "config_audit": "配置审计",
                }.get(name, name),
                "type": "preset",
                "tool_server": cfg.get("tool_server", ""),
                "tool_name": cfg.get("tool_name", ""),
                "tool_args": cfg.get("tool_args", {}),
                "schedule_mode": "interval",
                "interval_seconds": cfg.get("interval_seconds", 600),
                "cron_expr": None,
                "run_at": None,
                "enabled": cfg.get("enabled", True),
                "paused": False,
                "notify_on": cfg.get("notify_on", []),
            })
        self._config["tasks"] = tasks

    def _ensure_default_tasks(self):
        """If no tasks exist, create the 5 default preset checks."""
        if self._config.get("tasks"):
            return
        tasks = []
        for name, cfg in LEGACY_CHECKS.items():
            tasks.append({
                "id": name,
                "name": {
                    "network_scan": "网络扫描", "cve_check": "CVE 漏洞检查",
                    "baseline_check": "安全基线检查", "traffic_analysis": "流量分析",
                    "config_audit": "配置审计",
                }.get(name, name),
                "type": "preset", **cfg,
                "schedule_mode": "interval",
                "cron_expr": None, "run_at": None,
                "enabled": True, "paused": False,
            })
        self._config["tasks"] = tasks

    # ── Lifecycle ─────────────────────────────────────────────────

    async def start(self):
        self._config = self._load_config()
        self._migrate_legacy_config()
        self._ensure_default_tasks()
        if not self._config.get("enabled", True):
            logger.info("Security scheduler disabled by config")
            return

        self._running = True
        for task_cfg in self._config.get("tasks", []):
            task = ScheduledTask(task_cfg)
            self._tasks[task.id] = task
            if task.enabled and not task.paused:
                self._spawn(task)

        self._save_config()
        logger.info(f"Security scheduler started: {len(self._tasks)} tasks")

    async def stop(self):
        self._running = False
        for t in self._async_tasks.values():
            t.cancel()
        self._async_tasks.clear()
        logger.info("Security scheduler stopped")

    def _spawn(self, task: ScheduledTask):
        if task.id in self._async_tasks:
            self._async_tasks[task.id].cancel()
        self._async_tasks[task.id] = asyncio.create_task(
            self._run_loop(task), name=f"scheduler_{task.id}"
        )

    async def _run_loop(self, task: ScheduledTask):
        while self._running and task.enabled and not task.paused:
            seconds = task.seconds_until_next()
            if seconds is None:
                task.enabled = False
                self._save_config()
                break
            if seconds > 0:
                try:
                    await asyncio.sleep(seconds)
                except asyncio.CancelledError:
                    return
            if not self._running or task.paused:
                break
            result = await task.execute()
            await self._record_run(task.id, result)
            issues = self._count_issues(result)
            await self._notify_if_needed(task.id, task, result, issues)
            # Once-mode task done
            if task.schedule_mode == "once":
                task.enabled = False
                self._save_config()
                break
            self._save_config()

    # ── Issue counting ────────────────────────────────────────────

    def _count_issues(self, result: dict) -> int:
        if not isinstance(result, dict):
            return 0
        # Direct issue count fields
        for key in ("issues_found", "vulnerabilities_found", "failed_checks",
                     "iocs_found", "total_findings", "total_cves"):
            if key in result:
                return result[key]
        # Baseline-specific: total_fail / critical_failures
        if "total_fail" in result:
            return result["total_fail"]
        if "critical_failures" in result:
            return result["critical_failures"]
        # Network scan: hosts_up is not an issue
        if "hosts_found" in result or "hosts_up" in result:
            return 0
        # Check nested structures (some tools return dict with nested counts)
        summary = result.get("summary", {})
        if isinstance(summary, dict) and "total_fail" in summary:
            return summary["total_fail"]
        return 0

    def _build_result_summary(self, name: str, result: dict) -> str:
        """Build a human-readable summary from the task result."""
        if not isinstance(result, dict):
            return ""
        if name == "network_scan":
            hosts = result.get("hosts_up", 0)
            return f"扫描完成，发现 {hosts} 台设备在线"
        if name == "cve_check":
            total = result.get("total_cves", 0)
            crit = result.get("critical", 0)
            high = result.get("high", 0)
            return f"发现 {total} 个 CVE（{crit} 个严重，{high} 个高危）"
        if name == "baseline_check":
            score = result.get("overall_score", 0)
            devices = result.get("devices_audited", 0)
            summary = result.get("summary", {})
            fail = summary.get("total_fail", 0) if isinstance(summary, dict) else 0
            crit_fail = summary.get("critical_failures", 0) if isinstance(summary, dict) else 0
            return f"审计 {devices} 台设备，评分 {score}/100，{fail} 项不合规（{crit_fail} 项严重）"
        if name == "traffic_analysis":
            iocs = result.get("iocs_found", 0)
            pkt_count = result.get("packets_analyzed", 0)
            return f"分析 {pkt_count} 个数据包，发现 {iocs} 个 IoC 指标" if pkt_count else f"发现 {iocs} 个 IoC 指标"
        if name == "config_audit":
            findings = result.get("total_findings", 0)
            crit = result.get("critical", 0)
            high = result.get("high", 0)
            device = result.get("device", "未知设备")
            return f"审计设备 {device}，发现 {findings} 个问题（{crit} 严重，{high} 高危）"
        return str(result)[:200]

    async def _notify_if_needed(self, name, task, result, issues, bypass_dedup=False):
        """Always send a completion notification via the notification bridge.
        Returns the notification guid (or None on failure)."""
        try:
            from .notification_bridge import get_notification_bridge
            bridge = get_notification_bridge()
            check_labels = {
                "network_scan": "网络扫描",
                "cve_check": "CVE 漏洞检查",
                "baseline_check": "安全基线检查",
                "traffic_analysis": "流量分析",
                "config_audit": "配置审计",
            }
            label = check_labels.get(name, task.name if hasattr(task, 'name') else name)
            is_error = isinstance(result, dict) and "error" in result
            summary = self._build_result_summary(name, result) if isinstance(result, dict) else ""

            if is_error:
                title = f"任务失败: {label}"
                message = f"{label} 执行出错: {str(result['error'])[:150]}"
                severity = "warning"
            elif issues > 0:
                title = f"安全检查: {label}"
                # mock/unavailable 结果不推 critical（避免假告警）：traffic mock IoC、
                # config-audit 假配置、cve mock fallback 等都曾因 issues>=5 被误报 critical
                _r = result if isinstance(result, dict) else {}
                rmode = _r.get("mode") or _r.get("source")
                if rmode in ("mock", "unavailable"):
                    severity = "info"
                    message = f"{label} 数据来源为 {rmode}（非真实采集），发现 {issues} 项，不升级为告警。{summary}"
                else:
                    severity = "critical" if issues >= 5 else "warning"
                    message = f"{label} 发现 {issues} 个问题。{summary}"
            else:
                title = f"任务完成: {label}"
                message = f"{label} 执行成功。{summary}" if summary else f"{label} 执行成功，未发现问题。"
                severity = "info"

            # 也写 security_events —— 让 /api/dashboard/alerts（chat 事件标签/HUD）
            # 能读到 scheduler 告警。否则 scheduler 告警只在 cyberclaw_notifications，
            # chat 事件看不到（两套管道分裂的根因）。
            try:
                from .nx_bridge import get_bridge
                await get_bridge().record_security_event(
                    source_type="scheduled_check", severity=severity,
                    message=f"{title}: {message}", source=name, target=name)
            except Exception as _e:
                logger.debug(f"record_security_event(scheduler) failed: {_e}")

            return await bridge._send(
                title=title, message=message,
                severity=severity, section="scheduled_checks",
                task_type=name,
                extra_data=result if isinstance(result, dict) else None,
                bypass_dedup=bypass_dedup,
            )
        except Exception as e:
            logger.warning(f"Scheduler notification failed for {name}: {e}")
            return None

    async def _record_run(self, name, result):
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scheduled_check_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        check_name TEXT NOT NULL,
                        status TEXT DEFAULT 'running',
                        result_summary TEXT DEFAULT '',
                        issues_found INTEGER DEFAULT 0,
                        started_at TEXT DEFAULT (datetime('now')),
                        completed_at TEXT DEFAULT '',
                        notification_sent INTEGER DEFAULT 0
                    )
                """)
                conn.execute("""
                    INSERT INTO scheduled_check_runs
                        (check_name, status, result_summary, issues_found, completed_at, notification_sent)
                    VALUES (?, ?, ?, ?, datetime('now'), 0)
                """, (name, "success" if not isinstance(result, dict) or "error" not in result else "error",
                      str(result)[:500], self._count_issues(result)))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Record scheduler run failed: {e}")

    # ── CRUD API ──────────────────────────────────────────────────

    def create_task(self, config: dict) -> ScheduledTask:
        if "id" not in config:
            config["id"] = uuid.uuid4().hex[:8]
        if "type" not in config:
            config["type"] = "custom"
        task = ScheduledTask(config)
        self._tasks[task.id] = task
        if task.enabled and not task.paused:
            self._spawn(task)
        self._save_config()
        return task

    def update_task(self, task_id: str, updates: dict) -> ScheduledTask | None:
        task = self._tasks.get(task_id)
        if not task:
            return None
        for k, v in updates.items():
            if v is not None and hasattr(task, k):
                setattr(task, k, v)
        # Re-spawn if schedule changed
        schedule_keys = {"schedule_mode", "interval_seconds", "cron_expr", "run_at"}
        if schedule_keys & set(updates.keys()):
            if task.id in self._async_tasks:
                self._async_tasks[task.id].cancel()
                self._async_tasks.pop(task.id, None)
            if task.enabled and not task.paused:
                self._spawn(task)
        self._save_config()
        return task

    def delete_task(self, task_id: str) -> bool:
        if task_id not in self._tasks:
            return False
        if task_id in self._async_tasks:
            self._async_tasks[task_id].cancel()
            self._async_tasks.pop(task_id, None)
        del self._tasks[task_id]
        self._save_config()
        return True

    def pause_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.paused = True
        if task_id in self._async_tasks:
            self._async_tasks[task_id].cancel()
            self._async_tasks.pop(task_id, None)
        self._save_config()
        return True

    def resume_task(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.paused = False
        self._spawn(task)
        self._save_config()
        return True

    def get_active_tasks(self) -> list[dict]:
        return [t.to_dict() for t in self._tasks.values()]

    # ── Timer registration (from chat.py) ─────────────────────────

    def register_timer_task(self, timer_id: str, prompt: str,
                            delay_seconds: int, created_at: float,
                            asyncio_task: asyncio.Task):
        run_at = datetime.fromtimestamp(created_at + delay_seconds, tz=timezone.utc)
        task = ScheduledTask({
            "id": timer_id, "name": prompt[:50], "type": "timer",
            "prompt": prompt, "schedule_mode": "once",
            "run_at": run_at.isoformat(),
            "enabled": True, "paused": False,
        })
        task._async_task = asyncio_task
        self._tasks[timer_id] = task

    def unregister_timer_task(self, timer_id: str):
        self._tasks.pop(timer_id, None)

    # ── Public query API ──────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "tasks": self.get_active_tasks(),
            "total_tasks": len(self._tasks),
            "active_tasks": sum(1 for t in self._tasks.values()
                                if t.enabled and not t.paused),
        }

    async def get_history(self, limit: int = 50) -> list[dict]:
        try:
            from ..db.compat import get_temp_db_connection
            conn = get_temp_db_connection()
            try:
                rows = conn.execute("""
                    SELECT check_name, status, result_summary, issues_found,
                           started_at, completed_at, notification_sent
                    FROM scheduled_check_runs ORDER BY id DESC LIMIT ?
                """, (limit,)).fetchall()
                return [{"check_name": r[0], "status": r[1], "result_summary": r[2],
                         "issues_found": r[3], "started_at": r[4], "completed_at": r[5],
                         "notification_sent": bool(r[6])} for r in rows]
            finally:
                conn.close()
        except Exception:
            return []

    async def trigger_check(self, name: str) -> dict | None:
        task = self._tasks.get(name)
        if not task:
            return None
        result = await task.execute()
        await self._record_run(name, result)
        issues = self._count_issues(result)
        guid = await self._notify_if_needed(name, task, result, issues, bypass_dedup=True)
        self._save_config()
        return {"check": name, "result": result, "issues": issues, "notif_guid": guid}


# ── Singleton ─────────────────────────────────────────────────────────

_scheduler: SecurityScheduler | None = None


def get_security_scheduler() -> SecurityScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = SecurityScheduler()
    return _scheduler
