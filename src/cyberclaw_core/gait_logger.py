import json
import logging
import os
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class GaitLogger:
    """JSON Lines audit logger for CyberClaw operations."""

    def __init__(self, log_dir: str | None = None):
        self.log_dir = log_dir or os.path.expanduser("~/.cyberclaw/logs")
        os.makedirs(self.log_dir, exist_ok=True)

    def log(self, action: str, details: dict | None = None) -> None:
        now = datetime.now(timezone.utc)
        entry = {
            "timestamp": now.isoformat(),
            "action": action,
            "details": details or {},
        }
        log_path = os.path.join(self.log_dir, f"{now.strftime('%Y-%m-%d')}.jsonl")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
