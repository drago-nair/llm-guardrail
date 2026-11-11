from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = "logs/audit.jsonl"


def _log_path() -> Path:
    return Path(os.environ.get("GUARDRAIL_AUDIT_LOG_PATH", DEFAULT_LOG_PATH))


def append_audit_log(
    *,
    processed_prompt: str,
    is_allowed: bool,
    rejection_reason: str | None,
    audit_flags: list[str],
) -> None:
    """Appends one JSON line describing a /check verdict to the audit log."""
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_allowed": is_allowed,
        "rejection_reason": rejection_reason,
        "audit_flags": audit_flags,
        "processed_prompt": processed_prompt,
    }

    log_path = _log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n")
