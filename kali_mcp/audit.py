"""Append-only JSONL audit log — the choke point CLAUDE.md §3/§4/§6 require.

Every command run_tool executes is recorded here, exactly once, regardless of how
it ended (ok / nonzero_exit / timeout / not_found). Nothing executes unlogged, and
this writer NEVER rewrites or truncates the file — it only appends. One JSON object
per line so the log stays grep-/tail-able and survives a partial write.

Log location comes from env KALI_MCP_AUDIT_LOG (default ./logs/audit.jsonl). The env
is read at call time, not import time, so tests can point it at a tmp file.

Container note: the default lives under /app/logs; /app is chowned to the non-root
`pentester` user in the Dockerfile, so creating ./logs at runtime is already
writable — no image change needed for this task.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_AUDIT_LOG = "./logs/audit.jsonl"


def _audit_path() -> Path:
    """Resolve the audit-log path from the environment at call time."""
    return Path(os.environ.get("KALI_MCP_AUDIT_LOG", DEFAULT_AUDIT_LOG))


def audit_log(entry: dict) -> None:
    """Append exactly ONE JSON object as one line (JSONL) to the audit log.

    Creates the parent directory if missing. Append-only: opening in "a" mode
    never truncates an existing log. ensure_ascii=False keeps non-ASCII readable;
    sort_keys gives each line a stable field order.
    """
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
