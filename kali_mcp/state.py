"""Tiny on-disk state store for the LAST rogue-host watch result (Phase 4, 4.1).

Why this exists: the Phase-4 dashboard (4.2) needs to show the network's rogue-host
status WITHOUT secretly running a scan to fill it (CLAUDE.md §2 — a dashboard that
fabricates an "all clear" is the exact lie this project kills). So the data flow is:

    arp_watch (3.3) runs a REAL scan  ->  persists its WatchResult here  ->
    network_status (4.1) READS that persisted result, never invents one.

If no watch has been persisted yet, load_last_watch returns None and the caller
reports network.available=false with a "run arp_watch first" note — an honest
"no data", never a fake summary.

This module is deliberately minimal: write one JSON file, read one JSON file. It
NEVER fabricates a result, and a missing/corrupt file is reported as absence (None),
not papered over with an empty-but-present verdict.

Path resolution (call time, so tests can redirect it): env KALI_MCP_STATE_DIR, else
./state. The file is gitignored — it can contain Mark's real device IP/MAC data.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_STATE_DIR = "./state"
LAST_WATCH_FILENAME = "last_watch.json"


def _state_dir() -> Path:
    """Resolve the state directory from the environment at call time."""
    return Path(os.environ.get("KALI_MCP_STATE_DIR", DEFAULT_STATE_DIR))


def _last_watch_path() -> Path:
    return _state_dir() / LAST_WATCH_FILENAME


def save_last_watch(watch_payload: dict, *, path: str | None = None) -> Path:
    """Persist the most recent arp_watch result so the dashboard can read it later.

    Stamps the save time as `as_of` and stores the verbatim watch payload under
    `watch`. Overwrites any previous file (we keep only the LATEST watch — a stale
    older one would mislead the dashboard). Returns the path written.

    The payload is whatever arp_watch returned (its to_dict() plus context); we do
    not reshape it here, so nothing is lost or invented.
    """
    target = Path(path) if path is not None else _last_watch_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "as_of": datetime.now(timezone.utc).isoformat(),
        "watch": watch_payload,
    }
    # Write atomically-ish: full json.dumps in memory, single write call.
    text = json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2)
    target.write_text(text + "\n", encoding="utf-8")
    return target


def load_last_watch(path: str | None = None) -> dict | None:
    """Return the last persisted watch record, or None if there is none / it's unreadable.

    Returns the stored {"as_of", "watch"} record. None means "no watch has been
    persisted (or the file is corrupt)" — an HONEST absence the caller turns into
    network.available=false, never a fabricated all-clear (CLAUDE.md §2). A corrupt
    file is treated as absence rather than crashing the whole status snapshot.
    """
    target = Path(path) if path is not None else _last_watch_path()
    if not target.is_file():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict) or "watch" not in data:
        return None
    return data
