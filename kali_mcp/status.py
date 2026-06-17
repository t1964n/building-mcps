"""build_status — the single honest data contract behind the Phase-4 dashboard.

Phase 4 is "make it shine", but a dashboard is only as honest as its data. This
module gathers the WHOLE platform's real state into one well-shaped snapshot so the
UI (4.2) never has to invent anything. Every field here is REAL or HONESTLY-ABSENT
(CLAUDE.md §2). It COMPOSES existing pieces — it does not re-implement them:

  * tools / install status  -> tools.meta.gather_tool_status (real shutil.which)
  * roster counts           -> registry.ROSTER
  * audit tallies           -> READ-ONLY parse of the real ./logs/audit.jsonl
  * whitelist state         -> whitelist.load_whitelist (its loud error captured)
  * network rogue status    -> state.load_last_watch (last REAL arp_watch, or absent)

THE ONE THING THIS MODULE MUST NEVER DO (it is the task): collapse the three states
a lazy dashboard merges into one green light. They stay distinguishable here:
  (a) all-known/clean      -> network.available=true, summary.rogue==0
  (b) couldn't-scan/no-data-> network.available=false, note says run arp_watch
  (c) whitelist-broken     -> whitelist.loaded=false, whitelist.error populated
None of these is allowed to look like the others.

This module does NO scanning and opens NO sockets. The audit log is opened
read-only; the whitelist is loaded read-only; the last-watch state is read-only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .audit import _audit_path
from .registry import ROSTER
from .state import load_last_watch
from .tools.meta import gather_tool_status
from .whitelist import WhitelistError, load_whitelist

# The audit statuses run_tool emits (executor.ToolResult.status). We seed the
# tally with all four so a present-but-quiet status reads as 0, not "missing".
_KNOWN_AUDIT_STATUSES = ("ok", "nonzero_exit", "timeout", "not_found")

DEFAULT_RECENT_AUDIT = 10


def _build_tools_section() -> tuple[list[dict], dict]:
    """Real install status of every roster tool + registered/installed counts.

    Reuses tools.meta.gather_tool_status verbatim (real shutil.which per CLAUDE.md
    §2 honesty rule 3) — the dashboard reflects the actual container, not the roster
    aspiration.
    """
    tools = gather_tool_status()
    installed = sum(1 for t in tools if t["installed"])
    counts = {"registered": len(ROSTER), "installed": installed}
    return tools, counts


def _build_audit_section(recent_count: int) -> dict:
    """READ-ONLY parse of the real audit log (respects KALI_MCP_AUDIT_LOG).

    Honesty rule 2: a MISSING log -> available=false (not an empty-but-present
    tally). Malformed lines are COUNTED and reported, never silently dropped to make
    the log look clean. by_status is seeded with all four known statuses so a quiet
    status shows 0 rather than vanishing.
    """
    path = _audit_path()
    if not path.is_file():
        return {
            "available": False,
            "total_entries": 0,
            "recent": [],
            "by_status": {s: 0 for s in _KNOWN_AUDIT_STATUSES},
            "note": (
                f"no audit log at {str(path)!r} yet — it is created the first time a "
                "tool runs. This is 'no data', not '0 commands run clean'."
            ),
        }

    entries: list[dict] = []
    unparseable = 0
    with path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue  # blank lines are not malformed entries
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                unparseable += 1
                continue
            if not isinstance(obj, dict):
                unparseable += 1
                continue
            entries.append(obj)

    by_status: dict[str, int] = {s: 0 for s in _KNOWN_AUDIT_STATUSES}
    for obj in entries:
        status = obj.get("status")
        if not isinstance(status, str):
            status = "unknown"
        # Increment whatever status appears — an unexpected status surfaces as its
        # own key rather than being dropped (honesty over a tidy fixed shape).
        by_status[status] = by_status.get(status, 0) + 1

    # `recent` = the last K entries, projected to the dashboard-relevant fields.
    recent = [
        {
            "timestamp": obj.get("timestamp"),
            "tool": obj.get("tool"),
            "target": obj.get("target"),
            "status": obj.get("status"),
            "exit_code": obj.get("exit_code"),
            "duration_s": obj.get("duration_s"),
        }
        for obj in entries[-recent_count:]
    ]

    section = {
        "available": True,
        "total_entries": len(entries),
        "recent": recent,
        "by_status": by_status,
    }
    if unparseable:
        # Surface the count of bad lines honestly — don't hide them (CLAUDE.md §2).
        section["unparseable_lines"] = unparseable
        section["note"] = (
            f"{unparseable} line(s) in the audit log could not be parsed and are "
            "excluded from the tallies above; the parseable entries are counted."
        )
    return section


def _build_whitelist_section(whitelist_path: str | None) -> dict:
    """State of the whitelist itself. Honesty rule 4: a load FAILURE is captured into
    `error` with loaded=false — distinct from a successfully-loaded 0-device list."""
    try:
        devices = load_whitelist(whitelist_path)
    except WhitelistError as exc:
        return {
            "loaded": False,
            "device_count": None,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "loaded": True,
        "device_count": len(devices),
        "error": None,
    }


def _build_network_section() -> dict:
    """The LAST rogue-host watch result, read from persisted state — NEVER scanned here.

    Honesty rule 1: this does not secretly run a scan. It reads what arp_watch (3.3)
    last persisted. No persisted watch -> available=false with a clear "run arp_watch"
    note (state (b) couldn't-scan/no-data) — never a fabricated summary, never
    zeros-meaning-unknown.
    """
    record = load_last_watch()
    if record is None:
        return {
            "available": False,
            "as_of": None,
            "summary": None,
            "rogues": None,
            "note": (
                "no rogue-host scan has been persisted yet — run arp_watch to populate "
                "this. This is 'no data', NOT an all-clear."
            ),
        }

    watch = record.get("watch", {})
    summary = {
        "known": watch.get("known_count", 0),
        "rogue": watch.get("rogue_count", 0),
        "ip_mismatch": watch.get("ip_mismatch_count", 0),
        "absent": watch.get("absent_count", 0),
    }
    return {
        "available": True,
        "as_of": record.get("as_of"),
        "summary": summary,
        "rogues": watch.get("rogues", []),
        # Carry arp_watch's own earned-or-not verdict so the dashboard need not re-derive
        # it. An empty rogues list is only an all-clear when all_clear is True.
        "note": watch.get("verdict"),
        "all_clear": watch.get("all_clear"),
    }


def build_status(
    *,
    whitelist_path: str | None = None,
    recent_audit: int = DEFAULT_RECENT_AUDIT,
) -> dict:
    """Assemble the whole-platform snapshot the dashboard renders.

    Pure composition of the real subsystems; every section reports real data or an
    honest absence. `generated_at` stamps the snapshot so the UI shows "as of X" and
    never pretends to be live. `recent_audit` caps how many recent audit entries are
    returned.
    """
    tools, tool_counts = _build_tools_section()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": tools,
        "tool_counts": tool_counts,
        "audit": _build_audit_section(recent_audit),
        "network": _build_network_section(),
        "whitelist": _build_whitelist_section(whitelist_path),
    }
