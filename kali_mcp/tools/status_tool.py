"""network_status — the dashboard's honest data source (Phase 4, Task 4.1).

A read/inspect tool: it runs NO scans, needs NO scope target, and opens NO sockets.
It composes kali_mcp.status.build_status into one structured snapshot of the whole
platform's real state — installed tools, audit tallies, whitelist state, and the last
persisted rogue-host watch — so the Phase-4 UI (4.2) renders facts, not fabrications.

Every field is real or honestly-absent (CLAUDE.md §2). In particular the three states
a lazy dashboard collapses into one green light stay distinguishable in this payload:
all-known/clean vs couldn't-scan/no-data vs whitelist-broken.
"""

from __future__ import annotations

from ..status import DEFAULT_RECENT_AUDIT, build_status


def register(mcp) -> None:
    """Attach network_status to the FastMCP app."""

    @mcp.tool
    def network_status(
        whitelist_path: str | None = None,
        recent_audit: int = DEFAULT_RECENT_AUDIT,
    ) -> dict:
        """Whole-platform status snapshot for the dashboard — READ-ONLY, no scanning.

        Gathers, all from REAL sources (never fabricated, CLAUDE.md §2):
          * tools: every roster tool with its real shutil.which install status, plus
            registered/installed counts.
          * audit: a read-only parse of the real audit log (KALI_MCP_AUDIT_LOG) —
            total entries, last `recent_audit` entries, and per-status tallies. A
            missing log reports available=false, NOT empty-but-clean tallies.
          * network: the LAST arp_watch result persisted to disk — it does NOT run a
            scan. If none has been run, available=false with a 'run arp_watch first'
            note (honest no-data, never a fake all-clear).
          * whitelist: loaded/device_count, or loaded=false with the load error string
            if the whitelist is broken (distinct from a 0-device list).

        `generated_at` stamps the snapshot so the dashboard shows 'as of X', never
        pretends to be live. Takes an optional whitelist_path and recent-audit count.
        """
        return build_status(
            whitelist_path=whitelist_path,
            recent_audit=recent_audit,
        )
