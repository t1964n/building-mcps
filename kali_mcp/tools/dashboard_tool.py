"""generate_dashboard — the MCP tool that writes the live, self-contained dashboard (4.3).

A read/inspect + write-a-file tool: it runs NO scans and opens NO port. It composes
kali_mcp.dashboard.generate_dashboard, which builds a REAL network_status snapshot (4.1),
inlines it into the 4.2 template, and writes a static .html artifact you open from disk.

Honest by construction (CLAUDE.md §2): if the snapshot can't be built it writes nothing
and returns an error; a stale scan is stamped with its age, never presented as current.
"""

from __future__ import annotations

from ..dashboard import DEFAULT_STALE_THRESHOLD_SECONDS, generate_dashboard


def register(mcp) -> None:
    """Attach generate_dashboard to the FastMCP app."""

    @mcp.tool
    def generate_dashboard_tool(
        output_path: str | None = None,
        whitelist_path: str | None = None,
        recent_audit: int = 10,
        stale_threshold_seconds: int = DEFAULT_STALE_THRESHOLD_SECONDS,
    ) -> dict:
        """Generate a REAL, self-contained dashboard HTML file from live network_status.

        Builds the actual status snapshot (installed tools, audit tallies, whitelist
        state, and the last persisted arp_watch result), inlines it into the dashboard
        template (no external deps, no network calls), and writes a static .html you open
        from disk — NO server, NO port.

        Returns the written path plus an honest summary. Two DISTINCT timestamps are
        surfaced: `generated_at` (when this snapshot was built) and the network section's
        own `as_of` (when arp_watch actually scanned) — a fresh snapshot can still carry an
        old scan, and a stale scan is flagged with its age. If the snapshot can't be built,
        it writes NOTHING and returns status='error' rather than a misleading file.

        Default output is ./state/dashboard.html (gitignored — may contain real device
        IP/MAC). Pass output_path to write elsewhere.
        """
        return generate_dashboard(
            output_path=output_path,
            whitelist_path=whitelist_path,
            recent_audit=recent_audit,
            stale_threshold_seconds=stale_threshold_seconds,
        )
