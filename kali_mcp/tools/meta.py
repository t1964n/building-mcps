"""The `list_tools` meta tool — the only tool exposed in Task 1.0.

It reports, for every entry in the ROSTER, whether the binary is ACTUALLY present
on PATH right now (shutil.which), never a hardcoded value. A tool that is in the
roster but not installed reports `installed: false` honestly — at this stage most
of the roster is expected to be missing (only nmap + tshark are installed in
Phase 1). That is correct output, not a bug to paper over (CLAUDE.md §2).
"""

from __future__ import annotations

import shutil

from ..registry import ROSTER


def gather_tool_status() -> list[dict]:
    """Return the real installed/missing status of every roster entry.

    Pure function (no MCP dependency) so it is trivially unit-testable. The only
    fact it asserts is what shutil.which reports on PATH at call time.
    """
    status: list[dict] = []
    for spec in ROSTER:
        status.append(
            {
                "name": spec.name,
                "category": spec.category,
                "purpose": spec.purpose,
                # Real check against PATH — the whole point of this tool.
                "installed": shutil.which(spec.name) is not None,
            }
        )
    return status


def register(mcp) -> None:
    """Attach list_tools to the FastMCP app."""

    @mcp.tool
    def list_tools() -> list[dict]:
        """List every tool in the server's roster with its REAL install status.

        For each roster entry returns: name, category, purpose, and `installed`
        (a real shutil.which check on PATH, not a hardcoded flag). Tools not yet
        installed report installed=false — expected during Phase 1.
        """
        return gather_tool_status()
