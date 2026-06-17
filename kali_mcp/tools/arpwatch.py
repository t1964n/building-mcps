"""arp_watch — the rogue-host watcher: arp-scan ⨯ whitelist diff (Phase 3, Task 3.3).

This is the feature the platform exists for (CLAUDE.md §5 rogue-host hunting): it runs
a live layer-2 discovery and DIFFS the result against Mark's device whitelist, so an
unlisted device on the segment surfaces as a ROGUE alert.

WHY A SEPARATE FILE (not bolted onto arpscan.py): tools/arpscan.py has a single, clean
concern — "report exactly what answered ARP, invent nothing, compare against nothing"
(its own docstring says so). arp_watch is a DIFFERENT concern layered on top: load a
trust source, run discovery, and pass judgement. Mixing the two would muddy arp-scan's
"no comparison is invented" contract and make both harder to test. So arp_watch
COMPOSES the existing pieces rather than duplicating them:
    load_whitelist (3.2)  +  arpscan.scan (2.4, reused verbatim)  +  diff (3.3)
No run_tool / argv / parsing logic is re-implemented here — the audit-logged arp-scan
run happens inside arpscan.scan, so this tool inherits 2.4's honesty for free.

HONESTY GUARDS this tool must never break (CLAUDE.md §2 — it's an alerting surface):
  * Whitelist fails to load -> REFUSE. We do NOT scan-and-call-everything-a-rogue.
    The 3.2 loader is loud by design; we surface its error and return NO verdict.
    A broken whitelist = no verdict, stated plainly — never a misleading "N rogues".
  * arp-scan itself errors / finds nothing -> that is the REAL arp-scan status,
    propagated as-is (not_found / nonzero_exit / timeout / 0-hosts). Never repackaged
    into a fake "0 rogues, all clear".
  * A real all-clear is EARNED (devices seen AND all matched), never a default — that
    distinction lives in watch.WatchResult.all_clear and is surfaced here untouched.
"""

from __future__ import annotations

from ..watch import diff_against_whitelist
from ..whitelist import WhitelistError, load_whitelist
from . import arpscan


async def watch(
    *,
    interface: str,
    scan_localnet: bool = True,
    target_range: str | None = None,
    whitelist_path: str | None = None,
) -> dict:
    """Load the whitelist, run a real arp-scan, and diff the two into a verdict.

    Returns a structured result with ROGUES and their count at the top (the headline),
    plus the neutral buckets, the raw arp-scan output, and the exact command. Refuses
    to produce a verdict if the whitelist can't load or the scan didn't succeed.
    """
    # 1. Load the whitelist FIRST and fail fast. If we can't establish what's KNOWN,
    #    there is no honest verdict to give — and running the scan anyway would only
    #    tempt a misleading "everything is a rogue". Surface the loud 3.2 error and stop.
    try:
        known = load_whitelist(whitelist_path)
    except WhitelistError as exc:
        return {
            "status": "whitelist_error",
            "ran": False,
            "reason": (
                "refusing to produce a rogue verdict: the device whitelist could not "
                "be loaded, so there is nothing trustworthy to diff against. "
                f"{type(exc).__name__}: {exc}"
            ),
            "error_type": type(exc).__name__,
        }

    # 2. Run the REAL arp-scan via the existing 2.4 wrapper. It validates the interface
    #    / range, runs the audit-logged subprocess, and returns its own honest status.
    scan_result = await arpscan.scan(
        interface=interface,
        scan_localnet=scan_localnet,
        target_range=target_range,
    )

    # 3. If the scan didn't cleanly succeed, propagate its real status. We do NOT
    #    diff (there are no trustworthy hosts) and we do NOT fake an all-clear.
    if scan_result.get("status") != "ok":
        return {
            "status": "scan_unavailable",
            "ran": scan_result.get("ran", False),
            "reason": (
                "no rogue verdict produced — the underlying arp-scan did not return a "
                f"clean host list (arp-scan status: {scan_result.get('status')!r}). "
                "This is the real scan outcome, not an all-clear."
            ),
            "whitelist_size": len(known),
            "scan": scan_result,  # the verbatim arp-scan result: stderr/exit_code/etc.
        }

    # 4. Clean scan -> diff the REAL discovered hosts against the whitelist.
    discovered = scan_result["parsed"]["hosts"]
    diff = diff_against_whitelist(discovered, known)

    result = {
        "status": "ok",
        "ran": True,
        # Headline first: rogues + count are impossible to miss.
        **diff.to_dict(),
        "whitelist_size": len(known),
        "interface": interface,
        "target": scan_result.get("target"),
        "command": scan_result.get("command"),
        "raw_output": scan_result.get("raw_output"),
    }
    return result


def register(mcp) -> None:
    """Attach arp_watch to the FastMCP app, alongside arp_scan and the rest."""

    @mcp.tool
    async def arp_watch(
        interface: str,
        scan_localnet: bool = True,
        target_range: str | None = None,
        whitelist_path: str | None = None,
    ) -> dict:
        """Rogue-host watcher: run arp-scan on the local segment and DIFF it against
        your device whitelist, flagging anything unlisted as a ROGUE.

        Loads the whitelist (from whitelist_path, else $KALI_MCP_WHITELIST, else
        ./whitelist.yaml) and refuses to give a verdict if it can't load — it will
        NOT scan and call everything a rogue. Runs the real arp-scan via the same
        wrapper as arp_scan (same interface/range validation, same audit log), then
        classifies every discovered host as KNOWN / ROGUE / IP_MISMATCH and lists any
        whitelisted device that was ABSENT. Returns rogues + count at the top, the
        neutral buckets below, plus the raw arp-scan output and exact command.
        'all_clear' is True only when devices were seen AND all matched — never a
        default; an empty or failed scan is reported as its real outcome, not a clear.
        """
        return await watch(
            interface=interface,
            scan_localnet=scan_localnet,
            target_range=target_range,
            whitelist_path=whitelist_path,
        )
