"""generate_dashboard — a REAL, self-contained dashboard file from live network_status.

This closes the Phase-4 loop: 4.1 produced the honest snapshot (build_status), 4.2 built
the honest canvas (dashboard/template.html + render()), and this module wires them — it
runs build_status() for REAL, embeds that snapshot into the 4.2 template inline (so the
written .html has NO external dependencies and NO network calls), and writes a static
point-in-time artifact stamped with generated_at.

NO web server, NO open port (CLAUDE.md §4): the output is a file you open from disk.

The §2 heart of this task — real data fails in ways mock data never does, and a stale or
failed snapshot must NEVER render as a confident green:

  * STALE: the dashboard shows TWO distinct timestamps — generated_at (when this snapshot
    was built) and the network section's own as_of (when arp_watch actually scanned). They
    are different facts and we never blur them. If the scan (as_of) is older than the
    staleness threshold, we compute the age and embed a `stale` flag so the UI marks it —
    a days-old all-clear is not a current all-clear.
  * SUBSYSTEM FAILURE: a broken whitelist / unreadable audit log already degrade honestly
    inside the 4.1 payload; we pass that payload through untouched so the 4.2 distinct
    states render it.
  * WHOLE-GENERATION FAILURE: if build_status itself raises, we DO NOT write a stale or
    blank file — we surface the error and leave any existing file untouched.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .status import build_status

# A network view whose underlying scan is older than this reads as STALE. One hour: a
# security snapshot of "who is on my network" older than that should not present as
# current. Surfaced as a sane default; the age is always shown regardless of threshold.
DEFAULT_STALE_THRESHOLD_SECONDS = 3600

# Default output lives under state/ — it can embed Mark's real device IP/MAC data, and
# state/ is already gitignored (Task 4.1). Never default it into a committed path.
DEFAULT_OUTPUT_PATH = "./state/dashboard.html"

_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "template.html"

_BOOTSTRAP_START = "// === DASHBOARD_BOOTSTRAP_START"
_BOOTSTRAP_END = "// === DASHBOARD_BOOTSTRAP_END ===\n"
_MOCK_SCRIPT_TAG = '<script src="mock_snapshots.js"></script>\n'


def _human_age(seconds: float) -> str:
    """Render an age in the largest sensible unit: 'just now' / 'N minutes' / 'N days'."""
    s = int(max(0, seconds))
    if s < 5:
        return "just now"
    if s < 60:
        return f"{s} seconds"
    minutes = s // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    days = hours // 24
    return f"{days} day{'s' if days != 1 else ''}"


def compute_network_staleness(
    snapshot: dict, *, threshold_seconds: int = DEFAULT_STALE_THRESHOLD_SECONDS
) -> dict:
    """Compare the network scan time (as_of) to the snapshot time (generated_at).

    Returns {available, as_of, generated_at, age_seconds, age_human, stale, threshold_seconds}.
    When the network section is unavailable (no scan persisted), this is NOT stale — it is
    the honest 'no data' state, handled separately by the UI; stale=False here so a
    no-data panel never gets an additional misleading stale marker.
    """
    net = snapshot.get("network") or {}
    generated_at = snapshot.get("generated_at")
    as_of = net.get("as_of")

    base = {
        "available": bool(net.get("available")),
        "as_of": as_of,
        "generated_at": generated_at,
        "age_seconds": None,
        "age_human": None,
        "stale": False,
        "threshold_seconds": threshold_seconds,
    }
    if not net.get("available") or not as_of or not generated_at:
        return base

    try:
        gen_dt = datetime.fromisoformat(generated_at)
        scan_dt = datetime.fromisoformat(as_of)
    except (TypeError, ValueError):
        # Unparseable timestamps -> we can't claim freshness; report unknown, not fresh.
        base["age_human"] = "unknown"
        base["stale"] = True
        return base

    age = (gen_dt - scan_dt).total_seconds()
    age = max(0.0, age)  # clock skew can't make a scan "from the future" look fresh-negative
    base["age_seconds"] = age
    base["age_human"] = _human_age(age)
    base["stale"] = age > threshold_seconds
    return base


def _embed_json(obj: dict) -> str:
    """JSON for safe inline embedding in <script>: escape '<' so a stray '</script>' or
    '<!--' in any value can never break out of the script element."""
    return json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c")


def render_dashboard_html(
    snapshot: dict,
    staleness: dict,
    *,
    template_path: Path | None = None,
) -> str:
    """Produce the self-contained HTML by inlining the real snapshot into the 4.2 template.

    Reuses 4.2's render() verbatim — only the data source changes: the external
    mock_snapshots.js dependency is removed and the mock bootstrap is replaced with the
    embedded live snapshot + meta. The result has no external URLs and no network calls.
    """
    template = (template_path or _TEMPLATE_PATH).read_text(encoding="utf-8")

    # Drop the external mock dependency -> self-contained.
    html = template.replace(_MOCK_SCRIPT_TAG, "")

    live_bootstrap = (
        "  // === live data embedded by generate_dashboard (Task 4.3) — self-contained ===\n"
        "  (function () {\n"
        f"    var snapshot = {_embed_json(snapshot)};\n"
        f"    var meta = {_embed_json({'network_staleness': staleness})};\n"
        "    var nav = document.getElementById('switcher');\n"
        "    if (nav) nav.style.display = 'none';\n"  # no mock switcher in the live file
        "    render(snapshot, meta);\n"
        "  })();\n"
    )

    start = html.index(_BOOTSTRAP_START)
    end = html.index(_BOOTSTRAP_END) + len(_BOOTSTRAP_END)
    html = html[:start] + live_bootstrap + html[end:]
    return html


def _network_summary_line(snapshot: dict, staleness: dict) -> str:
    """A short, honest one-liner about the network state for the tool's return value."""
    net = snapshot.get("network") or {}
    wl = snapshot.get("whitelist") or {}
    if wl.get("loaded") is False:
        return "whitelist ERROR — no trustworthy rogue verdict (see whitelist.error)"
    if not net.get("available"):
        return "no scan data — run arp_watch (this is NOT an all-clear)"
    s = net.get("summary") or {}
    stale_tag = f" [STALE: {staleness.get('age_human')} old]" if staleness.get("stale") else ""
    if s.get("rogue", 0) > 0:
        return f"⚠ {s['rogue']} ROGUE device(s) on the segment{stale_tag}"
    if net.get("all_clear") is True:
        return f"all clear — {s.get('known', 0)} known device(s) matched{stale_tag}"
    return f"review — 0 rogues but not a clean match ({s.get('ip_mismatch', 0)} IP mismatch){stale_tag}"


def generate_dashboard(
    *,
    output_path: str | None = None,
    whitelist_path: str | None = None,
    recent_audit: int = 10,
    stale_threshold_seconds: int = DEFAULT_STALE_THRESHOLD_SECONDS,
) -> dict:
    """Build a REAL snapshot, render the self-contained dashboard, and write it to a file.

    Returns a dict with the written path + a short honest summary. On failure to build the
    snapshot it returns status='error' and writes NOTHING — never a stale/blank file
    presented as current (CLAUDE.md §2).
    """
    try:
        snapshot = build_status(
            whitelist_path=whitelist_path, recent_audit=recent_audit
        )
    except Exception as exc:  # noqa: BLE001 — we must surface ANY generation failure honestly
        return {
            "status": "error",
            "wrote": False,
            "error": f"{type(exc).__name__}: {exc}",
            "reason": (
                "dashboard generation failed while building the status snapshot; no file "
                "was written (refusing to leave a stale or blank dashboard that could read "
                "as current)."
            ),
        }

    staleness = compute_network_staleness(
        snapshot, threshold_seconds=stale_threshold_seconds
    )
    html = render_dashboard_html(snapshot, staleness)

    target = Path(output_path) if output_path is not None else Path(DEFAULT_OUTPUT_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")

    net = snapshot.get("network") or {}
    return {
        "status": "ok",
        "wrote": True,
        "path": str(target),
        "generated_at": snapshot.get("generated_at"),  # snapshot time
        "network": {
            "available": bool(net.get("available")),
            "as_of": net.get("as_of"),                 # scan time (distinct!)
            "stale": staleness.get("stale"),
            "age_human": staleness.get("age_human"),
            "summary": net.get("summary"),
        },
        "tool_counts": snapshot.get("tool_counts"),
        "summary": _network_summary_line(snapshot, staleness),
        "note": (
            "open this file from disk — it is self-contained (no server, no network). It is "
            "a point-in-time snapshot; the network panel shows its own scan time (as_of), "
            "which may be older than the snapshot time (generated_at)."
        ),
    }
