"""Tests for generate_dashboard (Phase 4, Task 4.3) — fully offline.

build_status is monkeypatched so NO real scan/probe runs; we assert on the GENERATED file
and the tool's return value. The properties pinned are the §2 ones that mock data can't
exercise but real data hits: self-containment, the fresh/stale distinction, honest
generation failure (no silent stale/blank file), and path safety (gitignored output).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from kali_mcp import dashboard


# ---------------------------------------------------------------------------
# A realistic build_status() fixture, with controllable timestamps.
# ---------------------------------------------------------------------------
def _snapshot(*, generated_at: str, as_of: str | None, available: bool = True,
              rogue: int = 0, all_clear: bool = True) -> dict:
    network = (
        {
            "available": True,
            "as_of": as_of,
            "summary": {"known": 3, "rogue": rogue, "ip_mismatch": 0, "absent": 1},
            "rogues": [{"ip": "192.168.51.91", "mac": "ca:fe:00:00:00:01", "vendor": "X"}]
            if rogue else [],
            "note": "verdict text",
            "all_clear": all_clear,
        }
        if available
        else {
            "available": False,
            "as_of": None,
            "summary": None,
            "rogues": None,
            "note": "no rogue-host scan has been persisted yet — run arp_watch …",
        }
    )
    return {
        "generated_at": generated_at,
        "tools": [
            {"name": "nmap", "category": "recon", "purpose": "scanner", "installed": True},
            {"name": "zeek", "category": "ids", "purpose": "nsm", "installed": False},
        ],
        "tool_counts": {"registered": 2, "installed": 1},
        "audit": {
            "available": True, "total_entries": 4,
            "recent": [{"timestamp": "t", "tool": "nmap", "target": "x",
                        "status": "ok", "exit_code": 0, "duration_s": 1.0}],
            "by_status": {"ok": 3, "nonzero_exit": 1, "timeout": 0, "not_found": 0},
        },
        "network": network,
        "whitelist": {"loaded": True, "device_count": 5, "error": None},
    }


def _patch_build(monkeypatch, snapshot):
    monkeypatch.setattr(dashboard, "build_status", lambda **kw: snapshot)


# ---------------------------------------------------------------------------
# generation writes a SELF-CONTAINED file with the embedded snapshot
# ---------------------------------------------------------------------------
def test_generation_writes_self_contained_file(monkeypatch, tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    snap = _snapshot(generated_at=now, as_of=now)
    _patch_build(monkeypatch, snap)

    out = tmp_path / "dashboard.html"
    res = dashboard.generate_dashboard(output_path=str(out))

    assert res["status"] == "ok" and res["wrote"] is True
    assert out.is_file()
    html = out.read_text(encoding="utf-8")

    # Embedded REAL snapshot data is present (not a mock reference).
    assert '"generated_at"' in html
    assert "nmap" in html and "zeek" in html
    assert "render(snapshot, meta)" in html

    # SELF-CONTAINED: no external URLs, no CDN, no mock dependency, no external <script src>.
    assert "http://" not in html
    assert "https://" not in html
    assert "mock_snapshots.js" not in html
    assert "<script src" not in html


def test_generated_at_and_as_of_are_distinct_timestamps(monkeypatch, tmp_path):
    # Snapshot built now, but the underlying scan happened a while earlier.
    gen = datetime(2026, 6, 17, 18, 0, 0, tzinfo=timezone.utc)
    scan = gen - timedelta(minutes=20)
    snap = _snapshot(generated_at=gen.isoformat(), as_of=scan.isoformat())
    _patch_build(monkeypatch, snap)

    out = tmp_path / "dashboard.html"
    res = dashboard.generate_dashboard(output_path=str(out))
    html = out.read_text(encoding="utf-8")

    # Both distinct timestamps are present in the file and the return value.
    assert gen.isoformat() in html
    assert scan.isoformat() in html
    assert res["generated_at"] == gen.isoformat()
    assert res["network"]["as_of"] == scan.isoformat()
    assert res["generated_at"] != res["network"]["as_of"]


# ---------------------------------------------------------------------------
# fresh vs stale
# ---------------------------------------------------------------------------
def test_fresh_snapshot_is_not_stale(monkeypatch, tmp_path):
    gen = datetime.now(timezone.utc)
    scan = gen - timedelta(seconds=30)  # 30s old -> fresh
    snap = _snapshot(generated_at=gen.isoformat(), as_of=scan.isoformat())
    _patch_build(monkeypatch, snap)

    res = dashboard.generate_dashboard(output_path=str(tmp_path / "d.html"))
    assert res["network"]["stale"] is False
    html = (tmp_path / "d.html").read_text(encoding="utf-8")
    assert '"stale": false' in html.lower() or '"stale":false' in html.lower()


def test_stale_snapshot_is_flagged(monkeypatch, tmp_path):
    gen = datetime.now(timezone.utc)
    scan = gen - timedelta(days=3)  # 3 days old -> stale
    snap = _snapshot(generated_at=gen.isoformat(), as_of=scan.isoformat(), all_clear=True)
    _patch_build(monkeypatch, snap)

    res = dashboard.generate_dashboard(output_path=str(tmp_path / "d.html"))
    assert res["network"]["stale"] is True
    assert "3 days" in res["network"]["age_human"]
    # A stale all-clear must NOT silently read as current: the embedded meta carries the flag.
    html = (tmp_path / "d.html").read_text(encoding="utf-8")
    assert '"stale": true' in html.lower().replace('"stale":true', '"stale": true')
    assert "3 days" in html  # the age is embedded for the UI banner


def test_staleness_threshold_is_respected(monkeypatch, tmp_path):
    gen = datetime.now(timezone.utc)
    scan = gen - timedelta(minutes=30)  # 30 min old
    snap = _snapshot(generated_at=gen.isoformat(), as_of=scan.isoformat())
    _patch_build(monkeypatch, snap)

    # 30 min < default 1h -> fresh; but with a 10-min threshold -> stale.
    fresh = dashboard.generate_dashboard(output_path=str(tmp_path / "a.html"))
    assert fresh["network"]["stale"] is False
    strict = dashboard.generate_dashboard(
        output_path=str(tmp_path / "b.html"), stale_threshold_seconds=600
    )
    assert strict["network"]["stale"] is True


def test_no_data_is_not_marked_stale(monkeypatch, tmp_path):
    # network unavailable -> 'no data', which is its OWN state, not 'stale'.
    now = datetime.now(timezone.utc).isoformat()
    snap = _snapshot(generated_at=now, as_of=None, available=False)
    _patch_build(monkeypatch, snap)

    res = dashboard.generate_dashboard(output_path=str(tmp_path / "d.html"))
    assert res["network"]["available"] is False
    assert res["network"]["stale"] is False
    assert "no scan data" in res["summary"].lower()


# ---------------------------------------------------------------------------
# subsystem failure passes through; whole-generation failure writes NOTHING
# ---------------------------------------------------------------------------
def test_broken_whitelist_passes_through_to_file(monkeypatch, tmp_path):
    now = datetime.now(timezone.utc).isoformat()
    snap = _snapshot(generated_at=now, as_of=None, available=False)
    snap["whitelist"] = {
        "loaded": False, "device_count": None,
        "error": "WhitelistValidationError: device #2: missing required 'mac'.",
    }
    _patch_build(monkeypatch, snap)

    res = dashboard.generate_dashboard(output_path=str(tmp_path / "d.html"))
    assert res["status"] == "ok"
    assert "whitelist error" in res["summary"].lower()
    html = (tmp_path / "d.html").read_text(encoding="utf-8")
    assert "missing required 'mac'" in html  # the real error reaches the UI


def test_generation_failure_writes_no_file(monkeypatch, tmp_path):
    def _boom(**kw):
        raise RuntimeError("audit log unreadable")
    monkeypatch.setattr(dashboard, "build_status", _boom)

    out = tmp_path / "dashboard.html"
    res = dashboard.generate_dashboard(output_path=str(out))

    assert res["status"] == "error"
    assert res["wrote"] is False
    assert "audit log unreadable" in res["error"]
    assert not out.exists()  # NO silent stale/blank file


def test_generation_failure_leaves_existing_file_untouched(monkeypatch, tmp_path):
    # A previous good dashboard must NOT be overwritten by a failed run.
    out = tmp_path / "dashboard.html"
    out.write_text("PREVIOUS GOOD DASHBOARD", encoding="utf-8")

    def _boom(**kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(dashboard, "build_status", _boom)

    res = dashboard.generate_dashboard(output_path=str(out))
    assert res["status"] == "error"
    assert out.read_text(encoding="utf-8") == "PREVIOUS GOOD DASHBOARD"


# ---------------------------------------------------------------------------
# path safety: the default output dir is gitignored
# ---------------------------------------------------------------------------
def test_default_output_path_is_under_gitignored_state():
    # Default path is under state/, and state/ is gitignored (may hold real IP/MAC).
    assert dashboard.DEFAULT_OUTPUT_PATH.startswith("./state/")
    from pathlib import Path
    repo_root = Path(__file__).resolve().parent.parent
    gitignore = (repo_root / ".gitignore").read_text(encoding="utf-8")
    assert "state/" in gitignore


# ---------------------------------------------------------------------------
# the staleness helper, in isolation
# ---------------------------------------------------------------------------
def test_compute_staleness_unparseable_timestamp_is_not_fresh():
    snap = {"generated_at": "not-a-date", "network": {"available": True, "as_of": "also-bad"}}
    st = dashboard.compute_network_staleness(snap)
    assert st["stale"] is True            # we never claim freshness we can't prove
    assert st["age_human"] == "unknown"


def test_human_age_units():
    assert dashboard._human_age(2) == "just now"
    assert dashboard._human_age(45) == "45 seconds"
    assert dashboard._human_age(60) == "1 minute"
    assert dashboard._human_age(3600) == "1 hour"
    assert dashboard._human_age(86400 * 3) == "3 days"
