"""Tests for the network_status snapshot (Phase 4, Task 4.1) — fully offline.

This is the dashboard's data contract, so the tests pin the ONE property that matters
(CLAUDE.md §2): every section reports real data or an HONEST absence, and the three
states a lazy dashboard collapses into one green light stay distinguishable —
  (a) clean/all-known, (b) couldn't-scan/no-data, (c) whitelist-broken.

No real scans, no real binaries assumed: the which-probe, the audit log path, the
whitelist path and the persisted-watch state are all pointed at mocks/tmp files.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from kali_mcp import state, status
from kali_mcp.tools import meta
from kali_mcp.watch import diff_against_whitelist
from kali_mcp.whitelist import KnownDevice


# =====================================================================
# tools section — install flags come from the REAL which-probe (mocked)
# =====================================================================

def test_tools_installed_flags_reflect_which_probe(monkeypatch):
    # Pretend only nmap and tshark are on PATH; everything else missing.
    present = {"nmap", "tshark"}
    monkeypatch.setattr(
        meta.shutil, "which", lambda name: f"/usr/bin/{name}" if name in present else None
    )
    snap = status.build_status()

    by_name = {t["name"]: t for t in snap["tools"]}
    assert by_name["nmap"]["installed"] is True
    assert by_name["tshark"]["installed"] is True
    assert by_name["sqlmap"]["installed"] is False
    # Counts: registered == full roster, installed == exactly the mocked-present ones.
    assert snap["tool_counts"]["registered"] == len(snap["tools"])
    assert snap["tool_counts"]["installed"] == 2
    # Every tool carries the dashboard fields.
    for t in snap["tools"]:
        assert set(t) >= {"name", "category", "purpose", "installed"}


# =====================================================================
# audit section — READ-ONLY parse of the real JSONL log
# =====================================================================

def _write_audit(path, entries):
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


def test_audit_present_tallies_and_recent(monkeypatch, tmp_path):
    log = tmp_path / "audit.jsonl"
    entries = [
        {"timestamp": "2026-06-17T10:00:00+00:00", "tool": "nmap", "target": "192.168.1.1",
         "status": "ok", "exit_code": 0, "duration_s": 1.2},
        {"timestamp": "2026-06-17T10:01:00+00:00", "tool": "nmap", "target": "192.168.1.2",
         "status": "nonzero_exit", "exit_code": 1, "duration_s": 0.5},
        {"timestamp": "2026-06-17T10:02:00+00:00", "tool": "masscan", "target": "192.168.1.0/24",
         "status": "timeout", "exit_code": None, "duration_s": 30.0},
        {"timestamp": "2026-06-17T10:03:00+00:00", "tool": "arp-scan", "target": None,
         "status": "ok", "exit_code": 0, "duration_s": 2.1},
    ]
    _write_audit(log, entries)
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(log))

    snap = status.build_status()
    audit = snap["audit"]
    assert audit["available"] is True
    assert audit["total_entries"] == 4
    assert audit["by_status"] == {"ok": 2, "nonzero_exit": 1, "timeout": 1, "not_found": 0}
    # recent projects the dashboard fields and keeps order (last K).
    assert len(audit["recent"]) == 4
    assert audit["recent"][-1]["tool"] == "arp-scan"
    assert audit["recent"][-1]["target"] is None
    assert set(audit["recent"][0]) == {
        "timestamp", "tool", "target", "status", "exit_code", "duration_s"
    }


def test_audit_recent_count_caps_list(monkeypatch, tmp_path):
    log = tmp_path / "audit.jsonl"
    entries = [
        {"timestamp": f"2026-06-17T10:0{i}:00+00:00", "tool": "nmap", "target": "x",
         "status": "ok", "exit_code": 0, "duration_s": 0.1}
        for i in range(8)
    ]
    _write_audit(log, entries)
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(log))

    snap = status.build_status(recent_audit=3)
    assert snap["audit"]["total_entries"] == 8     # all counted
    assert len(snap["audit"]["recent"]) == 3       # but only last 3 shown
    # last-3 means the highest-index timestamps.
    assert snap["audit"]["recent"][-1]["timestamp"] == "2026-06-17T10:07:00+00:00"


def test_audit_missing_log_is_unavailable_not_empty_tally(monkeypatch, tmp_path):
    # CRITICAL §2 distinction: missing log != "0 commands run clean".
    missing = tmp_path / "does_not_exist.jsonl"
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(missing))

    snap = status.build_status()
    audit = snap["audit"]
    assert audit["available"] is False
    assert audit["total_entries"] == 0
    assert audit["recent"] == []
    assert "note" in audit and "no audit log" in audit["note"]


def test_audit_malformed_lines_counted_not_dropped(monkeypatch, tmp_path):
    # A junk line + a non-dict JSON line mixed with good ones: good ones counted,
    # unparseable count reported honestly, no crash.
    log = tmp_path / "audit.jsonl"
    log.write_text(
        json.dumps({"timestamp": "t1", "tool": "nmap", "status": "ok",
                    "exit_code": 0, "duration_s": 1.0}) + "\n"
        + "this is not json at all\n"
        + "[1, 2, 3]\n"  # valid JSON, but not a dict -> unparseable as an entry
        + "\n"           # blank line -> ignored, NOT counted as malformed
        + json.dumps({"timestamp": "t2", "tool": "masscan", "status": "timeout",
                      "exit_code": None, "duration_s": 5.0}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(log))

    snap = status.build_status()
    audit = snap["audit"]
    assert audit["available"] is True
    assert audit["total_entries"] == 2                      # the two good entries
    assert audit["by_status"]["ok"] == 1
    assert audit["by_status"]["timeout"] == 1
    assert audit["unparseable_lines"] == 2                  # junk line + non-dict json
    assert "could not be parsed" in audit["note"]


# =====================================================================
# whitelist section — broken load is DISTINCT from 0 devices (§2 rule 4)
# =====================================================================

def _write_whitelist(path, body):
    path.write_text(body, encoding="utf-8")


def test_whitelist_ok_loaded_with_count(tmp_path):
    wl = tmp_path / "whitelist.yaml"
    _write_whitelist(wl, """
devices:
  - mac: ac:9e:17:aa:bb:cc
    name: ASUS Router
    ip: 192.168.51.1
  - mac: dc:a6:32:11:22:33
    name: Raspberry Pi
""")
    snap = status.build_status(whitelist_path=str(wl))
    wls = snap["whitelist"]
    assert wls["loaded"] is True
    assert wls["device_count"] == 2
    assert wls["error"] is None


def test_whitelist_broken_populates_error_distinct_from_zero(tmp_path):
    # Malformed: a device missing its required 'mac'. Loader raises loudly.
    wl = tmp_path / "whitelist.yaml"
    _write_whitelist(wl, """
devices:
  - name: No MAC Device
""")
    snap = status.build_status(whitelist_path=str(wl))
    wls = snap["whitelist"]
    assert wls["loaded"] is False
    # device_count is None (unknown), NOT 0 — a broken whitelist is not an empty one.
    assert wls["device_count"] is None
    assert wls["error"] is not None
    assert "ValidationError" in wls["error"]


def test_whitelist_missing_file_is_loaded_false_with_error(tmp_path):
    missing = tmp_path / "nope.yaml"
    snap = status.build_status(whitelist_path=str(missing))
    wls = snap["whitelist"]
    assert wls["loaded"] is False
    assert wls["device_count"] is None
    assert "NotFound" in wls["error"]


# =====================================================================
# network section — reads PERSISTED watch state; never fabricates a verdict
# =====================================================================

def test_network_no_data_is_unavailable_with_run_arp_watch_note(monkeypatch, tmp_path):
    # No persisted watch -> available=false + "run arp_watch", NOT a fake summary.
    monkeypatch.setenv("KALI_MCP_STATE_DIR", str(tmp_path / "state"))
    snap = status.build_status()
    net = snap["network"]
    assert net["available"] is False
    assert net["summary"] is None       # NOT zeros-meaning-unknown
    assert net["rogues"] is None
    assert net["as_of"] is None
    assert "arp_watch" in net["note"]


def test_network_with_persisted_watch_populates_summary_and_rogues(monkeypatch, tmp_path):
    # Produce a REAL WatchResult via the pure diff, persist it the way arp_watch does,
    # then prove network_status reads it back faithfully.
    monkeypatch.setenv("KALI_MCP_STATE_DIR", str(tmp_path / "state"))
    router = KnownDevice(mac="ac:9e:17:aa:bb:cc", name="ASUS Router", ip="192.168.51.1", note=None)
    discovered = [
        {"ip": "192.168.51.1", "mac": "ac:9e:17:aa:bb:cc", "vendor": "ASUSTek"},   # KNOWN
        {"ip": "192.168.51.91", "mac": "ca:fe:00:00:00:01", "vendor": "Mystery"},  # ROGUE
    ]
    result = diff_against_whitelist(discovered, [router])
    state.save_last_watch(result.to_dict())

    snap = status.build_status()
    net = snap["network"]
    assert net["available"] is True
    assert net["summary"] == {"known": 1, "rogue": 1, "ip_mismatch": 0, "absent": 0}
    assert net["rogues"][0]["mac"] == "ca:fe:00:00:00:01"
    assert net["all_clear"] is False
    # as_of is set by save_last_watch and must be a real ISO timestamp.
    datetime.fromisoformat(net["as_of"])


def test_network_corrupt_state_degrades_to_unavailable(monkeypatch, tmp_path):
    # A corrupt state file is treated as ABSENCE, not a crash and not a fake verdict.
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "last_watch.json").write_text("{ not valid json", encoding="utf-8")
    monkeypatch.setenv("KALI_MCP_STATE_DIR", str(state_dir))

    snap = status.build_status()
    assert snap["network"]["available"] is False
    assert snap["network"]["summary"] is None


# =====================================================================
# the snapshot envelope
# =====================================================================

def test_generated_at_is_present_and_iso8601(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(tmp_path / "none.jsonl"))
    snap = status.build_status()
    assert "generated_at" in snap
    # Parses as ISO8601 (raises if not) and is timezone-aware (UTC).
    parsed = datetime.fromisoformat(snap["generated_at"])
    assert parsed.tzinfo is not None


def test_three_states_are_distinguishable(monkeypatch, tmp_path):
    # The whole point: clean vs no-data vs whitelist-broken must NOT look the same.
    # Here: no audit log + no watch + broken whitelist all in one snapshot, each
    # section degrading in its OWN distinct way.
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(tmp_path / "missing.jsonl"))
    monkeypatch.setenv("KALI_MCP_STATE_DIR", str(tmp_path / "state"))
    wl = tmp_path / "whitelist.yaml"
    wl.write_text("devices:\n  - name: broken\n", encoding="utf-8")

    snap = status.build_status(whitelist_path=str(wl))
    # (b) couldn't-scan/no-data
    assert snap["network"]["available"] is False
    # (c) whitelist-broken — distinct from a 0-device whitelist
    assert snap["whitelist"]["loaded"] is False
    assert snap["whitelist"]["error"] is not None
    # audit absent, not fake-clean
    assert snap["audit"]["available"] is False
