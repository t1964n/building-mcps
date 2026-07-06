"""Tests for the desktop control-panel backend — the Qt-free, honest core.

No PySide6, no Docker, no network. build_view_model is pure; DockerScanRunner takes an
INJECTED process runner so the whole scan path is exercised with fakes. The point of
these tests is the §2 guarantees: the honest states stay distinct, and a failed scan is
surfaced as its real error, never a fabricated 'all clear'.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from desktop.backend import (
    DockerScanRunner,
    ScanOutcome,
    build_view_model,
    _parse_verdict,
)


# --------------------------------------------------------------- view model states

def _snap(*, network=None, whitelist=None, tool_counts=None, audit=None):
    return {
        "generated_at": "2026-07-06T00:00:00+00:00",
        "network": network if network is not None else {},
        "whitelist": whitelist if whitelist is not None else {"loaded": True, "device_count": 3, "error": None},
        "tool_counts": tool_counts or {"registered": 35, "installed": 6},
        "audit": audit or {"recent": []},
    }


def test_no_data_is_not_all_clear():
    snap = _snap(network={"available": False})
    vm = build_view_model(snap, {"stale": False})
    assert vm.level == "no_data"
    assert "NOT an all-clear" in vm.headline


def test_whitelist_error_beats_everything():
    # Even with a scan present, a broken whitelist is surfaced first — no trustworthy verdict.
    snap = _snap(
        whitelist={"loaded": False, "device_count": None, "error": "bad YAML"},
        network={"available": True, "all_clear": True, "summary": {"known": 5, "rogue": 0}},
    )
    vm = build_view_model(snap, {"stale": False})
    assert vm.level == "whitelist_error"
    assert "bad YAML" in vm.headline


def test_rogue_is_the_headline():
    snap = _snap(network={
        "available": True, "all_clear": False,
        "summary": {"known": 4, "rogue": 2, "ip_mismatch": 0, "absent": 1},
        "rogues": [{"ip": "192.168.1.9", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Unknown"}],
    })
    vm = build_view_model(snap, {"stale": False})
    assert vm.level == "rogue"
    assert vm.counts["rogue"] == 2
    assert vm.rogues[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_earned_all_clear():
    snap = _snap(network={
        "available": True, "all_clear": True,
        "summary": {"known": 7, "rogue": 0, "ip_mismatch": 0, "absent": 0},
    })
    vm = build_view_model(snap, {"stale": False})
    assert vm.level == "all_clear"


def test_stale_flag_carried_through():
    snap = _snap(network={"available": True, "all_clear": True, "summary": {"known": 3, "rogue": 0}})
    vm = build_view_model(snap, {"stale": True, "age_human": "2 days"})
    assert vm.level == "all_clear" and vm.stale is True and vm.age_human == "2 days"


# --------------------------------------------------------------- docker argv shape

def test_argv_is_a_shell_free_list_with_env_and_mount():
    runner = DockerScanRunner()
    argv = runner.build_argv("wlan0", None)
    assert argv[0] == "docker" and "run" in argv
    # interface travels as an env var, never interpolated into the script body
    assert "-e" in argv and "SCAN_IFACE=wlan0" in argv
    assert "python" in argv and "-c" in argv
    # the container gets the caps + host net + the repo mount
    assert "--cap-add" in argv and "NET_RAW" in argv
    assert any(a.endswith(":/app") for a in argv)
    # the interface is NOT spliced into the python -c body (injection guard)
    script = argv[argv.index("-c") + 1]
    assert "wlan0" not in script


# --------------------------------------------------------------- scan outcome honesty

def _fake_cp(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_scan_success_returns_verdict():
    payload = json.dumps({"status": "ok", "verdict": "all clear — 5 known device(s) matched"})
    runner = DockerScanRunner(proc_runner=lambda argv: _fake_cp(0, stdout=payload))
    out = runner.run_arp_watch(interface="wlan0")
    assert out.ok and out.error is None
    assert "all clear" in out.verdict


def test_nonzero_docker_exit_is_an_honest_error():
    runner = DockerScanRunner(proc_runner=lambda argv: _fake_cp(1, stderr="permission denied"))
    out = runner.run_arp_watch(interface="wlan0")
    assert out.ok is False and "permission denied" in out.error
    assert out.verdict is None  # never a fabricated result


def test_non_ok_wrapper_status_is_not_a_clear():
    # arp_watch ran but refused (e.g. whitelist error). That must surface as an error,
    # never as a silent 'clear' (CLAUDE.md §2).
    payload = json.dumps({"status": "whitelist_error", "reason": "whitelist could not be loaded"})
    runner = DockerScanRunner(proc_runner=lambda argv: _fake_cp(0, stdout=payload))
    out = runner.run_arp_watch(interface="wlan0")
    assert out.ok is False and "whitelist could not be loaded" in out.error


def test_docker_missing_is_reported_not_raised():
    def _boom(argv):
        raise FileNotFoundError("docker")
    runner = DockerScanRunner(proc_runner=_boom)
    out = runner.run_arp_watch(interface="wlan0")
    assert out.ok is False and "docker" in out.error.lower()


def test_timeout_is_reported_not_raised():
    def _slow(argv):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=180)
    runner = DockerScanRunner(proc_runner=_slow)
    out = runner.run_arp_watch(interface="wlan0")
    assert out.ok is False and "timed out" in out.error


def test_parse_verdict_ignores_noise_lines():
    stdout = "some banner line\n" + json.dumps({"status": "ok", "verdict": "0 rogues"})
    verdict, err = _parse_verdict(stdout)
    assert err is None and verdict == "0 rogues"


def test_parse_verdict_empty_is_error():
    verdict, err = _parse_verdict("   ")
    assert verdict is None and "no output" in err
