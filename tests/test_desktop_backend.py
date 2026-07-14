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
    NmapOutcome,
    ScanOutcome,
    build_view_model,
    normalize_range,
    _nmap_outcome_from_stdout,
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


# --------------------------------------------------------------- target-range input

@pytest.mark.parametrize("raw", ["", "   ", None])
def test_empty_range_means_whole_segment(raw):
    # No range entered -> scan the whole segment; never treated as an error.
    rng, err = normalize_range(raw)
    assert rng is None and err is None


@pytest.mark.parametrize("raw", ["192.168.50.0/24", "  10.0.0.0/8  ", "192.168.50.10"])
def test_private_range_is_accepted_and_stripped(raw):
    rng, err = normalize_range(raw)
    assert err is None and rng == raw.strip()


@pytest.mark.parametrize("raw", ["8.8.8.0/24", "100.64.0.0/10", "1.1.1.1", "not a cidr!"])
def test_out_of_scope_range_is_refused(raw):
    # Same scope gate the container enforces — a public/CGNAT/garbage range is refused
    # here, with a reason, and yields no range to scan.
    rng, err = normalize_range(raw)
    assert rng is None and err is not None and "out of scope" in err


class _Capture:
    """A proc runner that records the argv it was handed and returns a canned clean scan."""

    def __init__(self):
        self.argv = None

    def __call__(self, argv):
        self.argv = argv
        payload = json.dumps({"status": "ok", "verdict": "0 rogues"})
        return _fake_cp(0, stdout=payload)


def test_valid_range_is_passed_through_to_the_container():
    cap = _Capture()
    runner = DockerScanRunner(proc_runner=cap)
    out = runner.run_arp_watch(interface="wlan0", target_range="192.168.50.0/24")
    assert out.ok and out.error is None
    # the (validated) range travels to the container as SCAN_RANGE, never spliced into code
    assert "SCAN_RANGE=192.168.50.0/24" in cap.argv
    script = cap.argv[cap.argv.index("-c") + 1]
    assert "192.168.50.0/24" not in script


def test_empty_range_scans_whole_segment_via_env():
    cap = _Capture()
    runner = DockerScanRunner(proc_runner=cap)
    out = runner.run_arp_watch(interface="wlan0", target_range="   ")
    assert out.ok
    # whole-segment scan: SCAN_RANGE is present but empty (container -> None -> --localnet)
    assert "SCAN_RANGE=" in cap.argv


def test_out_of_scope_range_refuses_without_running_docker():
    cap = _Capture()
    runner = DockerScanRunner(proc_runner=cap)
    out = runner.run_arp_watch(interface="wlan0", target_range="8.8.8.0/24")
    assert out.ok is False
    assert "out of scope" in out.error
    assert out.verdict is None          # no fabricated result
    assert cap.argv is None             # docker was NEVER invoked
    assert out.command == []            # and no command was built


# --------------------------------------------------------------- nmap action

_NMAP_OK = {
    "status": "ok",
    "summary": "1 host(s) up, 2 open port(s)",
    "parsed": {
        "hosts": [
            {
                "address": "192.168.50.1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "state": "up",
                "ports": [
                    {"portid": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6"},
                    {"portid": 53, "protocol": "tcp", "state": "closed", "service": "domain"},
                    {"portid": 80, "protocol": "tcp", "state": "open", "service": "http", "product": None, "version": None},
                ],
            }
        ],
        "hosts_up": 1,
        "open_ports": 2,
    },
}


class _CaptureNmap:
    """A proc runner that records the argv and returns a canned clean nmap result."""

    def __init__(self, payload=None):
        self.argv = None
        self._payload = payload if payload is not None else _NMAP_OK

    def __call__(self, argv):
        self.argv = argv
        return _fake_cp(0, stdout=json.dumps(self._payload))


def test_nmap_success_returns_summary_and_open_ports():
    cap = _CaptureNmap()
    runner = DockerScanRunner(proc_runner=cap)
    out = runner.run_nmap(target="192.168.50.1", scan_type="default")
    assert out.ok and out.error is None
    assert out.open_ports == 2
    assert "2 open port(s)" in out.summary
    # only the genuinely-open ports are surfaced by the view; the parsed hosts carry them all
    assert out.hosts[0]["address"] == "192.168.50.1"


def test_nmap_target_scan_type_ports_travel_as_env_not_code():
    cap = _CaptureNmap()
    runner = DockerScanRunner(proc_runner=cap)
    runner.run_nmap(target="192.168.50.10", scan_type="syn", ports="22,80,443")
    assert "NMAP_TARGET=192.168.50.10" in cap.argv
    assert "NMAP_SCAN_TYPE=syn" in cap.argv
    assert "NMAP_PORTS=22,80,443" in cap.argv
    # target is NOT spliced into the python -c body (injection guard)
    script = cap.argv[cap.argv.index("-c") + 1]
    assert "192.168.50.10" not in script


def test_nmap_empty_ports_means_default_via_env():
    cap = _CaptureNmap()
    runner = DockerScanRunner(proc_runner=cap)
    runner.run_nmap(target="192.168.50.1", scan_type="quick", ports="   ")
    assert "NMAP_PORTS=" in cap.argv  # present but empty -> container maps to None (nmap default)


def test_nmap_out_of_scope_target_refuses_without_running_docker():
    cap = _CaptureNmap()
    runner = DockerScanRunner(proc_runner=cap)
    out = runner.run_nmap(target="8.8.8.8", scan_type="default")
    assert out.ok is False
    assert "out of scope" in out.error
    assert out.summary is None and out.hosts == []   # nothing fabricated
    assert cap.argv is None                          # docker NEVER invoked
    assert out.command == []


def test_nmap_empty_target_is_refused():
    cap = _CaptureNmap()
    runner = DockerScanRunner(proc_runner=cap)
    out = runner.run_nmap(target="   ", scan_type="default")
    assert out.ok is False and "no target" in out.error
    assert cap.argv is None


def test_nmap_container_scope_denied_is_an_honest_error():
    # An in-scope target passes the pre-check, but the container wrapper still refuses
    # (e.g. a hostname that resolves out of scope). That must surface as its real reason.
    payload = {"status": "scope_denied", "reason": "public/global (9.9.9.9) — outside your private scope, denied"}
    runner = DockerScanRunner(proc_runner=lambda argv: _fake_cp(0, stdout=json.dumps(payload)))
    out = runner.run_nmap(target="192.168.50.1", scan_type="default")
    assert out.ok is False and "outside your private scope" in out.error
    assert out.hosts == []  # never a fabricated finding


def test_nmap_nonzero_docker_exit_is_honest():
    runner = DockerScanRunner(proc_runner=lambda argv: _fake_cp(1, stderr="image not found"))
    out = runner.run_nmap(target="192.168.50.1")
    assert out.ok is False and "image not found" in out.error


def test_nmap_docker_missing_is_reported_not_raised():
    def _boom(argv):
        raise FileNotFoundError("docker")
    runner = DockerScanRunner(proc_runner=_boom)
    out = runner.run_nmap(target="192.168.50.1")
    assert out.ok is False and "docker" in out.error.lower()


def test_nmap_timeout_is_reported_not_raised():
    def _slow(argv):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=180)
    runner = DockerScanRunner(proc_runner=_slow)
    out = runner.run_nmap(target="192.168.50.1")
    assert out.ok is False and "timed out" in out.error


def test_nmap_host_down_is_a_real_ok_result_not_an_error():
    payload = {"status": "ok", "summary": "host down / no response — 0 host(s) up of 1 in output",
               "parsed": {"hosts": [{"address": "192.168.50.9", "state": "down", "ports": []}], "hosts_up": 0, "open_ports": 0}}
    runner = DockerScanRunner(proc_runner=lambda argv: _fake_cp(0, stdout=json.dumps(payload)))
    out = runner.run_nmap(target="192.168.50.9")
    assert out.ok and "host down" in out.summary and out.open_ports == 0


def test_nmap_unparseable_stdout_is_error_not_empty_result():
    out = _nmap_outcome_from_stdout("some banner but no json", ["docker"], 0)
    assert out.ok is False and "could not parse" in out.error
