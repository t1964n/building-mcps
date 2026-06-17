"""Tests for the masscan wrapper — fully offline. Real masscan is NEVER invoked here;
run_tool is monkeypatched to return canned ToolResults built from real masscan -oJ output.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from kali_mcp.executor import ToolResult
from kali_mcp.tools import masscan


# --- Fixtures: real masscan `-oJ -` output shapes ----------------------------
# masscan frames results as a JSON array, ONE self-contained object per result, with a
# bare-comma separator line between records and a closing ']'. This is the authentic
# on-the-wire shape (the framing that a naive whole-blob json.loads can trip over).
JSON_TWO_OPEN = """[
{   "ip": "192.168.51.1",   "timestamp": "1718900000", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
,
{   "ip": "192.168.51.1",   "timestamp": "1718900000", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 117} ] }
]
"""

# No findings: masscan emits just the empty array frame.
JSON_EMPTY = "[\n]\n"


def _ok(stdout: str, command=None) -> ToolResult:
    return ToolResult(
        command=command or ["masscan", "192.168.51.1", "-p80", "--rate", "1000", "-oJ", "-"],
        status="ok", exit_code=0, stdout=stdout, stderr="", duration_s=0.1,
    )


def _run(coro):
    return asyncio.run(coro)


# --- Scope refusal: run_tool must NEVER be called ----------------------------

def test_scope_denied_does_not_run(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(masscan, "run_tool", mock)
    res = _run(masscan.scan(target="8.8.8.8", ports="80,443"))
    assert res["status"] == "scope_denied"
    assert res["allowed"] is False
    assert res["ran"] is False
    assert res["command"] is None
    mock.assert_not_called()  # the refusal never reached the executor


def test_scope_denied_cidr_spanning_public(monkeypatch):
    # 10.0.0.0/7 (strict=False) spans 10.x AND 11.x — 11.x is public, so the whole
    # range is out of scope. Proves scope composition: a CIDR touching public is denied.
    mock = MagicMock()
    monkeypatch.setattr(masscan, "run_tool", mock)
    res = _run(masscan.scan(target="10.0.0.0/7", ports="80"))
    assert res["status"] == "scope_denied"
    assert res["ran"] is False
    assert res["command"] is None
    mock.assert_not_called()


# --- Parse real JSON: open ports surface per host ----------------------------

def test_parse_open_ports(monkeypatch):
    monkeypatch.setattr(masscan, "run_tool", lambda *a, **k: _ok(JSON_TWO_OPEN))
    res = _run(masscan.scan(target="192.168.51.1", ports="80,443"))
    assert res["status"] == "ok"
    host = res["parsed"]["hosts"][0]
    assert host["address"] == "192.168.51.1"
    by_port = {p["port"]: p for p in host["ports"]}
    assert by_port[80]["state"] == "open" and by_port[80]["protocol"] == "tcp"
    assert by_port[443]["state"] == "open"
    assert res["parsed"]["open_ports"] == 2
    assert res["raw_output"] == JSON_TWO_OPEN  # raw kept for reproducibility


# --- Zero open: a real result, NOT an error, NOT a fabricated all-clear -------

def test_zero_open_reported_honestly(monkeypatch):
    monkeypatch.setattr(masscan, "run_tool", lambda *a, **k: _ok(JSON_EMPTY))
    res = _run(masscan.scan(target="192.168.51.1", ports="80,443"))
    assert res["status"] == "ok"                 # not an error
    assert res["parsed"]["open_ports"] == 0
    assert res["parsed"]["hosts"] == []
    assert "0 open ports" in res["summary"]


# --- Raw-socket permission/caps error: surfaced verbatim, no fabricated ports -

def test_perms_error_surfaced(monkeypatch):
    def _fail(*a, **k):
        return ToolResult(
            command=["masscan", "192.168.51.1", "-p80", "--rate", "1000", "-oJ", "-"],
            status="nonzero_exit", exit_code=1,
            stdout="",
            stderr="FAIL: could not determine default interface\n"
                   "FAIL: permission denied (raw socket) — are you root or do you have "
                   "CAP_NET_RAW?\n",
            duration_s=0.05,
        )
    monkeypatch.setattr(masscan, "run_tool", _fail)
    res = _run(masscan.scan(target="192.168.51.1", ports="80"))
    assert res["status"] == "nonzero_exit"
    assert res["exit_code"] == 1
    assert "permission denied" in res["stderr"].lower()
    assert "parsed" not in res  # no fabricated ports


# --- Missing ports: REQUIRED — Pydantic rejects, run_tool NEVER called --------

def test_missing_ports_rejected():
    # ports has no default on the input model -> omission is a hard validation error.
    with pytest.raises(ValidationError):
        masscan.MasscanInput(target="127.0.0.1")


def test_empty_ports_rejected_before_running(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(masscan, "run_tool", mock)
    res = _run(masscan.scan(target="127.0.0.1", ports="   "))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


# --- Bad ports input: rejected by validation, run_tool NEVER called -----------

def test_bad_ports_rejected_before_running(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(masscan, "run_tool", mock)
    res = _run(masscan.scan(target="127.0.0.1", ports="80; rm -rf"))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


# --- Rate ceiling: the safety control — absurd rate rejected with a clear msg -

def test_rate_ceiling_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(masscan, "run_tool", mock)
    res = _run(masscan.scan(target="127.0.0.1", ports="80", max_rate=masscan.MAX_RATE_CEILING + 1))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    assert "ceiling" in res["reason"]            # a clear, specific message
    mock.assert_not_called()


# --- argv shape: list only, -p<ports> + --rate + -oJ -, no shell string -------

def test_argv_shape(monkeypatch):
    captured = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _ok(JSON_EMPTY, command=argv)

    monkeypatch.setattr(masscan, "run_tool", _capture)
    res = _run(masscan.scan(target="192.168.51.1", ports="80,443", max_rate=500))
    assert res["status"] == "ok"

    argv = captured["argv"]
    assert isinstance(argv, list)                       # a list, never a shell string
    assert argv[0] == "masscan"
    assert "192.168.51.1" in argv
    assert "-p80,443" in argv                           # combined ports form
    assert argv[argv.index("--rate") + 1] == "500"      # the safety-bounded rate
    assert "-oJ" in argv and argv[argv.index("-oJ") + 1] == "-"  # JSON to stdout
    # no element smuggles a shell metacharacter or a joined command line
    assert not any(";" in part or " " in part for part in argv)
    assert captured["kwargs"]["tool"] == "masscan"
