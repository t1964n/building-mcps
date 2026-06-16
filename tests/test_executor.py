"""Tests for run_tool — the four outcomes must be distinguishable and clean.

Uses only echo/ls/sleep so it is fast, deterministic and offline. Every test
points the audit log at a tmp file so the suite never writes ./logs/audit.jsonl.
"""

from __future__ import annotations

import pytest

from kali_mcp.executor import run_tool


@pytest.fixture(autouse=True)
def _tmp_audit_log(tmp_path, monkeypatch):
    """Redirect the audit log to a throwaway tmp file for every test."""
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


def test_ok():
    r = run_tool(["echo", "hello"], timeout_s=5, tool="echo")
    assert r.status == "ok"
    assert r.exit_code == 0
    assert "hello" in r.stdout
    assert r.command == ["echo", "hello"]  # exact argv, reproducible
    assert r.parsed is None  # executor never invents parsed output


def test_nonzero_exit():
    r = run_tool(["ls", "/no_such_path_xyz"], timeout_s=5, tool="ls")
    assert r.status == "nonzero_exit"
    assert r.exit_code is not None and r.exit_code != 0
    assert r.stderr != ""
    # The core §2 guarantee: an error is NOT "found nothing".
    assert r.status != "ok"


def test_timeout():
    r = run_tool(["sleep", "5"], timeout_s=1, tool="sleep")
    assert r.status == "timeout"
    assert r.exit_code is None
    # Proves we KILLED it at ~1s rather than waiting the full 5s.
    assert r.duration_s < 3


def test_not_found():
    # Must NOT raise — a missing binary is a reported status.
    r = run_tool(["definitely_not_a_binary_xyz"], timeout_s=5, tool="definitely_not_a_binary_xyz")
    assert r.status == "not_found"
    assert r.exit_code is None
    assert r.stderr != ""  # explains what was missing
