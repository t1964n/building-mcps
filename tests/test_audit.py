"""Tests for the audit hook — every run_tool call leaves exactly one JSONL line.

This is the §3/§4/§6 choke point: nothing executes unlogged. We drive it through
run_tool (rather than calling audit_log directly) to prove the wiring is real.
"""

from __future__ import annotations

import json

from kali_mcp.executor import run_tool


def test_run_tool_appends_one_audit_line(tmp_path, monkeypatch):
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(log))

    r = run_tool(["echo", "hi"], timeout_s=5, tool="echo", target="192.168.1.1")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1  # exactly one line appended

    entry = json.loads(lines[0])  # it parses to a JSON object
    assert entry["tool"] == "echo"
    assert entry["target"] == "192.168.1.1"
    assert entry["argv"] == ["echo", "hi"]
    assert entry["status"] == "ok"
    assert entry["status"] == r.status  # log agrees with the returned result
    assert entry["exit_code"] == 0
    assert "timestamp" in entry and entry["timestamp"]
    assert "duration_s" in entry


def test_each_invocation_appends_another_line(tmp_path, monkeypatch):
    """Append-only: a second run adds a line, never overwrites the first."""
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("KALI_MCP_AUDIT_LOG", str(log))

    run_tool(["echo", "one"], timeout_s=5, tool="echo")
    run_tool(["definitely_not_a_binary_xyz"], timeout_s=5, tool="missing")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    statuses = [json.loads(line)["status"] for line in lines]
    assert statuses == ["ok", "not_found"]  # not_found is logged too
