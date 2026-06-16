"""Unit tests for the list_tools meta tool.

We test the pure backing function `gather_tool_status` and patch shutil.which to
prove `installed` reflects reality in BOTH directions — present and absent — and
is never a hardcoded constant (CLAUDE.md §2, §6: the failure/absent path is a
first-class case to test).
"""

from __future__ import annotations

from kali_mcp.registry import ROSTER
from kali_mcp.tools import meta


def test_every_entry_has_required_shape():
    rows = meta.gather_tool_status()
    assert len(rows) == len(ROSTER)
    for row in rows:
        assert set(row.keys()) == {"name", "category", "purpose", "installed"}
        assert isinstance(row["name"], str) and row["name"]
        assert isinstance(row["category"], str) and row["category"]
        assert isinstance(row["purpose"], str) and row["purpose"]
        assert isinstance(row["installed"], bool)


def test_all_present_when_which_finds_everything(monkeypatch):
    monkeypatch.setattr(meta.shutil, "which", lambda name: f"/usr/bin/{name}")
    rows = meta.gather_tool_status()
    assert all(row["installed"] is True for row in rows)


def test_all_absent_when_which_finds_nothing(monkeypatch):
    monkeypatch.setattr(meta.shutil, "which", lambda name: None)
    rows = meta.gather_tool_status()
    assert all(row["installed"] is False for row in rows)


def test_installed_tracks_reality_per_tool(monkeypatch):
    # Only nmap + tshark "installed" — the Phase 1 reality.
    present = {"nmap", "tshark"}
    monkeypatch.setattr(
        meta.shutil, "which", lambda name: f"/usr/bin/{name}" if name in present else None
    )
    rows = {row["name"]: row["installed"] for row in meta.gather_tool_status()}
    assert rows["nmap"] is True
    assert rows["tshark"] is True
    assert rows["sqlmap"] is False
    assert rows["hydra"] is False
