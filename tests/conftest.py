"""Shared pytest fixtures / isolation for the whole suite.

The one job here: keep tests from touching real on-disk state. arp_watch now persists
its last result (Phase 4, 4.1) to $KALI_MCP_STATE_DIR (default ./state). Without
isolation, running the arpwatch tests would write a real ./state/last_watch.json into
the repo and could even pollute a live network_status demo. This autouse fixture
redirects every test's state dir to a per-test tmp path, so the suite stays
side-effect-free and each test starts from a clean 'no watch persisted' state.

Tests that exercise state on purpose (test_status.py) override KALI_MCP_STATE_DIR /
pass explicit paths themselves; this fixture just guarantees a clean default.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_STATE_DIR", str(tmp_path / "state"))
