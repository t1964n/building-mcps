"""Tests for the tshark wrapper — fully offline. Real tshark is NEVER invoked;
run_tool is monkeypatched to return canned ToolResults built from sample -T fields
(tab-separated) output.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from kali_mcp.executor import ToolResult
from kali_mcp.tools import tshark


# Fixture: tab-separated -T fields rows.
# cols = frame.number, frame.time_epoch, ip.src, ip.dst, _ws.col.Protocol, frame.len
CAPTURE_4 = "\n".join(
    [
        "1\t1700000000.000001\t192.168.51.227\t192.168.51.1\tTCP\t74",
        "2\t1700000000.000123\t192.168.51.1\t192.168.51.227\tTCP\t66",
        "3\t1700000000.001000\t192.168.51.227\t8.8.8.8\tICMP\t98",
        "4\t1700000000.002000\t\t\tARP\t42",  # non-IP packet: empty src/dst
    ]
)


def _ok(stdout: str, command=None) -> ToolResult:
    return ToolResult(
        command=command or ["tshark", "-i", "lo"],
        status="ok", exit_code=0, stdout=stdout, stderr="", duration_s=5.0,
    )


def _run(coro):
    return asyncio.run(coro)


# --- bound enforcement: no bound -> rejected, run_tool NEVER called ----------

def test_no_bound_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(tshark, "run_tool", mock)
    res = _run(tshark.capture(interface="eth0"))  # neither duration nor count
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


def test_over_limit_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(tshark, "run_tool", mock)
    res = _run(tshark.capture(interface="eth0", duration_s=99999))
    assert res["status"] == "invalid_input"
    assert "300" in res["reason"]  # the documented upper limit
    mock.assert_not_called()


def test_bad_interface_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(tshark, "run_tool", mock)
    res = _run(tshark.capture(interface="eth0; rm -rf", duration_s=5))
    assert res["status"] == "invalid_input"
    mock.assert_not_called()


# --- parse real capture: packet count + protocol breakdown -------------------

def test_parse_packets(monkeypatch):
    monkeypatch.setattr(tshark, "run_tool", lambda *a, **k: _ok(CAPTURE_4))
    res = _run(tshark.capture(interface="lo", packet_count=4))
    assert res["status"] == "ok"
    summary = res["summary"]
    assert summary["total_packets"] == 4
    assert summary["protocols"] == {"TCP": 2, "ICMP": 1, "ARP": 1}
    # The ARP row had no IPs -> not counted as a talker pair.
    assert ["192.168.51.227 -> 192.168.51.1", 1] in summary["top_talkers"]
    # The non-IP packet is still present in the list, with null src/dst.
    arp = res["parsed"]["packets"][3]
    assert arp["protocol"] == "ARP" and arp["src"] is None and arp["length"] == 42


# --- zero packets: a real result, not an error, not fabricated ---------------

def test_zero_packets_reported_honestly(monkeypatch):
    monkeypatch.setattr(tshark, "run_tool", lambda *a, **k: _ok(""))
    res = _run(tshark.capture(interface="lo", duration_s=5))
    assert res["status"] == "ok"               # not an error
    assert res["summary"]["total_packets"] == 0
    assert "0 packets" in res["summary"]["note"]
    assert res["parsed"]["packets"] == []


# --- permission error: surfaced verbatim, no fake "0 packets" ----------------

def test_permission_error_surfaced(monkeypatch):
    def _fail(*a, **k):
        return ToolResult(
            command=["tshark", "-i", "eth0", "-a", "duration:5"],
            status="nonzero_exit", exit_code=2,
            stdout="",
            stderr="tshark: The capture session could not be initiated on capture "
                   "device \"eth0\" (You don't have permission to capture on that device)\n",
            duration_s=0.1,
        )
    monkeypatch.setattr(tshark, "run_tool", _fail)
    res = _run(tshark.capture(interface="eth0", duration_s=5))
    assert res["status"] == "nonzero_exit"
    assert res["exit_code"] == 2
    assert "permission" in res["stderr"].lower()
    assert "parsed" not in res  # no fabricated 0-packet result


# --- argv shape: bounded, list only, no shell string -------------------------

def test_argv_shape(monkeypatch):
    captured = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _ok("", command=argv)

    monkeypatch.setattr(tshark, "run_tool", _capture)
    res = _run(tshark.capture(interface="eth0", duration_s=10))
    assert res["status"] == "ok"

    argv = captured["argv"]
    assert isinstance(argv, list)                       # never a shell string
    assert argv[0] == "tshark"
    assert argv[argv.index("-i") + 1] == "eth0"         # -i eth0
    assert "-a" in argv and "duration:10" in argv       # the hard duration bound
    assert "-T" in argv and "fields" in argv            # chosen output mode
    assert not any(";" in part for part in argv)        # no smuggled metacharacters
    # watchdog timeout is set ABOVE the capture bound (10s + margin).
    assert captured["kwargs"]["timeout_s"] > 10
    assert captured["kwargs"]["tool"] == "tshark"


def test_read_pcap_mode_needs_no_bound(monkeypatch):
    """Offline read: no interface/duration/count required, and -r is used."""
    captured = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        return _ok(CAPTURE_4, command=argv)

    monkeypatch.setattr(tshark, "run_tool", _capture)
    res = _run(tshark.capture(read_pcap="/tmp/sample.pcapng"))
    assert res["status"] == "ok"
    assert captured["argv"][:3] == ["tshark", "-r", "/tmp/sample.pcapng"]
    assert res["summary"]["total_packets"] == 4
