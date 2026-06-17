"""Tests for the arp-scan wrapper — fully offline. Real arp-scan is NEVER invoked here;
run_tool is monkeypatched to return canned ToolResults built from real arp-scan output
(the `-x --format='${ip}\t${mac}\t${vendor}'` tab-separated host lines).
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from kali_mcp.executor import ToolResult
from kali_mcp.tools import arpscan


# --- Fixtures: real arp-scan tab-separated host lines (ip<TAB>mac<TAB>vendor) ---
THREE_HOSTS = "\n".join(
    [
        "192.168.51.1\tac:9e:17:aa:bb:cc\tASUSTek COMPUTER INC.",
        "192.168.51.50\tdc:a6:32:11:22:33\tRaspberry Pi Trading Ltd",
        "192.168.51.227\t9c:b6:d0:44:55:66\tIntel Corporate",
    ]
)


def _ok(stdout: str, command=None) -> ToolResult:
    return ToolResult(
        command=command or ["arp-scan", "-I", "wlan0", "--localnet", "-x",
                            r"--format=${ip}\t${mac}\t${vendor}"],
        status="ok", exit_code=0, stdout=stdout, stderr="", duration_s=2.5,
    )


def _run(coro):
    return asyncio.run(coro)


# --- Parse hosts: 3 responders surface with correct MACs + count -------------

def test_parse_hosts(monkeypatch):
    monkeypatch.setattr(arpscan, "run_tool", lambda *a, **k: _ok(THREE_HOSTS))
    res = _run(arpscan.scan(interface="wlan0"))
    assert res["status"] == "ok"
    hosts = res["parsed"]["hosts"]
    assert len(hosts) == 3
    assert res["parsed"]["responders"] == 3
    by_ip = {h["ip"]: h for h in hosts}
    assert by_ip["192.168.51.1"]["mac"] == "ac:9e:17:aa:bb:cc"
    assert by_ip["192.168.51.1"]["vendor"] == "ASUSTek COMPUTER INC."  # spaces preserved
    assert by_ip["192.168.51.50"]["mac"] == "dc:a6:32:11:22:33"
    assert res["raw_output"] == THREE_HOSTS  # raw kept for reproducibility


# --- Zero responders: a real result, NOT an error, NOT fabricated ------------

def test_zero_responders_reported_honestly(monkeypatch):
    monkeypatch.setattr(arpscan, "run_tool", lambda *a, **k: _ok(""))
    res = _run(arpscan.scan(interface="wlan0"))
    assert res["status"] == "ok"                 # not an error
    assert res["parsed"]["responders"] == 0
    assert res["parsed"]["hosts"] == []
    assert "0 hosts answered" in res["summary"]


# --- Raw-socket permission/caps error: surfaced verbatim, no fabricated hosts -

def test_perms_error_surfaced(monkeypatch):
    def _fail(*a, **k):
        return ToolResult(
            command=["arp-scan", "-I", "wlan0", "--localnet", "-x",
                     r"--format=${ip}\t${mac}\t${vendor}"],
            status="nonzero_exit", exit_code=1,
            stdout="",
            stderr="arp-scan: pcap_open_live: socket: Operation not permitted "
                   "(you may need to be root, or have CAP_NET_RAW)\n",
            duration_s=0.03,
        )
    monkeypatch.setattr(arpscan, "run_tool", _fail)
    res = _run(arpscan.scan(interface="wlan0"))
    assert res["status"] == "nonzero_exit"
    assert res["exit_code"] == 1
    assert "not permitted" in res["stderr"].lower()
    assert "parsed" not in res  # no fabricated hosts


# --- Bad interface: rejected by validation, run_tool NEVER called -------------

def test_bad_interface_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(arpscan, "run_tool", mock)
    res = _run(arpscan.scan(interface="eth0; rm -rf"))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


# --- Bad range: non-private/garbage target_range -> rejected, run_tool NOT called -

def test_public_range_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(arpscan, "run_tool", mock)
    res = _run(arpscan.scan(interface="wlan0", target_range="8.8.8.0/24"))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


def test_garbage_range_rejected(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(arpscan, "run_tool", mock)
    res = _run(arpscan.scan(interface="wlan0", target_range="not-a-cidr!!"))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


# --- argv shape: list only, -I <iface> + --localnet + parse flags, no shell str -

def test_argv_shape_localnet(monkeypatch):
    captured = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _ok("", command=argv)

    monkeypatch.setattr(arpscan, "run_tool", _capture)
    res = _run(arpscan.scan(interface="eth0", scan_localnet=True))
    assert res["status"] == "ok"

    argv = captured["argv"]
    assert isinstance(argv, list)                       # a list, never a shell string
    assert argv[0] == "arp-scan"
    assert argv[argv.index("-I") + 1] == "eth0"         # -I eth0
    assert "--localnet" in argv                         # safe default: own subnet
    assert "-x" in argv                                 # plain output (no header/footer)
    assert any(p.startswith("--format=") for p in argv)  # stable parse format
    # no element smuggles a shell metacharacter or a joined command line
    assert not any(";" in part for part in argv)
    assert captured["kwargs"]["tool"] == "arp-scan"


# --- argv shape: explicit validated-private range replaces --localnet --------

def test_argv_shape_private_range(monkeypatch):
    captured = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        return _ok("", command=argv)

    monkeypatch.setattr(arpscan, "run_tool", _capture)
    res = _run(arpscan.scan(interface="wlan0", target_range="192.168.51.0/24"))
    assert res["status"] == "ok"
    argv = captured["argv"]
    assert "192.168.51.0/24" in argv     # the validated private range, positional
    assert "--localnet" not in argv      # range takes precedence over localnet
