"""Tests for the nmap wrapper — fully offline. Real nmap is NEVER invoked here;
run_tool is monkeypatched to return canned ToolResults built from real nmap -oX XML.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from kali_mcp.executor import ToolResult
from kali_mcp.tools import nmap


# --- Fixtures: real nmap -oX output shapes -----------------------------------

XML_OPEN_PORTS = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -oX - 192.168.50.1" version="7.94">
<host>
<status state="up" reason="syn-ack"/>
<address addr="192.168.50.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.4"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx"/></port>
</ports>
</host>
<runstats><finished time="1700000000" elapsed="0.12"/>
<hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""

XML_HOST_DOWN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sn -oX - 192.168.50.99" version="7.94">
<host>
<status state="down" reason="no-response"/>
<address addr="192.168.50.99" addrtype="ipv4"/>
</host>
<runstats><finished time="1700000000" elapsed="0.05"/>
<hosts up="0" down="1" total="1"/></runstats>
</nmaprun>"""

XML_MINIMAL_OK = """<?xml version="1.0"?>
<nmaprun version="7.94"><runstats><hosts up="0" down="0" total="0"/></runstats></nmaprun>"""


def _ok(stdout: str, command=None) -> ToolResult:
    return ToolResult(
        command=command or ["nmap", "-sT", "-oX", "-", "127.0.0.1"],
        status="ok", exit_code=0, stdout=stdout, stderr="", duration_s=0.1,
    )


def _run(coro):
    return asyncio.run(coro)


# --- Scope refusal: run_tool must NEVER be called ----------------------------

def test_scope_denied_does_not_run(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(nmap, "run_tool", mock)
    res = _run(nmap.scan(target="8.8.8.8"))
    assert res["status"] == "scope_denied"
    assert res["allowed"] is False
    assert res["ran"] is False
    assert res["command"] is None
    mock.assert_not_called()  # the refusal never reached the executor


# --- Bad ports: rejected by validation, run_tool NEVER called ----------------

def test_bad_ports_rejected_before_running(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(nmap, "run_tool", mock)
    res = _run(nmap.scan(target="127.0.0.1", ports="80; rm -rf"))
    assert res["status"] == "invalid_input"
    assert res["ran"] is False
    mock.assert_not_called()


# --- Parse real XML: open ports surface with service names -------------------

def test_parse_open_ports(monkeypatch):
    monkeypatch.setattr(nmap, "run_tool", lambda *a, **k: _ok(XML_OPEN_PORTS))
    res = _run(nmap.scan(target="192.168.50.1", scan_type="connect"))
    assert res["status"] == "ok"
    host = res["parsed"]["hosts"][0]
    assert host["state"] == "up"
    by_port = {p["portid"]: p for p in host["ports"]}
    assert by_port[22]["state"] == "open" and by_port[22]["service"] == "ssh"
    assert by_port[80]["state"] == "open" and by_port[80]["service"] == "http"
    assert res["parsed"]["open_ports"] == 2
    assert res["raw_output"] == XML_OPEN_PORTS  # raw kept for reproducibility


# --- Host down: reported as down, NOT an error, NOT a fake all-clear ----------

def test_host_down_reported_honestly(monkeypatch):
    monkeypatch.setattr(nmap, "run_tool", lambda *a, **k: _ok(XML_HOST_DOWN))
    res = _run(nmap.scan(target="192.168.50.99", scan_type="ping"))
    assert res["status"] == "ok"            # not an error
    assert res["parsed"]["hosts_up"] == 0
    assert res["parsed"]["hosts"][0]["state"] == "down"
    assert "down" in res["summary"]


# --- Non-zero exit: surface real stderr/exit_code, fabricate nothing ---------

def test_nonzero_exit_surfaced(monkeypatch):
    def _fail(*a, **k):
        return ToolResult(
            command=["nmap", "-sS", "-oX", "-", "127.0.0.1"],
            status="nonzero_exit", exit_code=1,
            stdout="", stderr="nmap: bad something\n", duration_s=0.02,
        )
    monkeypatch.setattr(nmap, "run_tool", _fail)
    res = _run(nmap.scan(target="127.0.0.1", scan_type="syn"))
    assert res["status"] == "nonzero_exit"
    assert res["exit_code"] == 1
    assert "bad something" in res["stderr"]
    assert "parsed" not in res  # no fabricated hosts


# --- argv shape: list only, contains -sS and -oX -, no shell string ----------

def test_argv_shape_syn(monkeypatch):
    captured = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _ok(XML_MINIMAL_OK, command=argv)

    monkeypatch.setattr(nmap, "run_tool", _capture)
    res = _run(nmap.scan(target="127.0.0.1", scan_type="syn", ports="22,80"))
    assert res["status"] == "ok"

    argv = captured["argv"]
    assert isinstance(argv, list)                 # a list, never a shell string
    assert argv[0] == "nmap"
    assert "-sS" in argv                          # syn -> -sS
    assert argv[argv.index("-oX") + 1] == "-"     # XML to stdout
    assert "-p" in argv and "22,80" in argv       # validated ports passed through
    assert "127.0.0.1" == argv[-1]
    # no element smuggles a shell metacharacter or a joined command line
    assert not any(";" in part or " " in part for part in argv)
    assert captured["kwargs"]["tool"] == "nmap"
