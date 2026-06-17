"""Tests for the rogue-host watcher (Phase 3, Task 3.3) — fully offline.

Two layers under test:
  * watch.diff_against_whitelist — the PURE diff. Fed canned discovered-host lists +
    hand-built KnownDevice whitelists; no scanning, no I/O.
  * tools.arpwatch.watch — the MCP tool. arpscan.scan and load_whitelist are
    monkeypatched so NO real arp-scan and NO real file read ever happen.

Because this is an alerting surface (CLAUDE.md §2), the tests pin BOTH failure modes:
a fabricated rogue (esp. the MAC-format guard) and a fake "all clear".
"""

from __future__ import annotations

import asyncio

import pytest

from kali_mcp.executor import ToolResult
from kali_mcp.tools import arpwatch
from kali_mcp.watch import WatchResult, diff_against_whitelist
from kali_mcp.whitelist import KnownDevice, WhitelistValidationError


def _dev(mac: str, name: str, ip: str | None = None) -> KnownDevice:
    return KnownDevice(mac=mac, name=name, ip=ip, note=None)


def _host(ip: str, mac: str, vendor: str | None = None) -> dict:
    return {"ip": ip, "mac": mac, "vendor": vendor}


def _run(coro):
    return asyncio.run(coro)


# A small realistic whitelist reused across the pure-diff tests.
ROUTER = _dev("ac:9e:17:aa:bb:cc", "ASUS Router", ip="192.168.51.1")
PI = _dev("dc:a6:32:11:22:33", "Raspberry Pi", ip="192.168.51.50")
LAPTOP = _dev("9c:b6:d0:44:55:66", "ThinkPad")  # DHCP, no fixed IP


# =====================================================================
# watch.diff_against_whitelist — the pure diff
# =====================================================================

# --- all known: every discovered host matches -> earned all-clear ------------

def test_all_known_earned_all_clear():
    discovered = [
        _host("192.168.51.1", "ac:9e:17:aa:bb:cc", "ASUSTek"),
        _host("192.168.51.50", "dc:a6:32:11:22:33", "Raspberry Pi"),
        _host("192.168.51.99", "9c:b6:d0:44:55:66", "Intel"),  # laptop, DHCP, any IP ok
    ]
    res = diff_against_whitelist(discovered, [ROUTER, PI, LAPTOP])
    assert res.rogues == []
    assert res.known_count == 3
    assert res.ip_mismatch_count == 0
    assert res.absent == []
    assert res.discovered_count == 3
    assert res.all_clear is True  # EARNED — devices seen and all matched


# --- one rogue: exactly the unlisted MAC is flagged, with ip/mac/vendor -------

def test_one_rogue_flagged_with_evidence():
    discovered = [
        _host("192.168.51.1", "ac:9e:17:aa:bb:cc", "ASUSTek"),
        _host("192.168.51.77", "de:ad:be:ef:00:99", "Unknown Vendor"),  # ROGUE
    ]
    res = diff_against_whitelist(discovered, [ROUTER, PI, LAPTOP])
    assert res.rogue_count == 1
    rogue = res.rogues[0]
    assert rogue["mac"] == "de:ad:be:ef:00:99"
    assert rogue["ip"] == "192.168.51.77"
    assert rogue["vendor"] == "Unknown Vendor"  # evidence to hunt it
    assert res.known_count == 1  # the router
    assert res.all_clear is False


# --- THE MOST IMPORTANT TEST: MAC format difference must NOT fake a rogue -----

def test_mac_format_difference_is_not_a_rogue():
    # Whitelist stores hyphen/upper form; arp-scan returns lowercase-colon form.
    # normalize_mac on BOTH sides must collapse them to the same device.
    whitelist = [_dev("AC-9E-17-AA-BB-CC", "ASUS Router", ip="192.168.51.1")]
    discovered = [_host("192.168.51.1", "ac:9e:17:aa:bb:cc", "ASUSTek")]
    res = diff_against_whitelist(discovered, whitelist)
    assert res.rogues == [], "format-only difference must NEVER be flagged as a rogue"
    assert res.known_count == 1
    assert res.all_clear is True


def test_mac_format_difference_cisco_dot_form():
    # Cisco dot form on the whitelist side -> same device as colon form discovered.
    whitelist = [_dev("AC9E.17AA.BBCC", "ASUS Router")]
    discovered = [_host("192.168.51.1", "ac:9e:17:aa:bb:cc")]
    res = diff_against_whitelist(discovered, whitelist)
    assert res.rogues == []
    assert res.known_count == 1


# --- ip mismatch: known MAC, unexpected IP -> IP_MISMATCH, reported neutrally -

def test_ip_mismatch_reported_neutrally():
    # Pi is known at .50 but answers at .80.
    discovered = [_host("192.168.51.80", "dc:a6:32:11:22:33", "Raspberry Pi")]
    res = diff_against_whitelist(discovered, [ROUTER, PI, LAPTOP])
    assert res.rogues == []  # NOT a rogue — it's a known device
    assert res.ip_mismatch_count == 1
    mm = res.ip_mismatches[0]
    assert mm["mac"] == "dc:a6:32:11:22:33"
    assert mm["discovered_ip"] == "192.168.51.80"
    assert mm["expected_ip"] == "192.168.51.50"
    assert res.all_clear is False  # an unmatched IP isn't a clean match
    # §2: any spoofing mention must be HEDGED as a hypothesis, never asserted as fact.
    summary = res.summary().lower()
    assert "not asserted" in summary  # explicitly labelled a hypothesis
    assert "spoofing!" not in summary and "is spoofing" not in summary


def test_no_ip_mismatch_when_whitelist_has_no_expected_ip():
    # Laptop has no fixed IP -> any IP is fine, KNOWN not IP_MISMATCH.
    discovered = [_host("192.168.51.200", "9c:b6:d0:44:55:66", "Intel")]
    res = diff_against_whitelist(discovered, [LAPTOP])
    assert res.ip_mismatches == []
    assert res.known_count == 1


# --- absent: whitelisted device not seen this scan -> ABSENT (neutral) --------

def test_absent_device_listed():
    # Only the router answered; Pi and laptop are absent.
    discovered = [_host("192.168.51.1", "ac:9e:17:aa:bb:cc")]
    res = diff_against_whitelist(discovered, [ROUTER, PI, LAPTOP])
    absent_macs = {a["mac"] for a in res.absent}
    assert absent_macs == {"dc:a6:32:11:22:33", "9c:b6:d0:44:55:66"}
    assert res.absent_count == 2
    # Absent alone does NOT break all-clear: a device being off is normal.
    assert res.rogues == []
    assert res.all_clear is True


# --- empty scan is NOT an all-clear (distinguish from earned empty-rogues) ----

def test_empty_scan_is_not_all_clear():
    res = diff_against_whitelist([], [ROUTER, PI])
    assert res.rogues == []  # no rogues...
    assert res.all_clear is False, "found NOTHING is not 'found nothing wrong'"
    assert res.discovered_count == 0
    assert res.absent_count == 2  # both whitelisted devices unseen
    assert "not an all-clear" in res.summary().lower()  # explicitly refuses to clear


# --- mixed realistic scenario: every host lands in the right bucket -----------

def test_mixed_scenario_buckets_and_counts():
    whitelist = [ROUTER, PI, LAPTOP, _dev("00:11:22:33:44:55", "NAS", ip="192.168.51.10")]
    discovered = [
        _host("192.168.51.1", "AC:9E:17:AA:BB:CC", "ASUSTek"),    # KNOWN (mixed case)
        _host("192.168.51.50", "dc:a6:32:11:22:33", "Raspberry"), # KNOWN (ip matches)
        _host("192.168.51.123", "9c:b6:d0:44:55:66", "Intel"),    # KNOWN (laptop, DHCP)
        _host("192.168.51.66", "de:ad:be:ef:13:37", "Espressif"), # ROGUE
        _host("192.168.51.250", "00:11:22:33:44:55", "Synology"), # IP_MISMATCH (.10)
        # NAS absent? no — it appeared (mismatch). No device is absent here.
    ]
    res = diff_against_whitelist(discovered, whitelist)
    assert res.known_count == 3
    assert res.rogue_count == 1
    assert res.rogues[0]["mac"] == "de:ad:be:ef:13:37"
    assert res.ip_mismatch_count == 1
    assert res.ip_mismatches[0]["mac"] == "00:11:22:33:44:55"
    assert res.absent == []  # all four whitelisted devices were seen
    assert res.discovered_count == 5
    assert res.all_clear is False
    assert "1 ROGUE" in res.summary()


def test_to_dict_puts_rogues_at_top():
    res = diff_against_whitelist(
        [_host("192.168.51.5", "de:ad:be:ef:00:01")], [ROUTER]
    )
    d = res.to_dict()
    # Headline fields present and unmissable.
    assert d["rogue_count"] == 1
    assert d["rogues"][0]["mac"] == "de:ad:be:ef:00:01"
    assert d["all_clear"] is False
    assert isinstance(res, WatchResult)


# =====================================================================
# tools.arpwatch.watch — the MCP tool (whitelist load + scan + diff)
# =====================================================================

def _ok_scan(hosts: list[dict], raw: str = "raw arp-scan output") -> dict:
    """A canned successful arpscan.scan(...) return."""
    return {
        "status": "ok",
        "ran": True,
        "target": "wlan0:localnet",
        "command": ["arp-scan", "-I", "wlan0", "--localnet", "-x"],
        "parsed": {"hosts": hosts, "responders": len(hosts), "summary": "..."},
        "raw_output": raw,
    }


def _patch_scan(monkeypatch, result: dict):
    async def _fake_scan(**kwargs):
        return result
    monkeypatch.setattr(arpwatch.arpscan, "scan", _fake_scan)


def _patch_whitelist(monkeypatch, known):
    monkeypatch.setattr(arpwatch, "load_whitelist", lambda path=None: known)


# --- tool: happy path threads the diff through and headlines rogues ----------

def test_tool_flags_rogue_end_to_end(monkeypatch):
    _patch_whitelist(monkeypatch, [ROUTER, PI])
    _patch_scan(monkeypatch, _ok_scan([
        _host("192.168.51.1", "ac:9e:17:aa:bb:cc", "ASUSTek"),
        _host("192.168.51.91", "ca:fe:00:00:00:01", "Mystery"),  # ROGUE
    ]))
    res = _run(arpwatch.watch(interface="wlan0"))
    assert res["status"] == "ok"
    assert res["rogue_count"] == 1
    assert res["rogues"][0]["mac"] == "ca:fe:00:00:00:01"
    assert res["all_clear"] is False
    assert res["raw_output"] == "raw arp-scan output"  # raw kept for reproducibility
    assert res["command"][0] == "arp-scan"


def test_tool_earned_all_clear(monkeypatch):
    _patch_whitelist(monkeypatch, [ROUTER, PI])
    _patch_scan(monkeypatch, _ok_scan([
        _host("192.168.51.1", "AC-9E-17-AA-BB-CC"),   # format differs from whitelist
        _host("192.168.51.50", "dc:a6:32:11:22:33"),
    ]))
    res = _run(arpwatch.watch(interface="wlan0"))
    assert res["status"] == "ok"
    assert res["rogues"] == []
    assert res["all_clear"] is True  # earned: both seen and matched despite MAC format


# --- tool: broken whitelist -> REFUSE, no rogue list, no fake clear -----------

def test_tool_broken_whitelist_refuses(monkeypatch):
    def _boom(path=None):
        raise WhitelistValidationError("device #2: missing required 'mac'.")
    monkeypatch.setattr(arpwatch, "load_whitelist", _boom)
    # If the scan were called it'd blow up the test — prove we never reach it.
    async def _must_not_run(**kwargs):
        raise AssertionError("arp-scan must NOT run when the whitelist is broken")
    monkeypatch.setattr(arpwatch.arpscan, "scan", _must_not_run)

    res = _run(arpwatch.watch(interface="wlan0"))
    assert res["status"] == "whitelist_error"
    assert res["ran"] is False
    assert "rogues" not in res          # NO rogue list produced
    assert "all_clear" not in res       # NO verdict at all
    assert res["error_type"] == "WhitelistValidationError"
    assert "missing required 'mac'" in res["reason"]


# --- tool: arp-scan empty -> honest, NOT a fake all-clear --------------------

def test_tool_empty_scan_not_all_clear(monkeypatch):
    # arp-scan succeeded but saw nothing. With a non-empty whitelist this is NOT
    # 'all clear' — and it must still go through the diff, not be faked.
    _patch_whitelist(monkeypatch, [ROUTER, PI])
    _patch_scan(monkeypatch, _ok_scan([]))
    res = _run(arpwatch.watch(interface="wlan0"))
    assert res["status"] == "ok"
    assert res["rogues"] == []
    assert res["all_clear"] is False    # nothing discovered -> not earned
    assert res["discovered_count"] == 0
    assert res["absent_count"] == 2     # both whitelisted devices unseen


# --- tool: arp-scan ERRORS -> real status propagated, not a fake all-clear ----

def test_tool_scan_error_propagated(monkeypatch):
    _patch_whitelist(monkeypatch, [ROUTER, PI])
    failed = {
        "status": "nonzero_exit",
        "ran": True,
        "exit_code": 1,
        "stderr": "arp-scan: pcap_open_live: socket: Operation not permitted",
        "command": ["arp-scan", "-I", "wlan0", "--localnet", "-x"],
        "target": "wlan0:localnet",
    }
    _patch_scan(monkeypatch, failed)
    res = _run(arpwatch.watch(interface="wlan0"))
    assert res["status"] == "scan_unavailable"
    assert "all_clear" not in res                 # NO verdict
    assert "rogues" not in res                     # NO fabricated rogue list
    assert res["scan"]["status"] == "nonzero_exit"  # the REAL arp-scan outcome
    assert "not permitted" in res["scan"]["stderr"].lower()


def test_tool_scan_not_found_propagated(monkeypatch):
    _patch_whitelist(monkeypatch, [ROUTER])
    notfound = {
        "status": "not_found",
        "ran": False,
        "reason": "arp-scan is not installed in this environment",
        "stderr": "binary not found: 'arp-scan'",
    }
    _patch_scan(monkeypatch, notfound)
    res = _run(arpwatch.watch(interface="wlan0"))
    assert res["status"] == "scan_unavailable"
    assert res["scan"]["status"] == "not_found"
    assert "all_clear" not in res


# --- tool: bad interface rejected by the reused arp-scan validation ----------

def test_tool_bad_interface_rejected(monkeypatch):
    _patch_whitelist(monkeypatch, [ROUTER])
    # Use the REAL arpscan.scan so its Pydantic validation runs; it returns
    # invalid_input without ever calling run_tool.
    res = _run(arpwatch.watch(interface="eth0; rm -rf"))
    assert res["status"] == "scan_unavailable"
    assert res["scan"]["status"] == "invalid_input"
    assert "all_clear" not in res
