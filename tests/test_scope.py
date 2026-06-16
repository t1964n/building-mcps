"""Tests for validate_target — the §3 scope gate.

Offline and deterministic. Where a hostname must resolve to a known ip, we
monkeypatch socket.getaddrinfo so the test never touches the network.
"""

from __future__ import annotations

import socket

import pytest

from kali_mcp.scope import validate_target


def _fake_getaddrinfo(ip: str):
    """Return a getaddrinfo replacement that always resolves to `ip`."""
    def _inner(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return _inner


@pytest.mark.parametrize("target", ["192.168.50.1", "10.0.0.5", "172.16.0.1"])
def test_private_v4_allowed(target):
    r = validate_target(target)
    assert r.allowed is True
    assert r.resolved_ip == target
    assert "RFC1918" in r.reason


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1"])
def test_public_v4_denied(target):
    r = validate_target(target)
    assert r.allowed is False
    assert "public/global" in r.reason


def test_boundary_just_outside_172_16_denied():
    # 172.32.0.1 is OUTSIDE 172.16.0.0/12 (which ends at 172.31.255.255).
    r = validate_target("172.32.0.1")
    assert r.allowed is False
    assert "public/global" in r.reason


def test_cgnat_denied():
    r = validate_target("100.64.0.1")
    assert r.allowed is False
    assert "CGNAT" in r.reason


def test_loopback_allowed():
    r = validate_target("127.0.0.1")
    assert r.allowed is True
    assert "loopback" in r.reason


def test_ula_v6_allowed():
    r = validate_target("fd00::1")
    assert r.allowed is True
    assert "ULA" in r.reason


def test_hostname_resolving_to_private_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("192.168.1.10"))
    r = validate_target("router.lan")
    assert r.allowed is True
    assert r.resolved_ip == "192.168.1.10"
    assert "192.168.1.10" in r.reason


def test_hostname_resolving_to_public_denied(monkeypatch):
    # The rebinding guard: a name that resolves to a public ip is denied.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    r = validate_target("evil.example.com")
    assert r.allowed is False
    assert r.resolved_ip == "93.184.216.34"
    assert "public/global" in r.reason


def test_multihomed_hostname_with_public_ip_denied(monkeypatch):
    # A name resolving to one private + one public ip must be DENIED, and the
    # offending public ip named. (The real security gap from the Task 1.2 flag.)
    def _multi(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.50.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        ]
    monkeypatch.setattr(socket, "getaddrinfo", _multi)
    r = validate_target("dual.lan")
    assert r.allowed is False
    assert "8.8.8.8" in r.reason  # the offending public ip is named
    assert "8.8.8.8" in (r.resolved_ip or "")


def test_unresolvable_hostname_denied(monkeypatch):
    def _boom(*args, **kwargs):
        raise socket.gaierror("Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    r = validate_target("nope.invalid")
    assert r.allowed is False
    assert r.resolved_ip is None
    assert "DNS" in r.reason  # no exception escaped


def test_private_cidr_allowed():
    r = validate_target("192.168.50.0/24")
    assert r.allowed is True
    assert "fully within" in r.reason


def test_mixed_cidr_denied():
    # 10.0.0.0/7 spans 10.0.0.0–11.255.255.255 — 11.x is public, so the whole
    # range is NOT fully private.
    r = validate_target("10.0.0.0/7")
    assert r.allowed is False
    assert "not fully within" in r.reason


@pytest.mark.parametrize("target", ["", "; rm -rf /", "192.168.1.1:8080"])
def test_garbage_denied_without_exception(target):
    r = validate_target(target)
    assert r.allowed is False
    assert r.reason  # a clear, non-empty reason — and no exception raised
