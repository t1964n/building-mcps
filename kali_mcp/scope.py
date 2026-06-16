"""validate_target — the scope gate that enforces CLAUDE.md §3 in code.

"My own devices only" written as a function: a target is allowed ONLY if it is (or
resolves to) an address in Mark's private network/lab. Everything else is denied,
with an honest, human-readable reason for BOTH the allow and the deny.

Design decisions (CLAUDE.md §3, and the Task 1.2 brief):
  * ALLOW buckets: loopback (127/8, ::1), RFC1918 (10/8, 172.16/12, 192.168/16),
    and RFC4193 ULA (fc00::/7).
  * DENY buckets: CGNAT shared space (100.64.0.0/10) and anything global/public.
  * DEFAULT-DENY: only the three allow buckets pass. Link-local (169.254/16,
    fe80::/10) is in NEITHER of Mark's named buckets, so it is denied and labelled
    as such — flagged to Mark rather than silently folded into "private".
  * Hostnames are resolved and the RESOLVED ip is re-checked — a name that resolves
    to a public ip is denied (a rebinding-style guard).

This is a PURE function: string in, ScopeResult out. No execution, no logging, no
side effects. It DECIDES; the caller (a later tool wrapper) acts and logs.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ScopeResult:
    allowed: bool
    target: str               # the original input, untouched
    resolved_ip: str | None   # the IP it resolved/parsed to (None if unresolvable)
    reason: str               # human-readable WHY — for both allow and deny


# --- The buckets, as explicit networks so the reason can name what matched. ---
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_ULA = ipaddress.ip_network("fc00::/7")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")

# Supernets a CIDR must sit ENTIRELY within to be allowed (used via subnet_of).
_ALLOWED_SUPERNETS = (
    _LOOPBACK_V4,
    *_RFC1918,
    ipaddress.ip_network("::1/128"),
    _ULA,
)

# Defence-in-depth: a real IP / CIDR / hostname only uses these characters. Anything
# else (spaces, shell metacharacters, non-ascii) is rejected before we go further.
_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9._:/-]+$")

# A single DNS label: alnum, internal hyphen/underscore, 1–63 chars.
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


def _looks_like_hostname(value: str) -> bool:
    """True for a plausible DNS name — so we never fire getaddrinfo at garbage."""
    name = value.rstrip(".")  # tolerate a trailing-dot FQDN
    if not name or len(name) > 253:
        return False
    return all(_HOSTNAME_LABEL.match(label) for label in name.split("."))


def _classify_ip(ip: IPAddress) -> tuple[bool, str]:
    """Map a single address to (allowed, reason). Default-deny."""
    # CGNAT is checked first so a future is_private quirk can't let it slip through.
    if ip in _CGNAT:
        return False, f"CGNAT shared space ({ip} in {_CGNAT}) — not your LAN, denied"
    if ip.is_loopback:
        return True, f"loopback ({ip}) — allowed"
    for net in _RFC1918:
        if ip in net:
            return True, f"RFC1918 private ({ip} in {net}) — allowed"
    if ip in _ULA:
        return True, f"RFC4193 ULA ({ip} in {_ULA}) — allowed"
    if ip in _LINK_LOCAL_V4 or ip in _LINK_LOCAL_V6:
        return False, f"link-local ({ip}) — not in the allowed loopback/RFC1918/ULA set, denied"
    return False, f"public/global ({ip}) — outside your private scope, denied"


def _classify_network(net: IPNetwork) -> tuple[bool, str]:
    """A CIDR is allowed only if it sits ENTIRELY within one allowed supernet."""
    if net.version == 4 and net.subnet_of(_CGNAT):
        return False, f"CIDR {net} is CGNAT space ({_CGNAT}) — denied"
    for sup in _ALLOWED_SUPERNETS:
        if sup.version != net.version:
            continue
        if net.subnet_of(sup):
            return True, f"CIDR {net} fully within private range {sup} — allowed"
    return False, f"CIDR {net} is not fully within a private range — denied"


def validate_target(target: str) -> ScopeResult:
    """Decide whether `target` is in scope. Never raises on bad input."""
    if not isinstance(target, str):
        return ScopeResult(False, str(target), None, "target is not a string — denied")

    raw = target.strip()
    if not raw:
        return ScopeResult(False, target, None, "empty target — denied")
    if not _ALLOWED_CHARS.match(raw):
        return ScopeResult(
            False, target, None,
            "target contains characters not valid in an IP, CIDR or hostname — denied",
        )

    # CIDR range (nmap/masscan accept these).
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            return ScopeResult(False, target, None, f"not a valid CIDR network ({exc}) — denied")
        allowed, reason = _classify_network(net)
        return ScopeResult(allowed, target, str(net), reason)

    # Bare IP literal.
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        ip = None
    if ip is not None:
        allowed, reason = _classify_ip(ip)
        return ScopeResult(allowed, target, str(ip), reason)

    # Hostname: resolve, then apply the SAME test to the resolved ip (rebinding guard).
    if not _looks_like_hostname(raw):
        return ScopeResult(False, target, None, "not a valid IP, CIDR or hostname — denied")
    try:
        infos = socket.getaddrinfo(raw, None)
    except socket.gaierror as exc:
        return ScopeResult(False, target, None, f"hostname did not resolve (DNS failure: {exc}) — denied")
    except (OSError, UnicodeError) as exc:
        return ScopeResult(False, target, None, f"hostname resolution error ({exc}) — denied")
    if not infos:
        return ScopeResult(False, target, None, "hostname resolved to no addresses — denied")

    resolved = infos[0][4][0]  # first address from the first answer
    try:
        ip = ipaddress.ip_address(resolved)
    except ValueError:
        return ScopeResult(False, target, resolved, f"resolved address {resolved!r} not parseable — denied")
    allowed, inner = _classify_ip(ip)
    return ScopeResult(allowed, target, str(ip), f"{raw} -> {ip} ({inner})")
