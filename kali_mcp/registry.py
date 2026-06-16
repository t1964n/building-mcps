"""The tool ROSTER and registration helpers.

This module is the SINGLE place the roster is declared (CLAUDE.md §5: the
authoritative list is what the server declares, not memory). The roster is pure
DATA — a binary name, a category, and a one-line purpose per tool. Whether each
binary is actually *present* is decided at call time by tools/meta.py via
shutil.which, never hardcoded here.

Roster source: CLAUDE.md §5 (offensive/recon set). `tshark` is added as the one
`capture` (defensive) entry because it is an explicit Phase 1 tool installed in
the image; flagged to Mark so the installed tool is visible to list_tools.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    """One roster entry. `name` must be the actual binary name on PATH."""

    name: str
    category: str
    purpose: str


# The roster. Order is presentation order. Categories are a small controlled set:
# recon | web | auth | smb | exploit | capture.
ROSTER: tuple[ToolSpec, ...] = (
    ToolSpec("nmap", "recon", "Network/port scanner with service & version detection"),
    ToolSpec("masscan", "recon", "High-speed asynchronous mass port scanner"),
    ToolSpec("whois", "recon", "Domain/IP registration lookup"),
    ToolSpec("dig", "recon", "DNS lookup and record query utility"),
    ToolSpec("whatweb", "web", "Web technology / CMS fingerprinter"),
    ToolSpec("gobuster", "web", "Directory, DNS and vhost brute-forcer"),
    ToolSpec("dirb", "web", "Web content / directory scanner"),
    ToolSpec("nikto", "web", "Web server vulnerability scanner"),
    ToolSpec("nuclei", "web", "Template-based vulnerability scanner"),
    ToolSpec("wpscan", "web", "WordPress vulnerability scanner"),
    ToolSpec("sqlmap", "web", "Automatic SQL-injection detection and exploitation"),
    ToolSpec("hydra", "auth", "Network login brute-forcer"),
    ToolSpec("enum4linux", "smb", "SMB / Windows share and user enumeration"),
    ToolSpec("searchsploit", "exploit", "Offline Exploit-DB search"),
    ToolSpec("tshark", "capture", "Terminal packet capture and protocol analysis"),
)


def register_all(mcp) -> None:
    """Register every exposed tool onto the FastMCP app.

    This is the single wiring point server.py calls. Imports are done here
    (function-local) to avoid a registry <-> tools import cycle.
    """
    from .tools import meta

    meta.register(mcp)
