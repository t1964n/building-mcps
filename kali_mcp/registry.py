"""The tool ROSTER and registration helpers.

This module is the SINGLE place the roster is declared (CLAUDE.md §5: the
authoritative list is what the server declares, not memory). The roster is pure
DATA — a binary name, a category, and a one-line purpose per tool. Whether each
binary is actually *present* is decided at call time by tools/meta.py via
shutil.which, never hardcoded here.

Roster source: CLAUDE.md §5 — the full offensive attack-chain AND defensive
visibility/detection/forensics roster. This is the BUILD TARGET; presence is
decided at call time, so it is correct (not a bug) that almost everything reports
installed=false until its package is added to the Dockerfile.

`name` is the REAL binary on PATH, which sometimes differs from the §5 display
name — probing the binary is the only way list_tools stays honest (CLAUDE.md §2):
  metasploit-framework -> msfconsole
  clamav               -> clamscan        (no `clamav` binary)
  fail2ban             -> fail2ban-client  (no bare `fail2ban`)
Binary names were verified with `command -v` on the host where the tool is
installed. The tools not present on this host (bettercap, suricata, zeek, snort,
lynis, chkrootkit, rkhunter, clamscan, aide, fail2ban-client) use their
documented primary binary and are flagged to Mark as host-unverified.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    """One roster entry. `name` MUST be the actual binary name on PATH — never the
    §5 display name where the two differ (e.g. msfconsole, clamscan,
    fail2ban-client). meta.py probes this name verbatim, so getting it wrong would
    make list_tools report a false-missing on an installed tool."""

    name: str
    category: str
    purpose: str


# The roster. Order is presentation order (offensive attack-chain first, then the
# defensive set), matching CLAUDE.md §5. Categories are a small controlled set:
# recon | web | auth | smb | exploit | crack | wireless | mitm
#   | capture | ids | audit | forensics | defense | host.
ROSTER: tuple[ToolSpec, ...] = (
    # --- Offensive: recon -> scan -> exploit -> crack (CLAUDE.md §5) ---
    ToolSpec("nmap", "recon", "Network/port scanner with service & version detection"),
    ToolSpec("masscan", "recon", "High-speed asynchronous mass port scanner"),
    ToolSpec("nikto", "web", "Web-server misconfig & known-vuln scanner"),
    ToolSpec("nuclei", "web", "Template-based vulnerability scanner"),
    ToolSpec("gobuster", "web", "Directory, DNS and vhost brute-forcer"),
    ToolSpec("dirb", "web", "Web content / directory scanner"),
    ToolSpec("whatweb", "web", "Web technology / CMS fingerprinter"),
    ToolSpec("wpscan", "web", "WordPress enumeration & vulnerability scanner"),
    ToolSpec("sqlmap", "web", "Automatic SQL-injection detection and exploitation"),
    ToolSpec("hydra", "auth", "Network login brute-forcer (SSH, HTTP, RDP, ...)"),
    ToolSpec("john", "crack", "John the Ripper — offline password-hash cracking"),
    ToolSpec("hashcat", "crack", "GPU-accelerated password-hash cracking"),
    ToolSpec("msfconsole", "exploit", "Metasploit Framework — exploitation & post-exploitation"),
    ToolSpec("searchsploit", "exploit", "Offline Exploit-DB search"),
    ToolSpec("enum4linux", "smb", "SMB / Windows share and user enumeration"),
    ToolSpec("aircrack-ng", "wireless", "Wireless auditing & WPA-handshake cracking"),
    ToolSpec("responder", "mitm", "LLMNR/NBT-NS/mDNS poisoner for NetNTLM credential capture"),
    ToolSpec("bettercap", "mitm", "MITM framework — ARP spoof, sniff, credential interception"),
    ToolSpec("whois", "recon", "Domain/IP registration lookup"),
    ToolSpec("dig", "recon", "DNS lookup and record query utility"),
    # --- Defensive: visibility -> detection -> forensics -> hardening (CLAUDE.md §5) ---
    ToolSpec("tshark", "capture", "Terminal packet capture and protocol analysis"),
    ToolSpec("tcpdump", "capture", "Lightweight CLI packet capture for quick taps"),
    ToolSpec("arp-scan", "recon", "Layer-2 host discovery & asset inventory"),
    ToolSpec("ngrep", "capture", "Grep-style pattern matching over live traffic or a pcap"),
    ToolSpec("suricata", "ids", "Network IDS/IPS; signature + protocol-anomaly detection"),
    ToolSpec("zeek", "ids", "Network security monitoring with protocol/connection logs"),
    ToolSpec("snort", "ids", "Signature-based network IDS/IPS"),
    ToolSpec("kismet", "wireless", "Wireless detector / WIDS; rogue-AP & evil-twin hunting"),
    ToolSpec("lynis", "audit", "Host security auditing & hardening checks"),
    ToolSpec("chkrootkit", "forensics", "Rootkit detection"),
    ToolSpec("rkhunter", "forensics", "Rootkit / backdoor / local-exploit checks"),
    ToolSpec("clamscan", "forensics", "ClamAV malware / AV scanner (binary: clamscan)"),
    ToolSpec("aide", "forensics", "File-integrity monitoring against a baseline"),
    ToolSpec("fail2ban-client", "defense", "Fail2ban control — log-driven intrusion prevention"),
    ToolSpec("ss", "host", "Live socket & connection inspection"),
    ToolSpec("netstat", "host", "Live socket & connection inspection (legacy net-tools)"),
)


def register_all(mcp) -> None:
    """Register every exposed tool onto the FastMCP app.

    This is the single wiring point server.py calls. Imports are done here
    (function-local) to avoid a registry <-> tools import cycle.
    """
    from .tools import (
        arpscan,
        arpwatch,
        dashboard_tool,
        masscan,
        meta,
        nmap,
        status_tool,
        tshark,
    )

    meta.register(mcp)
    nmap.register(mcp)
    masscan.register(mcp)
    tshark.register(mcp)
    arpscan.register(mcp)
    arpwatch.register(mcp)
    status_tool.register(mcp)
    dashboard_tool.register(mcp)
