"""nmap wrapper — the first real tool, and the ACTIVE-scanner archetype.

This is where the three Phase-1 primitives combine end-to-end:
  scope.validate_target  (the §3 gate)  ->  argv list  ->  executor.run_tool
  (faithful run + audit)  ->  real-XML parse  ->  structured, honest result.

Honesty rules it must never break (CLAUDE.md §2/§8):
  * Scope failure is a REFUSAL, not a tool error — nmap never runs, no argv is built.
  * A missing binary, a non-zero exit, and a timeout are each reported AS THEMSELVES,
    with the real stderr/exit_code and the exact command — never a fabricated finding.
  * "host down / no response" is a real, successful nmap outcome — reported as such,
    never as an error and never as a fake "all clear".
  * Open ports come ONLY from parsing nmap's real -oX XML. Nothing is invented.

Input is a constrained Pydantic model — an ALLOW-LIST of scan types and a shape-checked
ports string. Arbitrary nmap flags are NOT accepted: no free-form flag injection.
"""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from ..executor import run_tool
from ..scope import validate_target

DEFAULT_TIMEOUT_S = 120.0

# Allow-list: scan_type -> the exact nmap flags it maps to. Input can pick a KEY only;
# it can never supply raw flags. -oX - (XML to stdout) is appended separately, always.
SCAN_TYPES: dict[str, list[str]] = {
    "ping": ["-sn"],            # host discovery, no port scan
    "quick": ["-T4", "-F"],     # fast, top-100 ports
    "connect": ["-sT"],         # TCP connect — no special caps needed
    "syn": ["-sS"],             # SYN scan — needs CAP_NET_RAW (the §4 caps)
    "version": ["-sV"],         # service/version detection
    "default": ["-sV", "-T4"],  # a sensible general scan
}

ScanType = Literal["ping", "quick", "connect", "syn", "version", "default"]

# A ports spec is digits, commas and dashes ONLY (e.g. "22,80,443" or "1-1024").
_PORTS_RE = re.compile(r"^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$")


class NmapInput(BaseModel):
    """Validated, constrained input. Rejects bad shape before any command is built."""

    target: str
    scan_type: ScanType = "default"
    ports: str | None = None
    timeout_s: float = Field(default=DEFAULT_TIMEOUT_S, gt=0, le=3600)

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _PORTS_RE.match(value):
            raise ValueError(
                "ports must be digits, commas and dashes only (e.g. '22,80,443' or "
                "'1-1024') — no flags or other characters"
            )
        return value


def _build_argv(inp: NmapInput) -> list[str]:
    """Assemble the nmap argv as a LIST. No string interpolation, ever."""
    argv = ["nmap", *SCAN_TYPES[inp.scan_type]]
    if inp.ports is not None and inp.scan_type != "ping":
        argv += ["-p", inp.ports]
    argv += ["-oX", "-", inp.target]  # XML to stdout for parsing; target last
    return argv


def parse_nmap_xml(xml_text: str) -> dict:
    """Parse real nmap -oX output into a structured dict. Raises ET.ParseError on
    malformed XML — the caller surfaces that rather than guessing."""
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        address = None
        mac = None
        for addr_el in host_el.findall("address"):
            atype = addr_el.get("addrtype")
            if atype in ("ipv4", "ipv6") and address is None:
                address = addr_el.get("addr")
            elif atype == "mac":
                mac = addr_el.get("addr")

        ports: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                pstate_el = port_el.find("state")
                svc_el = port_el.find("service")
                ports.append(
                    {
                        "portid": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol"),
                        "state": pstate_el.get("state") if pstate_el is not None else None,
                        "service": svc_el.get("name") if svc_el is not None else None,
                        "product": svc_el.get("product") if svc_el is not None else None,
                        "version": svc_el.get("version") if svc_el is not None else None,
                    }
                )
        hosts.append({"address": address, "mac": mac, "state": state, "ports": ports})

    hosts_up = sum(1 for h in hosts if h["state"] == "up")
    open_ports = sum(1 for h in hosts for p in h["ports"] if p["state"] == "open")
    if not hosts or hosts_up == 0:
        summary = (
            f"host down / no response — {hosts_up} host(s) up of {len(hosts)} in output"
        )
    else:
        summary = f"{hosts_up} host(s) up, {open_ports} open port(s)"
    return {
        "hosts": hosts,
        "hosts_up": hosts_up,
        "open_ports": open_ports,
        "summary": summary,
    }


async def scan(
    *,
    target: str,
    scan_type: str = "default",
    ports: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict:
    """Run a scope-gated nmap scan and return a structured, honest result dict."""
    # 1. Validate/constrain input. A shape failure is rejected before any command.
    try:
        inp = NmapInput(target=target, scan_type=scan_type, ports=ports, timeout_s=timeout_s)
    except ValidationError as exc:
        return {
            "status": "invalid_input",
            "allowed": None,
            "ran": False,
            "target": target,
            "command": None,
            "reason": f"input rejected before building any command: {exc.errors()}",
        }

    # 2. Scope gate FIRST. Denied -> refusal; nmap never runs, no argv built.
    #    Offloaded: a hostname target makes validate_target do a blocking getaddrinfo,
    #    which must not stall the MCP event loop (run_tool is offloaded for the same
    #    reason). An IP/CIDR target resolves instantly; the thread hop is negligible.
    sr = await asyncio.to_thread(validate_target, inp.target)
    if not sr.allowed:
        return {
            "status": "scope_denied",
            "allowed": False,
            "ran": False,
            "target": inp.target,
            "resolved_ip": sr.resolved_ip,
            "command": None,
            "reason": sr.reason,
        }

    # 3. Build argv and run off the event loop (run_tool is sync/blocking — §async note).
    argv = _build_argv(inp)
    result = await asyncio.to_thread(
        run_tool, argv, timeout_s=inp.timeout_s, tool="nmap", target=inp.target
    )

    # 4/5. Interpret faithfully — never fabricate.
    base = {
        "allowed": True,
        "target": inp.target,
        "command": result.command,
        "duration_s": result.duration_s,
    }
    # An audit-write failure travels WITH the (real) result — surfaced, never hidden.
    if result.audit_error is not None:
        base["audit_error"] = result.audit_error

    if result.status == "not_found":
        return {**base, "status": "not_found", "ran": False,
                "reason": "nmap is not installed in this environment",
                "stderr": result.stderr}

    if result.status in ("nonzero_exit", "timeout"):
        return {**base, "status": result.status, "ran": True,
                "exit_code": result.exit_code, "stderr": result.stderr,
                "stdout": result.stdout,
                "reason": f"nmap {result.status} — see stderr/exit_code; no findings fabricated"}

    # status == ok: parse the REAL XML.
    try:
        parsed = parse_nmap_xml(result.stdout)
    except ET.ParseError as exc:
        return {**base, "status": "parse_error", "ran": True,
                "reason": f"nmap exited 0 but its XML did not parse ({exc})",
                "raw_output": result.stdout, "stderr": result.stderr}

    return {**base, "status": "ok", "ran": True,
            "parsed": parsed, "summary": parsed["summary"],
            "raw_output": result.stdout}


def register(mcp) -> None:
    """Attach nmap_scan to the FastMCP app, alongside list_tools."""

    @mcp.tool
    async def nmap_scan(
        target: str,
        scan_type: ScanType = "default",
        ports: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> dict:
        """Scope-gated nmap scan of a target on your OWN private network/lab.

        target is validated against the private-range scope gate BEFORE anything
        runs; a public/out-of-scope target is refused, not scanned. scan_type is an
        allow-list (ping/quick/connect/syn/version/default) — arbitrary nmap flags
        are not accepted. ports, if given, is digits/commas/dashes only. Returns the
        parsed open ports/services AND the raw XML AND the exact command run.
        """
        return await scan(target=target, scan_type=scan_type, ports=ports, timeout_s=timeout_s)
