"""arp-scan wrapper — the ACTIVE mould stretched to LAYER-2 LOCAL discovery.

This tool is the crossover of the two Phase-2 archetypes:
  * Like tshark (the PASSIVE archetype): there is NO remote target to scope-check. arp-scan
    operates on the LOCAL segment through an interface, sweeping the iface's own broadcast
    domain via ARP. So this wrapper deliberately does NOT call scope.validate_target on a
    remote IP — there isn't one.
  * Like masscan (the raw-socket archetype): ARP is a raw layer-2 operation, so arp-scan
    needs CAP_NET_RAW — supplied by the §4 cap_add bounding set + the §2.1 file-caps
    `setcap`'d onto the arp-scan binary in the Dockerfile (the third raw-socket tool to
    reuse that one pattern).

WHY no scope gate is the CORRECT call here (not an oversight): ARP is non-routable. An ARP
request physically cannot leave the local broadcast domain — there is no "scan 8.8.8.8 by
ARP". arp-scan is therefore self-limiting to exactly the segment the host is already on,
which aligns with §3's intent ("your own LAN/lab only") at the protocol level rather than
needing a software gate. The safety boundary that DOES apply is shape-validating the
interface name, and — IF an explicit address range is supplied instead of the safe
--localnet default — validating that range is a private CIDR (reusing the §3 scope helper).

Honesty rules it must never break (CLAUDE.md §2/§8):
  * Input rejected (bad iface / non-private range) is a REFUSAL, not a tool error — arp-scan
    never runs, no argv is built.
  * not_found / nonzero_exit / timeout are each reported AS THEMSELVES, with the real
    stderr/exit_code and the exact command — a raw-socket permission error is surfaced
    VERBATIM, never turned into a fake "0 hosts".
  * "0 hosts answered ARP" is a real, successful outcome (unusual on a live LAN, but valid)
    — reported as such, never as an error and never fabricated.
  * The host list comes ONLY from real arp-scan output. No whitelist comparison is invented;
    we report exactly what answered.
"""

from __future__ import annotations

import asyncio
import re

from pydantic import BaseModel, ValidationError, field_validator, model_validator

from ..executor import run_tool
from ..scope import validate_target

# arp-scan of a /24 via --localnet finishes in a few seconds (256 hosts, a couple of
# retries). This is a BACKSTOP watchdog above that, not the primary stop.
DEFAULT_TIMEOUT_S = 60.0

# Interface: alnum plus . _ - only (eth0, wlan0, br-lan). Same shape rule as tshark.
_IFACE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Sanity shapes for PARSING real output: a dotted-quad IPv4 and a colon-separated MAC.
# Lines that don't match both are not host lines and are skipped (robust, never invented).
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

# Output: -x suppresses arp-scan's header/footer, --format pins a stable tab-separated
# line per responding host. Tab-separated (not space) because the vendor field contains
# spaces ("ASUSTek COMPUTER INC.") but never a tab — so split("\t") is unambiguous.
_FORMAT = r"--format=${ip}\t${mac}\t${vendor}"


class ArpScanInput(BaseModel):
    """Validated, constrained input. Rejects bad shape before any command is built."""

    interface: str
    scan_localnet: bool = True
    target_range: str | None = None

    @field_validator("interface")
    @classmethod
    def _check_iface(cls, value: str) -> str:
        value = value.strip()
        if not _IFACE_RE.match(value):
            raise ValueError(
                "interface must be alphanumeric plus . _ - only (e.g. eth0, wlan0)"
            )
        return value

    @field_validator("target_range")
    @classmethod
    def _check_range(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        # Reuse the §3 scope gate: an explicit range is only allowed if it is a CIDR that
        # sits ENTIRELY within a private supernet. Public / CGNAT / garbage -> refused.
        sr = validate_target(value)
        if not sr.allowed:
            raise ValueError(
                f"target_range must be a private CIDR (e.g. 192.168.51.0/24); refused: {sr.reason}"
            )
        return value

    @model_validator(mode="after")
    def _check_has_spec(self) -> "ArpScanInput":
        # Need SOMETHING to scan: either the safe --localnet default, or an explicit
        # (validated-private) range. Both off is a no-op and is rejected up front.
        if self.target_range is None and not self.scan_localnet:
            raise ValueError(
                "nothing to scan: set scan_localnet=True (the iface's own subnet) or "
                "supply a private target_range"
            )
        return self


def _build_argv(inp: ArpScanInput) -> list[str]:
    """Assemble the arp-scan argv as a LIST. No string interpolation into a shell, ever.

    An explicit (already private-validated) range wins; otherwise --localnet scans the
    interface's own subnet — the safe default.
    """
    argv = ["arp-scan", "-I", inp.interface]
    if inp.target_range is not None:
        argv.append(inp.target_range)
    else:
        argv.append("--localnet")
    argv += ["-x", _FORMAT]
    return argv


def parse_arpscan(stdout: str) -> dict:
    """Parse arp-scan's tab-separated host lines into {hosts, responders, summary}.

    Every host comes from a real `ip<TAB>mac<TAB>vendor` line that passes the IP+MAC
    sanity check; anything else is skipped. 0 hosts is a valid, real result.
    """
    hosts: list[dict] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 2:
            continue  # not a host line
        ip, mac = cols[0].strip(), cols[1].strip()
        if not _IP_RE.match(ip) or not _MAC_RE.match(mac):
            continue  # stray / non-host line -> skip, never guess
        vendor = cols[2].strip() if len(cols) > 2 and cols[2].strip() else None
        hosts.append({"ip": ip, "mac": mac.lower(), "vendor": vendor})

    responders = len(hosts)
    if responders:
        summary = f"{responders} host(s) answered ARP on the local segment"
    else:
        summary = (
            "0 hosts answered ARP — a real result (unusual on a live LAN, but valid), "
            "not an error and not a fabricated empty inventory"
        )
    return {"hosts": hosts, "responders": responders, "summary": summary}


async def scan(
    *,
    interface: str,
    scan_localnet: bool = True,
    target_range: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict:
    """Run a layer-2 arp-scan of the local segment and return a structured, honest result."""
    # 1. Validate/constrain input. A shape/range failure is rejected before any command.
    try:
        inp = ArpScanInput(
            interface=interface, scan_localnet=scan_localnet, target_range=target_range
        )
    except ValidationError as exc:
        return {
            "status": "invalid_input",
            "ran": False,
            "command": None,
            "reason": f"input rejected before building any command: {exc.errors()}",
        }

    # 2. Build argv and run off the event loop (run_tool is sync/blocking). No scope gate:
    #    ARP is non-routable, so the scan is inherently confined to the local segment.
    argv = _build_argv(inp)
    audit_target = inp.target_range if inp.target_range is not None else f"{inp.interface}:localnet"
    result = await asyncio.to_thread(
        run_tool, argv, timeout_s=timeout_s, tool="arp-scan", target=audit_target
    )

    base = {
        "target": audit_target,
        "command": result.command,
        "duration_s": result.duration_s,
    }

    if result.status == "not_found":
        return {**base, "status": "not_found", "ran": False,
                "reason": "arp-scan is not installed in this environment",
                "stderr": result.stderr}

    if result.status in ("nonzero_exit", "timeout"):
        # arp-scan needs raw layer-2 sockets; a permission/caps error lands here and is
        # surfaced VERBATIM (exactly what the §2.1 setcap is meant to prevent).
        return {**base, "status": result.status, "ran": True,
                "exit_code": result.exit_code, "stderr": result.stderr,
                "stdout": result.stdout,
                "reason": f"arp-scan {result.status} — see stderr/exit_code; no hosts fabricated"}

    # status == ok: parse the REAL output.
    parsed = parse_arpscan(result.stdout)
    return {**base, "status": "ok", "ran": True,
            "parsed": parsed, "summary": parsed["summary"],
            "raw_output": result.stdout}


def register(mcp) -> None:
    """Attach arp_scan to the FastMCP app, alongside the other tools."""

    @mcp.tool
    async def arp_scan(
        interface: str,
        scan_localnet: bool = True,
        target_range: str | None = None,
    ) -> dict:
        """Layer-2 host discovery on the local segment via ARP (live device inventory).

        Sweeps the broadcast domain on `interface` and lists every device that answers as
        {ip, mac, vendor} — a real rogue-host inventory for your own LAN. There is NO
        remote target: ARP is non-routable, so the scan is inherently confined to the
        local segment (no scope gate needed). By default it scans the interface's own
        subnet (scan_localnet=True / --localnet); supply target_range only for an explicit
        PRIVATE CIDR (it is rejected otherwise). Returns the parsed host list + responder
        count AND the raw output AND the exact command. '0 hosts answered' is a real result.
        """
        return await scan(
            interface=interface,
            scan_localnet=scan_localnet,
            target_range=target_range,
        )
