"""tshark wrapper — the PASSIVE archetype (bounded capture, no target IP).

The mirror image of the nmap wrapper. There is no target to scope-check; the safety
boundary here is THE BOUND (a capture must never run unbounded) and the interface name
shape. So this tool deliberately does NOT call scope.validate_target.

Safety model:
  * A live capture MUST be bounded — duration_s and/or packet_count, both within hard
    upper limits. No "capture forever" path exists (enforced at the Pydantic layer).
  * tshark's own `-a duration:N` is the CLEAN stop; run_tool's timeout is set ABOVE it
    as a backstop watchdog, never the primary stop.
  * The interface name and the BPF capture filter are shape-validated before argv is
    built — no flag/shell injection through either.

Honesty rules (CLAUDE.md §2/§8):
  * input rejected      -> a refusal, never ran.
  * not_found           -> tshark isn't installed.
  * nonzero_exit/timeout -> ran and failed; surface real stderr/exit_code/command. A
    live capture needs CAP_NET_RAW (dumpcap); a permissions error is reported VERBATIM,
    never silently turned into "0 packets".
  * ok with 0 packets   -> a real, valid result (quiet network / tight filter), reported
    as exactly that — not an error, not fabricated.
  * The packet list and all counts come ONLY from real captured output.

Output mode: `-T fields` with a fixed `-e` set and a TAB separator. Chosen over -T json
because the fixed column set is all we need and one-tab-delimited-line-per-packet is
trivial and robust to parse (IPs/protocols never contain a tab); -T json would be
heavier to walk for no extra value here.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter

from pydantic import BaseModel, ValidationError, field_validator, model_validator

from ..executor import run_tool

# Hard caps so a fat-finger can't pin the box.
MAX_DURATION_S = 300
MAX_PACKET_COUNT = 100_000
# run_tool watchdog = capture bound + margin (backstop, not the primary stop).
TIMEOUT_MARGIN_S = 15.0
# packet_count-only captures have no time bound of their own — give the watchdog a
# sane ceiling so "wait for N packets" on a quiet network can't hang.
DEFAULT_PACKET_TIMEOUT_S = 60.0
READ_PCAP_TIMEOUT_S = 60.0

# The fixed field set we ask tshark to print, in column order.
FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "frame.len",
)

# Interface: alnum plus . _ - only (eth0, wlan0, lo, any).
_IFACE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# BPF capture filter — CONSERVATIVE allow-list. Permitted: letters, digits, spaces and
# . : / -  → covers the common primitives ("tcp port 80", "host 192.168.1.1",
# "net 10.0.0.0/8", "portrange 1-1024", IPv6 "::1", "udp and not arp"). REJECTED:
# brackets, &, |, ;, quotes, arithmetic — i.e. tshark's advanced byte-offset filters and
# anything shell-ish. Flagged to Mark: we trade some BPF expressiveness for safety.
_BPF_RE = re.compile(r"^[A-Za-z0-9 ._:/-]+$")
# read_pcap: a .pcap/.pcapng path with safe characters only.
_PCAP_RE = re.compile(r"^[A-Za-z0-9 ._/-]+\.(pcap|pcapng)$")


class TsharkInput(BaseModel):
    """Validated, constrained capture parameters. Rejects bad shape/limits up front."""

    interface: str | None = None
    duration_s: int | None = None
    packet_count: int | None = None
    capture_filter: str | None = None
    read_pcap: str | None = None

    @field_validator("interface")
    @classmethod
    def _check_iface(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _IFACE_RE.match(value):
            raise ValueError(
                "interface must be alphanumeric plus . _ - only (e.g. eth0, wlan0, lo, any)"
            )
        return value

    @field_validator("capture_filter")
    @classmethod
    def _check_filter(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if not _BPF_RE.match(value):
            raise ValueError(
                "capture_filter allows only letters, digits, spaces and . : / - "
                "(BPF primitives like 'tcp port 80', 'host 192.168.1.1', "
                "'net 10.0.0.0/8'); brackets/arithmetic/metacharacters are rejected"
            )
        return value

    @field_validator("read_pcap")
    @classmethod
    def _check_pcap(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _PCAP_RE.match(value):
            raise ValueError(
                "read_pcap must be a .pcap/.pcapng path with safe characters only"
            )
        return value

    @model_validator(mode="after")
    def _check_bounds(self) -> "TsharkInput":
        # Offline read: live-capture params don't apply, nothing to bound.
        if self.read_pcap is not None:
            return self

        if self.interface is None:
            raise ValueError("interface is required for a live capture")
        if self.duration_s is None and self.packet_count is None:
            raise ValueError(
                "a live capture MUST be bounded: set duration_s and/or packet_count "
                "(there is no capture-forever path)"
            )
        if self.duration_s is not None and not (1 <= self.duration_s <= MAX_DURATION_S):
            raise ValueError(f"duration_s must be between 1 and {MAX_DURATION_S} seconds")
        if self.packet_count is not None and not (1 <= self.packet_count <= MAX_PACKET_COUNT):
            raise ValueError(f"packet_count must be between 1 and {MAX_PACKET_COUNT}")
        return self


def _fields_args() -> list[str]:
    """The -T fields output spec: fixed columns, tab-separated, no header."""
    args = ["-T", "fields"]
    for field in FIELDS:
        args += ["-e", field]
    # separator=/t -> a real tab between columns; first occurrence only; no header row.
    args += ["-E", "separator=/t", "-E", "occurrence=f", "-E", "header=n"]
    return args


def _build_argv(inp: TsharkInput) -> list[str]:
    """Assemble the tshark argv as a LIST. No string interpolation, ever."""
    if inp.read_pcap is not None:
        return ["tshark", "-r", inp.read_pcap, *_fields_args()]

    argv = ["tshark", "-i", inp.interface]
    if inp.duration_s is not None:
        argv += ["-a", f"duration:{inp.duration_s}"]
    if inp.packet_count is not None:
        argv += ["-c", str(inp.packet_count)]
    if inp.capture_filter is not None:
        argv += ["-f", inp.capture_filter]
    argv += _fields_args()
    return argv


def _timeout_for(inp: TsharkInput) -> float:
    """run_tool watchdog timeout — always ABOVE the capture's own clean stop."""
    if inp.read_pcap is not None:
        return READ_PCAP_TIMEOUT_S
    if inp.duration_s is not None:
        return float(inp.duration_s) + TIMEOUT_MARGIN_S
    return DEFAULT_PACKET_TIMEOUT_S  # packet_count-only: watchdog is the only ceiling


def parse_tshark_fields(text: str) -> dict:
    """Parse the tab-separated -T fields output into packets + a summary.

    Counts derive ONLY from the real lines present. Zero packets is a valid result.
    """
    packets: list[dict] = []
    protocols: Counter = Counter()
    talkers: Counter = Counter()

    for line in text.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        cols += [""] * (len(FIELDS) - len(cols))  # pad short rows (non-IP packets)
        number, time_epoch, src, dst, protocol, length = cols[: len(FIELDS)]

        try:
            frame_no = int(number)
        except ValueError:
            frame_no = None
        try:
            length_i = int(length)
        except ValueError:
            length_i = None

        packets.append(
            {
                "frame": frame_no,
                "time_epoch": time_epoch or None,
                "src": src or None,
                "dst": dst or None,
                "protocol": protocol or None,
                "length": length_i,
            }
        )
        if protocol:
            protocols[protocol] += 1
        if src and dst:
            talkers[f"{src} -> {dst}"] += 1

    total = len(packets)
    summary = {
        "total_packets": total,
        "protocols": dict(protocols),
        "top_talkers": [[pair, n] for pair, n in talkers.most_common(5)],
    }
    if total == 0:
        summary["note"] = (
            "captured 0 packets in the window (quiet network or tight filter) — "
            "a real result, not an error"
        )
    return {"packets": packets, "summary": summary}


async def capture(
    *,
    interface: str | None = None,
    duration_s: int | None = None,
    packet_count: int | None = None,
    capture_filter: str | None = None,
    read_pcap: str | None = None,
) -> dict:
    """Run a bounded tshark capture (or offline pcap read) and return a structured,
    honest result dict."""
    try:
        inp = TsharkInput(
            interface=interface,
            duration_s=duration_s,
            packet_count=packet_count,
            capture_filter=capture_filter,
            read_pcap=read_pcap,
        )
    except ValidationError as exc:
        return {
            "status": "invalid_input",
            "ran": False,
            "command": None,
            "reason": f"input rejected before building any command: {exc.errors()}",
        }

    argv = _build_argv(inp)
    audit_target = f"pcap:{inp.read_pcap}" if inp.read_pcap is not None else inp.interface
    result = await asyncio.to_thread(
        run_tool, argv, timeout_s=_timeout_for(inp), tool="tshark", target=audit_target
    )

    base = {
        "target": audit_target,
        "command": result.command,
        "duration_s": result.duration_s,
    }

    if result.status == "not_found":
        return {**base, "status": "not_found", "ran": False,
                "reason": "tshark is not installed in this environment",
                "stderr": result.stderr}

    if result.status in ("nonzero_exit", "timeout"):
        return {**base, "status": result.status, "ran": True,
                "exit_code": result.exit_code, "stderr": result.stderr,
                "stdout": result.stdout,
                "reason": f"tshark {result.status} — see stderr/exit_code; no packets fabricated"}

    # status == ok: parse the REAL captured output.
    parsed = parse_tshark_fields(result.stdout)
    return {**base, "status": "ok", "ran": True,
            "parsed": parsed, "summary": parsed["summary"],
            "raw_output": result.stdout}


def register(mcp) -> None:
    """Attach tshark_capture to the FastMCP app, alongside nmap_scan and list_tools."""

    @mcp.tool
    async def tshark_capture(
        interface: str | None = None,
        duration_s: int | None = None,
        packet_count: int | None = None,
        capture_filter: str | None = None,
        read_pcap: str | None = None,
    ) -> dict:
        """Bounded packet capture on a local interface (or read an offline pcap).

        A LIVE capture MUST be bounded: provide duration_s and/or packet_count (within
        limits) — there is no capture-forever mode. interface is shape-validated;
        capture_filter is a conservative BPF allow-list. Set read_pcap to a .pcap/.pcapng
        path to parse a file instead of capturing live. Returns the parsed packet list +
        protocol/talker summary AND the raw output AND the exact command run.
        """
        return await capture(
            interface=interface,
            duration_s=duration_s,
            packet_count=packet_count,
            capture_filter=capture_filter,
            read_pcap=read_pcap,
        )
