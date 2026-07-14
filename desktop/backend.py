"""Desktop control-panel backend — the testable core beneath the Qt view.

Honest by construction (CLAUDE.md §2 + the 2026-07-06 desktop decision):

  * DISPLAY reads produced state ONLY. snapshot() calls build_status() (read-only:
    persisted state/ + audit log). It NEVER scans to fill the screen, so "no scan
    data" can never masquerade as "all clear".

  * TRIGGERING a scan goes through the SAME audited, scope-gated wrapper the MCP layer
    uses — arp_watch, run inside the kali-mcp container via `docker run`. The GUI builds
    NO tool command of its own; scope validation + the audit log apply unchanged. The
    interface is passed as an ENV VAR (never interpolated into code), and the docker
    command is an argv LIST (no shell) — the same no-injection discipline as the wrappers.

Everything here is plain Python with an INJECTABLE process runner, so the whole backend
is unit-testable with no Qt, no Docker and no live network.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from kali_mcp.dashboard import compute_network_staleness
from kali_mcp.scope import validate_target
from kali_mcp.status import build_status

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGE = "kali-mcp:phase1"
DEFAULT_SCAN_TIMEOUT_S = 180

# Fixed in-container script: reads the interface/range from env vars (NEVER interpolated
# into code), runs the audited + scope-gated arp_watch wrapper, and prints its JSON
# verdict to stdout. FastMCP-free; a plain wrapper call, so the audit log + scope gate
# fire exactly as they do for an MCP-triggered scan.
_CONTAINER_SCRIPT = (
    "import os, json, asyncio;"
    "from kali_mcp.tools.arpwatch import watch;"
    "print(json.dumps(asyncio.run(watch("
    "interface=os.environ['SCAN_IFACE'],"
    "target_range=(os.environ.get('SCAN_RANGE') or None)))))"
)

# The same pattern for nmap: target / scan_type / ports arrive as env vars (NEVER
# interpolated into code), and the audited + scope-gated nmap wrapper runs inside the
# container. The wrapper's OWN scope gate + allow-list + audit log fire exactly as they
# do for an MCP-triggered scan — the GUI builds no nmap command of its own.
_NMAP_CONTAINER_SCRIPT = (
    "import os, json, asyncio;"
    "from kali_mcp.tools.nmap import scan;"
    "print(json.dumps(asyncio.run(scan("
    "target=os.environ['NMAP_TARGET'],"
    "scan_type=os.environ['NMAP_SCAN_TYPE'],"
    "ports=(os.environ.get('NMAP_PORTS') or None)))))"
)

# The scan_type allow-list, mirrored from kali_mcp.tools.nmap.SCAN_TYPES so the GUI can
# populate a dropdown. The container's NmapInput remains the authoritative validator; a
# bad value would be refused there as invalid_input, never run.
NMAP_SCAN_TYPES = ("default", "ping", "quick", "connect", "syn", "version")


def ensure_paths() -> None:
    """Pin the read-only state/audit/whitelist paths to the repo so the GUI works from
    any CWD, WITHOUT overriding anything the operator set explicitly (tests set their own).
    """
    os.environ.setdefault("KALI_MCP_AUDIT_LOG", str(REPO_ROOT / "logs" / "audit.jsonl"))
    os.environ.setdefault("KALI_MCP_STATE_DIR", str(REPO_ROOT / "state"))
    os.environ.setdefault("KALI_MCP_WHITELIST", str(REPO_ROOT / "whitelist.yaml"))


# --------------------------------------------------------------------------- snapshot

def snapshot(*, whitelist_path: str | None = None, recent_audit: int = 10) -> tuple[dict, dict]:
    """Return (snapshot, staleness) — the honest, read-only platform state for display.

    Pure composition of existing pieces: build_status() (§4.1 honest snapshot) and
    compute_network_staleness() (§4.3 age of the last scan). No scanning happens here.
    """
    snap = build_status(whitelist_path=whitelist_path, recent_audit=recent_audit)
    staleness = compute_network_staleness(snap)
    return snap, staleness


# ------------------------------------------------------------------------ view model

@dataclass(frozen=True)
class ViewModel:
    """The reduced, display-ready state. `level` is the ONE honest headline state; the
    §2 distinctions a lazy UI collapses (no_data vs all_clear vs whitelist_error) are kept
    separate here, and `stale` is carried alongside so a days-old all-clear reads as stale."""

    level: str            # rogue | all_clear | review | no_data | whitelist_error
    symbol: str           # status glyph (never colour-alone: always paired with `label`)
    label: str            # short status text
    headline: str         # one honest sentence
    stale: bool
    age_human: str | None
    generated_at: str | None
    as_of: str | None
    counts: dict          # {known, rogue, ip_mismatch, absent}
    rogues: list          # [{ip, mac, vendor}, ...] — the headline hunt list
    whitelist: dict       # {loaded, device_count, error}
    tools_installed: str  # "6 / 35"
    audit_tail: list      # last few audit rows for the activity panel


def build_view_model(snapshot: dict, staleness: dict) -> ViewModel:
    """Reduce a build_status() snapshot to a ViewModel. Pure; never fabricates a verdict.

    Precedence mirrors the HTML dashboard's honest states: a broken whitelist and a
    missing scan are surfaced as THEMSELVES before any rogue/all-clear verdict, because
    neither is a trustworthy basis for "all clear".
    """
    net = snapshot.get("network") or {}
    wl = snapshot.get("whitelist") or {}
    tool_counts = snapshot.get("tool_counts") or {}
    audit = snapshot.get("audit") or {}
    summary = net.get("summary") or {}

    counts = {
        "known": summary.get("known", 0),
        "rogue": summary.get("rogue", 0),
        "ip_mismatch": summary.get("ip_mismatch", 0),
        "absent": summary.get("absent", 0),
    }

    if wl.get("loaded") is False:
        level, symbol, label = "whitelist_error", "⚠", "WHITELIST ERROR"
        headline = wl.get("error") or "the device whitelist could not be loaded — no trustworthy verdict"
    elif not net.get("available"):
        level, symbol, label = "no_data", "ⓘ", "NO SCAN DATA"
        headline = "run arp_watch to populate this — this is NOT an all-clear"
    elif counts["rogue"] > 0:
        level, symbol, label = "rogue", "⚠", f"{counts['rogue']} ROGUE DEVICE(S)"
        headline = "unlisted device(s) on the segment — investigate"
    elif net.get("all_clear") is True:
        level, symbol, label = "all_clear", "✓", "ALL CLEAR"
        headline = f"{counts['known']} known device(s) matched the whitelist"
    else:
        level, symbol, label = "review", "≠", "REVIEW"
        headline = f"0 rogues, but {counts['ip_mismatch']} device(s) on an unexpected IP"

    return ViewModel(
        level=level,
        symbol=symbol,
        label=label,
        headline=headline,
        stale=bool(staleness.get("stale")),
        age_human=staleness.get("age_human"),
        generated_at=snapshot.get("generated_at"),
        as_of=net.get("as_of"),
        counts=counts,
        rogues=net.get("rogues") or [],
        whitelist=wl,
        tools_installed=f"{tool_counts.get('installed', 0)} / {tool_counts.get('registered', 0)}",
        audit_tail=(audit.get("recent") or [])[-6:],
    )


# ------------------------------------------------------------------------ scan runner

ProcRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def normalize_range(raw: str | None) -> tuple[str | None, str | None]:
    """Normalise + scope-check a GUI-entered target range. Returns (range, error) with
    exactly one meaningful value.

      * empty / whitespace  -> (None, None): scan the whole segment (--localnet), as today.
      * a non-empty range   -> checked with the SAME scope gate the container enforces
        (kali_mcp.scope.validate_target) so an out-of-scope CIDR is refused INSTANTLY with
        the identical rule — this is NOT a second, divergent gate. The container's
        ArpScanInput stays the authoritative boundary (defence in depth); this pre-check is
        just fast, honest feedback so the operator isn't made to wait on a Docker spin-up
        only to be told the range was never in scope.

    A refusal returns (None, <reason>) and the caller must NOT run the scan — an out-of-scope
    range is a refusal, never a tool error and never a fabricated 'nothing found'.
    """
    text = (raw or "").strip()
    if not text:
        return None, None
    sr = validate_target(text)
    if not sr.allowed:
        return None, f"range refused — out of scope: {sr.reason}"
    return text, None


@dataclass(frozen=True)
class ScanOutcome:
    """The honest result of a GUI-triggered scan. ok=False ALWAYS carries a real error
    string (docker missing, timeout, tool failure, unparseable output) — never a fake
    'nothing found'. verdict is the wrapper's own one-line verdict on success."""

    ok: bool
    verdict: str | None
    error: str | None
    command: list[str]
    returncode: int | None


@dataclass(frozen=True)
class NmapOutcome:
    """The honest result of a GUI-triggered nmap scan. Unlike arp_watch there is no single
    verdict — nmap returns hosts + open ports — so this carries the wrapper's own honest
    `summary` line plus the parsed `hosts`. ok=False ALWAYS carries a real error (out of
    scope, docker missing, timeout, nmap non-zero exit, unparseable XML) and NO findings —
    never a fabricated 'nothing open'. 'host down / no response' is a REAL ok result, not
    an error, surfaced through `summary`."""

    ok: bool
    summary: str | None
    hosts: list          # [{address, mac, state, ports:[{portid, protocol, state, service, ...}]}]
    open_ports: int | None
    error: str | None
    command: list[str]
    returncode: int | None


class ScanRunner(Protocol):
    def run_arp_watch(self, *, interface: str, target_range: str | None = None) -> ScanOutcome: ...
    def run_nmap(self, *, target: str, scan_type: str = "default", ports: str | None = None) -> NmapOutcome: ...


def _default_proc_runner(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(argv, capture_output=True, text=True, timeout=DEFAULT_SCAN_TIMEOUT_S)


def _parse_verdict(stdout: str) -> tuple[str | None, str | None]:
    """Extract (verdict, error) from the container's stdout. Returns exactly one non-None.

    The container prints one JSON object (the arp_watch result). We read the last line
    that parses as a JSON object so any incidental leading output is ignored, and we
    honour the wrapper's own status: a non-ok status becomes an ERROR here, never a
    silently-swallowed 'clear' (CLAUDE.md §2)."""
    text = (stdout or "").strip()
    if not text:
        return None, "scan produced no output"
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("status") == "ok":
            return (obj.get("verdict") or "scan complete"), None
        return None, (obj.get("reason") or f"arp_watch did not return a clean result (status: {obj.get('status')!r})")
    return None, "could not parse a scan verdict from the scan output"


def _last_json_obj(stdout: str) -> dict | None:
    """Return the last line of stdout that parses as a JSON object, else None. The
    container prints one JSON result object; any incidental leading output is ignored."""
    for line in reversed((stdout or "").strip().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        return obj
    return None


def _nmap_outcome_from_stdout(stdout: str, argv: list[str], returncode: int | None) -> NmapOutcome:
    """Turn the container's nmap-result JSON into an honest NmapOutcome. A non-ok wrapper
    status (scope_denied, not_found, nonzero_exit, timeout, parse_error, invalid_input) is
    surfaced as its real reason — never a silently-swallowed 'nothing found' (CLAUDE.md §2)."""
    obj = _last_json_obj(stdout)
    if obj is None:
        return NmapOutcome(False, None, [], None, "could not parse an nmap result from the scan output", argv, returncode)
    if obj.get("status") == "ok":
        parsed = obj.get("parsed") or {}
        return NmapOutcome(
            True,
            obj.get("summary") or parsed.get("summary"),
            parsed.get("hosts") or [],
            parsed.get("open_ports"),
            None,
            argv,
            returncode,
        )
    reason = obj.get("reason") or f"nmap did not return a clean result (status: {obj.get('status')!r})"
    return NmapOutcome(False, None, [], None, reason, argv, returncode)


@dataclass
class DockerScanRunner:
    """Runs arp_watch inside the kali-mcp container. The one execution path, and it goes
    THROUGH the audited/scope-gated wrapper — the GUI never touches a tool binary."""

    image: str = IMAGE
    repo_root: Path = REPO_ROOT
    proc_runner: ProcRunner = _default_proc_runner

    def build_argv(self, interface: str, target_range: str | None) -> list[str]:
        """The docker argv as a LIST (no shell). Interface/range travel as env vars, never
        interpolated into the in-container script."""
        return [
            "docker", "run", "--rm",
            "--network", "host",
            "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
            "-e", f"SCAN_IFACE={interface}",
            "-e", f"SCAN_RANGE={target_range or ''}",
            "-v", f"{self.repo_root}:/app",
            self.image, "python", "-c", _CONTAINER_SCRIPT,
        ]

    def run_arp_watch(self, *, interface: str, target_range: str | None = None) -> ScanOutcome:
        # Scope-check the range FIRST, with the same gate the container enforces. An
        # out-of-scope range is refused here — no docker run, no fabricated result — so the
        # operator gets an instant, honest reason instead of waiting on a container only to
        # have ArpScanInput reject it. Empty/None -> whole segment (--localnet), unchanged.
        rng, range_err = normalize_range(target_range)
        if range_err is not None:
            return ScanOutcome(False, None, range_err, [], None)

        argv = self.build_argv(interface, rng)
        try:
            cp = self.proc_runner(argv)
        except FileNotFoundError:
            return ScanOutcome(False, None, "docker was not found on PATH — is Docker installed and running?", argv, None)
        except subprocess.TimeoutExpired:
            return ScanOutcome(False, None, f"scan timed out after {DEFAULT_SCAN_TIMEOUT_S}s", argv, None)

        if cp.returncode != 0:
            err = (cp.stderr or "").strip() or f"docker exited with code {cp.returncode}"
            return ScanOutcome(False, None, err, argv, cp.returncode)

        verdict, err = _parse_verdict(cp.stdout or "")
        if err is not None:
            return ScanOutcome(False, None, err, argv, cp.returncode)
        return ScanOutcome(True, verdict, None, argv, cp.returncode)

    # -------------------------------------------------------------------- nmap
    def build_nmap_argv(self, target: str, scan_type: str, ports: str | None) -> list[str]:
        """The docker argv as a LIST (no shell). target / scan_type / ports travel as env
        vars, NEVER interpolated into the in-container script — the same injection
        discipline as the arp_watch path and the wrappers themselves."""
        return [
            "docker", "run", "--rm",
            "--network", "host",
            "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
            "-e", f"NMAP_TARGET={target}",
            "-e", f"NMAP_SCAN_TYPE={scan_type}",
            "-e", f"NMAP_PORTS={ports or ''}",
            "-v", f"{self.repo_root}:/app",
            self.image, "python", "-c", _NMAP_CONTAINER_SCRIPT,
        ]

    def run_nmap(self, *, target: str, scan_type: str = "default", ports: str | None = None) -> NmapOutcome:
        # Scope-check the target FIRST with the same gate the nmap wrapper enforces, so an
        # out-of-scope target is refused instantly — no docker run, no fabricated finding.
        # The container's nmap wrapper stays the authoritative gate (defence in depth); this
        # is fast, honest feedback. A hostname target triggers a DNS lookup here, but this
        # runs on the worker thread, never the UI thread.
        target = (target or "").strip()
        if not target:
            return NmapOutcome(False, None, [], None, "no target given — enter an IP/host on your own network", [], None)
        sr = validate_target(target)
        if not sr.allowed:
            return NmapOutcome(False, None, [], None, f"target refused — out of scope: {sr.reason}", [], None)

        argv = self.build_nmap_argv(target, scan_type, (ports or "").strip() or None)
        try:
            cp = self.proc_runner(argv)
        except FileNotFoundError:
            return NmapOutcome(False, None, [], None, "docker was not found on PATH — is Docker installed and running?", argv, None)
        except subprocess.TimeoutExpired:
            return NmapOutcome(False, None, [], None, f"scan timed out after {DEFAULT_SCAN_TIMEOUT_S}s", argv, None)

        if cp.returncode != 0:
            err = (cp.stderr or "").strip() or f"docker exited with code {cp.returncode}"
            return NmapOutcome(False, None, [], None, err, argv, cp.returncode)

        return _nmap_outcome_from_stdout(cp.stdout or "", argv, cp.returncode)
