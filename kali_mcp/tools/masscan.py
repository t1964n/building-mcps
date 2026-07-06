"""masscan wrapper — the ACTIVE-scanner archetype again, nmap's fast/loud cousin.

Same skeleton as the nmap wrapper (CLAUDE.md §2/§3/§8):
  scope.validate_target (the §3 gate)  ->  argv list  ->  executor.run_tool
  (faithful run + audit)  ->  real-output parse  ->  structured, honest result.

Three ways masscan differs from nmap, all handled here honestly:
  1. ALWAYS raw-socket. masscan has no connect-scan mode; it forges TCP SYNs, so it
     needs CAP_NET_RAW just like nmap -sS. That is supplied by the §4 cap_add bounding
     set + the §2.1 file-caps `setcap`'d onto the masscan binary in the Dockerfile. If
     masscan reports a permission/caps error, that is surfaced VERBATIM (it is exactly
     the failure the 2.1 setcap is meant to prevent).
  2. Its own output format. We ask for `-oJ -` (JSON to stdout) and parse THAT. Chosen
     over `-oX -`: masscan is JSON-native and emits one self-contained JSON object per
     result, which is trivial and robust to parse per-record (see parse_masscan_json) —
     more robust than walking masscan's nmap-mimicking XML. Open ports come ONLY from
     real parsed records; nothing is invented.
  3. Fast and LOUD. masscan can saturate a link, so --rate is a real SAFETY control,
     not a knob: it defaults CONSERVATIVE and is hard-capped (see MAX_RATE_CEILING) so a
     fat-finger can't flood your own LAN.

Honesty rules it must never break (CLAUDE.md §2/§8):
  * Scope failure is a REFUSAL, not a tool error — masscan never runs, no argv is built.
  * not_found / nonzero_exit / timeout are each reported AS THEMSELVES, with the real
    stderr/exit_code and the exact command — never a fabricated finding.
  * "0 open ports found" is a real, successful masscan outcome — reported as such, never
    as an error and never as a fake "all clear".

Input is a constrained Pydantic model: a shape-checked ports string (REQUIRED — masscan
has no default port set) and a bounded rate. Arbitrary masscan flags are NOT accepted.
"""

from __future__ import annotations

import asyncio
import json
import re

from pydantic import BaseModel, ValidationError, field_validator

from ..executor import run_tool
from ..scope import validate_target

# masscan can run long on big ranges at low rate (runtime ~= ports*hosts/rate plus
# masscan's own ~10s post-send wait for late replies). This is a BACKSTOP watchdog
# above the expected runtime, not the primary stop; a genuinely huge range at a low
# rate can exceed it and get killed -> reported honestly as status="timeout".
DEFAULT_TIMEOUT_S = 300.0

# --rate safety envelope (packets/sec). Default is deliberately CONSERVATIVE so the
# common case is gentle on your own LAN; the ceiling rejects absurd rates outright so a
# typo (e.g. 10_000_000) can't turn into a self-inflicted flood. Raise the default per
# call up to the ceiling when you knowingly want a faster sweep.
DEFAULT_MAX_RATE = 1_000
MAX_RATE_CEILING = 100_000

# A ports spec is digits, commas and dashes ONLY (e.g. "80,443" or "8000-8100"). TCP
# only for now — masscan's "U:53" UDP syntax is intentionally NOT supported yet (it
# would need its own validation + parse handling); flag if UDP sweeps are wanted.
_PORTS_RE = re.compile(r"^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$")


class MasscanInput(BaseModel):
    """Validated, constrained input. Rejects bad shape/limits before any command runs."""

    target: str
    ports: str  # REQUIRED — unlike nmap, masscan has no default port set
    max_rate: int = DEFAULT_MAX_RATE

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("ports is required for masscan (e.g. '80,443' or '8000-8100')")
        if not _PORTS_RE.match(value):
            raise ValueError(
                "ports must be digits, commas and dashes only (e.g. '80,443' or "
                "'8000-8100') — no flags or other characters"
            )
        return value

    @field_validator("max_rate")
    @classmethod
    def _check_rate(cls, value: int) -> int:
        if value < 1:
            raise ValueError("max_rate must be at least 1 packet/sec")
        if value > MAX_RATE_CEILING:
            raise ValueError(
                f"max_rate {value} exceeds the safety ceiling of {MAX_RATE_CEILING} "
                "packets/sec — refused so a fat-finger can't flood your own LAN"
            )
        return value


def _build_argv(inp: MasscanInput) -> list[str]:
    """Assemble the masscan argv as a LIST. No string interpolation into a shell, ever.

    `-p<ports>` is masscan's idiomatic combined form; `-oJ -` streams JSON to stdout for
    parsing; `--rate` carries the safety-bounded packet rate.
    """
    return [
        "masscan",
        inp.target,
        f"-p{inp.ports}",
        "--rate",
        str(inp.max_rate),
        "-oJ",
        "-",
    ]


def parse_masscan_json(stdout: str) -> dict:
    """Parse masscan `-oJ -` output into {hosts, open_ports, summary}.

    masscan frames its results as a JSON array, but each RESULT is a self-contained
    object on its own line; the array brackets and the separators between records are
    structural (and some masscan builds emit a stray/trailing comma that breaks a naive
    json.loads of the whole blob). So we parse PER record line — every port we return
    therefore comes from a real masscan record, never invented. A '{'-line that does not
    parse is a real problem and is raised, so the caller can surface it (CLAUDE.md §8)
    rather than guessing past it.
    """
    by_host: dict[str, list[dict]] = {}
    for line in stdout.splitlines():
        s = line.strip().rstrip(",").strip()
        if not s.startswith("{"):
            continue  # '[', ']', bare ',', blank lines, comments -> structural, skip
        rec = json.loads(s)  # may raise json.JSONDecodeError -> parse_error upstream
        ip = rec.get("ip")
        for p in rec.get("ports", []):
            by_host.setdefault(ip, []).append(
                {
                    "port": p.get("port"),
                    "protocol": p.get("proto"),
                    "state": p.get("status"),
                    "reason": p.get("reason"),
                    "ttl": p.get("ttl"),
                }
            )

    hosts = [{"address": ip, "ports": ports} for ip, ports in by_host.items()]
    open_ports = sum(1 for h in hosts for p in h["ports"] if p["state"] == "open")
    if hosts:
        summary = f"{len(hosts)} host(s) with results, {open_ports} open port(s)"
    else:
        summary = (
            "0 open ports found — a real result (nothing responded on the scanned "
            "ports), not an error and not a fabricated all-clear"
        )
    return {"hosts": hosts, "open_ports": open_ports, "summary": summary}


async def scan(
    *,
    target: str,
    ports: str,
    max_rate: int = DEFAULT_MAX_RATE,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict:
    """Run a scope-gated, rate-limited masscan and return a structured, honest result."""
    # 1. Validate/constrain input. A shape/limit failure is rejected before any command.
    try:
        inp = MasscanInput(target=target, ports=ports, max_rate=max_rate)
    except ValidationError as exc:
        return {
            "status": "invalid_input",
            "allowed": None,
            "ran": False,
            "target": target,
            "command": None,
            "reason": f"input rejected before building any command: {exc.errors()}",
        }

    # 2. Scope gate FIRST. Denied -> refusal; masscan never runs, no argv built. CIDR
    #    composes: scope already rejects a range that touches public space.
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

    # 3. Build argv and run off the event loop (run_tool is sync/blocking).
    argv = _build_argv(inp)
    result = await asyncio.to_thread(
        run_tool, argv, timeout_s=timeout_s, tool="masscan", target=inp.target
    )

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
                "reason": "masscan is not installed in this environment",
                "stderr": result.stderr}

    if result.status in ("nonzero_exit", "timeout"):
        # masscan needs raw sockets; a permission/caps error lands here and is surfaced
        # VERBATIM (this is exactly what the §2.1 setcap is meant to prevent).
        return {**base, "status": result.status, "ran": True,
                "exit_code": result.exit_code, "stderr": result.stderr,
                "stdout": result.stdout,
                "reason": f"masscan {result.status} — see stderr/exit_code; no ports fabricated"}

    # status == ok: parse the REAL JSON records.
    try:
        parsed = parse_masscan_json(result.stdout)
    except json.JSONDecodeError as exc:
        return {**base, "status": "parse_error", "ran": True,
                "reason": f"masscan exited 0 but a JSON record did not parse ({exc})",
                "raw_output": result.stdout, "stderr": result.stderr}

    return {**base, "status": "ok", "ran": True,
            "parsed": parsed, "summary": parsed["summary"],
            "raw_output": result.stdout}


def register(mcp) -> None:
    """Attach masscan_scan to the FastMCP app, alongside nmap_scan and the others."""

    @mcp.tool
    async def masscan_scan(
        target: str,
        ports: str,
        max_rate: int = DEFAULT_MAX_RATE,
    ) -> dict:
        """High-speed TCP port sweep of a private target (IP or CIDR) with masscan.

        target is scope-gated to private ranges (your own LAN/lab) — public targets are
        refused without scanning. ports is REQUIRED (digits/commas/dashes, e.g. '80,443'
        or '8000-8100'). max_rate is the packets/sec cap, a SAFETY control: it defaults
        conservative (1000) and is hard-capped at 100000 so a typo can't flood your LAN.
        Returns the parsed open-port list per host AND the raw output AND the exact
        command. '0 open ports' is a real result, not an error.
        """
        return await scan(target=target, ports=ports, max_rate=max_rate)
