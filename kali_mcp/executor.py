"""run_tool — the single faithful executor every tool wrapper calls.

This is the linchpin (CLAUDE.md §2): it keeps "the tool ERRORED" and "the tool
found NOTHING" two different, distinguishable facts. It runs a binary from an argv
list (never a shell), times it, terminates it cleanly on timeout (whole process
group, so nmap/masscan children die too), and reports honestly — a missing binary
is a reported status, never a crash and never a fake "all clear". Every call is
written to the audit log before the result is returned.

run_tool is an EXECUTOR, not an authorizer (§ requirement 7): it assumes argv was
already validated upstream (Task 1.2 scope guard + Task 1.3+ Pydantic models). Its
only jobs are run / time / terminate / report / log.

ASYNC NOTE: run_tool is SYNC and blocking. The MCP wrappers in later tasks MUST call
it via asyncio.to_thread(run_tool, ...) so a long scan can't block the event loop.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .audit import audit_log


@dataclass(frozen=True)
class ToolResult:
    command: list[str]      # exact argv that ran — the reproducibility guarantee
    status: str             # "ok" | "nonzero_exit" | "timeout" | "not_found"
    exit_code: int | None   # None when not_found or timeout
    stdout: str             # raw, decoded utf-8 errors="replace" — never trimmed/faked
    stderr: str             # raw, decoded utf-8 errors="replace"
    duration_s: float       # wall-clock via time.monotonic()
    parsed: dict | None = None  # ALWAYS None here; wrappers fill it later via
                                # dataclasses.replace(...). Never invented.


def _decode(raw: bytes | None) -> str:
    """Decode subprocess bytes as UTF-8 with errors="replace".

    "replace" (not "ignore"): we surface undecodable bytes as the replacement
    char rather than silently dropping them — dropping output would be a §2 lie.
    """
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")


def _kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group so spawned children die too.

    start_new_session=True made the child a process-group leader, so its PID is
    also its PGID. Killing the group reaps nmap/masscan helper processes that a
    plain proc.kill() would orphan.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass  # already exited between timeout and kill — nothing to do


def run_tool(
    argv: list[str],
    *,
    timeout_s: float,
    tool: str,
    target: str | None = None,
) -> ToolResult:
    """Run argv as a real subprocess and report the outcome faithfully.

    Never uses a shell. Enforces timeout_s by terminating the whole process group.
    A missing binary returns status="not_found" rather than raising. Writes one
    audit-log line on every invocation, whatever the outcome.
    """
    start = time.monotonic()

    def finish(status: str, exit_code: int | None, stdout: str, stderr: str) -> ToolResult:
        """Build the ToolResult, audit it, and return it — the single exit path."""
        duration_s = time.monotonic() - start
        command = list(argv)
        audit_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": tool,
                "target": target,
                "argv": command,
                "status": status,
                "exit_code": exit_code,
                "duration_s": duration_s,
            }
        )
        return ToolResult(
            command=command,
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_s=duration_s,
        )

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,  # own process group, so we can kill children too
        )
    except FileNotFoundError as exc:
        # "isn't installed" is a fact we REPORT, never a crash (CLAUDE.md §2).
        return finish(
            "not_found",
            None,
            "",
            f"binary not found: {argv[0]!r} ({exc})",
        )

    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        # Drain whatever partial output exists at kill time — don't discard it.
        out, err = proc.communicate()
        return finish("timeout", None, _decode(out), _decode(err))

    exit_code = proc.returncode
    # Exited 0 -> ok; non-zero -> nonzero_exit. These stay distinguishable from each
    # other AND from an empty-but-successful run (which is ok with empty stdout).
    status = "ok" if exit_code == 0 else "nonzero_exit"
    return finish(status, exit_code, _decode(out), _decode(err))
