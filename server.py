"""FastMCP entry point for the Kali MCP server.

Run directly (`python server.py`) to serve over stdio — the transport an MCP
client connects to. This file just builds the app and wires the roster; the
tools themselves live in kali_mcp/tools/. Task 1.0 exposes only `list_tools`.

Network exposure is stdio only — never bound to 0.0.0.0 (CLAUDE.md §4).
"""

from __future__ import annotations

from fastmcp import FastMCP

from kali_mcp.registry import register_all

mcp = FastMCP(
    name="kali-mcp",
    instructions=(
        "Curated Kali security tools for authorized testing of the operator's own "
        "private network and lab only. Tool output is always the real result or a "
        "clearly-labelled failure — never fabricated. Task 1.0 exposes only "
        "list_tools, which reports each roster tool's real install status."
    ),
)

register_all(mcp)


def main() -> None:
    # stdio transport by default; no port is opened.
    mcp.run()


if __name__ == "__main__":
    main()
