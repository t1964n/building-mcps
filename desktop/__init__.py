"""Desktop control panel for the Kali MCP server (CLAUDE.md desktop decision 2026-07-06).

`backend` is the testable, Qt-free core (state reads + honest view-model + scan runner).
`app` is the thin PySide6 view on top. Import Qt only from `app`, never from `backend`,
so the backend stays unit-testable with no display.
"""
