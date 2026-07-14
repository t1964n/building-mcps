# Desktop control panel (PySide6)

A native desktop GUI for the Kali MCP server — the operator-facing companion to the
stdio MCP tools. It **displays** the honest platform state and can **trigger** a
rogue-host scan, all from a native window. Locked design in
[`../CLAUDE.md`](../CLAUDE.md) ("Desktop control panel", 2026-07-06).

## Why a native app (and not a web UI)

The server's locked §4 rule is **no open network port, ever**. A native window honours
that — nothing is served, nothing listens. That is *why* this is a desktop app rather
than a local web dashboard.

## What it does

- **Displays** `network_status` (read-only): the honest rogue/all-clear/no-data/
  whitelist-broken states, device counts, the rogue hunt-list, staleness of the last
  scan, whitelist state, installed-tool count, and the recent audit tail. It **never
  scans to fill the screen** — "no scan data" stays visually distinct from "all clear".
- **Triggers** `arp_watch` on a chosen interface — and, optionally, a specific **target
  range** (leave it blank to scan the whole segment) — through the **same audited,
  scope-gated wrapper** the MCP layer uses (run inside the `kali-mcp` container via
  `docker run`). The GUI builds no tool command of its own, so scope validation + the
  audit log apply to a GUI-triggered scan exactly as to an MCP one. An out-of-scope range
  is refused **before** any container runs, using the same scope gate the wrapper enforces
  — so a public/CGNAT CIDR gets an instant, honest reason, not a fabricated result. The
  scan runs on a worker thread, so the window never freezes; a failed scan shows its
  **real error**, never a fabricated "all clear".
- **Triggers** `nmap_scan` against a chosen target — pick a `scan_type` from the
  allow-list dropdown (`default`/`ping`/`quick`/`connect`/`syn`/`version`) and optionally a
  ports spec — through the **same scope-gated, audited wrapper** the MCP layer uses. The
  target is scope-checked **before** any container runs, so a public/out-of-scope target is
  refused instantly with a real reason, not scanned. The last result renders in its own
  panel: open ports per host with service/version, honestly distinguishing "no scan yet",
  "host down / no open ports", and "scan failed" — none is dressed up as another.
- **Generates** the self-contained dashboard HTML (`generate_dashboard`) from the same
  produced state the display reads. This is a **read + write-a-file action, not a scan** —
  it runs no tool binary and opens no port, so it runs **in-process** (like the display),
  not through the container: there is no target to scope-check and no offensive tool to
  gate. On success the panel shows the written file path and, if the underlying scan is old,
  stamps its age (a fresh file built on a stale scan is **not** current data). If the
  snapshot can't be built it writes **nothing** and shows the real reason — never a path to
  a blank/stale file dressed up as current.

## Architecture (thin shell, testable core)

```
desktop/
├── backend.py   # Qt-FREE, fully unit-tested:
│                 #   snapshot()          -> read-only build_status() + staleness
│                 #   build_view_model()  -> pure reduction to the honest ViewModel
│                 #   DockerScanRunner    -> runs arp_watch/nmap in the container (injectable
│                 #                          process runner, so it's tested without Docker)
│                 #   run_generate_dashboard() -> writes the dashboard in-process from state
│                 #                          (injectable generator, tested without disk/state)
└── app.py       # PySide6 view ONLY: builds widgets, moves ViewModel data into them.
                 #   No business logic lives here.
```

All the logic that matters is in `backend.py` under `tests/test_desktop_backend.py`
(no Qt, no Docker, no network). The scan path goes through an injected `proc_runner`,
so success / non-zero exit / non-ok wrapper status / docker-missing / timeout are all
exercised with fakes.

## Requirements

PySide6 Qt modules (on Kali/Debian):

```sh
sudo apt-get install -y python3-pyside6.qtcore python3-pyside6.qtgui python3-pyside6.qtwidgets
```

Triggering a scan also needs the built container image (`kali-mcp:phase1`) and Docker —
see [`../CONNECTING.md`](../CONNECTING.md). The **display** works without Docker (it
only reads persisted `state/` + the audit log).

## Run it

```sh
cd ~/building-mcps
python3 -m desktop.app        # opens the native window
```

The interface field defaults to `wlan0`; set it to your real LAN interface before
hitting **Run arp_watch**. Leave **Range** blank to scan the whole segment, or enter a
private CIDR (e.g. `192.168.50.0/24`) to scan just that range — anything outside your
private scope is refused. Use **Refresh** to re-read state without scanning.

For **Run nmap**, enter a target (e.g. `192.168.50.1`), pick a scan type, and optionally
a ports spec (`22,80,443` or `1-1024`); an out-of-scope target is refused before any
container runs. Results — open ports per host with service/version — render in the
**LAST NMAP SCAN** panel.

**Generate dashboard** takes no input: it writes `state/dashboard.html` from the current
produced state (needs no Docker) and shows the path in the **DASHBOARD** panel — open that
file from disk (it is self-contained: no server, no port). If it can't build a snapshot it
writes nothing and shows the real reason.

## Accessibility

Carries over the HTML dashboard's rules: high contrast on near-black, ≥19px text, and
**status is never colour alone** — every state pairs a colour with a symbol + text label
(`✓ KNOWN`, `⚠ ROGUE`, `≠ IP MISMATCH`, `○ ABSENT`).

## Status — first vertical slice

Done: the honest read-only display of all states + three working actions — `arp_watch`
(with an optional scope-checked target range) and `nmap_scan` (target + allow-list scan
type + optional ports), both wired through the gated container wrapper on a worker thread,
plus `generate_dashboard` (writes the self-contained HTML in-process from produced state,
off the UI thread). The backend for all three is fully under test. Natural next steps (not
built yet): a live rogue timeline and auto-refresh.

> Note: `state/` and `logs/` hold your real device data and are gitignored — the app
> reads them locally; they are never committed.
