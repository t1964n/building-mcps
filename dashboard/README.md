# Dashboard shell (Phase 4, Task 4.2)

A self-contained, high-contrast **dark-terminal** dashboard that renders a
`network_status` snapshot (the Task 4.1 data contract). This task is the **shell** only:
it renders from **mock fixtures**, not the live tool. Task 4.3 swaps the mock for real
`network_status` output — no render changes needed.

## Files

- `template.html` — the dashboard. Self-contained: inline CSS + JS, no CDN, no external
  fonts, no network calls. Opens straight from `file://`.
- `mock_snapshots.js` — 4 fixture payloads matching the real 4.1 shape exactly.
- `shots/` — headless screenshots, one per state (regenerate with the command below).

## How to view each state

Open the file in a browser and switch states with the `?mock=` query param (or click the
switcher chips in the header):

```
file:///…/dashboard/template.html?mock=rogues_present     # loud red alert path
file:///…/dashboard/template.html?mock=all_clear          # earned green all-clear
file:///…/dashboard/template.html?mock=no_data            # NEUTRAL "no scan data"
file:///…/dashboard/template.html?mock=whitelist_broken   # amber whitelist-error
```

No `?mock=` defaults to the first fixture (`rogues_present`).

## Live generation (Task 4.3 — done)

`template.html` exposes a single `render(snapshot, meta)` function (snapshot-in → DOM-out).
Opened directly it runs the mock bootstrap (the `?mock=` viewer above). The
`generate_dashboard` MCP tool (`kali_mcp/dashboard.py`) reuses this same template: it builds
a REAL `build_status()` snapshot, removes the external `mock_snapshots.js` dependency, and
replaces the bootstrap (between the `DASHBOARD_BOOTSTRAP_START/END` markers) with the live
snapshot embedded inline. The output is a **self-contained** static file (default
`./state/dashboard.html`, gitignored — may hold real IP/MAC) with no server and no network
calls.

Live honesty added on top of the 4.2 states:
- header shows `generated_at` (snapshot time); the network panel shows its own `as_of`
  (scan time) — **distinct** timestamps, never blurred.
- a **stale** banner (amber, above the panel) appears when the scan `as_of` is older than
  the threshold (default 1h) — a days-old all-clear is not a current all-clear.
- if `build_status()` fails, the tool writes **nothing** and returns an error rather than a
  stale/blank file.

Generate it:

```
# via the MCP tool `generate_dashboard`, or directly:
python -c "from kali_mcp.dashboard import generate_dashboard as g; print(g())"
```

## Regenerate the screenshots

```
cd dashboard
for m in rogues_present all_clear no_data whitelist_broken; do
  chromium --headless --no-sandbox --disable-gpu --window-size=1100,1500 \
    --screenshot=shots/$m.png "file://$PWD/template.html?mock=$m"
done
```

## Accessibility / §2 notes

- Operator has a vision impairment: base font ≥ 19px monospace, AAA-level contrast
  (bright `#f0f6fc` foreground on near-black `#0a0e14`), no mid-grey body text.
- **Status is never colour alone** — every status carries a symbol + text label
  (`✓ KNOWN`, `⚠ ROGUE`, `≠ IP MISMATCH`, `○ ABSENT`), so it reads without colour
  perception (colour-blind / one-eye safe).
- **CLAUDE.md §2 made visual:** the three states a lazy dashboard merges into one green
  light are deliberately distinct here:
  - all-clear → **green** (shown *only* for an earned all-clear),
  - no-data → **neutral grey/blue "ⓘ NO SCAN DATA"** (must NOT look like a pass),
  - whitelist-broken → **amber "⚠ WHITELIST ERROR"** (not green, not a rogue count).
  A green light is never shown because data failed to load.
