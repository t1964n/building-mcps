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

## How 4.3 will wire it

`template.html` exposes a single `render(snapshot)` function (snapshot-in → DOM-out).
The bootstrap at the bottom currently calls `render(MOCK_SNAPSHOTS[key])`. In 4.3 that one
call is replaced with the real `network_status` payload; everything else stays.

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
