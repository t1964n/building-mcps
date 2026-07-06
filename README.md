# Kali MCP Server

A Docker-based [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
exposes a curated set of Kali Linux security tools to an MCP client (Claude Desktop / Claude
Code) over stdio. It is built on `kalilinux/kali-rolling`, written in Python with
[FastMCP](https://github.com/jlowin/fastmcp), and runs as a **non-root** user with only the
specific Linux capabilities the offensive tools need. It exists for one purpose: **authorized,
hands-on security testing of the operator's _own_ home network and lab devices.** Targets are
restricted in code to private ranges (192.168.x.x, 10.x.x.x, 172.16–31.x.x) — that permits the
full toolset against every device you own, and blocks pointing a tool at anything that isn't
yours. Nothing else.

---

## The contract: no BS, no hallucination

This server's whole identity is **trustworthy output**. Mark makes real security decisions
based on what these tools report, and a fabricated result is worse than no result — it can send
you chasing a vulnerability that doesn't exist, or quietly reassure you about one that does. So
every wrapper is built to the same rules:

- **Real output or a real failure — never a fabrication.** A tool reports its actual stdout/stderr
  and the exact command that ran, or it says plainly that it didn't run.
- **"Errored" is not "found nothing."** A tool that times out, isn't installed, or hits a
  permission error is a *different fact* from a tool that ran cleanly and found nothing. The two
  are never conflated.
- **Verdicts are earned, not defaulted.** The rogue-host watcher's "all clear" only happens when
  devices were actually seen *and* every one matched — an empty or failed scan is reported as
  exactly that, not as a clean bill of health.
- **No invented specifics.** IPs, MACs, ports, versions, CVEs — if there's no real result, the
  honest answer is "couldn't determine."

The authoritative statement of these rules — and of the locked architecture/scope decisions — is
[`CLAUDE.md`](./CLAUDE.md). **That file is the source of truth for this project**; this README is
the front door.

---

## Tools implemented today

These are the tools the server **actually wraps and registers** right now (verified in
[`kali_mcp/registry.py`](./kali_mcp/registry.py)). Each one validates its input, runs the real
binary via an argument list (never a shell), captures real stdout/stderr, and surfaces a non-zero
exit as a clear failure:

| Tool | What it does | Safety model |
|------|--------------|--------------|
| `list_tools` | Reports every tool in the roster with its **real** install status (a live `shutil.which` check, never hardcoded). | Read-only; no target. |
| `nmap_scan` | Port / service / version discovery. `scan_type` is an allow-list: `ping`, `quick`, `connect`, `syn`, `version`, `default`. | **Scope-gated** (private-range only); `scan_type`/`ports` are validated keys, not arbitrary flags. |
| `masscan_scan` | High-speed asynchronous port sweep. | **Scope-gated** + **rate-limited** (`max_rate` default 1000 pps, ceiling 100000). |
| `tshark_capture` | Bounded packet capture & protocol/talker summary; can also read an offline `.pcap`. | **Bounded** (mandatory `duration_s` ≤ 300 and/or `packet_count` ≤ 100000) + interface/BPF shape validation. |
| `arp_scan` | Layer-2 host discovery on the local segment → `{ip, mac, vendor}` per responder. | No scope gate needed (ARP is non-routable, self-limiting to the segment); interface shape-validated, explicit ranges must be private CIDRs. |
| `arp_watch` | Runs `arp_scan` and **diffs the result against your device whitelist**, flagging unlisted devices. Persists its last result to `state/last_watch.json` so the dashboard can read it. | **Whitelist-diffed**; refuses to give a verdict if the whitelist can't load. |
| `network_status` | Composes the whole platform's state into **one honest snapshot**: each roster tool's real install status, audit-log tallies, the whitelist's load state, and the **last** `arp_watch` result (read from persisted state — it does **not** scan). | Read-only; no target. Never fabricates a verdict — "no scan data", "all clear", and "whitelist broken" stay distinct (no data ≠ all clear). |
| `generate_dashboard` | Renders `network_status` into a **self-contained** static HTML dashboard file — no server, no port, opened straight from disk. A point-in-time snapshot stamped `generated_at`. | Read-only + writes one HTML file (default `state/dashboard.html`, gitignored). Writes **nothing** if the snapshot fails — never a stale/blank file. |

> **Roster vs. reality.** [`CLAUDE.md §5`](./CLAUDE.md) lists a much larger offensive + defensive
> roster (nikto, nuclei, sqlmap, hydra, metasploit, suricata, zeek, …). That roster is the
> **build target**, not a claim of completion. Of the eight tools above, six wrap a roster binary
> and two (`network_status`, `generate_dashboard`) are platform tools that compose the others.
> `list_tools` reports each roster binary's real install status — and everything outside the six
> wrapped binaries currently reports `installed: false`, honestly, because it hasn't been wrapped
> or installed yet.

---

## Security architecture

- **Non-root by design.** The container runs as the unprivileged `pentester` user — never root,
  never `--privileged`.
- **Capabilities, not root.** Raw-socket tools (nmap `-sS`, masscan, arp-scan, tshark's dumpcap)
  get exactly `CAP_NET_RAW` + `CAP_NET_ADMIN` via the compose `cap_add` bounding set **plus** a
  reusable `setcap …+eip` step in the [`Dockerfile`](./Dockerfile). This is the Phase-2 caps
  pattern: a tool that ships without file-caps gets them added to one explicit list — never a
  blanket grant. (`nmap` already ships its own caps and rides the bounding set for free.)
- **Scope gate.** [`kali_mcp/scope.py`](./kali_mcp/scope.py) validates every routable target
  against private ranges (loopback + RFC1918 + ULA allowed; CGNAT, global, and link-local
  denied). It is enforced in **both** network modes — host networking gives more *reach*, never a
  weaker *gate* (8.8.8.8 stays refused under `--network host`).
- **Append-only audit log.** Every command run is logged as JSONL (tool, argv, target, exit code,
  duration, timestamp) to `logs/audit.jsonl` (override with `KALI_MCP_AUDIT_LOG`). No code path
  bypasses it. A **failed** audit write (disk full, read-only mount, permission) never discards the
  real result or masquerades as a tool crash — the command's output is returned intact, the failure
  is surfaced on the result (`audit_error`) and shouted to stderr, so a run that couldn't be logged
  is loud rather than silent.
- **DNS resolution off the event loop.** Scope validation of a hostname target does a blocking
  `getaddrinfo`; like the tool subprocess itself, it runs in a worker thread so a slow/hung resolver
  can't stall the MCP server.
- **Input validation, no shell injection.** Inputs are Pydantic-validated and commands are built
  as argument lists — no `shell=True` with interpolated input.

> **Honest caveat — VPN killswitch vs. layer.** On a host with an active Mullvad VPN killswitch
> (policy-routing `fwmark` rule), kernel-socket tools (nmap `-sT`/`-sS`, curl) read LAN TCP ports
> as filtered/down, while layer-2 / raw tools (masscan via AF_PACKET, arp-scan via ARP) still see
> the true LAN state — because they bypass the IP-socket policy routing. So on such a host the L2
> tools reflect reality and the socket-based modes can disagree. That's the VPN, not a bug; keep
> it in mind when nmap and masscan/arp-scan diverge.

---

## Network modes

Same image, same caps, same stdio — only the container's network stack differs (full reasoning in
[`NETWORKING.md`](./NETWORKING.md)):

| Compose service | Network | Use it for |
|-----------------|---------|------------|
| `kali-mcp` | bridge (default, isolated) | loopback / self-tests. **Start here.** On bridge, host-discovery to LAN hosts is filtered, so your own router reads "down". |
| `kali-mcp-lan` | `--network host` (opt-in, profile `lan`) | **real LAN scans** — your actual devices become reachable. A deliberate opt-in because it drops the bridge isolation layer. |

---

## Quick start

### 1. Build the image

```sh
cd ~/building-mcps
docker compose build          # tags kali-mcp:phase1
docker images | grep kali-mcp # confirm it exists
```

### 2. Connect an MCP client

The server speaks MCP over the container's **stdio** (no network port is ever opened). The client
launches the container per session. Full instructions — Claude Desktop and Claude Code, both
network modes — are in [`CONNECTING.md`](./CONNECTING.md); copy from
[`mcp-client-config.example.json`](./mcp-client-config.example.json). The short version:

```sh
# Claude Code, bridge (default):
claude mcp add-json kali-mcp '{"command":"docker","args":["run","-i","--rm","--cap-add","NET_RAW","--cap-add","NET_ADMIN","kali-mcp:phase1","python","server.py"]}'

# Claude Code, real-LAN (opt-in):
claude mcp add-json kali-mcp-lan '{"command":"docker","args":["run","-i","--rm","--network","host","--cap-add","NET_RAW","--cap-add","NET_ADMIN","kali-mcp:phase1","python","server.py"]}'
```

### 3. Set up your device whitelist (for `arp_watch`)

```sh
cp whitelist.example.yaml whitelist.yaml   # whitelist.yaml is gitignored — your real inventory
$EDITOR whitelist.yaml                       # add your devices: mac (required) + name; ip/note optional
```

### 4. Run a first scan

Ask the client (in real-LAN mode) to run `list_tools`, then e.g. an `arp_scan` on your interface,
then `arp_watch` to diff it against your whitelist.

---

## The whitelist & rogue-host watcher

`arp_watch` is the platform's headline feature: it answers *"is there anything on my network I
don't recognize?"*

1. Copy `whitelist.example.yaml` → `whitelist.yaml` (gitignored, so your real MACs are never
   committed) and list your known devices. A `mac` is accepted in any common form (colon, hyphen,
   Cisco-dot, any case) and canonicalized internally, so format differences never cause a false
   alarm. `name` is required; `ip` and `note` are optional.
2. Run `arp_watch` on your interface. It loads the whitelist, runs a real `arp_scan`, and classifies
   every discovered host into exactly one bucket, plus computes what's missing:

   | Verdict | Meaning |
   |---------|---------|
   | **KNOWN** | MAC is in the whitelist (and, if an IP was specified, it matches). |
   | **ROGUE** | MAC is **not** in the whitelist — the headline alert; reported with ip/mac/vendor so you can hunt it. |
   | **IP_MISMATCH** | Known MAC, but on a different IP than expected — reported **neutrally** (could be DHCP, could be spoofing; stated as a fact, not an accusation). |
   | **ABSENT** | A whitelisted device that didn't answer this scan — neutral (off/asleep/away). |

3. **A broken whitelist produces no verdict.** If the whitelist is missing or malformed, `arp_watch`
   *refuses* and surfaces the load error instead of scanning and calling everything a rogue — a
   false alarm on a security tool is itself a failure. Likewise, if the underlying `arp_scan`
   errors or finds nothing, that real status is propagated — never repackaged as a fake "all clear."

The whitelist loader lives in [`kali_mcp/whitelist.py`](./kali_mcp/whitelist.py); the pure diff in
[`kali_mcp/watch.py`](./kali_mcp/watch.py).

---

## The dashboard (Phase 4)

`generate_dashboard` turns the platform's real state into a **self-contained static HTML file** —
no web server, no open port, no external fonts or CDN. You open it straight from disk (`file://`).
It is a **point-in-time snapshot**, stamped with `generated_at`, not a live view — and it says so.

### The full loop

The dashboard never scans on its own. It reads state that `arp_watch` produced, so the data flow
is explicit and each stage is independently honest:

```
arp_watch            network_status              generate_dashboard
  │ runs a REAL         │ reads the persisted        │ inlines that snapshot into a
  │ arp-scan + diff     │ last_watch + probes        │ self-contained HTML file
  ▼                     ▼ tools/audit/whitelist      ▼
state/last_watch.json ──► one honest snapshot  ──────► state/dashboard.html  ──► open in a browser
```

1. **`arp_watch`** runs a real `arp_scan` and diffs it against your whitelist, then persists the
   result to `state/last_watch.json` (gitignored — it holds real device MAC/IP).
2. **`network_status`** reads that persisted result (it does **not** run a scan), and probes the
   live install status, audit log, and whitelist, returning one structured snapshot.
3. **`generate_dashboard`** embeds that snapshot into the dashboard template and writes
   `state/dashboard.html` — self-contained, open it anywhere.

### Honest states (this is the project's identity, in the UI)

The dashboard's whole reason to exist is that the three things a lazy dashboard collapses into one
green light stay **visually distinct** — a green "all clear" is shown **only** when it's genuinely
earned, never because data failed to load or is old:

| State | What the dashboard shows |
|-------|--------------------------|
| **Fresh + all clear** | Green "ALL CLEAR — every device known" — only when devices were seen *and* all matched. |
| **Rogues present** | A loud red alert with the rogue count and each rogue's ip/mac/vendor — the loudest thing on the page. |
| **Stale** | An amber "⏱ DATA IS N OLD — re-run arp_watch" banner above the panel. A days-old all-clear is **not** a current all-clear. |
| **No data** | A neutral grey/blue "ⓘ NO SCAN DATA — run arp_watch" panel — deliberately **not** green, never a pass. |
| **Whitelist broken** | An amber "⚠ WHITELIST ERROR" with the load error — not green, not a rogue count. |
| **Generation failed** | `generate_dashboard` writes **nothing** and returns an error rather than a misleading file. |

Two timestamps are shown and never blurred: **`generated_at`** (when the snapshot was built) in the
header, and the network panel's own **`as_of`** (when `arp_watch` actually scanned). A fresh
snapshot can still carry an old scan — staleness is measured on `as_of` (default threshold 1 hour).

### Accessibility (a requirement, not a nicety)

The dark-terminal theme is built for legibility: near-black background with bright (~17:1, past
WCAG AAA) foreground, large monospace text (≥19px), and **status is never signalled by colour
alone** — every state carries a symbol + text label (`✓ KNOWN`, `⚠ ROGUE`, `≠ IP MISMATCH`,
`○ ABSENT`), so it reads without colour perception.

### Generate one

```sh
# 1. whitelist in place (see above), then run arp_watch in the real-LAN container so it persists state:
docker compose --profile lan run --rm -v "$PWD":/app kali-mcp-lan \
  python -c "import asyncio; from kali_mcp.tools.arpwatch import watch; \
             print(asyncio.run(watch(interface='wlan0'))['verdict'])"

# 2. build the dashboard from that real state:
docker compose --profile lan run --rm -v "$PWD":/app kali-mcp-lan \
  python -c "from kali_mcp.dashboard import generate_dashboard as g; print(g()['path'])"

# 3. open it (it's self-contained — no server):
xdg-open state/dashboard.html
```

In normal use you'd drive steps 1–2 by asking your MCP client to run the `arp_watch` and
`generate_dashboard` tools; the commands above are the equivalent direct invocations. The
dashboard template + mock-state viewer are documented in
[`dashboard/README.md`](./dashboard/README.md).

---

## Project status

Built one scoped task at a time; each commit on the branch is one task. Where things stand:

- **Phase 1 — core + first wrappers (done):** the faithful executor (`run_tool`) + audit logging,
  the private-range scope gate, honest `list_tools`, and the first two tool archetypes —
  `nmap_scan` (active) and `tshark_capture` (passive/bounded).
- **Phase 2 — capabilities & networking (done):** the reusable non-root `setcap` raw-socket
  pattern, the bridge-vs-host network modes, and two more wrappers — `masscan_scan` and
  `arp_scan`.
- **Phase 3 — drivable + rogue-host watcher (done):** real MCP-client connection config
  ([`CONNECTING.md`](./CONNECTING.md)), the validated device whitelist store, and the `arp_watch`
  rogue-host watcher.
- **Phase 4 — the dashboard (done):** the `network_status` honest snapshot contract, the
  high-contrast accessible dashboard template, and `generate_dashboard` — a self-contained static
  HTML view of real platform state, with the fresh / stale / no-data / whitelist-broken /
  generation-failure states all kept visually distinct.

**Deliberately _not_ done yet** (so this README doesn't imply more than exists):

- Most of the [`CLAUDE.md §5`](./CLAUDE.md) roster is unwrapped and uninstalled (nikto, nuclei,
  gobuster, sqlmap, hydra, john/hashcat, metasploit, enum4linux, the NIDS suite, etc.).
- `nmap_scan` exposes a fixed scan-type allow-list only — **no `-Pn`** (host-discovery skip) and
  **no UDP** (`-sU`) scanning yet.
- `tshark_capture`'s BPF filter is a **conservative** allow-list (letters/digits/spaces and
  `. : / -`); brackets, arithmetic, and byte-offset filters are rejected, trading expressiveness
  for safety. Widening it is a future decision.
- GPU cracking, monitor-mode wireless, and session tools (responder/bettercap) need hardware
  passthrough and are not wrapped.

---

## Tests

```sh
python -m pytest -q     # 133 tests, all green
```

The suite is **fully offline**: `run_tool` is monkeypatched with canned `ToolResult`s built from
real sample tool output, so **no live scanning or capture happens during tests**. Every wrapper
has both happy-path and failure-path coverage (tool missing, bad input, timeout, permission
error) — failure handling is treated as a feature, not an afterthought.

---

## Layout

```
.
├── CLAUDE.md                     # source of truth: rules, scope, locked decisions
├── README.md                     # this file
├── CONNECTING.md                 # connect an MCP client (Desktop / Code)
├── NETWORKING.md                 # bridge vs --network host, and why
├── Dockerfile                    # kali-rolling image; non-root pentester + setcap caps
├── docker-compose.yml            # kali-mcp (bridge) + kali-mcp-lan (host, profile lan)
├── mcp-client-config.example.json
├── requirements.txt              # fastmcp, pyyaml, pytest
├── pyproject.toml                # pytest config (pythonpath, testpaths)
├── server.py                     # FastMCP entry point (stdio); wires the roster
├── whitelist.example.yaml        # placeholder whitelist (committed)
├── whitelist.yaml                # your real device inventory (gitignored)
├── dashboard/
│   ├── template.html             # self-contained dark-terminal dashboard + render()
│   ├── mock_snapshots.js         # fixture states for the offline mock viewer
│   └── README.md                 # dashboard shell + live-generation notes
├── kali_mcp/
│   ├── executor.py               # run_tool — the single faithful executor
│   ├── audit.py                  # append-only JSONL audit log
│   ├── scope.py                  # private-range target validator
│   ├── registry.py               # the tool ROSTER + register_all wiring
│   ├── whitelist.py              # device whitelist store + normalize_mac
│   ├── watch.py                  # pure rogue-host diff (KNOWN/ROGUE/IP_MISMATCH/ABSENT)
│   ├── state.py                  # persist/read the last arp_watch result (state/last_watch.json)
│   ├── status.py                 # build_status — the honest whole-platform snapshot
│   ├── dashboard.py              # generate_dashboard core (snapshot -> self-contained HTML)
│   └── tools/
│       ├── meta.py               # list_tools
│       ├── nmap.py               # nmap_scan
│       ├── masscan.py            # masscan_scan
│       ├── tshark.py             # tshark_capture
│       ├── arpscan.py            # arp_scan
│       ├── arpwatch.py           # arp_watch
│       ├── status_tool.py        # network_status
│       └── dashboard_tool.py     # generate_dashboard
├── tests/                        # offline unit tests (run_tool monkeypatched)
├── state/                        # last_watch.json + generated dashboard.html (gitignored)
└── logs/audit.jsonl              # runtime audit log (gitignored)
```
