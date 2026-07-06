# CLAUDE.md — Kali MCP Server

> Read this file in full at the start of every session. It is the single source of truth for this project.
> Keep it short, current, and **honest**. When a decision changes, update this file first — before writing code.

---

## 1. What this project is

A **Model Context Protocol (MCP) server** that exposes a curated set of Kali Linux security tools
(nmap, nikto, sqlmap, etc.) to an AI assistant over MCP. It runs inside a **Docker** container built on
`kalilinux/kali-rolling`, written in **Python with FastMCP**.

**Purpose:** authorized, hands-on security testing of **Mark's own home network and lab devices**, and
learning. Nothing else.

**The single most important property of this server:** its output has to be *trustworthy*. Mark makes
real security decisions based on what these tools report. A fabricated result is worse than no result.

---

## 2. Ground rules — no BS, no hallucination (read this twice)

This is the reason this file exists. In a security context a made-up answer isn't a harmless guess — it
can send Mark chasing a vulnerability that doesn't exist, or quietly reassure him about one that does.
So:

- **Never fabricate tool output.** If a tool ran, show its *actual* output and the *exact* command you
  ran. If it didn't run, say so plainly. Do not write a plausible-looking result from memory.

- **A tool that errors is NOT a tool that found nothing.** "nmap reported no open ports" and "nmap
  failed / timed out / isn't installed" are completely different facts. Report which one actually
  happened, with the real error text and exit code.

- **Never invent specifics.** Do not make up IP addresses, MACs, hostnames, service versions, open
  ports, directory paths, usernames, or **CVE IDs**. If you don't have a real result for one of these,
  you don't have it — say "couldn't determine" rather than producing a confident fake.

- **Don't claim a vulnerability without evidence.** "Target is vulnerable to CVE-XXXX-YYYY" needs either
  real tool evidence or a cited, current source — never an assertion from memory. If it's a hypothesis,
  label it as a hypothesis.

- **Separate fact from interpretation.** Be explicit about which lines are raw tool output and which are
  your reading of them. Mark should always be able to tell the two apart.

- **When you don't know, say so.** "I don't know", "I couldn't verify that", and "the tool didn't return
  enough to answer this" are correct, useful answers here. A wrong confident answer is the exact failure
  mode this project is trying to kill.

- **Don't merge old results with new ones.** Each run stands on its own. Don't fold remembered output
  from an earlier scan into a new answer.

- **Don't silently swap tools.** If Mark asks for tool A and you run tool B (because A failed, isn't
  installed, etc.), say so out loud — don't present B's output as if it were A's.

---

## 3. Scope & authorization (a design constraint, not a disclaimer)

This is built into the server by design, so keep it built in:

- Targets are restricted to **private ranges** (192.168.x.x, 10.x.x.x, 172.16–31.x.x) — Mark's own
  network and lab. Note this *permits the entire home network and lab* — every device Mark owns is
  fair game for the full offensive toolset. The only thing it blocks is pointing a tool at something
  that isn't his. That's not a brake on offensive work; it's the "my own devices only" rule written
  in code.
- The server keeps an **audit log** of every command run. Don't add a code path that bypasses it.
- If a task would point a tool at something outside Mark's own authorized scope, stop and flag it rather
  than running it.

---

## 4. Locked decisions

| Decision | Value | Notes |
| --- | --- | --- |
| Base image | `kalilinux/kali-rolling` | Track a known tag; don't switch base distros without updating this file. |
| Server | **Python + FastMCP** | One wrapped function per tool, each with Pydantic-validated inputs. |
| Privilege | **Non-root** (`pentester` user) granted the specific Linux capabilities the offensive tools need — `CAP_NET_RAW` + `CAP_NET_ADMIN` for raw-socket scans (nmap `-sS`, masscan, hping, etc.) | This gives the full offensive toolset its teeth **without** full root. Mark owns this lab: if a specific tool genuinely needs more, grant *that* capability — or run that container as root for that job — as a considered choice. Reach for full root last, not first, because caps already cover the normal kit. |
| Network exposure | Local / loopback only, **never `0.0.0.0` with an open unauthenticated port** | We rejected that design once already, for good reason. |
| Auth | Real authentication required to reach the server | No unauthenticated `/execute`-style endpoints. |
| Input handling | Pydantic validation + command-injection prevention — argument lists, **no** `shell=True` with interpolated user input | |
| Output | Both human-readable **text and structured JSON**; results saved to files | |
| Logging | Audit log on, always | |

If something here is unclear, or you're about to make an architecture/security choice **not** listed
above, stop and ask Mark before writing code.

### Desktop control panel (locked decision, 2026-07-06)

A native **PySide6 (Qt for Python)** desktop app under `desktop/` — the operator-facing GUI for
this server. Locked properties; keep them built in:

- **No network port. Ever.** It is a native window, not a served web app — this preserves the §4
  "local/loopback only, no open port" decision. That is *why* a desktop app was chosen over a web
  UI, not an accident.
- **It never bypasses the gate.** The panel triggers a scan by invoking the SAME audited,
  scope-gated tool wrapper (`kali_mcp.tools.*`, run inside the `kali-mcp` container via `docker
  run`) that the MCP layer uses — never by building its own tool command. The scope gate and the
  audit log apply to a GUI-triggered scan exactly as to an MCP-triggered one. Do not add a code
  path that runs a tool binary directly from the GUI.
- **Display reads produced state only.** The dashboard view reads `build_status()` (persisted
  `state/` + audit log, read-only) — it does NOT scan to fill the screen. "No scan data" stays
  visually distinct from "all clear" (the same §2 honesty the HTML dashboard enforces).
- **Testable core, thin shell.** State-reading, the honest view-model reduction, and the
  scan-runner are plain Python under pytest (injectable process runner — no Docker needed to test);
  the Qt layer is a thin view with no business logic. Framework note: PySide6 is what's installed;
  PyQt5 is a near-drop-in if ever needed.
- **Accessibility carries over** from the HTML dashboard: high contrast, ≥19px, and status is
  never colour alone — every state carries a symbol + text label.

---

## 5. Tools exposed

The authoritative list of tools is **whatever the server actually registers** — check the server code
(or the tool registry / `list_tools`), don't assume from memory. The roster below is the **build
target**: the tools to wrap, not a claim that any of them is already wired up.

> **Base-image reality:** `kalilinux/kali-rolling` is *minimal* — none of these ship in it. Every tool
> here is `apt`-installed in the Dockerfile. If a package fails to install, that must surface as a
> **build error**, never a silently-skipped tool. Heavier installs to budget for: `metasploit-framework`
> (large), and `suricata` / `zeek` / `snort` (rulesets + deps).

### Offensive — the attack chain (recon → scan → exploit → crack)

1. **`nmap`** — port / service / OS discovery; the backbone of recon.
2. **`masscan`** — internet-scale fast port sweeps.
3. **`nikto`** — web-server misconfig & known-vuln scanner.
4. **`nuclei`** — templated vulnerability scanning across a target list.
5. **`gobuster`** — directory / vhost / DNS brute-forcing (alts: `dirb`, `feroxbuster`).
6. **`whatweb`** — web tech / CMS fingerprinting.
7. **`wpscan`** — WordPress enumeration & vuln checks.
8. **`sqlmap`** — automated SQL-injection discovery & exploitation.
9. **`hydra`** — network login brute-forcer (SSH, HTTP, RDP, …).
10. **`john`** (John the Ripper) — offline password-hash cracking.
11. **`hashcat`** — GPU-accelerated cracking *(needs GPU passthrough to the container to be useful)*.
12. **`metasploit-framework`** (`msfconsole`) — exploitation & post-exploitation framework.
13. **`searchsploit`** — offline Exploit-DB lookup.
14. **`enum4linux`** — SMB / Windows enumeration.
15. **`aircrack-ng`** suite — wireless auditing & WPA-handshake cracking *(needs a monitor-mode adapter passed through to the container)*.
16. **`responder`** — LLMNR / NBT-NS / mDNS poisoner + rogue auth server for NetNTLM credential capture; classic internal-AD red-team. *(Session-based — see the wrapping note below.)*
17. **`bettercap`** — MITM / network-attack framework (ARP spoofing, sniffing, credential interception, BLE/Wi-Fi modules). *(Session-based — see the wrapping note below.)*

*Lightweight recon helpers `whois` and `dig` stay in too.*

> **Wrapping `responder` & `bettercap`:** both are *session* tools, not one-shot commands — `responder`
> sits and listens/captures, `bettercap` runs a caplet or interactive session. Wrap each as a
> **bounded-duration run** and return what it actually captured (hashes, intercepted creds, sniffed
> data); don't expose them as a persistent service through the MCP layer. Both need `CAP_NET_RAW` +
> `CAP_NET_ADMIN` (the caps already granted in §4) for their layer-2 work, and both are **loud on the
> wire** — completely fine on your own segment, which is exactly what the §3 scope rule keeps them
> pointed at.

### Defensive — visibility → detection → forensics → hardening

1. **Wireshark → `tshark`** — packet capture & deep protocol analysis. A headless container means you wrap **`tshark`** (Wireshark's CLI sibling); the GUI doesn't fit a request/response tool. **(REQUESTED)**
2. **`tcpdump`** — lightweight CLI packet capture for quick taps.
3. **`arp-scan`** — layer-2 host discovery & asset inventory; surfaces rogue devices and ARP-spoof anomalies on the segment. Dual-use, but a natural fit for your rogue-host / MAC-whitelist hunting. **(REQUESTED)**
4. **`ngrep`** — grep-style pattern matching across live traffic or a pcap.
5. **`suricata`** — network IDS/IPS; signature + protocol-anomaly detection.
6. **`zeek`** — network security monitoring with rich protocol / connection logs.
7. **`snort`** — long-standing signature-based IDS/IPS.
8. **`kismet`** — wireless detector / WIDS; rogue-AP & evil-twin hunting *(needs a monitor-mode adapter)* — right up your street.
9. **`lynis`** — host security auditing & hardening checks.
10. **`chkrootkit`** — rootkit detection.
11. **`rkhunter`** — rootkit / backdoor / local-exploit checks.
12. **`clamav`** — open-source malware / AV scanning.
13. **`aide`** — file-integrity monitoring against a baseline (detect tampering).
14. **`fail2ban`** — log-driven intrusion prevention (auto-ban brute-forcers).
15. **`ss` / `netstat`** — live socket & connection inspection (what's listening, what's connected).

> **Wrapping the heavyweight NIDS:** `suricata`, `zeek`, and `snort` are built to run as long-lived
> daemons, which doesn't map onto a one-shot MCP call. Wrap them in **"analyse a capture"** mode
> (`suricata -r capture.pcap`, `zeek -r capture.pcap`) or a **bounded-duration** live run, and return
> the parsed alerts/logs — don't try to expose them as a persistent service through the MCP layer.

Every tool wrapper must: validate and sanitize inputs, run the real binary via a safe argument list,
capture **both stdout and stderr**, return the real result (text + JSON), and surface a non-zero exit
code as a clear failure — not as an empty "all clear". A tool that isn't installed says so plainly; it
never gets faked.

---

## 6. Coding conventions

- One concern per tool wrapper; keep wrappers small and individually testable.
- Validate every input with Pydantic. Reject out-of-scope targets at the boundary.
- No `shell=True` with interpolated input. Build argument lists explicitly.
- Every wrapper gets a unit test, **including a test for the failure path** (tool missing, bad input,
  timeout). Failure handling is a feature here, not an afterthought.
- Structured logging on every invocation: tool, args, target, exit code, timestamp.
- Small, reviewable commits. One concern per commit.
- Acceptance criteria come from the task Mark gives you, not from a file in this repo. A task isn't
  "done" until those criteria pass and tests are green.

---

## 7. Reality check — what you (Claude Code) cannot verify from code alone

Be explicit with Mark about these. Do **not** claim them as "working" just by reading the code:

1. **Whether a tool actually runs in the container** — only confirmed by executing it inside the built
   image, not by inspecting the wrapper.
2. **Real scan results** (open ports, discovered hosts, findings) — these exist only after the tool runs
   against a live target. Never pre-write them.
3. **Container build success and capabilities/permissions** — confirmed by actually building and
   running, not by reading the Dockerfile.
4. **Network reachability of a target** — confirmed by a real probe, not assumed.
5. **CVE / version claims** — require a current cited source or real tool output, never memory.

When a task touches these, either run it for real and show the actual output, or hand Mark the exact
command to run and tell him plainly what you have and haven't verified.

---

## 8. When a tool breaks (failure protocol)

1. Show the **exact command** you ran.
2. Show the **real error** — stderr and exit code, verbatim. Don't paraphrase it into something tidier
   than it was.
3. State what that error most likely means **as a clearly-labelled hypothesis**, not as established
   fact.
4. Don't silently retry-until-it-looks-fine and hide the earlier failures. If you retried, say what
   changed between attempts.
5. Don't fill the gap with a guess about what the tool "would have" found.
6. If you're unsure how to proceed, ask Mark rather than assuming.

---

## 9. Reference & workflow

Repo files (source of truth over anything remembered): `Dockerfile`, `docker-compose.yml`, the FastMCP
server (`*_mcp_server.py` / `server.py`), `requirements.txt`, `README.md`.

**How work arrives:** Mark drives this one scoped task at a time. Do the task he gives you, make its
acceptance criteria pass, **show the real commands and real output**, then stop and wait for the next
one. If you're unsure what's next, ask — don't invent a roadmap.
