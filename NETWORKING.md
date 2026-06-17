# Networking modes — bridge (default) vs real-LAN (opt-in)

The Kali MCP Server runs in one of two network modes. Both use the **same image**, the
same §4 cap_adds (`NET_RAW`/`NET_ADMIN`), and the same §2.1 file-caps baked into the
image. The only difference is the container's network stack.

## Mode 1 — bridge (DEFAULT, isolated)

```sh
docker compose run --rm kali-mcp
```

The container sits on Docker's bridge network, one isolation layer away from the host
LAN. This is the **safe default**.

**Known limitation (Phase 1, reconfirmed in Task 2.2):** on bridge, nmap's
host-discovery probes to a LAN host are filtered, so your own router reads **"down"** and
never gets scanned. Bridge mode is for loopback / self-tests, not for surveying the real
LAN. Verified on-device:

```
# bridge: ping-scan of the router
target    : 192.168.51.1
scan_type : ping
status    : ok
summary   : host down / no response — 0 host(s) up of 0 in output
```

## Mode 2 — real-LAN (OPT-IN, host networking)

```sh
docker compose --profile lan run --rm kali-mcp-lan
```

The `kali-mcp-lan` service uses `network_mode: host`, so the container shares the host's
network stack and sees the real LAN exactly as the host does — your own devices become
scannable. It is gated behind the `lan` compose profile, so a plain
`docker compose up`/`run` **never** puts the container on the host network by accident.
Verified on-device — the *same* scan that read "down" on bridge:

```
# real-LAN: ping-scan of the router
target    : 192.168.51.1
scan_type : ping
status    : ok
summary   : 1 host(s) up, 0 open port(s)
host      : 192.168.51.1 state=up
```

Host mode **alone** fixed host-discovery — no `-Pn`/no-ping option was needed (the
container is now on the host's L2 segment, so normal ARP/ping discovery works). If a
`-Pn` scan_type is ever wanted for genuinely ping-suppressing hosts, that's a separate
task (a `scan_type` allow-list change), not part of this one.

## Why opt-in real-LAN is an acceptable tradeoff *here*

Host networking removes the bridge isolation layer, so it is deliberately **not** the
default. It's acceptable for this project specifically because:

1. **The control channel doesn't need it.** The MCP client talks to the server over
   **stdio**, not a network port, so host networking is needed only for the *scan
   traffic* — never for reaching the server.
2. **Scope still gates every target.** §3 enforcement (`scope.py`) restricts every target
   to private ranges in **both** modes. "Sees the LAN" never becomes "can hit the internet
   unchecked." Verified under the real-LAN profile:
   ```
   target    : 8.8.8.8
   status    : scope_denied
   allowed   : False
   command   : None        # nmap never ran
   reason    : public/global (8.8.8.8) — outside your private scope, denied
   ```
   Host mode gives more network **reach**, not a weaker **gate**.
3. **You run it deliberately, on your own lab.** This is a single-operator tool pointed at
   your own network (§3).

## Honest notes

- **Published ports are ignored in host mode.** Under `network_mode: host`, Docker does
  not map ports — the container binds host ports directly. We publish none, so nothing
  changes for us, but it's called out so it isn't surprising. `cap_add` is orthogonal to
  the network namespace and still applies in host mode.
- **macvlan was considered and rejected for now.** Host networking is simpler and
  sufficient for a single-operator lab. Revisit macvlan only if the container needs its
  own distinct LAN IP without inheriting the host's full stack.
- **"Host up, 0 open ports" is a real result, not a failure.** In testing, the router
  showed up via discovery but returned no open ports on the probed set (its management
  UI is restricted / on a non-standard port, and a VPN was active on the host). Per §2
  that's reported as-is — no ports are fabricated.
```
