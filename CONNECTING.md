# Connecting an MCP client to the Kali MCP Server

This server speaks MCP over the **stdio** of its Docker container (CLAUDE.md §4 —
stdio transport, no network port is ever opened). An MCP client (Claude Desktop or
Claude Code) connects by *launching a command* and talking JSON-RPC over that
command's stdin/stdout. So the command you give the client is the full
`docker run -i ... python server.py` invocation.

There is no separate "start the server" step: the client starts a fresh container
per session and stops it on exit (`--rm`).

Example config to copy from: [`mcp-client-config.example.json`](./mcp-client-config.example.json).

---

## 0. Pick a mode: bridge vs real-LAN

Same image, same caps, same stdio — the only difference is the container's network
stack (full reasoning in [`NETWORKING.md`](./NETWORKING.md)).

| Entry | Network | Use it for |
|-------|---------|-----------|
| `kali-mcp` | bridge (default, isolated) | loopback / self-tests. **Default — start here.** On bridge, host-discovery to LAN hosts is filtered, so your own router reads "down". |
| `kali-mcp-lan` | `--network host` (opt-in) | **real network scans** — nmap/masscan/arp-scan against your actual LAN devices. Removes the bridge isolation layer, so it is a deliberate opt-in. |

Both gate every target to private ranges via `scope.py` (CLAUDE.md §3) — host mode
gives more network *reach*, never a weaker *gate*. Add only the entry you need.

---

## 1. Build the image

```sh
cd ~/building-mcps
docker compose build          # tags kali-mcp:phase1
# or: docker build -t kali-mcp:phase1 .
```

Confirm it exists:

```sh
docker images | grep kali-mcp
# kali-mcp   phase1   ...
```

The client config references `kali-mcp:phase1` by tag, so the image must be built
**before** the client tries to launch it.

---

## 2. Copy the config into your client

> The example file has **two** entries (`kali-mcp` and `kali-mcp-lan`). If you
> already have other MCP servers configured, **merge** these into your existing
> `mcpServers` object — don't overwrite the whole file.

### Claude Desktop (Linux)

Config path: `~/.config/Claude/claude_desktop_config.json`

Add the entry/entries under `mcpServers`, e.g.:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
               "kali-mcp:phase1", "python", "server.py"]
    }
  }
}
```

(macOS path, for reference:
`~/Library/Application Support/Claude/claude_desktop_config.json`.)

### Claude Code (CLI)

Either run the helper (adds it to `~/.claude.json` for the current scope):

```sh
# bridge (default)
claude mcp add-json kali-mcp '{"command":"docker","args":["run","-i","--rm","--cap-add","NET_RAW","--cap-add","NET_ADMIN","kali-mcp:phase1","python","server.py"]}'

# real-LAN (opt-in)
claude mcp add-json kali-mcp-lan '{"command":"docker","args":["run","-i","--rm","--network","host","--cap-add","NET_RAW","--cap-add","NET_ADMIN","kali-mcp:phase1","python","server.py"]}'
```

…or hand-edit the `mcpServers` block of `~/.claude.json` (or a project-scoped
`.mcp.json`) with the same shape as the Desktop example above.

---

## 3. Restart the client

- **Claude Desktop:** fully quit and reopen (a window reload is not enough — it
  re-reads `claude_desktop_config.json` only on a cold start).
- **Claude Code:** start a new session, or `claude mcp list` to force a re-read.

---

## 4. Confirm the tools appear

- **Claude Desktop:** the tools show under the 🔌 / tools menu. You should see
  `list_tools`, `nmap_scan`, `masscan_scan`, `tshark_capture`, `arp_scan`, `arp_watch`.
- **Claude Code:** `claude mcp list` should show `kali-mcp` as connected; in-session,
  ask it to run `list_tools`.

Quick non-client smoke test (the same path a client uses, driven by hand):

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  | docker run -i --rm kali-mcp:phase1 python server.py 2>/dev/null | head -1
```

The first line on **stdout** must be a JSON-RPC `initialize` result. The FastMCP
startup banner and logs go to **stderr** (`2>/dev/null` above hides them), so the
stdio JSON-RPC stream stays clean — this is required for MCP stdio to work and was
verified for this image (FastMCP 3.4.2 routes the banner/logs to stderr on its own;
no code change was needed).

---

## Notes

- **stdin must stay open** (`-i`): MCP is a back-and-forth over stdin/stdout. Without
  `-i` the container gets EOF immediately and exits.
- **No secrets** are needed; the example file stays `.example` only so you copy it to
  the client's own location.
- **Logs:** the audit log (CLAUDE.md §3) is written inside the container; it does not
  pollute the stdio protocol stream.
