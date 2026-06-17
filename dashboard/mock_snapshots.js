/*
 * mock_snapshots.js — fixture network_status payloads for the dashboard SHELL (Task 4.2).
 *
 * These mirror the REAL shape produced by kali_mcp/status.py:build_status (Task 4.1,
 * commit b9dfc0f) EXACTLY, so the UI is built against the true data contract and 4.3 can
 * swap these mocks for the live tool output with no render changes.
 *
 * Contract reminder (the parts the UI keys on):
 *   network.summary  = COUNTS only {known, rogue, ip_mismatch, absent}
 *   network.rogues   = the one DETAILED list [{ip, mac, vendor}, ...]  (or null when no data)
 *   network.available / network.all_clear distinguish clean vs no-data vs review
 *   whitelist.loaded=false + whitelist.error  = the "broken" state (NOT 0 devices)
 *   audit.available=false  = no log yet (NOT empty-but-clean tallies)
 *
 * Four fixtures cover every honest state the dashboard must show distinctly (CLAUDE.md §2):
 *   rogues_present  — the loud alert path + every status colour
 *   all_clear       — the EARNED green state
 *   no_data         — network + audit unavailable (must NOT look like a pass)
 *   whitelist_broken— a distinct error state (not green, not a rogue count)
 */

// A representative tools roster (subset of the real 36-tool roster) with realistic
// install flags. tool_counts is kept consistent with this list so the mock is honest.
const MOCK_TOOLS = [
  { name: "nmap", category: "recon", purpose: "Network/port scanner with service & version detection", installed: true },
  { name: "masscan", category: "recon", purpose: "High-speed asynchronous mass port scanner", installed: true },
  { name: "arp-scan", category: "recon", purpose: "Layer-2 host discovery & asset inventory", installed: true },
  { name: "nikto", category: "web", purpose: "Web-server misconfig & known-vuln scanner", installed: true },
  { name: "nuclei", category: "web", purpose: "Template-based vulnerability scanner", installed: true },
  { name: "gobuster", category: "web", purpose: "Directory, DNS and vhost brute-forcer", installed: true },
  { name: "whatweb", category: "web", purpose: "Web technology / CMS fingerprinter", installed: true },
  { name: "sqlmap", category: "web", purpose: "Automatic SQL-injection detection and exploitation", installed: true },
  { name: "hydra", category: "auth", purpose: "Network login brute-forcer (SSH, HTTP, RDP, ...)", installed: true },
  { name: "john", category: "crack", purpose: "John the Ripper — offline password-hash cracking", installed: true },
  { name: "msfconsole", category: "exploit", purpose: "Metasploit Framework — exploitation & post-exploitation", installed: true },
  { name: "enum4linux", category: "smb", purpose: "SMB / Windows share and user enumeration", installed: true },
  { name: "tshark", category: "capture", purpose: "Terminal packet capture and protocol analysis", installed: true },
  { name: "tcpdump", category: "capture", purpose: "Lightweight CLI packet capture for quick taps", installed: true },
  { name: "suricata", category: "ids", purpose: "Network IDS/IPS; signature + protocol-anomaly detection", installed: false },
  { name: "zeek", category: "ids", purpose: "Network security monitoring with protocol/connection logs", installed: false },
  { name: "snort", category: "ids", purpose: "Signature-based network IDS/IPS", installed: false },
  { name: "lynis", category: "audit", purpose: "Host security auditing & hardening checks", installed: false },
  { name: "chkrootkit", category: "forensics", purpose: "Rootkit detection", installed: false },
  { name: "clamscan", category: "forensics", purpose: "ClamAV malware / AV scanner", installed: false },
];

const INSTALLED_COUNT = MOCK_TOOLS.filter((t) => t.installed).length;
const TOOL_COUNTS = { registered: MOCK_TOOLS.length, installed: INSTALLED_COUNT };

// ---------------------------------------------------------------------------
// 1) rogues_present — the headline alert path: KNOWN + 2 ROGUE + IP_MISMATCH + ABSENT.
// ---------------------------------------------------------------------------
const rogues_present = {
  generated_at: "2026-06-17T18:42:11.331204+00:00",
  tools: MOCK_TOOLS,
  tool_counts: TOOL_COUNTS,
  audit: {
    available: true,
    total_entries: 12,
    recent: [
      { timestamp: "2026-06-17T18:30:02+00:00", tool: "arp-scan", target: "wlan0:localnet", status: "ok", exit_code: 0, duration_s: 2.01 },
      { timestamp: "2026-06-17T18:28:44+00:00", tool: "nmap", target: "192.168.51.66", status: "ok", exit_code: 0, duration_s: 5.42 },
      { timestamp: "2026-06-17T18:25:10+00:00", tool: "nmap", target: "192.168.51.91", status: "nonzero_exit", exit_code: 1, duration_s: 0.31 },
      { timestamp: "2026-06-17T18:20:55+00:00", tool: "masscan", target: "192.168.51.0/24", status: "timeout", exit_code: null, duration_s: 30.0 },
      { timestamp: "2026-06-17T18:15:09+00:00", tool: "wpscan", target: "192.168.51.10", status: "not_found", exit_code: null, duration_s: 0.002 },
    ],
    by_status: { ok: 8, nonzero_exit: 2, timeout: 1, not_found: 1 },
  },
  network: {
    available: true,
    as_of: "2026-06-17T18:30:04.118233+00:00",
    summary: { known: 4, rogue: 2, ip_mismatch: 1, absent: 1 },
    rogues: [
      { ip: "192.168.51.66", mac: "de:ad:be:ef:13:37", vendor: "Espressif Inc." },
      { ip: "192.168.51.91", mac: "ca:fe:00:00:00:01", vendor: "(unknown)" },
    ],
    note: "⚠ 2 ROGUE device(s) on the segment — not in the whitelist; also 1 known device(s) on an unexpected IP",
    all_clear: false,
  },
  whitelist: { loaded: true, device_count: 6, error: null },
};

// ---------------------------------------------------------------------------
// 2) all_clear — every discovered host KNOWN, 0 rogues: the EARNED green state.
// ---------------------------------------------------------------------------
const all_clear = {
  generated_at: "2026-06-17T18:45:00.002001+00:00",
  tools: MOCK_TOOLS,
  tool_counts: TOOL_COUNTS,
  audit: {
    available: true,
    total_entries: 5,
    recent: [
      { timestamp: "2026-06-17T18:44:50+00:00", tool: "arp-scan", target: "wlan0:localnet", status: "ok", exit_code: 0, duration_s: 1.98 },
      { timestamp: "2026-06-17T18:40:12+00:00", tool: "nmap", target: "192.168.51.1", status: "ok", exit_code: 0, duration_s: 3.10 },
    ],
    by_status: { ok: 5, nonzero_exit: 0, timeout: 0, not_found: 0 },
  },
  network: {
    available: true,
    as_of: "2026-06-17T18:44:52.665417+00:00",
    summary: { known: 5, rogue: 0, ip_mismatch: 0, absent: 1 },
    rogues: [],
    note: "all clear — every one of the 5 discovered device(s) matched the whitelist (5 known, 1 whitelisted device(s) not seen)",
    all_clear: true,
  },
  whitelist: { loaded: true, device_count: 6, error: null },
};

// ---------------------------------------------------------------------------
// 3) no_data — network NOT available (no scan yet) + audit NOT available.
//    The §2-in-UI proof: this must render DISTINCTLY from all_clear, never a pass.
// ---------------------------------------------------------------------------
const no_data = {
  generated_at: "2026-06-17T18:50:30.900100+00:00",
  tools: MOCK_TOOLS,
  tool_counts: TOOL_COUNTS,
  audit: {
    available: false,
    total_entries: 0,
    recent: [],
    by_status: { ok: 0, nonzero_exit: 0, timeout: 0, not_found: 0 },
    note: "no audit log at './logs/audit.jsonl' yet — it is created the first time a tool runs. This is 'no data', not '0 commands run clean'.",
  },
  network: {
    available: false,
    as_of: null,
    summary: null,
    rogues: null,
    note: "no rogue-host scan has been persisted yet — run arp_watch to populate this. This is 'no data', NOT an all-clear.",
  },
  whitelist: { loaded: true, device_count: 6, error: null },
};

// ---------------------------------------------------------------------------
// 4) whitelist_broken — whitelist failed to load: a distinct error state.
//    arp_watch refuses without a trustworthy whitelist, so network is unavailable too.
// ---------------------------------------------------------------------------
const whitelist_broken = {
  generated_at: "2026-06-17T18:55:01.440000+00:00",
  tools: MOCK_TOOLS,
  tool_counts: TOOL_COUNTS,
  audit: {
    available: true,
    total_entries: 3,
    recent: [
      { timestamp: "2026-06-17T18:54:00+00:00", tool: "nmap", target: "192.168.51.1", status: "ok", exit_code: 0, duration_s: 2.7 },
    ],
    by_status: { ok: 3, nonzero_exit: 0, timeout: 0, not_found: 0 },
  },
  network: {
    available: false,
    as_of: null,
    summary: null,
    rogues: null,
    note: "no rogue-host scan has been persisted yet — run arp_watch to populate this. This is 'no data', NOT an all-clear.",
  },
  whitelist: {
    loaded: false,
    device_count: null,
    error: "WhitelistValidationError: device #2 (ac:9e:17:aa:bb:cc): duplicate MAC ac:9e:17:aa:bb:cc in whitelist (entries 1 and #2): an ambiguous whitelist can't be a source of truth.",
  },
};

// Exposed as a global map so template.html can pick one via ?mock=<key>.
window.MOCK_SNAPSHOTS = {
  rogues_present,
  all_clear,
  no_data,
  whitelist_broken,
};
