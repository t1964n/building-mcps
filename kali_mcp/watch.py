"""The rogue-host diff — arp-scan's live hosts ⨯ the device whitelist (Phase 3, 3.3).

This is the headline Phase-3 feature: it takes what arp-scan ACTUALLY saw on the
segment and compares it, MAC by MAC, against the known-device whitelist from 3.2,
classifying every host into exactly one bucket and reporting what's missing.

This module is a PURE FUNCTION. It does NO scanning, NO network, NO I/O, NO logging
— it takes already-discovered hosts + an already-loaded whitelist and returns a
verdict. The scanning and whitelist-loading (and their honest failure handling) live
in tools/arpwatch.py; keeping the diff pure makes it trivially testable offline and
keeps the one risky thing — the comparison an alert is built on — small and auditable.

Because this is a SECURITY-ALERTING surface, CLAUDE.md §2 cuts both ways here and the
guards below are not optional:

  * A FABRICATED ROGUE is a failure. A case/format difference between the whitelist
    (AA-BB-CC-...) and arp-scan's output (aa:bb:cc:...) must NEVER turn a known device
    into a false alarm. So BOTH sides are run through normalize_mac — the single
    source of truth from 3.2 — before any comparison. This is the single most
    important guard in this file.

  * A FALSE "ALL CLEAR" is equally a failure. rogues == [] is only an EARNED all-clear
    when devices were actually discovered AND every one of them matched. A scan that
    saw NOTHING is not "all clear" — discovered_count carries that fact so the caller
    can never mistake "found nothing" for "found nothing wrong".

  * Hypotheses stay labelled as hypotheses (§2). A known MAC on an unexpected IP and a
    whitelisted device that didn't answer are reported NEUTRALLY (IP_MISMATCH / ABSENT)
    — they can be benign (DHCP, a powered-off device) or could be spoofing; this module
    states the fact and does NOT declare malice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .whitelist import KnownDevice, normalize_mac


@dataclass(frozen=True)
class WatchResult:
    """The classified diff. Four mutually-exclusive-by-construction buckets plus the
    count of hosts actually discovered, so a true empty-rogues (earned all-clear) is
    always distinguishable from a scan that simply saw nothing.

    Every entry is a plain dict so the MCP layer can serialise it as-is:
      known         {ip, mac, vendor, name}            — matched the whitelist
      rogues        {ip, mac, vendor}                  — NOT in the whitelist (headline)
      ip_mismatches {mac, name, vendor, discovered_ip, expected_ip}
      absent        {mac, name, expected_ip}           — whitelisted, didn't answer
    """

    known: list[dict] = field(default_factory=list)
    rogues: list[dict] = field(default_factory=list)
    ip_mismatches: list[dict] = field(default_factory=list)
    absent: list[dict] = field(default_factory=list)
    discovered_count: int = 0

    @property
    def rogue_count(self) -> int:
        return len(self.rogues)

    @property
    def known_count(self) -> int:
        return len(self.known)

    @property
    def ip_mismatch_count(self) -> int:
        return len(self.ip_mismatches)

    @property
    def absent_count(self) -> int:
        return len(self.absent)

    @property
    def all_clear(self) -> bool:
        """True ONLY when this is an EARNED all-clear: at least one device was
        discovered AND every discovered device fully matched the whitelist (no rogues,
        no IP mismatches). An empty scan (discovered_count == 0) is NOT all-clear —
        there was nothing to clear. Absent devices don't break all-clear: a known
        device being off/asleep is the normal, neutral case, not an alert."""
        return (
            self.discovered_count > 0
            and not self.rogues
            and not self.ip_mismatches
        )

    def summary(self) -> str:
        """A one-line, honest verdict — never a default 'all clear'."""
        if self.discovered_count == 0:
            return (
                "no hosts were discovered to diff — NOT an all-clear; there was "
                "nothing on the segment to compare against the whitelist"
            )
        if self.rogues:
            line = f"⚠ {self.rogue_count} ROGUE device(s) on the segment — not in the whitelist"
            if self.ip_mismatches:
                line += f"; also {self.ip_mismatch_count} known device(s) on an unexpected IP"
            return line
        if self.ip_mismatches:
            return (
                f"0 rogues, but {self.ip_mismatch_count} known device(s) answered on an "
                "unexpected IP — reported neutrally (DHCP churn or possible spoofing; "
                "not asserted)"
            )
        return (
            f"all clear — every one of the {self.discovered_count} discovered device(s) "
            f"matched the whitelist ({self.known_count} known"
            + (f", {self.absent_count} whitelisted device(s) not seen" if self.absent else "")
            + ")"
        )

    def to_dict(self) -> dict:
        """Flatten to a JSON-ready dict with ROGUES and the count up top (the headline),
        the neutral buckets below, and the earned-or-not all_clear made explicit."""
        return {
            "rogue_count": self.rogue_count,
            "rogues": self.rogues,
            "all_clear": self.all_clear,
            "verdict": self.summary(),
            "discovered_count": self.discovered_count,
            "known_count": self.known_count,
            "known": self.known,
            "ip_mismatch_count": self.ip_mismatch_count,
            "ip_mismatches": self.ip_mismatches,
            "absent_count": self.absent_count,
            "absent": self.absent,
        }


def diff_against_whitelist(
    discovered: list[dict], known: list[KnownDevice]
) -> WatchResult:
    """Classify every discovered host against the whitelist; compute absences.

    `discovered` is arp-scan's parsed hosts: [{ip, mac, vendor}, ...].
    `known` is the loaded whitelist (KnownDevice objects from 3.2).

    BOTH sides' MACs are run through normalize_mac before comparison so the match is
    apples-to-apples regardless of case/separator — the guard that stops a known
    device from being mis-flagged as a rogue (CLAUDE.md §2). The whitelist loader
    already normalises, but we normalise the known side here too so this function is
    correct even if a KnownDevice were constructed by hand with a raw MAC.

    Buckets (each discovered host lands in exactly one):
      KNOWN        MAC in whitelist AND (no expected IP, or the IP matches)
      ROGUE        MAC not in the whitelist                       — the headline alert
      IP_MISMATCH  MAC in whitelist but on a different IP than expected (neutral)
    Plus ABSENT: whitelisted devices whose MAC didn't appear in this scan (neutral).
    """
    # Normalise the known side once; last-wins is irrelevant because load_whitelist
    # already rejects duplicate MACs, but a hand-built list with dupes won't crash.
    known_by_mac: dict[str, KnownDevice] = {
        normalize_mac(dev.mac): dev for dev in known
    }

    known_hits: list[dict] = []
    rogues: list[dict] = []
    ip_mismatches: list[dict] = []
    seen_macs: set[str] = set()

    for host in discovered:
        # normalize_mac on the discovered side too — the same canonicaliser, always.
        mac = normalize_mac(host["mac"])
        ip = host.get("ip")
        vendor = host.get("vendor")
        seen_macs.add(mac)

        dev = known_by_mac.get(mac)
        if dev is None:
            # Unlisted MAC -> rogue. Carry ip/mac/vendor so Mark can hunt it.
            rogues.append({"ip": ip, "mac": mac, "vendor": vendor})
        elif dev.ip is not None and ip is not None and dev.ip != ip:
            # Known device, but not where the whitelist expects it. State the fact;
            # do NOT call it spoofing — it could just as well be DHCP reassignment.
            ip_mismatches.append(
                {
                    "mac": mac,
                    "name": dev.name,
                    "vendor": vendor,
                    "discovered_ip": ip,
                    "expected_ip": dev.ip,
                }
            )
        else:
            known_hits.append(
                {"ip": ip, "mac": mac, "vendor": vendor, "name": dev.name}
            )

    # ABSENT: whitelisted devices that didn't answer this scan. Neutral — off/asleep,
    # or spoofed-away; reported as a plain fact, not an accusation.
    absent = [
        {"mac": mac, "name": dev.name, "expected_ip": dev.ip}
        for mac, dev in known_by_mac.items()
        if mac not in seen_macs
    ]

    return WatchResult(
        known=known_hits,
        rogues=rogues,
        ip_mismatches=ip_mismatches,
        absent=absent,
        discovered_count=len(discovered),
    )
