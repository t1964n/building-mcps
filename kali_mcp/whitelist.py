"""The device-whitelist store: loader + strict validation + types.

This is the source-of-truth loader for "devices Mark knows about" (CLAUDE.md §5
rogue-host hunting). Task 3.3 will diff a live arp-scan against the list this
returns and flag anything absent as a possible rogue — so the ONE behaviour that
matters most here is honesty under failure (CLAUDE.md §2):

  A malformed whitelist MUST fail loudly. It must NEVER silently load a partial or
  empty list, because in 3.3 an empty/partial whitelist makes every real device
  look like a rogue (or hides a real one). "I couldn't load the whitelist" is a
  correct, useful answer; a quietly-truncated list is the exact failure this
  project exists to kill.

Pure-ish: reads ONE file, returns typed objects. No scanning, no network, no
logging, no side effects beyond the read. Validation problems are explicit
exceptions with messages that say which entry and why.

`normalize_mac` is the SINGLE SOURCE OF TRUTH for MAC canonical form. Task 3.3
imports it too and normalises arp-scan output MACs the same way, so comparison is
apples-to-apples (aa:bb:cc:dd:ee:ff on both sides).
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

import yaml

# Path resolution order: explicit arg -> env -> default in CWD.
ENV_WHITELIST_PATH = "KALI_MCP_WHITELIST"
DEFAULT_WHITELIST_PATH = "whitelist.yaml"

# Strip these separators before validating the 12 hex nibbles of a MAC.
_MAC_SEPARATORS = re.compile(r"[\s:.\-]")
_TWELVE_HEX = re.compile(r"\A[0-9a-f]{12}\Z")


class WhitelistError(Exception):
    """Base class for every whitelist load/validation failure."""


class WhitelistNotFoundError(WhitelistError):
    """The whitelist file does not exist at the resolved path.

    Deliberately DISTINCT from a validation error and from an empty list: "no file"
    and "file present but bad" and "file present and empty" are different facts, and
    3.3 must be able to tell them apart (CLAUDE.md §2).
    """


class WhitelistValidationError(WhitelistError):
    """The file exists but its content is not a valid whitelist."""


@dataclass(frozen=True)
class KnownDevice:
    """One known device. `mac` is ALWAYS the normalised canonical form
    (lowercase, colon-separated) — never the raw input string."""

    mac: str
    name: str
    ip: str | None
    note: str | None


def normalize_mac(raw: str) -> str:
    """Canonicalise any common MAC form to lowercase colon-separated.

    Accepts colon (AA:BB:CC:DD:EE:FF), hyphen (AA-BB-CC-DD-EE-FF), Cisco dot
    (AABB.CCDD.EEFF), bare 12-hex, and any case; returns 'aa:bb:cc:dd:ee:ff'.
    Raises WhitelistValidationError on anything that is not exactly 12 hex nibbles.

    Single source of truth for MAC form — 3.3 normalises arp-scan MACs through here
    too, so both sides of the diff use one canonical string.
    """
    if not isinstance(raw, str):
        raise WhitelistValidationError(
            f"MAC must be a string, got {type(raw).__name__}: {raw!r}"
        )
    stripped = _MAC_SEPARATORS.sub("", raw).lower()
    if not _TWELVE_HEX.match(stripped):
        raise WhitelistValidationError(
            f"invalid MAC address {raw!r}: expected 12 hex digits "
            "(e.g. aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF or AABB.CCDD.EEFF)"
        )
    return ":".join(stripped[i : i + 2] for i in range(0, 12, 2))


def _validate_ip(raw: object, *, device_label: str) -> str:
    """Validate an optional IP value and return it as a string. Raises on garbage."""
    if not isinstance(raw, str) or not raw.strip():
        raise WhitelistValidationError(
            f"device {device_label}: ip must be a non-empty string if present, "
            f"got {raw!r}"
        )
    try:
        ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise WhitelistValidationError(
            f"device {device_label}: invalid ip {raw!r} ({exc})"
        ) from exc
    return raw.strip()


def _resolve_path(path: str | None) -> str:
    """arg -> env KALI_MCP_WHITELIST -> ./whitelist.yaml."""
    if path is not None:
        return path
    return os.environ.get(ENV_WHITELIST_PATH, DEFAULT_WHITELIST_PATH)


def load_whitelist(path: str | None = None) -> list[KnownDevice]:
    """Load, parse and STRICTLY validate the whitelist into KnownDevice objects.

    Any problem raises a WhitelistError subclass with a useful message; this function
    never returns a partial/empty list to paper over a bad file (CLAUDE.md §2).
    """
    resolved = _resolve_path(path)

    if not os.path.isfile(resolved):
        raise WhitelistNotFoundError(
            f"whitelist file not found: {resolved!r}. "
            "Copy whitelist.example.yaml to whitelist.yaml (or set "
            f"{ENV_WHITELIST_PATH}) and list your known devices. "
            "Refusing to continue with no whitelist — that would flag every device "
            "as a rogue."
        )

    with open(resolved, encoding="utf-8") as fh:
        try:
            doc = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise WhitelistValidationError(
                f"whitelist {resolved!r} is not valid YAML: {exc}"
            ) from exc

    if doc is None:
        raise WhitelistValidationError(
            f"whitelist {resolved!r} is empty. Expected a top-level 'devices:' list "
            "with at least one entry."
        )
    if not isinstance(doc, dict) or "devices" not in doc:
        raise WhitelistValidationError(
            f"whitelist {resolved!r} must be a mapping with a top-level 'devices:' "
            f"list (got {type(doc).__name__})."
        )

    devices_raw = doc["devices"]
    if not isinstance(devices_raw, list) or not devices_raw:
        raise WhitelistValidationError(
            f"whitelist {resolved!r}: 'devices' must be a non-empty list "
            f"(got {type(devices_raw).__name__})."
        )

    devices: list[KnownDevice] = []
    seen_macs: dict[str, int] = {}

    for index, entry in enumerate(devices_raw):
        label = f"#{index + 1}"
        if not isinstance(entry, dict):
            raise WhitelistValidationError(
                f"device {label}: each entry must be a mapping with at least "
                f"'mac' and 'name' (got {type(entry).__name__})."
            )

        if "mac" not in entry or entry["mac"] is None:
            raise WhitelistValidationError(f"device {label}: missing required 'mac'.")
        mac = normalize_mac(entry["mac"])
        # Re-label using the canonical MAC now that we have it — better error text.
        label = f"#{index + 1} ({mac})"

        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise WhitelistValidationError(
                f"device {label}: missing required non-empty 'name'."
            )

        ip = None
        if entry.get("ip") is not None:
            ip = _validate_ip(entry["ip"], device_label=label)

        note = entry.get("note")
        if note is not None and not isinstance(note, str):
            raise WhitelistValidationError(
                f"device {label}: 'note' must be a string if present, "
                f"got {type(note).__name__}."
            )

        if mac in seen_macs:
            raise WhitelistValidationError(
                f"duplicate MAC {mac} in whitelist (entries {seen_macs[mac]} and "
                f"{label}): an ambiguous whitelist can't be a source of truth."
            )
        seen_macs[mac] = index + 1

        devices.append(
            KnownDevice(mac=mac, name=name.strip(), ip=ip, note=note)
        )

    return devices
