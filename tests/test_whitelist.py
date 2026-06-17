"""Tests for the device-whitelist loader (Phase 3, Task 3.2).

Offline only: every test writes a fixture file to a tmp_path or calls normalize_mac
directly. No network, no scanning. The emphasis (CLAUDE.md §2) is the failure paths:
a malformed whitelist must raise, never quietly return a partial/empty list.
"""

from __future__ import annotations

import textwrap

import pytest

from kali_mcp.whitelist import (
    KnownDevice,
    WhitelistError,
    WhitelistNotFoundError,
    WhitelistValidationError,
    load_whitelist,
    normalize_mac,
)


def _write(tmp_path, content: str):
    path = tmp_path / "whitelist.yaml"
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_valid_load_returns_three_normalised_devices(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "AA:BB:CC:DD:EE:01"
            name: "Router"
            ip: "192.168.1.1"
            note: "gateway"
          - mac: "AA-BB-CC-DD-EE-02"
            name: "Phone"
          - mac: "AABB.CCDD.EE03"
            name: "Laptop"
            ip: "10.0.0.5"
        """,
    )
    devices = load_whitelist(path)

    assert len(devices) == 3
    assert all(isinstance(d, KnownDevice) for d in devices)
    # MACs normalised to lowercase-colon regardless of input form.
    assert [d.mac for d in devices] == [
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
        "aa:bb:cc:dd:ee:03",
    ]
    assert devices[0] == KnownDevice(
        mac="aa:bb:cc:dd:ee:01", name="Router", ip="192.168.1.1", note="gateway"
    )
    # Optional fields default to None.
    assert devices[1].ip is None and devices[1].note is None


def test_committed_example_file_loads():
    """The committed example must itself be a valid, loadable whitelist."""
    devices = load_whitelist("whitelist.example.yaml")
    assert len(devices) >= 3
    assert all(d.mac == d.mac.lower() for d in devices)
    # The hyphen/dot placeholder entries normalised to colon form.
    macs = {d.mac for d in devices}
    assert "aa:bb:cc:00:00:02" in macs
    assert "aa:bb:cc:00:00:03" in macs


# --------------------------------------------------------------------------- #
# MAC normalisation
# --------------------------------------------------------------------------- #


def test_equivalent_macs_across_forms_normalise_identically(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "AA-BB-CC-DD-EE-FF"
            name: "hyphen form"
        """,
    )
    (device,) = load_whitelist(path)
    assert device.mac == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "raw",
    [
        "AA:BB:CC:DD:EE:FF",
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "AABB.CCDD.EEFF",
        "aabbccddeeff",
        "AABBCCDDEEFF",
    ],
)
def test_normalize_mac_canonical_form(raw):
    assert normalize_mac(raw) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-mac",
        "GG:HH:II:JJ:KK:LL",  # non-hex
        "AA:BB:CC:DD:EE",  # too short
        "AA:BB:CC:DD:EE:FF:00",  # too long
        "",
    ],
)
def test_normalize_mac_rejects_garbage(bad):
    with pytest.raises(WhitelistValidationError):
        normalize_mac(bad)


def test_normalize_mac_rejects_non_string():
    with pytest.raises(WhitelistValidationError):
        normalize_mac(123456789012)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Validation failures — must raise LOUDLY, never return a partial list
# --------------------------------------------------------------------------- #


def test_invalid_mac_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "not-a-mac"
            name: "Bad"
        """,
    )
    with pytest.raises(WhitelistValidationError, match="invalid MAC"):
        load_whitelist(path)


def test_duplicate_mac_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "AA:BB:CC:00:00:01"
            name: "First"
          - mac: "aa-bb-cc-00-00-01"
            name: "Same MAC different form"
        """,
    )
    with pytest.raises(WhitelistValidationError, match="duplicate MAC"):
        load_whitelist(path)


def test_missing_name_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "AA:BB:CC:00:00:01"
        """,
    )
    with pytest.raises(WhitelistValidationError, match="name"):
        load_whitelist(path)


def test_missing_mac_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - name: "No MAC"
        """,
    )
    with pytest.raises(WhitelistValidationError, match="mac"):
        load_whitelist(path)


def test_bad_ip_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "AA:BB:CC:00:00:01"
            name: "Bad IP"
            ip: "999.1.1.1"
        """,
    )
    with pytest.raises(WhitelistValidationError, match="invalid ip"):
        load_whitelist(path)


# --------------------------------------------------------------------------- #
# File-level failures
# --------------------------------------------------------------------------- #


def test_missing_file_raises_distinct_error(tmp_path):
    missing = str(tmp_path / "does-not-exist.yaml")
    with pytest.raises(WhitelistNotFoundError):
        load_whitelist(missing)


def test_missing_file_is_not_an_empty_list(tmp_path):
    """Regression guard for the §2 failure mode: 'no file' must NOT be 'empty list'."""
    missing = str(tmp_path / "nope.yaml")
    try:
        load_whitelist(missing)
    except WhitelistNotFoundError:
        pass
    else:
        pytest.fail("missing file silently returned instead of raising")


def test_empty_file_raises(tmp_path):
    path = _write(tmp_path, "")
    with pytest.raises(WhitelistValidationError, match="empty"):
        load_whitelist(path)


def test_non_mapping_top_level_raises(tmp_path):
    path = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(WhitelistValidationError, match="devices"):
        load_whitelist(path)


def test_garbage_scalar_file_raises(tmp_path):
    path = _write(tmp_path, "just a string, not a whitelist\n")
    with pytest.raises(WhitelistValidationError):
        load_whitelist(path)


def test_empty_devices_list_raises(tmp_path):
    path = _write(tmp_path, "devices: []\n")
    with pytest.raises(WhitelistValidationError, match="non-empty list"):
        load_whitelist(path)


def test_device_entry_not_mapping_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        devices:
          - "AA:BB:CC:00:00:01"
        """,
    )
    with pytest.raises(WhitelistValidationError, match="mapping"):
        load_whitelist(path)


# --------------------------------------------------------------------------- #
# Path resolution
# --------------------------------------------------------------------------- #


def test_env_var_path_is_used(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        """
        devices:
          - mac: "AA:BB:CC:00:00:09"
            name: "Via env"
        """,
    )
    monkeypatch.setenv("KALI_MCP_WHITELIST", path)
    devices = load_whitelist()  # no arg -> should read env
    assert devices[0].name == "Via env"


def test_all_errors_share_base_class():
    assert issubclass(WhitelistNotFoundError, WhitelistError)
    assert issubclass(WhitelistValidationError, WhitelistError)
