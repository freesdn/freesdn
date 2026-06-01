# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Honesty guardrails for the SPLIT adapter maturity (reads graded separately
from writes).

A release-honesty audit found the single ``Verified`` badge oversold the WRITE
surface — reads are live-validated on the owner's fleet, but most writes are
gated + mock-tested and never proven on real hardware. These tests lock the
honest split so a write grade can't silently re-inflate to ``LIVE_VALIDATED``
(which must require PERSISTED real-device evidence, e.g. a cassette).
"""
from __future__ import annotations

from app.adapters.base import AdapterMaturity, WriteMaturity
from app.adapters.maturity import ADAPTER_MATURITY, MaturityInfo, get_maturity


def test_every_entry_carries_a_write_grade() -> None:
    """Each adapter is graded for writes (the field is mandatory on the model)."""
    for adapter_id, info in ADAPTER_MATURITY.items():
        assert isinstance(info.write_maturity, WriteMaturity), adapter_id


def test_write_default_is_the_non_overselling_mock_tested() -> None:
    """The honest default — an unproven write surface is MOCK_TESTED, never
    silently LIVE_VALIDATED (mirrors EXPERIMENTAL being the read default)."""
    assert MaturityInfo(AdapterMaturity.VERIFIED).write_maturity == WriteMaturity.MOCK_TESTED
    # Unknown adapter ⇒ experimental read AND a non-overselling write default.
    fallback = get_maturity("totally-unknown-vendor")
    assert fallback.maturity == AdapterMaturity.EXPERIMENTAL
    assert fallback.write_maturity == WriteMaturity.MOCK_TESTED


def test_no_write_is_live_validated_without_deliberate_evidence() -> None:
    """HONESTY RATCHET: today NO adapter's writes are graded LIVE_VALIDATED — the
    honest baseline (even UniFi, with one persisted VLAN cassette, is only
    PARTIAL). Upgrading any adapter to LIVE_VALIDATED is a deliberate act that
    must come with persisted real-device proof (a cassette) AND an update here —
    this test is the friction that prevents a silent re-oversell."""
    live = [a for a, i in ADAPTER_MATURITY.items() if i.write_maturity == WriteMaturity.LIVE_VALIDATED]
    assert live == [], (
        f"{live} now claim LIVE_VALIDATED writes — confirm each is backed by a "
        f"PERSISTED real-device write cassette before allowing it, then update this test."
    )


def test_known_honest_write_grades_are_locked() -> None:
    """Lock the audited grades so a regression can't quietly change them."""
    expected = {
        # reads live (owner's fleet) but writes only mock-tested:
        "omada": WriteMaturity.MOCK_TESTED,
        "opnsense": WriteMaturity.MOCK_TESTED,
        "truenas": WriteMaturity.MOCK_TESTED,
        "hikvision": WriteMaturity.MOCK_TESTED,
        "grandstream": WriteMaturity.MOCK_TESTED,
        "mikrotik": WriteMaturity.MOCK_TESTED,
        # some live-proven (historically / one persisted cassette), rest mock:
        "unifi": WriteMaturity.PARTIAL,
        "freepbx": WriteMaturity.PARTIAL,
        # writes intentionally off:
        "proxmox": WriteMaturity.DISABLED,
        # experimental adapters — writes experimental:
        "pfsense": WriteMaturity.EXPERIMENTAL,
        "openwrt": WriteMaturity.EXPERIMENTAL,
    }
    for adapter_id, wm in expected.items():
        assert ADAPTER_MATURITY[adapter_id].write_maturity == wm, adapter_id


def test_verified_read_adapters_document_their_write_state() -> None:
    """A Verified-read adapter must carry a write_note (so the UI tooltip + docs
    explain the write reality) UNLESS its writes are experimental."""
    for adapter_id, info in ADAPTER_MATURITY.items():
        if info.maturity == AdapterMaturity.VERIFIED:
            assert info.write_note.strip(), f"{adapter_id} verified-read but no write_note"
