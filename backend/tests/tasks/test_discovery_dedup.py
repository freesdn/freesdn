# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Device de-duplication contract for discovery.

Two duplicate classes were observed live and fixed here:

1. **Real-MAC dups** — overlapping syncs race the app-level MAC dedup and both
   INSERT. The backstop is the partial unique index ``uq_devices_mac_alive``;
   it must be declared on the *model* (not only in the migration) or a
   ``create_all()`` bootstrap silently omits it (which is exactly how a live
   DB ended up without the constraint).
2. **MAC-less dups** — an adapter that surfaces the controller itself as a
   single device (firewall/gateway "self" device) emits an empty MAC every
   sync; the MAC dedup can't match it, so each sync INSERTed another copy.
   ``_macless_key`` provides the stable per-controller fallback key.
"""
from __future__ import annotations

from app.models.devices import Device
from app.tasks.discovery import _macless_key


class TestMaclessKey:
    def test_prefers_serial_then_ip_then_name(self) -> None:
        assert _macless_key("SN123", "10.0.0.1", "fw") == "sn123"
        assert _macless_key("", "10.0.0.1", "fw") == "10.0.0.1"  # empty serial skipped
        assert _macless_key(None, None, "Edge-FW") == "edge-fw"

    def test_lowercased_and_stripped(self) -> None:
        assert _macless_key(None, "  10.0.0.1  ", None) == "10.0.0.1"
        assert _macless_key("AA:BB", None, None) == "aa:bb"

    def test_empty_when_no_identifier(self) -> None:
        # No stable key → caller must NOT dedup (treat as a fresh device),
        # never collapse unrelated rows under "".
        assert _macless_key(None, None, None) == ""
        assert _macless_key("", "", "") == ""


class TestUniqueMacIndexDeclaredOnModel:
    """The model must declare the partial unique index so create_all() (tests,
    dev bootstrap) produces it — the live bug was the model lacking it."""

    def _index(self):
        return next(
            (ix for ix in Device.__table__.indexes if ix.name == "uq_devices_mac_alive"),
            None,
        )

    def test_index_present_and_unique(self) -> None:
        ix = self._index()
        assert ix is not None, "uq_devices_mac_alive missing from Device model"
        assert ix.unique is True
        assert [c.name for c in ix.columns] == ["mac_address"]

    def test_partial_predicate_excludes_null_empty_and_deleted(self) -> None:
        ix = self._index()
        where = str(ix.dialect_options["postgresql"]["where"]).lower()
        assert "mac_address is not null" in where  # NULL MAC excluded
        assert "<> ''" in where                    # empty-string MAC excluded
        assert "deleted_at is null" in where        # soft-deleted rows excluded


class TestPerfIndexesMirroredOnModel:
    """Migration PERF_INDEXES that aren't otherwise model-indexed must be
    declared on the model too, or a create_all() fresh-install (the supported
    scripts/migrate.py path) silently omits them — the exact model-vs-migration
    drift class that left uq_devices_mac_alive uncreated on the live DB."""

    def _index_cols(self) -> dict[str, list[str]]:
        return {ix.name: [c.name for c in ix.columns] for ix in Device.__table__.indexes}

    def test_credential_fk_is_indexed(self) -> None:
        # Postgres does NOT auto-index FKs; a missing index here was a real gap.
        assert self._index_cols().get("ix_devices_credential_id") == ["credential_id"]

    def test_composite_type_site_deleted_index_present(self) -> None:
        assert self._index_cols().get("ix_devices_type_site_deleted") == [
            "device_type", "site_id", "deleted_at"
        ]
