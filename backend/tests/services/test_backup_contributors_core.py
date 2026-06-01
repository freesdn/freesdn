# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for the CoreBackupContributor (enterprise backup chapter, Phase 2a).

The contributor is a delegation wrapper around the existing
``BackupService.collect_backup_data`` + ``BackupService._restore_data``
internals. These tests use a mocked BackupService to verify the
delegation + payload-shape conversion is correct, without depending
on a live database.

End-to-end correctness of the underlying ``collect_backup_data`` is
covered by ``test_backup_service_security.py`` — we don't duplicate
that here. What we DO verify is:

  - The protocol's ``collect()`` correctly passes through the new-
    backup dialog's options to the legacy collect_backup_data kwargs.
  - The resulting ContributorPayload's ``counts`` reflect list
    lengths from the underlying data (so the manifest preview is
    accurate).
  - The protocol's ``restore()`` correctly aggregates the per-model
    return shape from ``_restore_data`` into the per-resource
    counts the operator-visible restore report consumes.
  - ``rejected_cross_org`` sub-counts surface as RestoreResult
    warnings (NOT silently absorbed) — the tenant-isolation event
    is operationally important.
  - Exceptions in the underlying call propagate as
    ``RestoreResult(status="error", errors=[...])`` instead of
    bubbling up — per-module independence (one failing contributor
    doesn't crash the restore loop).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from app.services.backup_contributors import (
    BackupContributor,
    CoreBackupContributor,
    ContributorPayload,
    RestoreResult,
    get_registry,
    reset_registry_for_tests,
)


# ── helpers ────────────────────────────────────────────────────────────


def _mock_backup_service(monkeypatch, *, collect_returns=None, restore_returns=None,
                          restore_raises=None) -> MagicMock:
    """Replace ``app.services.backup.BackupService`` with a mock whose
    ``collect_backup_data`` / ``_restore_data`` are AsyncMocks the
    test drives.

    The contributor instantiates ``BackupService(session)`` inside its
    ``collect()`` / ``restore()`` — we monkeypatch the class so that
    constructor returns our mock instance.
    """
    instance = MagicMock()
    instance.org_id = None  # contributor sets this on restore
    if collect_returns is not None:
        instance.collect_backup_data = AsyncMock(return_value=collect_returns)
    if restore_raises is not None:
        instance._restore_data = AsyncMock(side_effect=restore_raises)
    elif restore_returns is not None:
        instance._restore_data = AsyncMock(return_value=restore_returns)

    import app.services.backup as svc_mod
    monkeypatch.setattr(svc_mod, "BackupService", lambda _session: instance)
    return instance


@pytest.fixture
def org_id() -> UUID:
    return uuid4()


@pytest.fixture
def session() -> MagicMock:
    return MagicMock()  # contributor passes it through, never touches it directly


# ── contributor protocol compliance ───────────────────────────────────


class TestProtocolCompliance:
    def test_core_contributor_satisfies_protocol(self) -> None:
        """CoreBackupContributor must structurally implement
        BackupContributor — caught at registration in production, but
        a fast-fail unit test here means a contract regression
        surfaces at PR time, not first prod restore."""
        contributor = CoreBackupContributor()
        assert isinstance(contributor, BackupContributor)

    def test_core_contributor_declarative_attrs(self) -> None:
        c = CoreBackupContributor()
        assert c.contributor_id == "core"
        assert c.schema_version == "1.0.0"
        # No depends_on — core is the bottom of the dependency graph.
        assert c.depends_on == ()
        # Included by default in every new backup.
        assert c.default_included is True

    def test_core_registers_cleanly_in_registry(self) -> None:
        """The contributor registers without raising and topological
        order returns it as a single-element list (no deps)."""
        reset_registry_for_tests()
        reg = get_registry()
        reg.register(CoreBackupContributor())
        ordered = reg.topological_order()
        assert len(ordered) == 1
        assert ordered[0].contributor_id == "core"


# ── collect() — option pass-through + counts derivation ────────────────


class TestCollect:
    @pytest.mark.asyncio
    async def test_collect_passes_options_through(
        self, monkeypatch, session, org_id,
    ) -> None:
        """The contributor's ``collect()`` translates the protocol's
        ``options`` dict into the underlying collect_backup_data's
        kwargs without re-shaping or filtering."""
        captured: dict[str, Any] = {}

        async def _fake_collect(**kwargs):
            captured.update(kwargs)
            return {"sites": [], "controllers": [], "devices": []}

        mock_svc = _mock_backup_service(monkeypatch, collect_returns={})
        mock_svc.collect_backup_data = AsyncMock(side_effect=_fake_collect)

        site_id = uuid4()
        device_ids = [uuid4(), uuid4()]
        opts = {
            "site_id": site_id,
            "device_ids": device_ids,
            "include_devices": False,
            "include_vlans": False,
            "include_ssids": True,
            "include_users": True,
            "include_automation": True,
            "unknown_future_option": "should-be-ignored",
        }

        contributor = CoreBackupContributor()
        await contributor.collect(session, org_id, opts)

        # Underlying call received the documented kwargs + organization_id
        # exactly as passed; the unknown future option was filtered out
        # because contributor.collect explicitly enumerates the keys it
        # consumes (it doesn't blindly **opts).
        assert captured["site_id"] == site_id
        assert captured["device_ids"] == device_ids
        assert captured["include_devices"] is False
        assert captured["include_vlans"] is False
        assert captured["include_ssids"] is True
        assert captured["include_users"] is True
        assert captured["include_automation"] is True
        assert captured["organization_id"] == org_id
        assert "unknown_future_option" not in captured

    @pytest.mark.asyncio
    async def test_collect_defaults_include_flags_to_true(
        self, monkeypatch, session, org_id,
    ) -> None:
        """Empty options → every include_* defaults to True (the
        operator-visible new-backup-dialog default state)."""
        captured: dict[str, Any] = {}

        async def _fake_collect(**kwargs):
            captured.update(kwargs)
            return {}

        mock_svc = _mock_backup_service(monkeypatch, collect_returns={})
        mock_svc.collect_backup_data = AsyncMock(side_effect=_fake_collect)

        contributor = CoreBackupContributor()
        await contributor.collect(session, org_id, options={})

        for k in ("include_devices", "include_vlans", "include_ssids",
                  "include_users", "include_automation"):
            assert captured[k] is True

    @pytest.mark.asyncio
    async def test_collect_returns_payload_with_correct_counts(
        self, monkeypatch, session, org_id,
    ) -> None:
        """Counts in the ContributorPayload must reflect list lengths
        of the underlying data — they're surfaced in the manifest
        header so the UI can preview without decrypting."""
        underlying = {
            "sites": [{"id": "s1"}, {"id": "s2"}, {"id": "s3"}],
            "controllers": [{"id": "c1"}],
            "devices": [],
            "users": [{"id": "u1"}, {"id": "u2"}],
            "automation_rules": [],
            "settings": {"version": "1"},  # non-list → count 1
            "absent": None,  # None → omitted
        }
        _mock_backup_service(monkeypatch, collect_returns=underlying)

        contributor = CoreBackupContributor()
        payload = await contributor.collect(session, org_id, options={})

        assert isinstance(payload, ContributorPayload)
        assert payload.schema_version == "1.0.0"
        assert payload.counts == {
            "sites": 3,
            "controllers": 1,
            "devices": 0,
            "users": 2,
            "automation_rules": 0,
            "settings": 1,  # non-list value reported as 1
        }
        # None values are omitted from the manifest preview.
        assert "absent" not in payload.counts
        # The data field is the underlying dict verbatim — no mutation.
        assert payload.data == underlying
        # Metadata records provenance for forensic trails.
        assert payload.metadata.get("source") == "core_contributor.collect"
        assert "captured_at" in payload.metadata

    @pytest.mark.asyncio
    async def test_collect_unwraps_collect_backup_data_envelope(
        self, monkeypatch, session, org_id,
    ) -> None:
        """REGRESSION (live-verification finding): the real
        ``collect_backup_data`` returns an ENVELOPE
        ``{version, schema_version, created_at, freesdn_version,
        organization_id, data: {sites, controllers, devices, users,
        automation_rules}}`` — the actual content is nested under
        ``data``. The contributor MUST unwrap it so:
          - counts reflect real resources (sites/devices), NOT the 6
            envelope keys, and
          - payload.data is the flat content ``_restore_data`` consumes
            (otherwise core restore silently writes nothing).

        The earlier mocked tests faked a flat dict and never exercised
        this — which is exactly why the bug shipped. This test pins the
        unwrap against the real envelope shape.
        """
        envelope = {
            "version": "2.0",
            "schema_version": 2,
            "created_at": "2026-05-29T00:00:00Z",
            "freesdn_version": "2026.05.02",
            "organization_id": str(org_id),
            "data": {
                "sites": [{"id": "s1"}, {"id": "s2"}],
                "controllers": [{"id": "c1"}],
                "devices": [{"id": "d1"}, {"id": "d2"}, {"id": "d3"}],
                "users": [{"id": "u1"}],
                "automation_rules": [],
            },
        }
        _mock_backup_service(monkeypatch, collect_returns=envelope)

        payload = await CoreBackupContributor().collect(session, org_id, {})

        # Counts MUST be the inner resource keys, never the envelope keys.
        assert payload.counts == {
            "sites": 2, "controllers": 1, "devices": 3,
            "users": 1, "automation_rules": 0,
        }
        envelope_only = {"version", "schema_version", "created_at",
                         "freesdn_version", "data"}
        assert not (set(payload.counts) & envelope_only), (
            "counts leaked envelope keys — the unwrap regressed"
        )
        # payload.data is the FLAT content (what _restore_data reads),
        # NOT the envelope.
        assert "sites" in payload.data and "data" not in payload.data
        assert payload.data == envelope["data"]
        # Provenance: the envelope version is preserved in metadata.
        assert payload.metadata.get("source_envelope_version") == "2.0"

    @pytest.mark.asyncio
    async def test_collect_tolerates_already_flat_dict(
        self, monkeypatch, session, org_id,
    ) -> None:
        """Backwards-compat: if collect_backup_data ever returns an
        already-flat dict (no ``data`` key), the unwrap is a no-op —
        ``raw.get('data', raw)`` falls back to the dict itself. Keeps
        the older mocked-shape tests valid."""
        flat = {"sites": [{"id": "s1"}], "devices": []}
        _mock_backup_service(monkeypatch, collect_returns=flat)
        payload = await CoreBackupContributor().collect(session, org_id, {})
        assert payload.data == flat
        assert payload.counts == {"sites": 1, "devices": 0}


# ── restore() — aggregation + error handling ──────────────────────────


class TestRestore:
    @pytest.mark.asyncio
    async def test_restore_aggregates_per_model_counts(
        self, monkeypatch, session, org_id,
    ) -> None:
        """The contributor's ``restore()`` turns the per-model dict
        ``_restore_data`` returns into per-resource RestoreResult
        counts."""
        underlying_result = {
            "sites": {"created": 5, "updated": 2, "skipped": 1,
                      "rejected_cross_org": 0},
            "controllers": {"created": 3, "updated": 0, "skipped": 0,
                            "rejected_cross_org": 0},
            "devices": {"created": 10, "updated": 4, "skipped": 2,
                        "rejected_cross_org": 0},
        }
        _mock_backup_service(monkeypatch, restore_returns=underlying_result)

        contributor = CoreBackupContributor()
        payload = ContributorPayload(
            schema_version="1.0.0",
            counts={},
            data={"sites": [], "controllers": [], "devices": []},
            metadata={},
        )

        result = await contributor.restore(
            session, org_id, payload, dry_run=False, options={},
        )

        assert isinstance(result, RestoreResult)
        assert result.contributor_id == "core"
        assert result.status == "ok"
        assert result.created == {"sites": 5, "controllers": 3, "devices": 10}
        assert result.updated == {"sites": 2, "controllers": 0, "devices": 4}
        assert result.skipped == {"sites": 1, "controllers": 0, "devices": 2}
        assert result.errors == []
        assert result.warnings == []  # no rejected_cross_org

    @pytest.mark.asyncio
    async def test_restore_dry_run_returns_dry_run_ok_status(
        self, monkeypatch, session, org_id,
    ) -> None:
        """A dry-run restore must NOT report status='ok' (the latter
        is reserved for actual successful writes). The dry_run_ok
        marker distinguishes the two in restore reports + monthly
        validate_restore output."""
        _mock_backup_service(monkeypatch, restore_returns={"sites": {}})

        contributor = CoreBackupContributor()
        payload = ContributorPayload(
            schema_version="1.0.0", counts={}, data={}, metadata={},
        )

        result = await contributor.restore(
            session, org_id, payload, dry_run=True, options={},
        )

        assert result.status == "dry_run_ok"

    @pytest.mark.asyncio
    async def test_restore_surfaces_rejected_cross_org_as_warning(
        self, monkeypatch, session, org_id,
    ) -> None:
        """Records rejected for being in another tenant must surface
        as RestoreResult warnings — never silently absorbed. This is
        an operationally important signal (operator may be restoring
        the wrong backup into the wrong org)."""
        _mock_backup_service(monkeypatch, restore_returns={
            "sites": {"created": 1, "updated": 0, "skipped": 3,
                      "rejected_cross_org": 3},
            "devices": {"created": 0, "updated": 0, "skipped": 0,
                        "rejected_cross_org": 0},
        })

        contributor = CoreBackupContributor()
        payload = ContributorPayload(
            schema_version="1.0.0", counts={}, data={}, metadata={},
        )

        result = await contributor.restore(
            session, org_id, payload, dry_run=False, options={},
        )

        # Single warning naming the resource (sites) + the count (3).
        assert len(result.warnings) == 1
        assert "3 sites" in result.warnings[0]
        assert "cross-tenant" in result.warnings[0].lower()
        # The skipped count INCLUDES the cross-org rejections — the
        # warning is supplementary explanation, not a replacement.
        assert result.skipped["sites"] == 3

    @pytest.mark.asyncio
    async def test_restore_exception_becomes_error_result(
        self, monkeypatch, session, org_id,
    ) -> None:
        """A raised exception in ``_restore_data`` must NOT crash the
        contributor — it must become a RestoreResult(status='error')
        so the central restore loop can move on to the next
        contributor (per-module independence)."""
        _mock_backup_service(
            monkeypatch,
            restore_raises=RuntimeError("FK constraint violated"),
        )

        contributor = CoreBackupContributor()
        payload = ContributorPayload(
            schema_version="1.0.0", counts={}, data={}, metadata={},
        )

        result = await contributor.restore(
            session, org_id, payload, dry_run=False, options={},
        )

        assert result.contributor_id == "core"
        assert result.status == "error"
        assert len(result.errors) == 1
        assert "FK constraint violated" in result.errors[0]
        # No partial counts — the underlying call never returned.
        assert result.created == {}
        assert result.updated == {}
        assert result.skipped == {}

    @pytest.mark.asyncio
    async def test_restore_passes_org_id_to_backup_service(
        self, monkeypatch, session, org_id,
    ) -> None:
        """``BackupService._restore_data`` requires ``self.org_id`` to
        be set before invocation (its tenant-isolation invariant).
        The contributor must set it from the protocol's
        ``organization_id`` parameter."""
        instance = _mock_backup_service(monkeypatch, restore_returns={})

        contributor = CoreBackupContributor()
        payload = ContributorPayload(
            schema_version="1.0.0", counts={}, data={}, metadata={},
        )

        await contributor.restore(
            session, org_id, payload, dry_run=False, options={},
        )

        # The mock's org_id was set by the contributor before
        # _restore_data was invoked.
        assert instance.org_id == org_id

    @pytest.mark.asyncio
    async def test_restore_passes_options_through(
        self, monkeypatch, session, org_id,
    ) -> None:
        """The contributor translates protocol-level ``options`` into
        the legacy kwargs of ``_restore_data``."""
        captured: dict[str, Any] = {}

        async def _fake_restore(data, **kwargs):
            captured.update(kwargs)
            return {}

        instance = _mock_backup_service(monkeypatch, restore_returns={})
        instance._restore_data = AsyncMock(side_effect=_fake_restore)

        contributor = CoreBackupContributor()
        payload = ContributorPayload(
            schema_version="1.0.0", counts={}, data={}, metadata={},
        )

        await contributor.restore(
            session, org_id, payload,
            dry_run=True,
            options={
                "overwrite_existing": True,
                "restore_devices": False,
                "restore_users": True,
            },
        )

        assert captured["dry_run"] is True
        assert captured["overwrite_existing"] is True
        assert captured["restore_devices"] is False
        assert captured["restore_users"] is True
