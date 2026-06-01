# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Integration tests for the BackupService → registry dispatch.

The CoreBackupContributor unit tests cover the contributor
in isolation. The foundation tests cover the registry +
manifest + version gate in isolation. This file pins the SEAM between
them — the new ``BackupService._assemble_backup_archive`` and
``_dispatch_restore_via_contributors`` helpers that drive the
contributor walk on production traffic.

These tests use mocked contributors registered into a clean registry,
so the helpers are exercised without depending on the real
CoreBackupContributor's DB queries. End-to-end tests against a live
DB live in the integration suite.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from app.services.backup_contributors import (
    BackupArchive,
    BackupContributor,
    BackupManifest,
    ContributorEntry,
    ContributorPayload,
    RestoreResult,
    get_registry,
    reset_registry_for_tests,
)


# ── helpers ──────────────────────────────────────────────────────────


class _FakeContributor:
    """Configurable test double satisfying the BackupContributor
    protocol. Each test wires the behaviour it needs via constructor
    kwargs — no AsyncMock plumbing required.
    """
    def __init__(
        self,
        *,
        contributor_id: str,
        schema_version: str = "1.0.0",
        depends_on: tuple[str, ...] = (),
        default_included: bool = True,
        collect_data: dict[str, Any] | None = None,
        collect_counts: dict[str, int] | None = None,
        collect_raises: Exception | None = None,
        restore_result: RestoreResult | None = None,
        restore_raises: Exception | None = None,
    ) -> None:
        self.contributor_id = contributor_id
        self.schema_version = schema_version
        self.depends_on = depends_on
        self.default_included = default_included
        self._collect_data = collect_data or {}
        self._collect_counts = collect_counts or {}
        self._collect_raises = collect_raises
        self._restore_result = restore_result
        self._restore_raises = restore_raises
        self.collect_calls: list[tuple] = []
        self.restore_calls: list[tuple] = []

    async def collect(self, session, organization_id, options):
        self.collect_calls.append((session, organization_id, options))
        if self._collect_raises is not None:
            raise self._collect_raises
        return ContributorPayload(
            schema_version=self.schema_version,
            counts=self._collect_counts,
            data=self._collect_data,
            metadata={"test_marker": self.contributor_id},
        )

    async def restore(self, session, organization_id, payload, *,
                       dry_run, options):
        self.restore_calls.append(
            (session, organization_id, payload, dry_run, options),
        )
        if self._restore_raises is not None:
            raise self._restore_raises
        return self._restore_result or RestoreResult(
            contributor_id=self.contributor_id,
            status="dry_run_ok" if dry_run else "ok",
            created={"things": 1},
        )


@pytest.fixture
def clean_registry():
    """Each test gets a clean registry — bleed across tests would
    cause real CoreBackupContributor (registered by other tests' use
    of BackupService) to interfere with the per-test mock setup."""
    reset_registry_for_tests()
    yield get_registry()
    reset_registry_for_tests()


@pytest.fixture
def mock_session():
    """The helpers pass the session to contributors verbatim; they
    never touch it directly, so a plain MagicMock is enough."""
    session = MagicMock()
    # begin_nested returns an async context manager that's a no-op.
    cm = MagicMock()
    cm.__aenter__ = MagicMock(return_value=cm)
    cm.__aexit__ = MagicMock(return_value=None)
    # async-method shape
    async def _aenter(*_a, **_kw): return cm
    async def _aexit(*_a, **_kw): return None
    cm.__aenter__ = _aenter
    cm.__aexit__ = _aexit
    session.begin_nested = MagicMock(return_value=cm)
    return session


def _make_service(session) -> Any:
    """Construct a BackupService with the patched session. Bypass the
    automatic discover_from_modules so our clean-registry contributors
    aren't overwritten by accidental real-module registration."""
    from app.services.backup import BackupService

    # The first BackupService instantiation auto-registers
    # CoreBackupContributor + runs discover_from_modules. Tests reset
    # the class flag so each test starts clean.
    BackupService._contributors_initialized = True  # already-handled flag
    svc = BackupService(session)
    return svc


# ── _assemble_backup_archive ──────────────────────────────────────────


class TestAssembleBackupArchive:
    @pytest.mark.asyncio
    async def test_walks_contributors_in_topo_order(
        self, clean_registry, mock_session,
    ) -> None:
        core = _FakeContributor(
            contributor_id="core",
            collect_data={"sites": [{"id": "s1"}]},
            collect_counts={"sites": 1},
        )
        voip = _FakeContributor(
            contributor_id="voip",
            depends_on=("core",),
            collect_data={"pbxes": [{"id": "p1"}]},
            collect_counts={"pbxes": 1},
        )
        clean_registry.register(voip)  # registration order is intentionally
        clean_registry.register(core)  # backwards from topo order

        svc = _make_service(mock_session)
        org_id = uuid4()
        backup_id = uuid4()

        archive = await svc._assemble_backup_archive(
            backup_id=backup_id,
            organization_id=org_id,
            options={"site_id": None},
        )

        assert isinstance(archive, BackupArchive)
        # The manifest entries are in topo-resolved order — core first,
        # voip second — regardless of registration order.
        ids = [e.id for e in archive.manifest.contributors]
        assert ids == ["core", "voip"]
        # The data is keyed by contributor_id, NOT positional.
        assert archive.contributors["core"] == {"sites": [{"id": "s1"}]}
        assert archive.contributors["voip"] == {"pbxes": [{"id": "p1"}]}
        # Counts in the manifest match what the contributors reported.
        core_entry = archive.manifest.contributors[0]
        assert core_entry.counts == {"sites": 1}
        # Per-contributor metadata is preserved.
        assert core_entry.metadata == {"test_marker": "core"}

    @pytest.mark.asyncio
    async def test_passes_options_and_org_id_to_each_contributor(
        self, clean_registry, mock_session,
    ) -> None:
        core = _FakeContributor(contributor_id="core")
        clean_registry.register(core)

        svc = _make_service(mock_session)
        org_id = uuid4()
        options = {"site_id": "abc", "include_users": False}

        await svc._assemble_backup_archive(
            backup_id=uuid4(),
            organization_id=org_id,
            options=options,
        )

        assert len(core.collect_calls) == 1
        _session, _org, _opts = core.collect_calls[0]
        assert _org == org_id
        assert _opts == options

    @pytest.mark.asyncio
    async def test_failing_contributor_is_omitted_others_proceed(
        self, clean_registry, mock_session,
    ) -> None:
        """A contributor's ``collect`` raising must NOT abort the whole
        backup. The contributor is omitted from the manifest with a
        log entry; siblings still produce their sections."""
        broken = _FakeContributor(
            contributor_id="broken",
            collect_raises=RuntimeError("upstream API timeout"),
        )
        working = _FakeContributor(
            contributor_id="working",
            collect_data={"things": [1, 2, 3]},
            collect_counts={"things": 3},
        )
        clean_registry.register(broken)
        clean_registry.register(working)

        svc = _make_service(mock_session)
        archive = await svc._assemble_backup_archive(
            backup_id=uuid4(),
            organization_id=uuid4(),
            options={},
        )

        # Manifest does NOT contain ``broken``.
        ids = [e.id for e in archive.manifest.contributors]
        assert "broken" not in ids
        assert "working" in ids
        # Working contributor's data is intact.
        assert archive.contributors["working"] == {"things": [1, 2, 3]}

    @pytest.mark.asyncio
    async def test_archive_carries_provenance_in_manifest(
        self, clean_registry, mock_session,
    ) -> None:
        clean_registry.register(_FakeContributor(contributor_id="core"))

        svc = _make_service(mock_session)
        org_id = uuid4()
        backup_id = uuid4()

        archive = await svc._assemble_backup_archive(
            backup_id=backup_id,
            organization_id=org_id,
            options={},
        )

        assert archive.manifest.backup_id == str(backup_id)
        assert archive.manifest.organization_id == str(org_id)
        # source_version comes from settings.APP_VERSION; should be set
        # (not None) — but it's a calver string, we don't care which.
        assert archive.manifest.format_version == "2.0"


# ── _dispatch_restore_via_contributors ────────────────────────────────


class TestDispatchRestore:
    def _archive(
        self, *, contributors: dict[str, dict[str, Any]],
        schema_by_id: dict[str, str] | None = None,
    ) -> BackupArchive:
        """Construct a synthetic BackupArchive for restore tests."""
        from datetime import UTC, datetime
        schemas = schema_by_id or {}
        return BackupArchive(
            manifest=BackupManifest(
                backup_id=str(uuid4()),
                created_at=datetime.now(UTC),
                organization_id=str(uuid4()),
                contributors=[
                    ContributorEntry(
                        id=cid,
                        schema_version=schemas.get(cid, "1.0.0"),
                        counts={"_test": len(data)},
                    )
                    for cid, data in contributors.items()
                ],
            ),
            contributors=contributors,
        )

    @pytest.mark.asyncio
    async def test_dispatches_each_contributor_in_order(
        self, clean_registry, mock_session,
    ) -> None:
        core = _FakeContributor(contributor_id="core")
        voip = _FakeContributor(contributor_id="voip", depends_on=("core",))
        clean_registry.register(voip)
        clean_registry.register(core)

        archive = self._archive(contributors={
            "core": {"sites": []}, "voip": {"pbxes": []},
        })
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
        )

        # Both contributors saw the dispatch.
        assert len(core.restore_calls) == 1
        assert len(voip.restore_calls) == 1
        # Per-contributor report appears in topo order.
        ids = [c["contributor_id"] for c in report["contributors"]]
        assert ids == ["core", "voip"]

    @pytest.mark.asyncio
    async def test_missing_section_reported_as_status_missing(
        self, clean_registry, mock_session,
    ) -> None:
        """When the backup's manifest doesn't include data for a
        registered contributor, that's not an error — the operator
        just gets a per-contributor ``status="missing"`` entry."""
        core = _FakeContributor(contributor_id="core")
        # ``voip`` is registered but NOT in the backup's contributors.
        voip = _FakeContributor(contributor_id="voip", depends_on=("core",))
        clean_registry.register(core)
        clean_registry.register(voip)

        archive = self._archive(contributors={"core": {}})
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
        )

        statuses = {
            c["contributor_id"]: c["status"] for c in report["contributors"]
        }
        assert statuses["core"] == "dry_run_ok"
        assert statuses["voip"] == "missing"
        # voip.restore was NOT called.
        assert voip.restore_calls == []

    @pytest.mark.asyncio
    async def test_schema_mismatch_skips_contributor_other_proceed(
        self, clean_registry, mock_session,
    ) -> None:
        """Payload at v2.x where code is at v1.x → cross-major refusal.
        The mismatched contributor reports ``schema_mismatch``; others
        proceed."""
        core_at_v1 = _FakeContributor(
            contributor_id="core", schema_version="1.0.0",
        )
        voip_at_v1 = _FakeContributor(
            contributor_id="voip", schema_version="1.0.0",
            depends_on=("core",),
        )
        clean_registry.register(core_at_v1)
        clean_registry.register(voip_at_v1)

        # Backup says voip is at v2.5.0 — incompatible with code's v1.0.0.
        archive = self._archive(
            contributors={"core": {}, "voip": {"pbxes": []}},
            schema_by_id={"voip": "2.5.0", "core": "1.0.0"},
        )
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
        )

        by_id = {c["contributor_id"]: c for c in report["contributors"]}
        assert by_id["core"]["status"] == "dry_run_ok"
        assert by_id["voip"]["status"] == "schema_mismatch"
        # The error message names the version mismatch.
        assert any("v2.5.0" in e for e in by_id["voip"]["errors"])
        # voip.restore was NOT called (skipped before dispatch).
        assert voip_at_v1.restore_calls == []

    @pytest.mark.asyncio
    async def test_restore_exception_isolated_per_module(
        self, clean_registry, mock_session,
    ) -> None:
        """One contributor raising during restore must NOT crash the
        loop; the failure is recorded and the next contributor runs.
        This is the per-module independence the scoping discussion
        explicitly chose."""
        core_failing = _FakeContributor(
            contributor_id="core",
            restore_raises=RuntimeError("FK violation"),
        )
        voip_ok = _FakeContributor(
            contributor_id="voip", depends_on=("core",),
            restore_result=RestoreResult(
                contributor_id="voip", status="dry_run_ok",
                created={"pbxes": 2},
            ),
        )
        clean_registry.register(core_failing)
        clean_registry.register(voip_ok)

        archive = self._archive(contributors={"core": {}, "voip": {}})
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
        )

        by_id = {c["contributor_id"]: c for c in report["contributors"]}
        assert by_id["core"]["status"] == "error"
        assert "FK violation" in by_id["core"]["errors"][0]
        # ``voip`` STILL ran despite core's failure — per-module
        # independence. This is the headline behavior of the chapter.
        assert by_id["voip"]["status"] == "dry_run_ok"
        assert len(voip_ok.restore_calls) == 1

    @pytest.mark.asyncio
    async def test_summary_aggregates_counts_across_contributors(
        self, clean_registry, mock_session,
    ) -> None:
        c1 = _FakeContributor(
            contributor_id="a",
            restore_result=RestoreResult(
                contributor_id="a", status="dry_run_ok",
                created={"sites": 3, "devices": 10},
                updated={"sites": 1},
                skipped={"devices": 2},
            ),
        )
        c2 = _FakeContributor(
            contributor_id="b",
            restore_result=RestoreResult(
                contributor_id="b", status="dry_run_ok",
                created={"pbxes": 5},
            ),
        )
        clean_registry.register(c1)
        clean_registry.register(c2)

        archive = self._archive(contributors={"a": {}, "b": {}})
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
        )

        s = report["summary"]
        assert s["total_created"] == 3 + 10 + 5
        assert s["total_updated"] == 1
        assert s["total_skipped"] == 2
        assert s["contributors_ok"] == 2
        assert s["contributors_failed"] == 0

    @pytest.mark.asyncio
    async def test_dry_run_does_not_open_savepoint(
        self, clean_registry, mock_session,
    ) -> None:
        """A dry-run restore must NOT enter ``begin_nested`` — there's
        nothing to roll back, and opening savepoints unnecessarily
        adds overhead on the monthly validate_restore sweep."""
        c = _FakeContributor(contributor_id="core")
        clean_registry.register(c)

        archive = self._archive(contributors={"core": {}})
        svc = _make_service(mock_session)

        await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
        )

        # begin_nested was NOT invoked.
        mock_session.begin_nested.assert_not_called()

    @pytest.mark.asyncio
    async def test_real_restore_uses_per_module_savepoint(
        self, clean_registry, mock_session,
    ) -> None:
        """When dry_run is False, each contributor's restore runs
        inside ``begin_nested`` so per-module rollback is possible."""
        c1 = _FakeContributor(contributor_id="a")
        c2 = _FakeContributor(contributor_id="b")
        clean_registry.register(c1)
        clean_registry.register(c2)

        archive = self._archive(contributors={"a": {}, "b": {}})
        svc = _make_service(mock_session)

        await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=False,
            restore_options={},
        )

        # One savepoint per contributor.
        assert mock_session.begin_nested.call_count == 2


# ── selective restore (Phase 6a) ──────────────────────────────────────


class TestSelectiveRestore:
    def _archive(self, *, contributors):
        from datetime import UTC, datetime
        return BackupArchive(
            manifest=BackupManifest(
                backup_id=str(uuid4()),
                created_at=datetime.now(UTC),
                organization_id=str(uuid4()),
                contributors=[
                    ContributorEntry(id=cid, schema_version="1.0.0",
                                     counts={"_t": len(d)})
                    for cid, d in contributors.items()
                ],
            ),
            contributors=contributors,
        )

    @pytest.mark.asyncio
    async def test_selected_subset_only_restores_those(
        self, clean_registry, mock_session,
    ) -> None:
        core = _FakeContributor(contributor_id="core")
        voip = _FakeContributor(contributor_id="voip", depends_on=("core",))
        cameras = _FakeContributor(contributor_id="cameras", depends_on=("core",))
        for c in (core, voip, cameras):
            clean_registry.register(c)

        archive = self._archive(contributors={
            "core": {}, "voip": {}, "cameras": {},
        })
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
            selected_contributors=["core", "voip"],   # cameras deselected
        )

        by_id = {c["contributor_id"]: c for c in report["contributors"]}
        assert by_id["core"]["status"] == "dry_run_ok"
        assert by_id["voip"]["status"] == "dry_run_ok"
        # cameras was deselected → status "skipped", restore() NOT called.
        assert by_id["cameras"]["status"] == "skipped"
        assert core.restore_calls and voip.restore_calls
        assert cameras.restore_calls == []

    @pytest.mark.asyncio
    async def test_none_selection_restores_all(
        self, clean_registry, mock_session,
    ) -> None:
        core = _FakeContributor(contributor_id="core")
        voip = _FakeContributor(contributor_id="voip", depends_on=("core",))
        clean_registry.register(core)
        clean_registry.register(voip)

        archive = self._archive(contributors={"core": {}, "voip": {}})
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
            selected_contributors=None,  # restore everything
        )
        statuses = {c["contributor_id"]: c["status"] for c in report["contributors"]}
        assert statuses == {"core": "dry_run_ok", "voip": "dry_run_ok"}

    @pytest.mark.asyncio
    async def test_skipped_distinct_from_missing(
        self, clean_registry, mock_session,
    ) -> None:
        """A DESELECTED contributor reports 'skipped'; a SELECTED
        contributor that's absent from the archive reports 'missing'.
        The two must be distinguishable in the report. Selection is
        applied first, so to observe 'missing' the contributor must be
        selected AND absent."""
        core = _FakeContributor(contributor_id="core")
        voip = _FakeContributor(contributor_id="voip", depends_on=("core",))
        cameras = _FakeContributor(contributor_id="cameras", depends_on=("core",))
        for c in (core, voip, cameras):
            clean_registry.register(c)

        # Archive has core + voip; cameras NOT in archive.
        archive = self._archive(contributors={"core": {}, "voip": {}})
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=True,
            restore_options={},
            # core+cameras selected (voip deselected). cameras is
            # selected but not in the archive → "missing". voip is
            # deselected → "skipped".
            selected_contributors=["core", "cameras"],
        )
        by_id = {c["contributor_id"]: c for c in report["contributors"]}
        assert by_id["core"]["status"] == "dry_run_ok"
        assert by_id["voip"]["status"] == "skipped"     # deselected
        assert by_id["cameras"]["status"] == "missing"  # selected but absent
