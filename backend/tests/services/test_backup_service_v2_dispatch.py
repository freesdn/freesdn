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
from uuid import uuid4

import pytest

from app.services.backup_contributors import (
    BackupArchive,
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
        counts_by_id: dict[str, dict[str, int]] | None = None,
    ) -> BackupArchive:
        """Construct a synthetic BackupArchive for restore tests."""
        from datetime import UTC, datetime
        schemas = schema_by_id or {}
        counts = counts_by_id or {}
        return BackupArchive(
            manifest=BackupManifest(
                backup_id=str(uuid4()),
                created_at=datetime.now(UTC),
                organization_id=str(uuid4()),
                contributors=[
                    ContributorEntry(
                        id=cid,
                        schema_version=schemas.get(cid, "1.0.0"),
                        counts=counts.get(cid, {"_test": len(data)}),
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
        assert by_id["core"]["errors"][0]
        assert "FK violation" not in by_id["core"]["errors"][0]
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
    def _archive(self, *, contributors, counts_by_id=None):
        from datetime import UTC, datetime
        counts = counts_by_id or {}
        return BackupArchive(
            manifest=BackupManifest(
                backup_id=str(uuid4()),
                created_at=datetime.now(UTC),
                organization_id=str(uuid4()),
                contributors=[
                    ContributorEntry(id=cid, schema_version="1.0.0",
                                     counts=counts.get(cid, {"_t": len(d)}))
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

    # ── archive sections this instance cannot restore ────────────────
    #
    # The mirror of ``test_missing_section_reported_as_status_missing``.
    # That one covers "registry has it, archive doesn't". The reverse --
    # "archive has it, registry doesn't" -- was structurally invisible:
    # the loop walks the LIVE registry and looks each id up in the
    # manifest, so a section whose module is not loaded here was never
    # visited, never counted and never named. Four modules of data could
    # vanish behind total_errors: 0 and a green "completed" job.
    #
    # Reachable in normal operation: ModuleLoader.load_all_modules
    # logs-and-continues on a module load failure, so a module that fails
    # on_load() leaves the app degraded-but-running with its contributor
    # gone from both backup and restore.

    @pytest.mark.asyncio
    async def test_archive_section_with_no_live_contributor_is_reported(
        self, clean_registry, mock_session,
    ) -> None:
        """registry={core}, archive={core, voip} → voip must appear in the
        report as a failure, not silently disappear.

        Mutation caught: deleting the post-loop walk over
        ``archive.manifest.contributors`` in
        ``_dispatch_restore_via_contributors``. Before it, the report held
        exactly ONE entry (core) and the summary was all zeros.
        """
        clean_registry.register(_FakeContributor(contributor_id="core"))

        archive = self._archive(
            contributors={"core": {}, "voip": {"extensions": [], "pbxes": []}},
            counts_by_id={"voip": {"extensions": 48, "pbxes": 2}},
        )
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=False,
            restore_options={},
        )

        by_id = {c["contributor_id"]: c for c in report["contributors"]}
        assert "voip" in by_id, "an unrestorable archive section vanished from the report"
        assert by_id["voip"]["status"] == "error"
        # The operator must be told WHICH records were left on the floor.
        assert by_id["voip"]["errors"], "no reason recorded for the dropped section"
        assert "voip" in by_id["voip"]["errors"][0]
        assert "50" in by_id["voip"]["errors"][0]  # 48 extensions + 2 pbxes

    @pytest.mark.asyncio
    async def test_dropped_section_counts_into_the_summary(
        self, clean_registry, mock_session,
    ) -> None:
        """The summary drives RestoreJob.items_failed and the UI's green
        tick. A restore that dropped 50 records must not report
        total_errors: 0 / contributors_failed: 0.

        Mutation caught: appending the entry with status="missing" (which
        contributors_failed does not count) or with empty ``skipped``.
        """
        clean_registry.register(_FakeContributor(contributor_id="core"))

        archive = self._archive(
            contributors={"core": {}, "voip": {}},
            counts_by_id={"voip": {"extensions": 48, "pbxes": 2}},
        )
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=False,
            restore_options={},
        )

        summary = report["summary"]
        assert summary["total_errors"] >= 1
        assert summary["contributors_failed"] == 1
        # RestoreJob.items_failed is fed from total_skipped.
        assert summary["total_skipped"] == 50

    @pytest.mark.asyncio
    async def test_deselected_absent_contributor_stays_skipped(
        self, clean_registry, mock_session,
    ) -> None:
        """An operator who deliberately deselected a module must not be
        told it failed -- 'I chose not to restore voip' and 'this instance
        cannot restore voip' are different facts.

        Mutation caught: dropping the ``selected`` guard from the new
        post-loop walk, which would flag every deselected section as an
        error.
        """
        clean_registry.register(_FakeContributor(contributor_id="core"))

        archive = self._archive(contributors={"core": {}, "voip": {}})
        svc = _make_service(mock_session)

        report = await svc._dispatch_restore_via_contributors(
            archive,
            organization_id=uuid4(),
            dry_run=False,
            restore_options={},
            selected_contributors=["core"],
        )

        by_id = {c["contributor_id"]: c for c in report["contributors"]}
        assert by_id["voip"]["status"] == "skipped"
        assert report["summary"]["contributors_failed"] == 0


# ── an incomplete archive must say so ─────────────────────────────────


class TestCollectOmissionsAreRecorded:
    @pytest.mark.asyncio
    async def test_failed_collect_is_recorded_for_the_backup_row(
        self, clean_registry, mock_session,
    ) -> None:
        """``_assemble_backup_archive`` deliberately keeps going when one
        contributor's collect() raises -- one broken module must not block
        a backup of the others. But the reason went only to the log, and
        create_backup still marked the row COMPLETED, so a module that was
        silently absent from the archive looked like a clean backup.

        Mutation caught: dropping the ``self._collect_omissions.append``
        in the except branch (the pre-fix state), which leaves the list
        empty and create_backup with nothing to stamp on
        Backup.error_message.
        """
        clean_registry.register(
            _FakeContributor(
                contributor_id="voip",
                collect_raises=RuntimeError("PBX adapter timeout"),
            )
        )
        clean_registry.register(_FakeContributor(contributor_id="core"))

        svc = _make_service(mock_session)
        archive = await svc._assemble_backup_archive(
            backup_id=uuid4(),
            organization_id=uuid4(),
            options={},
        )

        assert [e.id for e in archive.manifest.contributors] == ["core"]
        assert len(svc._collect_omissions) == 1
        assert "voip" in svc._collect_omissions[0]
        assert "RuntimeError" in svc._collect_omissions[0]
        assert "PBX adapter timeout" not in svc._collect_omissions[0]

    @pytest.mark.asyncio
    async def test_clean_collect_records_no_omission(
        self, clean_registry, mock_session,
    ) -> None:
        """The flag must be per-run, not sticky: a healthy backup taken
        after a broken one must not inherit its warning.

        Mutation caught: initialising ``_collect_omissions`` only in
        __init__ instead of resetting it at the top of every assemble.
        """
        clean_registry.register(_FakeContributor(contributor_id="core"))

        svc = _make_service(mock_session)
        svc._collect_omissions = ["voip (stale run)"]
        await svc._assemble_backup_archive(
            backup_id=uuid4(),
            organization_id=uuid4(),
            options={},
        )
        assert svc._collect_omissions == []

    @pytest.mark.asyncio
    async def test_create_backup_stamps_the_omission_on_the_row(
        self, clean_registry,
    ) -> None:
        """The end the operator sees. Backup.error_message is rendered by the
        catalog card, the list row and the history drawer regardless of status,
        so an archive that is missing a module now says so there instead of
        only in a log file.

        Mutation caught: deleting the ``if self._collect_omissions:`` block in
        create_backup -- the row would go back to COMPLETED with a blank
        error_message while the voip section is absent from the archive.
        """
        from app.modules.backup.models import BackupStatus

        clean_registry.register(
            _FakeContributor(
                contributor_id="voip",
                collect_raises=RuntimeError("PBX adapter timeout"),
            )
        )
        clean_registry.register(_FakeContributor(contributor_id="core"))

        class _Backend:
            def __init__(self):
                self.files = {}

            async def save(self, backup_id, data, filename):
                path = f"/backups/{filename}"
                self.files[path] = data
                return path

            async def load(self, path):
                return self.files[path]

        class _Session:
            def add(self, obj): pass
            async def flush(self): pass
            async def commit(self): pass
            async def refresh(self, obj): pass

        svc = _make_service(_Session())
        svc._resolve_storage = lambda *_a, **_kw: _coro((_Backend(), None))

        backup = await svc.create_backup(
            name="nightly",
            organization_id=uuid4(),
            passphrase="a-long-enough-passphrase",
        )

        assert backup.status == BackupStatus.COMPLETED
        assert backup.error_message
        assert "voip" in backup.error_message
        assert "NOT in this archive" in backup.error_message


async def _coro(value):
    return value


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [ValueError, RuntimeError])
async def test_collect_diagnostics_exclude_exception_text(clean_registry, mock_session, caplog, failure):
    marker = "synthetic-contributor-private-detail-must-not-escape"
    clean_registry.register(_FakeContributor(contributor_id="voip", collect_raises=failure(marker)))
    clean_registry.register(_FakeContributor(contributor_id="core"))
    svc = _make_service(mock_session)
    archive = await svc._assemble_backup_archive(backup_id=uuid4(), organization_id=uuid4(), options={})
    assert [e.id for e in archive.manifest.contributors] == ["core"]
    assert len(svc._collect_omissions) == 1 and "voip" in svc._collect_omissions[0]
    assert marker not in svc._collect_omissions[0]
    assert marker not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [True, False])
async def test_restore_report_excludes_contributor_exception_text(clean_registry, mock_session, caplog, dry_run):
    import json
    marker = "synthetic-contributor-restore-private-detail-must-not-escape"
    clean_registry.register(_FakeContributor(contributor_id="core", restore_raises=RuntimeError(marker)))
    svc = _make_service(mock_session)
    archive = await svc._assemble_backup_archive(backup_id=uuid4(), organization_id=uuid4(), options={})
    report = await svc._dispatch_restore_via_contributors(archive, organization_id=uuid4(), dry_run=dry_run, restore_options={})
    assert report["summary"]["contributors_failed"] == 1
    assert report["summary"]["total_errors"] >= 1
    assert marker not in json.dumps(report)
    assert marker not in caplog.text


@pytest.mark.asyncio
async def test_core_restore_result_excludes_private_exception_text(mock_session, monkeypatch):
    import json
    from dataclasses import asdict
    from unittest.mock import AsyncMock

    from app.services.backup import BackupService
    from app.services.backup_contributors.core import CoreBackupContributor

    marker = "synthetic-core-restore-private-detail-must-not-escape"
    monkeypatch.setattr(BackupService, "_restore_data", AsyncMock(side_effect=RuntimeError(marker)))
    result = await CoreBackupContributor().restore(
        mock_session, uuid4(), ContributorPayload(schema_version="1.0.0", data={}),
        dry_run=True, options={},
    )
    assert result.status == "error" and result.errors
    assert marker not in json.dumps(asdict(result))


@pytest.mark.asyncio
async def test_record_insert_warning_excludes_private_exception_text():
    import json
    from dataclasses import asdict
    from unittest.mock import AsyncMock

    from app.models.core import Organization
    from app.services.backup_contributors.restore_helpers import restore_records

    marker = "synthetic-insert-private-detail-must-not-escape"
    session = MagicMock()
    session.get = AsyncMock(return_value=None)
    session.flush = AsyncMock(side_effect=RuntimeError(marker))
    result = RestoreResult(contributor_id="owned", status="ok")
    restored = await restore_records(
        session, model_cls=Organization,
        records=[{"id": uuid4(), "name": "Owned", "slug": uuid4().hex}],
        result=result, resource="organizations", dry_run=False, overwrite=False,
    )
    assert not restored and result.skipped["organizations"] == 1
    assert result.warnings and "insert failed" in result.warnings[0]
    assert marker not in json.dumps(asdict(result))
