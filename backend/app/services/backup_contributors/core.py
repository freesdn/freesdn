# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Core backup contributor — sites, controllers, devices, users, automation.

This is the foundational contributor that maps 1:1 to the data shape
the pre-Phase-2 ``BackupService.collect_backup_data`` already
produces. Bringing it into the contributor framework first
demonstrates the protocol is implementable against real
production logic (no abstract toys) and gives us a working baseline
before adding module-specific contributors in Phases 3-5.

Architecture notes:

- This file lives in ``app/services/backup_contributors/`` (next to
  the protocol) rather than in ``app/modules/backup/`` because the
  "core" data set crosses module boundaries — it captures objects
  owned by ``core`` (Sites, Users, Organizations), the Network
  module (Controllers + Devices), and the Automation module's rules.
  No single module owns "core", so it can't be exposed via the
  ``BaseModule.get_backup_contributor()`` discovery hook the way
  module-specific contributors will be. The BackupService registers
  this one explicitly during construction.

- The contributor DELEGATES to ``BackupService.collect_backup_data``
  + ``BackupService._restore_data``. We deliberately do NOT
  re-implement the field-tested logic here; the contributor is
  a protocol-facing wrapper, not a rewrite. Phase 2b's BackupService
  refactor (in a follow-up commit) will invert the relationship:
  ``BackupService.create_backup`` will walk the registry and call
  ``contributor.collect()`` for each, instead of calling
  ``collect_backup_data`` directly. The free function moves no code,
  it just reverses the direction of the call.

- Schema version 1.0.0 corresponds to the data shape produced by
  ``collect_backup_data``: top-level
  ``sites`` / ``controllers`` / ``devices`` / ``users`` /
  ``automation_rules`` keys, each a list of dicts. A future major
  bump means restructuring the dict (renaming keys, changing
  nesting); minor/patch bumps stay backwards-compatible (add
  optional fields only).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

from .protocol import ContributorPayload, RestoreResult

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class CoreBackupContributor:
    """Backup/restore for the core configuration domain.

    Captured: sites, controllers, devices, users, automation rules.
    NOT captured (will move to dedicated contributors in later
    phases): VoIP / Cameras / Firewall / Hypervisor module data,
    audit hash chain, encrypted credential ciphertexts, agent
    registry, plugin install state, sessions / Redis state.
    """

    contributor_id: str = "core"
    schema_version: str = "1.0.0"
    depends_on: tuple[str, ...] = ()
    default_included: bool = True

    async def collect(
        self,
        session: AsyncSession,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> ContributorPayload:
        """Collect core configuration into a portable payload.

        Delegates to ``BackupService.collect_backup_data`` (the
        existing pre-Phase-2 monolithic collector). The returned dict
        is wrapped in a ``ContributorPayload`` with counts derived
        from list lengths for the manifest header preview.

        ``options`` keys understood (others ignored — the protocol
        guarantees forward-compat for unknown keys):
          - ``site_id`` (UUID): single-site backup scope.
          - ``device_ids`` (list[UUID]): device-specific backup.
          - ``include_devices``, ``include_vlans``, ``include_ssids``,
            ``include_users``, ``include_automation`` (bool): per-
            category opt-outs from the new-backup dialog. Default
            True except for explicit overrides.
        """
        # Lazy import to break the cycle between BackupService and
        # the contributor framework. Both live in app/services/ but
        # the contributor framework is a sibling package — importing
        # BackupService here at call time (not module top) is safe.
        from app.services.backup import BackupService

        svc = BackupService(session)
        # collect_backup_data raises ValueError if organization_id is
        # missing — explicit is better than inferred for tenant scope.
        raw = await svc.collect_backup_data(
            site_id=options.get("site_id"),
            device_ids=options.get("device_ids"),
            include_devices=options.get("include_devices", True),
            include_vlans=options.get("include_vlans", True),
            include_ssids=options.get("include_ssids", True),
            include_users=options.get("include_users", True),
            include_automation=options.get("include_automation", True),
            include_secrets=options.get("include_secrets", False),
            organization_id=organization_id,
        )

        # ``collect_backup_data`` wraps the real content under a ``data``
        # key inside an envelope (version / schema_version / created_at /
        # freesdn_version / organization_id). Unwrap it so the
        # contributor payload carries the FLAT
        # {sites, controllers, devices, users, automation_rules} that
        # ``_restore_data`` consumes — and so the manifest counts reflect
        # real resources, not the 6 envelope keys.
        #
        # This unwrap is the other half of the live-verification fix: the
        # mocked unit tests faked a flat dict, so they never exercised the
        # envelope and ``restore`` would otherwise have fed the whole
        # envelope to ``_restore_data`` (which reads top-level
        # ``sites``/``controllers``/… keys) and silently restored nothing.
        data = raw.get("data", raw) if isinstance(raw, dict) else raw
        if not isinstance(data, dict):
            data = {}

        # Manifest-facing counts. Anything that's a list surfaces its
        # length; anything non-null that's not a list is reported as
        # 1 (covers ``settings`` blocks). Missing keys are omitted —
        # the manifest doesn't need to advertise empty resources.
        counts: dict[str, int] = {}
        for key, value in data.items():
            if isinstance(value, list):
                counts[key] = len(value)
            elif value is not None:
                counts[key] = 1

        return ContributorPayload(
            schema_version=self.schema_version,
            counts=counts,
            data=data,
            metadata={
                "captured_at": time.time(),
                "source": "core_contributor.collect",
                # Preserve the source envelope's version for provenance.
                "source_envelope_version": (raw.get("version") if isinstance(raw, dict) else None),
            },
        )

    async def restore(
        self,
        session: AsyncSession,
        organization_id: UUID,
        payload: ContributorPayload,
        *,
        dry_run: bool,
        options: dict[str, Any],
    ) -> RestoreResult:
        """Apply a previously-collected core payload back to the DB.

        Delegates to ``BackupService._restore_data`` (the existing
        pre-Phase-2 restore walker, which already enforces the
        tenant-isolation invariants: cross-org records are
        rejected, ``organization_id`` is forced on every insert,
        sensitive fields like ``hashed_password`` / ``role`` /
        ``is_superuser`` are blocked on both update + insert).

        The per-model dict it returns (``{"sites": {"created": N,
        "updated": N, "skipped": N, "rejected_cross_org": N}, ...}``)
        is aggregated into the contributor protocol's
        ``RestoreResult`` shape with per-resource counts the
        operator-visible restore report consumes.

        ``options`` keys understood:
          - ``overwrite_existing`` (bool, default False): update
            rows that already exist; otherwise skipped.
          - ``restore_devices`` (bool, default True): include the
            devices subset of the restore.
          - ``restore_users`` (bool, default False): include users.
            Default OFF because users can carry MFA + session state
            the operator may not want overwritten.
        """
        from app.services.backup import BackupService

        svc = BackupService(session)
        svc.org_id = organization_id

        start = time.monotonic()

        try:
            per_model = await svc._restore_data(
                payload.data,
                dry_run=dry_run,
                overwrite_existing=options.get("overwrite_existing", False),
                restore_devices=options.get("restore_devices", True),
                restore_users=options.get("restore_users", False),
                include_secrets=options.get("include_secrets", False),
            )
        except Exception as exc:
            return RestoreResult(
                contributor_id=self.contributor_id,
                status="error",
                errors=[f"core restore raised: {exc}"],
                duration_sec=time.monotonic() - start,
            )

        # Aggregate per-model counts → per-resource RestoreResult counts.
        # The existing _restore_data returns ``rejected_cross_org`` as a
        # separate sub-count; we surface that as a warning rather than
        # a skip so operators clearly see tenant-isolation events.
        created: dict[str, int] = {}
        updated: dict[str, int] = {}
        skipped: dict[str, int] = {}
        warnings: list[str] = []

        for resource, counts in per_model.items():
            if not isinstance(counts, dict):
                # _restore_data should always return dict-of-dict, but
                # be defensive in case a future caller changes the shape.
                continue
            created[resource] = counts.get("created", 0)
            updated[resource] = counts.get("updated", 0)
            skipped[resource] = counts.get("skipped", 0)
            if counts.get("rejected_cross_org"):
                warnings.append(
                    f"{counts['rejected_cross_org']} {resource} record(s) "
                    f"rejected as cross-tenant (NOT restored). This is a "
                    f"normal outcome when restoring a backup taken on a "
                    f"different organization."
                )

        return RestoreResult(
            contributor_id=self.contributor_id,
            status="dry_run_ok" if dry_run else "ok",
            created=created,
            updated=updated,
            skipped=skipped,
            warnings=warnings,
            duration_sec=time.monotonic() - start,
        )


__all__ = ["CoreBackupContributor"]
