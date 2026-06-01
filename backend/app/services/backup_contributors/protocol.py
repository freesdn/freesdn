# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Backup contributor protocol — each module owns its backup contract.

A ``BackupContributor`` is a module-local object that knows how to
``collect()`` its own data into a JSON-serializable payload, and how
to ``restore()`` that payload back into the database. The Backup
service runs registered contributors in dependency-resolved order;
adding a new module's backup support is a self-contained PR, not a
central refactor.

Industry parallel: pfSense's per-package backup hooks; UniFi's
per-service serializers; Cisco DNA Center's per-component archives.
Each module's authors own their own backup shape, version it
independently, and the central archive format stitches them together.

Protocol (not ABC): the contributor is a structural type. Module
authors can implement it on any class — a service-layer class, a
plain dataclass, a singleton. The Registry checks structural
compatibility via ``isinstance(x, BackupContributor)`` (PEP 544 works
because we mark the Protocol as ``@runtime_checkable``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Payload + result types ─────────────────────────────────────────────


@dataclass
class ContributorPayload:
    """The data + metadata a contributor produces during ``collect()``.

    The Backup service stitches these into the archive's per-contributor
    section. The shape inside ``data`` is the contributor's own
    schema — opaque to the central code.
    """

    schema_version: str
    """Strict semver (X.Y.Z) describing the shape of ``data``. Bumped
    on incompatible field changes. See ``version.is_compatible``."""

    counts: dict[str, int] = field(default_factory=dict)
    """Per-resource counts (``{"pbxes": 2, "extensions": 47}``). Exposed
    in the manifest header so operators can preview a backup's contents
    without decrypting + parsing the payload."""

    data: dict[str, Any] = field(default_factory=dict)
    """The actual exportable data. Shape is contributor-defined."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Extras: timestamps, source instance metadata, contributor-
    specific hints. Surfaced verbatim in the manifest."""


@dataclass
class RestoreResult:
    """Per-contributor restore outcome. Aggregated into the overall
    restore report so operators see exactly which modules succeeded,
    which were skipped, and why."""

    contributor_id: str
    status: str
    """One of:
      ``"ok"``              — payload applied successfully.
      ``"dry_run_ok"``      — dry-run validated (no DB writes).
      ``"skipped"``         — operator chose not to include this module.
      ``"schema_mismatch"`` — payload schema major differs from code;
                               restore for this contributor refused.
      ``"missing"``         — backup did not include this contributor.
      ``"error"``           — contributor raised during restore.
    """

    created: dict[str, int] = field(default_factory=dict)
    """Per-resource creation counts. Filled by ``restore()``."""

    updated: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    """Per-resource skip counts. Skipped reasons live in ``warnings``."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    duration_sec: float = 0.0


# ── The protocol ───────────────────────────────────────────────────────


@runtime_checkable
class BackupContributor(Protocol):
    """A module's backup/restore contract.

    Module authors implement this on a class within their module
    (typically ``app/modules/<module>/backup.py``) and expose it via
    their ``BaseModule.get_backup_contributor()`` hook. The Backup
    service discovers contributors through the module registry — no
    global registration code.

    All methods are ``async`` so contributors can do DB I/O. The
    session passed in is the same session as the Backup service's
    own, so contributors share the transaction.
    """

    contributor_id: str
    """Stable identifier for this contributor (``"core"``, ``"voip"``,
    ``"cameras"``, ``"firewall"``). Used to key the manifest, the
    UI checkbox, and the dependency graph. Must be unique across
    all registered contributors. Lowercase, snake_case."""

    schema_version: str
    """Strict semver (X.Y.Z) describing the shape of ``ContributorPayload.data``.
    Bumped on incompatible changes. See ``version.is_compatible``."""

    depends_on: tuple[str, ...]
    """Other contributors that must restore BEFORE this one. E.g. VoIP
    depends on ``("core",)`` because extensions reference sites. The
    registry topologically sorts contributors before passing them to
    the restore loop. Cycles are detected + rejected at registration
    time."""

    default_included: bool
    """Whether this contributor is checked by default in the
    new-backup dialog. ``True`` for the core configuration modules;
    ``False`` for opt-in modules like Hypervisor whose payloads can
    be large (VM definitions)."""

    async def collect(
        self,
        session: AsyncSession,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> ContributorPayload:
        """Read the module's tables for the given org and return a
        JSON-serializable payload.

        Args:
          session: Shared async DB session — read-only for collect.
          organization_id: Tenant scope. The contributor MUST filter
            every query by this org_id to prevent cross-tenant data
            leakage in a multi-tenant deployment.
          options: Operator-supplied flags from the new-backup dialog.
            Common keys: ``site_id`` (single-site backup), ``include_*``
            booleans, contributor-specific knobs. Contributors must
            ignore keys they don't understand.

        Returns:
          The ContributorPayload to embed in the archive.

        Raises:
          Any exception → the Backup service catches it, marks this
          contributor's section as failed in the manifest, and continues
          with other contributors (per-module independence — same
          contract as restore).
        """
        ...

    async def restore(
        self,
        session: AsyncSession,
        organization_id: UUID,
        payload: ContributorPayload,
        *,
        dry_run: bool,
        options: dict[str, Any],
    ) -> RestoreResult:
        """Apply a previously-collected payload into the running
        instance's database.

        Args:
          session: Shared async DB session. The contributor commits
            via ``await session.flush()`` (the central service
            controls the outer transaction / per-module savepoints).
          organization_id: Tenant scope to write into.
          payload: The contributor's section of the backup. The
            central service has already verified
            ``payload.schema_version`` is compatible (same major) via
            ``version.is_compatible``; the contributor only needs to
            handle minor/patch differences within its own major.
          dry_run: If True, validate + count only — do NOT write to
            the database. Used by the monthly validate_restore task
            and the operator's pre-restore preview.
          options: Operator-supplied flags from the restore dialog.

        Returns:
          A ``RestoreResult`` with per-resource counts + any
          per-record errors/warnings.
        """
        ...


# ── Optional migration hook (separate protocol) ────────────────────────


@runtime_checkable
class MigratingContributor(BackupContributor, Protocol):
    """Extends ``BackupContributor`` with a migration hook.

    Contributors that want to support cross-major-schema restores
    implement this protocol instead. The central restore loop checks
    ``isinstance(contrib, MigratingContributor)`` before refusing an
    incompatible-major payload — if the contributor declares
    ``migrate_from``, the loop calls it to convert the old payload to
    the current schema before passing it to ``restore``.

    Most contributors will NOT implement this (and that's fine — a
    major bump means a clean migration release with explicit operator
    action). Provided here so well-funded modules with strong
    backwards-compat needs (e.g. core) can extend it.
    """

    def migrate_from(
        self,
        old_version: str,
        payload: ContributorPayload,
    ) -> ContributorPayload | None:
        """Convert a payload of ``old_version`` (different major) to
        the current ``self.schema_version``. Return ``None`` to refuse
        the conversion (restore skipped with schema_mismatch).

        Implementations should be careful: data lost during a forward
        migration is unrecoverable on restore. When in doubt, return
        ``None`` and require operator action."""
        ...


__all__ = [
    "BackupContributor",
    "ContributorPayload",
    "MigratingContributor",
    "RestoreResult",
]
