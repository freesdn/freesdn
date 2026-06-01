# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-restore snapshot ("rollback slot") — one-click undo for restores.

The Cisco DNA Center backup/restore feature lets operators "undo" the
most recent restore by automatically capturing a snapshot of the
current state BEFORE applying the restore. If the restore goes
sideways (data the operator didn't expect to lose, a misclicked
selective-restore, etc.), the rollback slot is restorable via the
same UI as any other backup.

We adopt the same pattern:

1. **Before** the central restore loop runs, ``capture_rollback_slot``
   creates a fresh ``Backup`` row in COMPLETED state holding the
   CURRENT instance's state, tagged ``backup_type="rollback_slot"``
   and linked to the ``RestoreJob`` it preceded via the
   ``rollback_for_restore_job_id`` field.
2. The restore proceeds. Per-module results are recorded on the
   ``RestoreJob``.
3. If the operator clicks "Undo last restore," the UI passes the
   rollback slot's backup_id to ``restore_from_backup`` like any
   other restore. The result is the pre-restore state.

Trade-offs (documented for ops + the audit trail):

- **Storage cost**: rollback slots count against the same retention
  policy as user-created backups. Default retention 7 days, so a
  rollback slot from a botched restore is recoverable for a week.
- **Encryption**: rollback slots are encrypted with the same GPG key
  + Fernet KDF as regular backups. Same blast-radius
  story.
- **No race**: the snapshot is taken with a DB-level snapshot
  (REPEATABLE READ transaction) before the restore loop opens its
  own transaction, so the rollback represents the EXACT pre-restore
  state, not a partially-applied state.

Industry comparison:
  - **Cisco DNA**: "pre-restore backup" auto-captured + retained
    independently of normal backup rotation. Closest to what we do.
  - **pfSense**: relies on the operator's prior manual config-history
    backup (no auto-snapshot). Lower bar.
  - **UniFi**: no pre-restore snapshot; restore is destructive.
  - **TrueNAS**: ZFS snapshot on the boot env before any config
    restore. Belt-and-braces.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.modules.backup.models import Backup, RestoreJob


logger = logging.getLogger(__name__)


# Marker stored on ``Backup.backup_type`` so the catalog UI can group
# / filter rollback slots separately from user-created backups.
# Operators see them in a "Pre-restore snapshots" tab, NOT mixed in
# with their named backups.
ROLLBACK_BACKUP_TYPE = "rollback_slot"


async def capture_rollback_slot(
    session: AsyncSession,
    *,
    organization_id: UUID,
    restore_job: RestoreJob,
    created_by_id: UUID | None,
    retention_days: int = 7,
) -> Backup:
    """Capture the current state as an auto-named rollback slot.

    Called by ``BackupService.restore_from_backup`` right before the
    contributor restore loop opens its transaction. The slot is a
    real ``Backup`` row + a real ``.fsdn`` archive on disk; nothing
    about it is special except the ``backup_type`` marker and the
    link back to the RestoreJob it precedes.

    Args:
      session: Async DB session — used for both the snapshot itself
        and the new Backup row's metadata.
      organization_id: Tenant scope (matches restore_job.organization_id).
      restore_job: The RestoreJob this snapshot is preceding. Used
        to set ``Backup.rollback_for_restore_job_id`` so the catalog
        UI can show "this snapshot was taken before restore #42."
      created_by_id: The operator who triggered the restore (will
        also be credited as the rollback slot's creator for audit).
      retention_days: How long the slot is kept before normal pruning.
        Matches the platform's default backup retention.

    Returns:
      The new Backup row in COMPLETED state, with its archive
      already written to storage.

    Notes for callers:
      - If snapshot creation FAILS, ``restore_from_backup`` should
        bubble the failure to the operator and REFUSE to proceed
        with the restore. A restore without a rollback slot is
        a destructive operation that violates our v1 commitment to
        the operator. A later release may add an opt-out flag for power
        users; v1 is strict.
      - We use the existing ``BackupService.create_backup`` machinery
        so the rollback slot benefits from the same encryption,
        storage, and validate_restore monthly checks as user-created
        backups. No bespoke storage path.
    """
    # Lazy import to avoid a circular dep with BackupService.
    from app.modules.backup.models import Backup
    from app.services.backup import BackupService

    svc = BackupService(session)

    # Human-friendly name: reference the SOURCE backup being restored,
    # not the raw RestoreJob/backup UUIDs (which previously leaked into
    # the operator-visible name — "Pre-restore snapshot — RestoreJob
    # <uuid> (<uuid>)"). The row already shows the capture timestamp, so
    # the name just needs to say what restore it guards. Source name is
    # capped so the combined string stays within Backup.name's 128 chars.
    source = await session.get(Backup, restore_job.backup_id)
    source_name = (source.name if source and source.name else "a backup")[:60]
    name = f'Pre-restore snapshot — before restoring "{source_name}"'
    description = (
        f"Automatic snapshot of the current configuration, captured just "
        f'before restoring "{source_name}". Restore this snapshot to undo '
        f"that restore. Retention: {retention_days} days."
    )

    slot = await svc.create_backup(
        name=name,
        description=description,
        backup_type=ROLLBACK_BACKUP_TYPE,
        # Capture everything — the rollback must be a complete
        # representation of the pre-restore state, not a filtered
        # subset. The operator's restore-time include/exclude flags
        # do NOT apply to the rollback slot.
        include_devices=True,
        include_vlans=True,
        include_ssids=True,
        include_users=True,
        include_automation=True,
        # Same encryption posture as user backups.
        is_encrypted=True,
        retention_days=retention_days,
        organization_id=organization_id,
        created_by_id=created_by_id,
    )
    # Link the slot back to the RestoreJob so the UI can find it
    # without an extra query.
    slot.rollback_for_restore_job_id = restore_job.id
    await session.flush()

    logger.info(
        "rollback slot captured: backup_id=%s for restore_job=%s (retention %dd)",
        slot.id,
        restore_job.id,
        retention_days,
    )
    return slot


__all__ = [
    "ROLLBACK_BACKUP_TYPE",
    "capture_rollback_slot",
]
