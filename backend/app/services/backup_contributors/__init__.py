# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Backup contributor framework — the foundation for the
enterprise backup/restore chapter.

Public API:

  - ``BackupContributor`` (protocol) — what each module implements
  - ``ContributorPayload`` / ``RestoreResult`` — data carriers
  - ``BackupContributorRegistry`` + ``get_registry()`` — process-wide
    singleton for discovery + dependency-ordered iteration
  - ``BackupManifest`` / ``BackupArchive`` / ``ContributorEntry`` —
    the v2.0 .fsdn payload shape (Pydantic models)
  - ``is_legacy_v1_payload`` / ``wrap_legacy_v1_as_archive`` —
    backwards-compat for reading pre-v2 archives
  - ``is_compatible`` / ``describe_mismatch`` — strict-semver gate
  - ``capture_rollback_slot`` / ``ROLLBACK_BACKUP_TYPE`` — Cisco-
    DNA-style pre-restore snapshot

Concrete contributors (Core, VoIP, Cameras, Firewall) and the
selective-restore UI build on this framework.
"""

from __future__ import annotations

from .core import CoreBackupContributor
from .manifest import (
    BackupArchive,
    BackupManifest,
    ContributorEntry,
    is_legacy_v1_payload,
    wrap_legacy_v1_as_archive,
)
from .protocol import (
    BackupContributor,
    ContributorPayload,
    MigratingContributor,
    RestoreResult,
)
from .registry import (
    BackupContributorRegistry,
    CyclicDependencyError,
    DuplicateContributorError,
    UnknownDependencyError,
    get_registry,
    reset_registry_for_tests,
)
from .restore_helpers import (
    NullableFK,
    RejectGuard,
    restore_records,
)
from .rollback import (
    ROLLBACK_BACKUP_TYPE,
    capture_rollback_slot,
)
from .version import (
    InvalidSchemaVersion,
    describe_mismatch,
    is_compatible,
    parse,
)

__all__ = [
    # Protocol + carriers
    "BackupContributor",
    "CoreBackupContributor",
    "MigratingContributor",
    "ContributorPayload",
    "RestoreResult",
    # Registry
    "BackupContributorRegistry",
    "CyclicDependencyError",
    "DuplicateContributorError",
    "UnknownDependencyError",
    "get_registry",
    "reset_registry_for_tests",
    # Restore primitives (shared by module contributors)
    "NullableFK",
    "RejectGuard",
    "restore_records",
    # Manifest / archive format
    "BackupArchive",
    "BackupManifest",
    "ContributorEntry",
    "is_legacy_v1_payload",
    "wrap_legacy_v1_as_archive",
    # Version compatibility
    "InvalidSchemaVersion",
    "describe_mismatch",
    "is_compatible",
    "parse",
    # Rollback slot
    "ROLLBACK_BACKUP_TYPE",
    "capture_rollback_slot",
]
