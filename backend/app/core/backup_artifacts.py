# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Versioned file identities relative to the trusted backup catalog.

Not signatures or fresh secret-export authorization. Historical checksum fields
are deliberately not inputs; only the new server-authored metadata is an anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Literal

from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES

ArtifactState = Literal["recorded", "verified", "legacy_unverified", "invalid"]


class BackupArtifactError(ValueError):
    """Fixed operator-safe diagnostics without archive/provider contents."""


def recorded_identity(metadata: Any) -> dict[str, Any] | None:
    """Absence is legacy; present malformed or unsupported metadata is refused."""
    if type(metadata) is not dict:
        raise BackupArtifactError("Backup archive identity metadata is invalid.")
    if "artifact_identity" not in metadata:
        return None
    value = metadata["artifact_identity"]
    if (
        type(value) is not dict
        or set(value) != {"version", "sha256", "bytes"}
        or type(value.get("version")) is not int
        or value["version"] != 1
        or type(value.get("bytes")) is not int
        or not 0 < value["bytes"] <= MAX_BACKUP_IMPORT_BYTES
        or type(value.get("sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
    ):
        raise BackupArtifactError("Backup archive identity is invalid or unsupported.")
    return dict(value)


def artifact_state(metadata: Any) -> ArtifactState:
    """Describe catalog metadata without asserting that current file bytes match."""
    try:
        return "recorded" if recorded_identity(metadata) is not None else "legacy_unverified"
    except BackupArtifactError:
        return "invalid"


def make_identity(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BACKUP_IMPORT_BYTES:
        raise BackupArtifactError("Backup archive is empty or exceeds its size limit.")
    return {"version": 1, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def verify_identity(data: bytes, expected: dict[str, Any] | None) -> ArtifactState:
    """Check exactly the buffer the caller will use; never upgrade legacy trust."""
    actual = make_identity(data)
    if expected is None:
        return "legacy_unverified"
    # Validate again at this boundary so callers cannot pass a partial identity.
    expected = recorded_identity({"artifact_identity": expected})
    if (
        expected is None
        or expected["bytes"] != actual["bytes"]
        or not hmac.compare_digest(expected["sha256"], actual["sha256"])
    ):
        raise BackupArtifactError("Backup archive does not match its recorded identity.")
    return "verified"
