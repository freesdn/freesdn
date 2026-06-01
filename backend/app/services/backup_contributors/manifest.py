# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Backup manifest — the JSON header that describes a ``.fsdn`` archive.

The manifest is the first thing read on restore, BEFORE decrypting the
payload. It carries enough metadata that:

- The restore UI can preview a backup's contents (which modules,
  what counts) without prompting the operator for the encryption
  passphrase yet.
- The schema-version check happens up-front per contributor — an
  incompatible-major contributor is identified BEFORE its data is
  decrypted + parsed.
- Cross-instance restores (taking a backup from instance A and
  restoring on instance B) carry enough provenance to be auditable.

Industry parallel:
  - pfSense's ``<version>`` element at the top of config.xml.
  - UniFi's ``meta.json`` inside the .unf tarball.
  - TrueNAS's ``manifest`` block in the config save.

File format v2.0 introduces this header alongside the legacy
top-level keys (sites, controllers, ...). Old v1 archives without
a manifest are still readable via a backwards-compat path that
treats them as a single ``core`` contributor payload.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ContributorEntry(BaseModel):
    """One contributor's metadata inside the manifest. The actual
    payload data lives in ``BackupArchive.contributors[<id>]``; this
    entry is the lightweight header description."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable contributor_id (e.g. 'core').")
    schema_version: str = Field(
        ...,
        description="Strict semver of the payload shape (e.g. '1.0.0').",
    )
    counts: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Per-resource counts surfaced in the UI restore preview (read by parsing "
            "the archive — which is decrypted first when the backup is encrypted)."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Contributor-specific extras (timestamps, hints).",
    )


class BackupManifest(BaseModel):
    """Top-level manifest written at the start of every v2.0+ .fsdn payload.

    It rides INSIDE the (optionally encrypted) payload alongside the
    contributor data — NOT the outer file header, which carries only
    backup_id / checksum / encrypted / version. The restore UI's preview
    therefore parses the archive, decrypting it first when the backup is
    encrypted. The manifest itself holds no secrets — only schema_versions
    and per-resource counts.
    """

    model_config = ConfigDict(extra="forbid")

    manifest_version: str = Field(
        "1.0",
        description=("Version of THIS manifest schema (not the contributor payloads inside)."),
    )
    format_version: str = Field(
        "2.0",
        description=(
            ".fsdn archive format version. v1.x = legacy monolithic; "
            "v2.0 = manifest + per-contributor payloads."
        ),
    )
    backup_id: str = Field(..., description="Source-instance Backup.id (UUID).")
    created_at: datetime
    source_instance_id: str | None = Field(
        None,
        description=(
            "Stable identifier for the FreeSDN instance that created "
            "the backup. ``None`` if the instance hasn't generated "
            "one yet (early deployments)."
        ),
    )
    source_version: str | None = Field(
        None,
        description=(
            "FreeSDN software version (CalVer, e.g. '26.05.0') at the "
            "time of backup. Diagnostic only — schema compat is per-"
            "contributor, not whole-archive."
        ),
    )
    organization_id: str
    contributors: list[ContributorEntry] = Field(
        default_factory=list,
        description=(
            "One entry per contributor whose data is included in this "
            "archive. Order is the order they were collected (which is "
            "the dependency-resolved order — see registry.topological)."
        ),
    )


class BackupArchive(BaseModel):
    """The fully-decoded shape of a v2.0+ archive's PAYLOAD (i.e. what
    sits inside the file's encrypted+compressed section, AFTER the
    outer file header is parsed).

    The outer ``.fsdn`` file format is unchanged:

      [4-byte BE header_len][header JSON][compressed (encrypted?) payload]

    For v2.0+ the OUTER header still carries ``checksum`` /
    ``encrypted`` / ``compressed`` / ``version`` etc. (so existing
    BackupService decode logic still parses it), AND the decoded
    PAYLOAD is now a ``BackupArchive`` JSON object instead of the
    legacy monolithic dict.

    Legacy v1 payloads (the old monolithic dict with top-level
    ``sites`` / ``controllers`` / ``devices`` / ``users`` /
    ``automation`` keys) are detected at decode time by the absence
    of a ``manifest`` key, and converted on the fly into a synthetic
    BackupArchive with a single ``core`` contributor section.
    """

    model_config = ConfigDict(extra="forbid")

    manifest: BackupManifest
    contributors: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description=(
            "Per-contributor data payloads keyed by contributor_id. "
            "Each value is a ContributorPayload's ``.data`` field — "
            "the shape is contributor-defined. Schema_version + counts "
            "live in the manifest entry, NOT duplicated here."
        ),
    )


def is_legacy_v1_payload(decoded: dict[str, Any]) -> bool:
    """True iff ``decoded`` (the parsed JSON payload) is a pre-v2 backup
    — i.e. anything that is NOT the v2 ``{manifest, contributors}`` shape
    but still carries restorable core content.

    Two real pre-v2 shapes are recognized (the second was the actual
    production format — the original Phase-1 detector only handled the
    first, so restoring a genuine pre-chapter ``.fsdn`` crashed in
    ``BackupArchive.model_validate``; surfaced by live verification):

      1. **Flat**: top-level ``sites`` / ``controllers`` / … keys.
      2. **Enveloped** (the real ``collect_backup_data`` output):
         ``{version, schema_version, created_at, freesdn_version,
         organization_id, data:{sites, controllers, …}}`` — detected by
         the presence of a ``data`` dict alongside ``schema_version``
         (and no ``manifest``).
    """
    if not isinstance(decoded, dict):
        return False
    if "manifest" in decoded:
        return False  # v2 contributor format
    # Enveloped pre-v2: a ``data`` dict with the old ``schema_version``.
    if isinstance(decoded.get("data"), dict) and "schema_version" in decoded:
        return True
    # Flat pre-v2: top-level resource keys.
    return any(k in decoded for k in ("sites", "controllers", "devices", "users", "automation"))


def _unwrap_legacy_content(legacy_payload: dict[str, Any]) -> dict[str, Any]:
    """Return the flat resource dict from either pre-v2 shape: the inner
    ``data`` for the enveloped format, or the payload itself for the flat
    format. Matches what ``CoreBackupContributor.restore`` →
    ``_restore_data`` expects (top-level ``sites``/``controllers``/…)."""
    inner = legacy_payload.get("data")
    if isinstance(inner, dict):
        return inner
    return legacy_payload


def wrap_legacy_v1_as_archive(
    legacy_payload: dict[str, Any],
    *,
    backup_id: str,
    created_at: datetime,
    organization_id: str,
) -> BackupArchive:
    """Convert a legacy v1 payload (flat OR enveloped) into a synthetic
    ``BackupArchive`` with a single ``core`` contributor section.

    Lets the v2 restore loop handle old + new archives uniformly
    without a separate code path. The ``core`` contributor's
    ``schema_version`` is reported as ``"1.0.0"`` so it routes through
    the same compatibility check as a freshly-created v2 archive's
    core section.
    """
    # Unwrap the enveloped format down to the flat resource dict so the
    # core contributor's restore (→ _restore_data) reads top-level
    # sites/controllers/… exactly as it does for a freshly-collected v2
    # core section.
    content = _unwrap_legacy_content(legacy_payload)
    return BackupArchive(
        manifest=BackupManifest(
            backup_id=backup_id,
            created_at=created_at,
            organization_id=organization_id,
            contributors=[
                ContributorEntry(
                    id="core",
                    schema_version="1.0.0",
                    counts={
                        # Best-effort counts from the legacy shape.
                        # Missing keys → 0.
                        k: len(content.get(k, []))
                        for k in ("sites", "controllers", "devices", "users", "automation_rules")
                        if isinstance(content.get(k), list)
                    },
                    metadata={"legacy_v1": True},
                ),
            ],
        ),
        contributors={"core": content},
    )


__all__ = [
    "BackupArchive",
    "BackupManifest",
    "ContributorEntry",
    "is_legacy_v1_payload",
    "wrap_legacy_v1_as_archive",
]
