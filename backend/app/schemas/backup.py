# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Backup Schemas
=============================

Pydantic v2 schemas for backup management API.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------

# Cap the operator-provided config blob on storage locations. The fields
# inside hold S3/SFTP/FTP non-secret configuration (region, endpoint
# URL, bucket name, path prefix) — values that should realistically be
# <4 KB. Without caps a logged-in admin can stash a 100 MB JSON blob
# inside ``backup.storage_locations.config`` and it will be loaded into
# memory on every list call.
_MAX_CONFIG_KEYS = 32
_MAX_CONFIG_VALUE = 8192

# SECURITY (readiness): keys whose presence in
# ``StorageLocation.config`` (or any future ``storage_config``-shaped
# JSONB field on BackupSchedule) almost certainly indicates the
# operator is trying to stash a plaintext credential in a non-encrypted
# column. Storage backend secrets MUST live in
# ``StorageLocation.encrypted_credentials`` (Fernet-encrypted at the
# service layer via ``app.core.crypto``), never in the plaintext config
# blob — otherwise they surface in pg_dump output, audit-log copies,
# and any superuser-readable SQL query.
#
# The check is substring-based so variants are caught — ``aws_secret``,
# ``client_secret_b64``, ``sftp_password``, ``api_token_v2``, etc.
# Patterns are normalized (no underscores/hyphens, lowercased) before
# comparison so both ``access_key`` and ``AccessKey`` match the same
# rule. Keep entries here in normalized form too.
_CREDENTIAL_KEY_PATTERNS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "privatekey",
        "apikey",
        "accesskey",
        # ``token`` is intentionally broad — catches access_token,
        # refresh_token, api_token, auth_token, bearer_token,
        # service_token, etc. No legitimate storage-config field uses
        # ``token`` (we use endpoint/bucket/region/path/timeout instead).
        "token",
        "clientsecret",
        "servicekey",
        "bearer",
    }
)


def _looks_like_credential_key(key: str) -> bool:
    """True iff ``key``, normalized (lower + strip ``_``/``-``), contains
    any pattern in ``_CREDENTIAL_KEY_PATTERNS``. Catches snake_case,
    PascalCase, and dashed variants (``AccessKey`` /
    ``client_secret_b64`` / ``sftp-password`` / ``access-token-v2``).

    Path / file references are exempt — ``private_key_path``,
    ``credentials_file``, ``api_token_file`` etc. are the documented
    indirection (see ``_validate_private_key_path`` in
    ``services/backup.py``). The actual secret lives in the
    sandboxed file the path points at, not in this config blob.
    """
    normalized = key.lower().replace("_", "").replace("-", "")
    # Allowlist path/file indirection so legitimate backends (SFTP key
    # paths, etc.) keep working.
    if normalized.endswith(("path", "file", "filename", "filepath")):
        return False
    return any(pat in normalized for pat in _CREDENTIAL_KEY_PATTERNS)


def _validate_storage_config(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    if len(v) > _MAX_CONFIG_KEYS:
        raise ValueError(f"config must contain at most {_MAX_CONFIG_KEYS} keys")
    for key, val in v.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("config keys must be strings of <= 128 chars")
        # reject credential-class keys in the plaintext blob.
        # Operators should put these in ``encrypted_credentials`` (Fernet-
        # encrypted at the service layer). This catches honest mistakes
        # and forces the secure path.
        if _looks_like_credential_key(key):
            raise ValueError(
                f"config['{key}'] looks like a credential — store "
                f"credentials in StorageLocation.encrypted_credentials "
                f"(Fernet-encrypted), not in the plaintext config blob. "
                f"Allowed config keys are non-secret backend settings "
                f"like region / endpoint_url / bucket / path."
            )
        # Strings are the common case (URLs, paths). Anything else
        # (bool/int/null) is small so skip length check.
        if isinstance(val, str) and len(val) > _MAX_CONFIG_VALUE:
            raise ValueError(f"config['{key}'] exceeds {_MAX_CONFIG_VALUE} chars")
    return v


# =============================================================================
# Storage Location Schemas
# =============================================================================


def _validate_credentials(v: dict[str, Any] | None) -> dict[str, Any] | None:
    """Validate the explicit credentials blob.

    Unlike ``config``, this field is INTENDED to hold credential-class keys
    (password, access_key, secret_key, …) — they are encrypted by the service
    layer into ``StorageLocation.encrypted_credentials`` (Fernet) and are never
    persisted in plaintext.

    We still enforce a size cap and reject non-string keys to bound the payload.
    We also reject path / file indirection keys here (those belong in ``config``).
    """
    if v is None:
        return v
    if len(v) > _MAX_CONFIG_KEYS:
        raise ValueError(f"credentials must contain at most {_MAX_CONFIG_KEYS} keys")
    for key, val in v.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("credentials keys must be strings of <= 128 chars")
        if isinstance(val, str) and len(val) > _MAX_CONFIG_VALUE:
            raise ValueError(f"credentials['{key}'] exceeds {_MAX_CONFIG_VALUE} chars")
    return v


class StorageLocationCreate(BaseSchema):
    """Create a storage location.

    ``credentials``: explicit, typed credential fields
    (access_key / secret_key / password / token / …).  The service layer
    encrypts them into ``StorageLocation.encrypted_credentials`` (Fernet) so
    they are never stored or echoed in plaintext.  Do NOT put credentials
    inside ``config`` — the validator on that field rejects credential-class
    keys intentionally.
    """

    name: str = Field(..., max_length=128)
    description: str | None = Field(None, max_length=2000)
    storage_type: str = Field(..., max_length=32)
    is_default: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    # Credential-class fields encrypted at the service layer.  Never echoed.
    credentials: dict[str, Any] | None = Field(
        None,
        description=(
            "Sensitive credentials (access_key, secret_key, password, …). "
            "These are Fernet-encrypted server-side into encrypted_credentials "
            "and are NEVER returned in API responses."
        ),
    )

    @field_validator("config")
    @classmethod
    def _cap_config(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_storage_config(v) or {}

    @field_validator("credentials")
    @classmethod
    def _cap_credentials(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_credentials(v)


class StorageLocationUpdate(BaseSchema):
    """Update a storage location.

    ``credentials``: when provided, the supplied dict
    is merged with any existing encrypted credentials (new keys win) and
    re-encrypted.  Pass an empty dict ``{}`` to clear all stored credentials.
    """

    name: str | None = Field(None, max_length=128)
    description: str | None = Field(None, max_length=2000)
    is_active: bool | None = None
    is_default: bool | None = None
    config: dict[str, Any] | None = None
    credentials: dict[str, Any] | None = Field(
        None,
        description=(
            "Credential-class fields to update (Fernet-encrypted server-side). "
            "Never returned in API responses."
        ),
    )

    @field_validator("config")
    @classmethod
    def _cap_config(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_storage_config(v)

    @field_validator("credentials")
    @classmethod
    def _cap_credentials(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_credentials(v)


class StorageLocationResponse(BaseSchema):
    """Storage location response."""

    id: UUID
    name: str
    description: str | None = None
    storage_type: str
    is_active: bool = True
    is_default: bool = False
    last_test_at: datetime | None = None
    last_test_status: str | None = None
    last_test_message: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class StorageLocationTestResult(BaseSchema):
    """Result of testing a storage location."""

    success: bool
    message: str
    latency_ms: float | None = None
    details: dict[str, Any] | None = None


class StorageTypeField(BaseSchema):
    """Field definition for a storage type."""

    name: str
    type: str
    label: str
    required: bool = False
    default: str | None = None
    placeholder: str | None = None


class StorageTypeInfo(BaseSchema):
    """Info about a supported storage type."""

    id: str
    name: str
    description: str
    icon: str
    fields: list[StorageTypeField] = Field(default_factory=list)


class SupportedStorageTypes(BaseSchema):
    """All supported storage types."""

    types: list[StorageTypeInfo] = Field(default_factory=list)


# =============================================================================
# Backup Schemas
# =============================================================================


class BackupCreate(BaseSchema):
    """Create a backup."""

    name: str = Field(..., max_length=128)
    description: str | None = Field(None, max_length=2000)
    backup_type: str = Field("full", max_length=32)
    site_id: UUID | None = None
    # ``device_ids`` capped to keep the IN-list bounded; legitimate
    # device-scoped backups are tens of devices, not thousands.
    device_ids: list[UUID] | None = Field(None, max_length=1000)
    include_devices: bool = True
    include_vlans: bool = True
    include_ssids: bool = True
    include_users: bool = True
    include_automation: bool = True
    storage_type: str = Field("local", max_length=32)
    storage_location_id: UUID | None = None
    # secure-by-default — encryption is ON unless the caller
    # explicitly passes is_encrypted=False.
    is_encrypted: bool = True
    # Secure (Full / .fsdnvault) backup: include ALL secrets — credentials, VPN keys,
    # user logins — sealed under ``passphrase`` (NOT the instance key) so the archive is
    # portable and re-keys onto the target at restore. Requires a passphrase (>=12 chars).
    include_secrets: bool = False
    passphrase: str | None = Field(None, min_length=12, max_length=512)
    retention_days: int = Field(30, ge=1, le=3650)


class BackupResponse(BaseSchema):
    """Backup response."""

    id: UUID
    name: str
    description: str | None = None
    backup_type: str
    status: str
    progress: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    storage_type: str
    storage_location_id: UUID | None = None
    storage_path: str | None = None
    file_size: int | None = None
    site_id: UUID | None = None
    device_ids: list[Any] | None = None
    include_devices: bool = True
    include_vlans: bool = True
    include_ssids: bool = True
    include_users: bool = True
    include_automation: bool = True
    is_encrypted: bool = False
    # True → a Full/secure (.fsdnvault) backup carrying secrets; restore needs a passphrase.
    include_secrets: bool = False
    retention_days: int = 30
    expires_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime
    created_by_id: UUID | None = None
    schedule_id: UUID | None = None
    # Set on auto-captured pre-restore snapshots (backup_type=
    # "rollback_slot") — links the slot to the RestoreJob it preceded so
    # the UI can render an "Undo restore #X" action. NULL on
    # user-created backups.
    rollback_for_restore_job_id: UUID | None = None


class BackupListResponse(BaseSchema):
    """Paginated backup list."""

    items: list[BackupResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20
    pages: int = 0


class BackupStats(BaseSchema):
    """Backup statistics."""

    total_backups: int = 0
    completed_backups: int = 0
    failed_backups: int = 0
    in_progress: int = 0
    total_size_bytes: int = 0
    total_size_gb: float = 0.0
    recent_backups: list[BackupResponse] = Field(default_factory=list)
    schedules_enabled: int = 0
    schedules_disabled: int = 0


# =============================================================================
# Schedule Schemas
# =============================================================================


class BackupScheduleCreate(BaseSchema):
    """Create a backup schedule."""

    name: str = Field(..., max_length=128)
    description: str | None = Field(None, max_length=2000)
    cron_expression: str = Field(..., max_length=256)
    timezone: str = Field("UTC", max_length=64)
    backup_type: str = Field("full", max_length=32)
    site_id: UUID | None = None
    device_ids: list[UUID] | None = Field(None, max_length=1000)
    include_devices: bool = True
    include_vlans: bool = True
    include_ssids: bool = True
    include_users: bool = True
    include_automation: bool = True
    storage_type: str = Field("local", max_length=32)
    storage_location_id: UUID | None = None
    # secure-by-default — encryption is ON unless the caller
    # explicitly passes is_encrypted=False.
    is_encrypted: bool = True
    retention_days: int = Field(30, ge=1, le=3650)
    max_backups: int = Field(10, ge=1, le=1000)

    @field_validator("cron_expression")
    @classmethod
    def _validate_cron(cls, v: str) -> str:
        from app.core.security_utils import validate_cron_expression

        result = validate_cron_expression(v)
        if result is None:
            raise ValueError("Invalid cron expression")
        return result


class BackupScheduleUpdate(BaseSchema):
    """Update a backup schedule."""

    name: str | None = Field(None, max_length=128)
    description: str | None = Field(None, max_length=2000)
    cron_expression: str | None = Field(None, max_length=256)
    timezone: str | None = Field(None, max_length=64)
    backup_type: str | None = Field(None, max_length=32)
    site_id: UUID | None = None
    device_ids: list[UUID] | None = Field(None, max_length=1000)
    include_devices: bool | None = None
    include_vlans: bool | None = None
    include_ssids: bool | None = None
    include_users: bool | None = None
    include_automation: bool | None = None
    storage_type: str | None = Field(None, max_length=32)
    storage_location_id: UUID | None = None
    is_encrypted: bool | None = None
    retention_days: int | None = Field(None, ge=1, le=3650)
    max_backups: int | None = Field(None, ge=1, le=1000)
    is_enabled: bool | None = None

    @field_validator("cron_expression")
    @classmethod
    def _validate_cron(cls, v: str | None) -> str | None:
        if v is not None:
            from app.core.security_utils import validate_cron_expression

            result = validate_cron_expression(v)
            if result is None:
                raise ValueError("Invalid cron expression")
            return result
        return v


class BackupScheduleResponse(BaseSchema):
    """Backup schedule response."""

    id: UUID
    name: str
    description: str | None = None
    cron_expression: str | None = None
    timezone: str = "UTC"
    backup_type: str = "full"
    site_id: UUID | None = None
    device_ids: list[Any] | None = None
    include_devices: bool = True
    include_vlans: bool = True
    include_ssids: bool = True
    include_users: bool = True
    include_automation: bool = True
    storage_type: str = "local"
    storage_location_id: UUID | None = None
    is_encrypted: bool = False
    retention_days: int = 30
    max_backups: int = 10
    is_enabled: bool = True
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime


# =============================================================================
# Restore Schemas
# =============================================================================


class RestoreRequest(BaseSchema):
    """Request to restore from backup."""

    backup_id: UUID
    target_site_id: UUID | None = None
    target_device_ids: list[UUID] | None = Field(None, max_length=1000)
    restore_devices: bool = True
    restore_vlans: bool = True
    restore_ssids: bool = True
    restore_users: bool = False
    restore_automation: bool = True
    overwrite_existing: bool = False
    dry_run: bool = True
    # Selective restore (enterprise backup v2): the subset of manifest
    # contributor ids to restore (e.g. ["core", "voip"]). None = restore
    # every contributor present in the archive. An empty list is rejected
    # (it would be a no-op restore — the caller almost certainly meant
    # None). Unknown ids are ignored by the dispatch (a contributor not
    # in the archive simply reports "missing").
    contributors: list[str] | None = Field(None, max_length=64)
    # Required to restore a Full (.fsdnvault) backup — the operator passphrase the
    # archive was sealed under. Ignored for a config snapshot (.fsdn).
    passphrase: str | None = Field(None, max_length=512)

    @field_validator("contributors")
    @classmethod
    def _reject_empty_selection(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and len(v) == 0:
            raise ValueError(
                "contributors=[] is a no-op restore; omit the field "
                "(or send null) to restore everything in the archive."
            )
        return v


class ContributorPreview(BaseSchema):
    """One contributor's entry in a backup manifest preview."""

    id: str
    schema_version: str
    counts: dict[str, int] = {}
    # Whether the running instance can restore this contributor's data
    # (same schema major). False → the UI shows it greyed-out with a
    # "schema vN.x — incompatible" note.
    restorable: bool = True
    incompatibility_reason: str | None = None


class BackupManifestPreview(BaseSchema):
    """Lightweight preview of a backup's manifest — read WITHOUT a full
    restore so the operator can choose which contributors to restore.

    For v1 (legacy monolithic) archives the manifest is synthesized as a
    single ``core`` contributor so the UI renders uniformly.
    """

    backup_id: UUID
    format_version: str
    created_at: datetime | None = None
    source_version: str | None = None
    organization_id: str | None = None
    contributors: list[ContributorPreview] = []


class RestoreJobResponse(BaseSchema):
    """Restore job response."""

    id: UUID
    backup_id: UUID
    status: str
    progress: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    dry_run: bool = False
    dry_run_report: dict[str, Any] | None = None
    restore_log: dict[str, Any] | None = None
    items_restored: int = 0
    items_failed: int = 0
    created_at: datetime


# =============================================================================
# Export / Import Schemas
# =============================================================================


class ImportResult(BaseSchema):
    """Result of a config import."""

    success: bool = False
    dry_run: bool = True
    would_import: dict[str, Any] | None = None
    imported: dict[str, Any] | None = None
    message: str | None = None
    metadata: dict[str, Any] | None = None
