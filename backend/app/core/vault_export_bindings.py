"""Private operation descriptors, not authentication or database authority.

Callers supply fresh server-read rows, never client-selected storage snapshots.
These functions do no SQL, secret collection or storage I/O. Endpoint callers
must independently enforce freshness, one-use claims and post-wait checks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from app.core.backup_artifacts import recorded_identity
from app.core.vault_export_proof import InvalidVaultProof, bind_export_value
from app.modules.backup.models import BackupStorageType
from app.schemas.backup import BackupCreate

_STORAGE_TYPES = frozenset(x.value for x in BackupStorageType) | {"truenas"}
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_MAX_STORAGE_BYTES = 4 * 1024 * 1024


def _invalid() -> InvalidVaultProof:
    return InvalidVaultProof("Vault export operation is invalid or changed")


def _uuid(value: Any) -> str:
    # Copy asyncpg UUID subclasses without accepting arbitrary request strings.
    if not isinstance(value, UUID):
        raise _invalid()
    return str(UUID(str(value)))


def _storage_commitment(value: dict[str, Any], key: bytes) -> str:
    """Bound complete current destination values, including finite JSON floats.

    The ordinary request commitment intentionally rejects floats. Storage
    settings can contain fractional timeouts; encode their complete JSON with
    fixed ordering instead of omitting or lossy-coercing them. The 4MiB budget
    covers the declared flat config/credential maxima including UTF-8 and
    encrypted credential expansion. Pathological nested historical rows refuse.
    """
    if type(key) is not bytes or len(key) < 32:
        raise _invalid()
    nodes = 0

    def check(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 10000 or depth > 8:
            raise _invalid()
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise _invalid()
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise _invalid()
            return
        if type(item) is str:
            if len(item) > 2 * 1024 * 1024:
                raise _invalid()
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict:
            for name, child in item.items():
                if type(name) is not str or len(name) > 128:
                    raise _invalid()
                check(child, depth + 1)
            return
        raise _invalid()

    check(value, 0)
    digest = hmac.new(key, b"FreeSDN/vault-export/storage-snapshot/v1\x00", hashlib.sha256)
    total = 0
    encoder = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        total += len(encoded)
        if total > _MAX_STORAGE_BYTES:
            raise _invalid()
        digest.update(encoded)
    return digest.hexdigest()


@dataclass(frozen=True, repr=False)
class ControllerStorageSnapshot:
    id: UUID
    site_id: UUID
    site_organization_id: UUID
    site_deleted_at: object
    controller_type: str
    host: str
    port: int
    use_ssl: bool
    verify_ssl: bool
    credential_id: UUID | None
    config: dict[str, Any]
    is_active: bool
    deleted_at: object


def _controller_value(
    controller: ControllerStorageSnapshot | None, config: dict[str, Any], org: str
) -> dict[str, Any]:
    # TrueNAS resolves credentials through this record. Its organization belongs
    # to Site, not a nonexistent Controller.organization_id column/property.
    if type(controller) is not ControllerStorageSnapshot:
        raise _invalid()
    try:
        selected = UUID(str(config.get("controller_id")))
    except (ValueError, TypeError, AttributeError):
        raise _invalid() from None
    if (
        _uuid(controller.id) != str(selected)
        or _uuid(controller.site_organization_id) != org
        or controller.site_deleted_at is not None
        or controller.deleted_at is not None
        or controller.is_active is not True
        or controller.controller_type != "truenas"
        or type(controller.host) is not str
        or not 1 <= len(controller.host) <= 255
        or type(controller.port) is not int
        or not 1 <= controller.port <= 65535
        or type(controller.use_ssl) is not bool
        or type(controller.verify_ssl) is not bool
        or type(controller.config) is not dict
    ):
        raise _invalid()
    return {
        "id": _uuid(controller.id),
        "site_id": _uuid(controller.site_id),
        "organization": org,
        "site_deleted_at": None,
        "controller_type": controller.controller_type,
        "host": controller.host,
        "port": controller.port,
        "use_ssl": controller.use_ssl,
        "verify_ssl": controller.verify_ssl,
        "credential_id": _uuid(controller.credential_id)
        if controller.credential_id is not None
        else None,
        "config": controller.config,
        "is_active": True,
        "deleted_at": None,
    }


@dataclass(frozen=True, repr=False)
class StorageDescriptor:
    organization_id: UUID
    location_id: UUID | None
    storage_type: str
    commitment: str


def describe_storage(
    *,
    organization_id: UUID,
    location_id: UUID | None,
    location_organization_id: UUID | None,
    storage_type: str,
    is_active: bool,
    config: dict[str, Any],
    encrypted_credentials: str | None,
    key: bytes,
    controller: ControllerStorageSnapshot | None = None,
) -> StorageDescriptor:
    """Commit an explicit current row, or the service's exact default location."""
    try:
        org = _uuid(organization_id)
        if (
            type(storage_type) is not str
            or storage_type not in _STORAGE_TYPES
            or is_active is not True
        ):
            raise _invalid()
        if type(config) is not dict or (
            encrypted_credentials is not None and type(encrypted_credentials) is not str
        ):
            raise _invalid()
        if location_id is None:
            if (
                location_organization_id is not None
                or config != {"path": "/data/backups"}
                or encrypted_credentials is not None
            ):
                raise _invalid()
            location = None
        else:
            location = _uuid(location_id)
            if _uuid(location_organization_id) != org:
                raise _invalid()
        values = {
            "organization": org,
            "location": location,
            "storage_type": storage_type,
            "active": True,
            "config": config,
            "encrypted_credentials": encrypted_credentials,
        }
        if storage_type == "truenas":
            if location is None:
                raise _invalid()
            values["controller"] = _controller_value(controller, config, org)
        elif controller is not None:
            raise _invalid()
        digest = _storage_commitment(values, key)
        return StorageDescriptor(
            UUID(org), UUID(location) if location else None, storage_type, digest
        )
    except Exception:
        raise _invalid() from None


def _storage(storage: StorageDescriptor, org: UUID, location_id: UUID | None) -> dict[str, Any]:
    if (
        type(storage) is not StorageDescriptor
        or _uuid(storage.organization_id) != _uuid(org)
        or storage.location_id != location_id
        or type(storage.commitment) is not str
        or _HEX.fullmatch(storage.commitment) is None
        or storage.storage_type not in _STORAGE_TYPES
    ):
        raise _invalid()
    return {
        "location": _uuid(location_id) if location_id is not None else None,
        "effective_storage_type": storage.storage_type,
        "commitment": storage.commitment,
    }


def bind_create_operation(
    data: BackupCreate,
    *,
    organization_id: UUID,
    storage: StorageDescriptor,
    key: bytes,
) -> str:
    try:
        if type(data) is not BackupCreate:
            raise _invalid()
        # Revalidate model_construct/mutation; never trust a type alone.
        checked = BackupCreate.model_validate(data.model_dump(mode="python"))
        if checked.include_secrets is not True or checked.passphrase is None:
            raise _invalid()
        if checked.storage_type not in _STORAGE_TYPES:
            raise _invalid()
        destination = _storage(storage, organization_id, checked.storage_location_id)
        if storage.location_id is None and checked.storage_type != storage.storage_type:
            raise _invalid()
        return bind_export_value(
            {
                "descriptor": "freesdn-vault-create-v1",
                "operation": "create",
                "organization": _uuid(organization_id),
                "request": checked.model_dump(mode="json"),
                "destination": destination,
                "effective_is_encrypted": True,
            },
            key=key,
            domain="request",
        )
    except Exception:
        raise _invalid() from None


@dataclass(frozen=True, repr=False)
class BackupExportSnapshot:
    id: UUID
    organization_id: UUID
    status: str
    site_id: UUID | None
    include_secrets: bool
    is_encrypted: bool
    storage_type: str
    storage_location_id: UUID | None
    storage_path: str
    metadata_json: dict[str, Any]


def bind_download_operation(
    snapshot: BackupExportSnapshot,
    *,
    organization_id: UUID,
    storage: StorageDescriptor,
    operation: Literal["download_recorded", "observe_legacy", "download_legacy"],
    legacy_acknowledged: bool,
    observed_identity: dict[str, Any] | None,
    key: bytes,
) -> str:
    """An observed legacy digest never becomes a recorded historical anchor."""
    try:
        if type(snapshot) is not BackupExportSnapshot or _uuid(snapshot.organization_id) != _uuid(
            organization_id
        ):
            raise _invalid()
        if (
            snapshot.status != "completed"
            or snapshot.include_secrets is not True
            or type(snapshot.is_encrypted) is not bool
        ):
            raise _invalid()
        if type(snapshot.storage_type) is not str or snapshot.storage_type not in _STORAGE_TYPES:
            raise _invalid()
        if type(snapshot.storage_path) is not str or not 1 <= len(snapshot.storage_path) <= 512:
            raise _invalid()
        destination = _storage(storage, organization_id, snapshot.storage_location_id)
        if storage.location_id is None and snapshot.storage_type != storage.storage_type:
            raise _invalid()
        recorded = recorded_identity(snapshot.metadata_json)
        if type(legacy_acknowledged) is not bool:
            raise _invalid()
        if operation == "download_recorded":
            if recorded is None or legacy_acknowledged or observed_identity is not None:
                raise _invalid()
        elif operation in {"observe_legacy", "download_legacy"}:
            if recorded is not None or not legacy_acknowledged:
                raise _invalid()
            if operation == "observe_legacy":
                if observed_identity is not None:
                    raise _invalid()
            else:
                # Same structural file identity, explicitly a current observation.
                observed_identity = recorded_identity({"artifact_identity": observed_identity})
        else:
            raise _invalid()
        return bind_export_value(
            {
                "descriptor": "freesdn-vault-download-v1",
                "operation": operation,
                "organization": _uuid(organization_id),
                "backup": _uuid(snapshot.id),
                "status": snapshot.status,
                "site": _uuid(snapshot.site_id) if snapshot.site_id is not None else None,
                "include_secrets": True,
                "is_encrypted": snapshot.is_encrypted,
                "storage_type": snapshot.storage_type,
                "locator": snapshot.storage_path,
                "destination": destination,
                "recorded_identity": recorded,
                "legacy_acknowledged": legacy_acknowledged,
                "observed_identity": observed_identity,
            },
            key=key,
            domain="artifact",
        )
    except Exception:
        raise _invalid() from None
