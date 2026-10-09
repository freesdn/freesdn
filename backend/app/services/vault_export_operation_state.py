"""Private one-statement operation snapshot; no export route invokes it yet.

Read-only current resolution. No storage constructor, credential decryption,
claim, factor confirmation or archive access. Callers still must consume and
refresh after waits and use the exact checked destination for later I/O.
"""

from __future__ import annotations

import hmac
import json
import math
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from typing import cast as type_cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import Select, String, and_, cast, false, func
from sqlalchemy.sql.elements import KeyedColumnElement

from app.core.backup_artifacts import recorded_identity
from app.core.vault_export_bindings import (
    BackupExportSnapshot,
    ControllerStorageSnapshot,
    StorageDescriptor,
    bind_create_operation,
    bind_download_operation,
    describe_storage,
)
from app.core.vault_export_proof import InvalidVaultProof
from app.core.vault_snapshot_bounds import bounded_snapshot
from app.models.core import Controller, Site
from app.modules.backup.models import Backup, StorageLocation
from app.schemas.backup import BackupCreate
from app.services.vault_export_authority import VaultAuthorityRow, VaultExportAuthority

type DownloadOperation = Literal["download_recorded", "observe_legacy", "download_legacy"]


def _refuse(status: int = 409) -> HTTPException:
    return HTTPException(status, "Vault export operation changed or is unavailable")


def _json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


@dataclass(frozen=True, repr=False)
class ExportIntent:
    operation: Literal["create", "download_recorded", "observe_legacy", "download_legacy"]
    create_json: str | None = None
    backup_id: UUID | None = None
    legacy_acknowledged: bool = False
    observation_json: str | None = None

    @classmethod
    def creation(cls, data: BackupCreate) -> ExportIntent:
        if type(data) is not BackupCreate:
            raise _refuse()
        try:
            checked = BackupCreate.model_validate(data.model_dump(mode="python"))
            if checked.include_secrets is not True or checked.passphrase is None:
                raise _refuse()
            return cls("create", _json(checked.model_dump(mode="json")))
        except Exception:
            raise _refuse() from None

    @classmethod
    def download(
        cls,
        backup_id: UUID | None,
        *,
        operation: str,
        legacy_acknowledged: bool = False,
        observed_identity: dict[str, Any] | None = None,
    ) -> ExportIntent:
        try:
            if not isinstance(backup_id, UUID) or type(legacy_acknowledged) is not bool:
                raise _refuse()
            if operation == "download_recorded":
                if legacy_acknowledged or observed_identity is not None:
                    raise _refuse()
            elif operation == "observe_legacy":
                if not legacy_acknowledged or observed_identity is not None:
                    raise _refuse()
            elif operation == "download_legacy":
                if not legacy_acknowledged:
                    raise _refuse()
                observed_identity = recorded_identity({"artifact_identity": observed_identity})
            else:
                raise _refuse()
            return cls(
                type_cast(DownloadOperation, operation),
                backup_id=UUID(str(backup_id)),
                legacy_acknowledged=legacy_acknowledged,
                observation_json=_json(observed_identity)
                if observed_identity is not None
                else None,
            )
        except Exception:
            raise _refuse() from None

    def checked(self) -> tuple[BackupCreate | None, dict[str, Any] | None]:
        try:
            if self.operation == "create":
                if (
                    self.backup_id is not None
                    or self.legacy_acknowledged is not False
                    or self.observation_json is not None
                ):
                    raise _refuse()
                if type(self.create_json) is not str or len(self.create_json) > 131072:
                    raise _refuse()
                data = BackupCreate.model_validate_json(self.create_json)
                if self != self.creation(data):
                    raise _refuse()
                return data, None
            if self.create_json is not None or (
                self.observation_json is not None
                and (type(self.observation_json) is not str or len(self.observation_json) > 1024)
            ):
                raise _refuse()
            observed = (
                json.loads(self.observation_json) if self.observation_json is not None else None
            )
            if self != self.download(
                self.backup_id,
                operation=self.operation,
                legacy_acknowledged=self.legacy_acknowledged,
                observed_identity=observed,
            ):
                raise _refuse()
            return None, observed
        except Exception:
            raise _refuse() from None


@dataclass(frozen=True, repr=False)
class ServerStoragePlan:
    """Server-only copied configuration; never serialize this as an API response."""

    descriptor: StorageDescriptor
    config_json: str
    encrypted_credentials: str | None
    controller_json: str | None


@dataclass(frozen=True, repr=False)
class ResolvedExportOperation:
    authority: VaultExportAuthority
    intent: ExportIntent
    binding: str
    credential_expires_at: int | None
    storage: ServerStoragePlan
    backup_path: str | None
    legacy_observation_binding: str | None = None
    artifact_identity_json: str | None = None


def _statement(
    authority: VaultExportAuthority, intent: ExportIntent, data: BackupCreate | None
) -> Select[*tuple[Any, ...]]:
    b, loc, ctrl = Backup.__table__, StorageLocation.__table__, Controller.__table__
    requested_site = Site.__table__.alias("vault_requested_site")
    controller_site = Site.__table__.alias("vault_controller_site")
    statement = authority._statement()
    location_id: UUID | KeyedColumnElement[Any] | None
    if data is not None:
        location_id = data.storage_location_id
        statement = statement.outerjoin(b, false()).outerjoin(
            requested_site, requested_site.c.id == data.site_id if data.site_id else false()
        )
    else:
        statement = statement.outerjoin(
            b, and_(b.c.id == intent.backup_id, b.c.organization_id == authority.organization_id)
        ).outerjoin(requested_site, false())
        location_id = b.c.storage_location_id
    statement = statement.outerjoin(
        loc, loc.c.id == location_id if location_id is not None else false()
    )
    # Compare normalized text instead of casting untrusted JSON to UUID. The
    # exact original value is validated by the Python UUID parser before use.
    selected = func.lower(
        func.replace(
            func.replace(func.replace(loc.c.config["controller_id"].astext, "-", ""), "{", ""),
            "}",
            "",
        )
    )
    statement = statement.outerjoin(
        ctrl,
        and_(
            loc.c.storage_type == "truenas",
            func.replace(cast(ctrl.c.id, String), "-", "") == selected,
        ),
    ).outerjoin(controller_site, controller_site.c.id == ctrl.c.site_id)
    statement = statement.add_columns(
        *(
            b.c[name].label("b_" + name)
            for name in (
                "id",
                "organization_id",
                "status",
                "site_id",
                "include_secrets",
                "is_encrypted",
                "storage_type",
                "storage_location_id",
                "storage_path",
                "metadata_json",
            )
        ),
        *(
            loc.c[name].label("s_" + name)
            for name in (
                "id",
                "organization_id",
                "storage_type",
                "is_active",
                "config",
                "encrypted_credentials",
            )
        ),
        *(
            ctrl.c[name].label("c_" + name)
            for name in (
                "id",
                "site_id",
                "controller_type",
                "host",
                "port",
                "use_ssl",
                "verify_ssl",
                "credential_id",
                "config",
                "is_active",
                "deleted_at",
            )
        ),
        requested_site.c.id.label("requested_site_id"),
        requested_site.c.organization_id.label("requested_site_org"),
        requested_site.c.deleted_at.label("requested_site_deleted"),
        controller_site.c.organization_id.label("controller_site_org"),
        controller_site.c.deleted_at.label("controller_site_deleted"),
    )
    return bounded_snapshot(statement)


def _resolve(
    authority: VaultExportAuthority,
    intent: ExportIntent,
    data: BackupCreate | None,
    observed: dict[str, Any] | None,
    row: VaultAuthorityRow | None,
) -> ResolvedExportOperation:
    authority._validate(row)
    row = type_cast(VaultAuthorityRow, row)
    if data is not None:
        if data.site_id is not None and (
            row["requested_site_id"] != data.site_id
            or row["requested_site_org"] != authority.organization_id
            or row["requested_site_deleted"] is not None
        ):
            raise _refuse(404)
        storage_id, storage_type = data.storage_location_id, data.storage_type
        backup_path = None
    else:
        if row["b_id"] != intent.backup_id or row["b_organization_id"] != authority.organization_id:
            raise _refuse(404)
        storage_id, storage_type = row["b_storage_location_id"], row["b_storage_type"]
        backup_path = row["b_storage_path"]
    controller = None
    if storage_id is None:
        config = {"path": "/data/backups"}
        encrypted = None
        location_org = None
        active = True
    else:
        if row["s_id"] != storage_id or row["s_organization_id"] != authority.organization_id:
            raise _refuse(404)
        storage_type = row["s_storage_type"]
        config = row["s_config"]
        encrypted = row["s_encrypted_credentials"]
        location_org = row["s_organization_id"]
        active = row["s_is_active"]
        if storage_type == "truenas":
            controller = ControllerStorageSnapshot(
                row["c_id"],
                row["c_site_id"],
                row["controller_site_org"],
                row["controller_site_deleted"],
                row["c_controller_type"],
                row["c_host"],
                row["c_port"],
                row["c_use_ssl"],
                row["c_verify_ssl"],
                row["c_credential_id"],
                row["c_config"],
                row["c_is_active"],
                row["c_deleted_at"],
            )
    descriptor = describe_storage(
        organization_id=authority.organization_id,
        location_id=storage_id,
        location_organization_id=location_org,
        storage_type=storage_type,
        is_active=active,
        config=config,
        encrypted_credentials=encrypted,
        key=authority.secret_key,
        controller=controller,
    )
    if data is not None:
        binding = bind_create_operation(
            data,
            organization_id=authority.organization_id,
            storage=descriptor,
            key=authority.secret_key,
        )
    else:
        snapshot = BackupExportSnapshot(
            *(
                row["b_" + name]
                for name in (
                    "id",
                    "organization_id",
                    "status",
                    "site_id",
                    "include_secrets",
                    "is_encrypted",
                    "storage_type",
                    "storage_location_id",
                    "storage_path",
                    "metadata_json",
                )
            )
        )
        binding = bind_download_operation(
            snapshot,
            organization_id=authority.organization_id,
            storage=descriptor,
            operation=type_cast(DownloadOperation, intent.operation),
            legacy_acknowledged=intent.legacy_acknowledged,
            observed_identity=observed,
            key=authority.secret_key,
        )
    observation_binding = None
    if data is None and intent.operation in {"observe_legacy", "download_legacy"}:
        observation_binding = bind_download_operation(
            snapshot,
            organization_id=authority.organization_id,
            storage=descriptor,
            operation="observe_legacy",
            legacy_acknowledged=True,
            observed_identity=None,
            key=authority.secret_key,
        )
    # The authority's expiry field is JWT-only. Expiring API keys require the
    # actual current key_expiry from this same snapshot, never a default None.
    expiry = row["key_expiry"] if authority.key_id else authority.expiry
    if isinstance(expiry, datetime):
        if expiry.tzinfo is None:
            raise _refuse()
        expiry = expiry.timestamp()
    if expiry is not None:
        if type(expiry) not in (int, float) or not math.isfinite(expiry):
            raise _refuse()
        expiry = math.floor(expiry)
        if time.time() >= expiry:
            raise _refuse(401)
    elif not authority.key_id:
        raise _refuse(401)
    controller_values = None
    if controller is not None:
        controller_values = {
            name: row["c_" + name]
            for name in (
                "id",
                "site_id",
                "controller_type",
                "host",
                "port",
                "use_ssl",
                "verify_ssl",
                "credential_id",
                "config",
                "is_active",
                "deleted_at",
            )
        }
        for name in ("id", "site_id", "credential_id"):
            if controller_values[name] is not None:
                controller_values[name] = str(controller_values[name])
        controller_values.update(
            organization_id=str(row["controller_site_org"]), site_deleted_at=None
        )
    return ResolvedExportOperation(
        authority,
        intent,
        binding,
        expiry,
        ServerStoragePlan(
            descriptor,
            _json(config),
            encrypted,
            _json(controller_values) if controller_values is not None else None,
        ),
        backup_path,
        observation_binding,
        _json(recorded_identity(row["b_metadata_json"]))
        if data is None and recorded_identity(row["b_metadata_json"]) is not None
        else None,
    )


async def resolve_current_operation(
    authority: VaultExportAuthority, intent: ExportIntent, *, expected_binding: str | None = None
) -> ResolvedExportOperation:
    """One snapshot including authority; no caller transaction or authentication commit."""
    if type(authority) is not VaultExportAuthority or type(intent) is not ExportIntent:
        raise _refuse()
    data, observed = intent.checked()
    if authority.action != ("create" if data is not None else "download"):
        raise _refuse(403)
    if expected_binding is not None and (
        type(expected_binding) is not str or len(expected_binding) != 64
    ):
        raise _refuse()
    try:
        row = await authority._read_owned(_statement(authority, intent, data))
    except Exception:
        await anyio.lowlevel.checkpoint()
        raise _refuse(503) from None
    await anyio.lowlevel.checkpoint()
    try:
        result = _resolve(authority, intent, data, observed, row)
        if expected_binding is not None and not hmac.compare_digest(
            result.binding, expected_binding
        ):
            raise _refuse()
        return result
    except HTTPException:
        raise
    except (InvalidVaultProof, ValueError, TypeError, KeyError):
        raise _refuse() from None
