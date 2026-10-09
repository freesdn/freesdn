# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bind catalogue downloads to fresh, read-only authority before delivery.

This is not fresh secret-export authentication. Each check has one database
snapshot and no row locks or caller commits. Its read is the authorization
boundary: revocation cannot retract bytes after delivery has begun.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from sqlalchemy import and_, exists, false, or_, select

from app.core.backup_artifacts import BackupArtifactError, recorded_identity
from app.core.dependencies import CurrentUser, is_unscoped_org_admin
from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User, UserSession
from app.modules.backup.models import Backup, StorageLocation
from app.services.backup import BackupService, BackupStorageBackend, get_storage_backend


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _backup_binding(backup: Any) -> tuple[Any, ...]:
    return (
        backup.id,
        backup.organization_id,
        backup.status,
        backup.site_id,
        backup.include_secrets,
        backup.storage_type,
        backup.storage_location_id,
        backup.storage_path,
        _digest(recorded_identity(backup.metadata_json)),
    )


@dataclass(frozen=True, repr=False)
class BackupDownloadAuthority:
    """Only copied identifiers, ceilings and digests; no raw token/session/ORM."""

    actor_id: UUID
    organization_id: UUID
    role: str
    password_digest: str = field(repr=False)
    token_version: int
    backup_binding: tuple[Any, ...] = field(repr=False)
    key_id: UUID | None = None
    key_digest: str | None = field(default=None, repr=False)
    jti: str | None = field(default=None, repr=False)
    expiry: float | None = None
    storage_binding: str | None = field(default=None, repr=False)

    @classmethod
    async def start(
        cls, request: Request, user: CurrentUser, backup: Backup
    ) -> tuple[BackupDownloadAuthority, BackupStorageBackend]:
        if not is_unscoped_org_admin(user) or user.organization_id is None:
            raise HTTPException(403, "Admin required")
        account = user.user
        version = account.token_version
        if type(version) is not int or not 0 <= version <= 2147483647:
            raise HTTPException(401, "Download authorization ended")
        claims = user.token_claims
        key_id, key_digest, jti, expiry = None, None, None, None
        if claims.get("auth_method") == "api_key":
            raw = request.headers.get("X-API-Key")
            try:
                key_id = UUID(claims["key_id"])
            except (KeyError, ValueError, TypeError, AttributeError):
                raise HTTPException(401, "Download authorization ended") from None
            if not raw:
                raise HTTPException(401, "Download authorization ended")
            # Bind the credential which actually authenticated this request,
            # never a replacement digest observed by a later database read.
            key_digest = hashlib.sha256(raw.encode()).hexdigest()
        else:
            expiry = claims.get("exp")
            if (
                claims.get("type") != "access"
                or claims.get("scope")
                or claims.get("sub") != str(account.id)
                or claims.get("tv", 0) != version
                or type(expiry) not in (float, int)
                or not math.isfinite(cast(float, expiry))
            ):
                raise HTTPException(401, "Download authorization ended")
            jti = claims.get("jti")
            if jti is not None and (not isinstance(jti, str) or not 1 <= len(jti) <= 1024):
                raise HTTPException(401, "Download authorization ended")
        initial = cls(
            account.id,
            user.organization_id,
            user.role,
            hashlib.sha256(account.hashed_password.encode()).hexdigest(),
            version,
            _backup_binding(backup),
            key_id,
            key_digest,
            jti,
            expiry,
        )
        row = await initial._current()
        initial._validate(row)
        storage_binding = initial._storage_fingerprint(row)
        # Resolve exactly this checked storage snapshot, without a second ORM
        # lookup which could silently adopt an intervening destination change.
        if row.storage_id is None:
            storage_type, config = row.backup_storage_type, {"path": "/data/backups"}
        else:
            storage_type = row.storage_type
            config = BackupService._storage_config(
                SimpleNamespace(
                    config=row.storage_config,
                    encrypted_credentials=row.storage_credentials,
                    storage_type=storage_type,
                    organization_id=row.storage_org,
                )
            )
        authority = cls(
            initial.actor_id,
            initial.organization_id,
            initial.role,
            initial.password_digest,
            initial.token_version,
            initial.backup_binding,
            key_id,
            key_digest,
            jti,
            expiry,
            storage_binding,
        )
        return authority, get_storage_backend(storage_type, config)

    async def _current(self) -> Any:
        """One statement, a new bounded session, no auth last_used commit."""
        jti_hash = hashlib.sha256(self.jti.encode()).hexdigest() if self.jti else None
        revoked_jti = exists().where(TokenRevocation.jti_hash == jti_hash) if jti_hash else false()
        revoked_session = (
            exists().where(
                UserSession.access_jti == self.jti,
                or_(UserSession.is_revoked.is_(True), UserSession.revoked_at.is_not(None)),
            )
            if self.jti
            else false()
        )
        statement = (
            select(
                User.id.label("actor_id"),
                User.organization_id.label("actor_org"),
                User.role.label("actor_role"),
                User.hashed_password.label("actor_password"),
                User.token_version.label("actor_version"),
                User.is_active.label("actor_active"),
                User.deleted_at.label("actor_deleted"),
                Backup.id.label("backup_id"),
                Backup.organization_id.label("backup_org"),
                Backup.status.label("backup_status"),
                Backup.site_id.label("backup_site"),
                Backup.include_secrets.label("backup_secrets"),
                Backup.storage_type.label("backup_storage_type"),
                Backup.storage_location_id.label("backup_storage_id"),
                Backup.storage_path.label("backup_path"),
                Backup.metadata_json.label("backup_metadata"),
                StorageLocation.id.label("storage_id"),
                StorageLocation.organization_id.label("storage_org"),
                StorageLocation.is_active.label("storage_active"),
                StorageLocation.storage_type.label("storage_type"),
                StorageLocation.config.label("storage_config"),
                StorageLocation.encrypted_credentials.label("storage_credentials"),
                APIKey.id.label("key_id"),
                APIKey.user_id.label("key_owner"),
                APIKey.key_hash.label("key_digest"),
                APIKey.is_active.label("key_active"),
                APIKey.scopes.label("key_scopes"),
                APIKey.expires_at.label("key_expiry"),
                revoked_jti.label("revoked_jti"),
                revoked_session.label("revoked_session"),
            )
            .select_from(User)
            .outerjoin(
                Backup,
                and_(
                    Backup.id == self.backup_binding[0],
                    Backup.organization_id == self.organization_id,
                ),
            )
            .outerjoin(StorageLocation, StorageLocation.id == Backup.storage_location_id)
            .outerjoin(APIKey, APIKey.id == self.key_id if self.key_id else false())
            .where(User.id == self.actor_id)
        )
        try:
            row = await self._read_owned(statement)
        except Exception:
            # A pending AnyIO cancellation must win after mandatory cleanup,
            # including when the close itself failed. No refusal headers yet.
            await anyio.lowlevel.checkpoint()
            # Never expose SQL, locators or credentials through an HTTP error.
            raise HTTPException(503, "Download authorization is unavailable") from None
        await anyio.lowlevel.checkpoint()
        return row

    @staticmethod
    @complete_before_cancellation
    async def _read_owned(statement: Any) -> Any:
        """Keep the read and its real session close owned through cancellation."""
        deadline = anyio.current_time() + 5
        # The read/acquisition deadline must not cancel SQLAlchemy's shielded
        # close task. Drain that close outside the expiring scope, then refuse
        # any result whose complete authorization operation exceeded five sec.
        # This does not bound a stuck driver close or survive process loss.
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                db = await cleanup.enter_async_context(sessions.security_session_factory())
                row = (await db.execute(statement)).one_or_none()
        if anyio.current_time() >= deadline:
            raise TimeoutError("Download authorization exceeded its deadline")
        return row

    @staticmethod
    def _storage_fingerprint(row: Any) -> str:
        return _digest(
            [
                str(row.storage_id),
                str(row.storage_org),
                row.storage_active,
                row.storage_type,
                row.storage_config,
                row.storage_credentials,
            ]
        )

    def _validate(self, row: Any) -> None:
        # This clock read happens after the awaited database read AND close.
        now = datetime.now(UTC)
        if (
            row is None
            or not row.actor_active
            or row.actor_deleted is not None
            or row.actor_org != self.organization_id
            or row.actor_version != self.token_version
            or not isinstance(row.actor_password, str)
            or not hmac.compare_digest(
                hashlib.sha256(row.actor_password.encode()).hexdigest(), self.password_digest
            )
        ):
            raise HTTPException(401, "Download authorization ended")
        if row.actor_role != self.role or row.actor_role not in {
            "admin",
            "org_admin",
            "super_admin",
        }:
            raise HTTPException(403, "Download authorization ended")
        if self.key_id:
            if (
                row.key_id != self.key_id
                or row.key_owner != self.actor_id
                or not row.key_active
                or not isinstance(row.key_digest, str)
                or self.key_digest is None
                or not hmac.compare_digest(row.key_digest, self.key_digest)
                or (row.key_expiry is not None and row.key_expiry <= now)
            ):
                raise HTTPException(401, "Download authorization ended")
            if row.key_scopes:
                raise HTTPException(403, "Download authorization ended")
        elif (
            self.expiry is None
            or now.timestamp() >= self.expiry
            or row.revoked_jti
            or row.revoked_session
        ):
            raise HTTPException(401, "Download authorization ended")
        if row.backup_id is None:
            raise HTTPException(404, "Backup not found")
        if row.backup_secrets and row.actor_role != "super_admin":
            raise HTTPException(403, "Super admin required to download a full vault backup")
        current = SimpleNamespace(
            id=row.backup_id,
            organization_id=row.backup_org,
            status=row.backup_status,
            site_id=row.backup_site,
            include_secrets=row.backup_secrets,
            storage_type=row.backup_storage_type,
            storage_location_id=row.backup_storage_id,
            storage_path=row.backup_path,
            metadata_json=row.backup_metadata,
        )
        try:
            binding = _backup_binding(current)
        except BackupArtifactError:
            raise HTTPException(409, "Backup archive identity changed") from None
        if row.backup_status != "completed" or binding != self.backup_binding:
            raise HTTPException(409, "Backup download changed; retry the request")
        if row.backup_storage_id is not None and (
            row.storage_id != row.backup_storage_id or row.storage_org != self.organization_id
        ):
            raise HTTPException(404, "Backup storage not found")
        if row.storage_id is not None and not row.storage_active:
            raise HTTPException(409, "Backup storage is unavailable")
        if (
            self.storage_binding is not None
            and self._storage_fingerprint(row) != self.storage_binding
        ):
            raise HTTPException(409, "Backup storage changed; retry the request")

    async def check(self) -> None:
        """Reject changed authority before headers; never reauthorize raw auth."""
        self._validate(await self._current())
