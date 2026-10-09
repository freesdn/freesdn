# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Current release-mutation authority; never authenticate or commit under locks.

This is ordinary permission continuity, not fresh signing-identity authorization.
It preserves scoped keys and role/org policy. The final caller-owned SQL fence
coordinates supported account/token/session/provider writers, not arbitrary SQL,
a mixed old deployment or commit/network acknowledgment after a deadline.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Self, cast
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from sqlalchemy import RowMapping, Select, exists, false, or_, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, AsyncSessionTransaction

from app.core.agent_signing_binding import signing_commitment
from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, CurrentUser, _permission_granted_by
from app.core.owned_async import complete_before_cancellation
from app.core.token_authority_lock import try_share_token_authority
from app.core.user_lifecycle import try_share_user_lifecycle
from app.db import session as sessions
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User, UserSession
from app.models.sso import SSOProvider
from app.services.agent_signing_authority import _ACCOUNT_FIELDS, _PROVIDER_FIELDS


def _ended(status: int = 401) -> HTTPException:
    return HTTPException(status, "Release authorization changed; retry with current credentials")


@dataclass(frozen=True, repr=False)
class ReleaseMutationAuthority:
    actor_id: UUID
    organization_id: UUID | None
    role: str
    scoped: bool
    permissions: tuple[str, ...]
    actor_digest: str
    secret_key: bytes = field(repr=False)
    key_id: UUID | None = None
    key_digest: str | None = field(default=None, repr=False)
    jti: str | None = field(default=None, repr=False)
    expiry: float | None = None
    provider_digest: str | None = None
    key_state_digest: str | None = None

    @staticmethod
    def _permission_allowed(user: CurrentUser) -> bool:
        return user.has_permission("agent:admin")

    @classmethod
    async def capture(cls, request: Request, user: CurrentUser, *, secret_key: bytes) -> Self:
        if not cls._permission_allowed(user):
            raise _ended(403)
        if type(secret_key) is not bytes or not 32 <= len(secret_key) <= 4096:
            raise _ended(503)
        key = hmac.digest(secret_key, b"FreeSDN/release-authority/v1", "sha256")
        account = {name: getattr(user.user, name) for name in _ACCOUNT_FIELDS}
        version = account["token_version"]
        if type(version) is not int or not 0 <= version <= 2147483647:
            raise _ended()
        claims = user.token_claims
        key_id: UUID | None = None
        key_digest: str | None = None
        jti: str | None = None
        expiry: float | None = None
        if claims.get("auth_method") == "api_key":
            try:
                key_id = UUID(claims["key_id"])
            except (KeyError, TypeError, ValueError, AttributeError):
                raise _ended() from None
            raw = request.headers.get("X-API-Key")
            if not raw or len(raw) > 1024:
                raise _ended()
            key_digest = hashlib.sha256(raw.encode()).hexdigest()
        else:
            expiry, jti = claims.get("exp"), claims.get("jti")
            if (
                claims.get("type") != "access"
                or claims.get("scope")
                or claims.get("sub") != str(user.id)
                or type(claims.get("tv", 0)) is not int
                or claims.get("tv", 0) != version
                or type(expiry) not in (int, float)
                or not math.isfinite(cast(float, expiry))
                or (jti is not None and (type(jti) is not str or not 1 <= len(jti) <= 1024))
            ):
                raise _ended()
        initial = cls(
            user.id,
            user.organization_id,
            user.role,
            user.is_scoped,
            tuple(sorted(user.permissions)),
            signing_commitment(account, key=key, domain="account"),
            key,
            key_id,
            key_digest,
            jti,
            expiry,
        )
        row = await initial._read()
        initial.validate(row)
        # validate() above refuses a missing row before any scalar access.
        row = cast(RowMapping, row)
        # Keep the credential deadline through the final clock read, including
        # an API key whose expiry is crossed after the scalar-state validation.
        deadline = (
            row["key_expiry"].timestamp()
            if key_id is not None and row["key_expiry"] is not None
            else expiry
        )
        return replace(
            initial,
            provider_digest=initial._provider_digest(row),
            expiry=deadline,
            key_state_digest=initial._key_state(row) if key_id else None,
        )

    def _provider_digest(self, row: RowMapping) -> str:
        return signing_commitment(
            {name: row["p_" + name] for name in _PROVIDER_FIELDS},
            key=self.secret_key,
            domain="provider",
        )

    def _key_state(self, row: RowMapping) -> str:
        return signing_commitment(
            {
                name: row[name]
                for name in (
                    "key_id",
                    "key_user",
                    "key_hash",
                    "key_active",
                    "key_scopes",
                    "key_expiry",
                )
            },
            key=self.secret_key,
            domain="key",
        )

    def statement(self) -> Select[*tuple[Any, ...]]:
        a, p, k = User.__table__.c, SSOProvider.__table__.c, APIKey.__table__.c
        rev, login = TokenRevocation.__table__.c, UserSession.__table__.c
        revoked = (
            exists().where(rev.jti_hash == hashlib.sha256(self.jti.encode()).hexdigest())
            if self.jti
            else false()
        )
        ended = (
            exists().where(
                login.access_jti == self.jti,
                or_(login.is_revoked.is_(True), login.revoked_at.is_not(None)),
            )
            if self.jti
            else false()
        )
        return (
            select(
                *(a[name].label("a_" + name) for name in _ACCOUNT_FIELDS),
                *(p[name].label("p_" + name) for name in _PROVIDER_FIELDS),
                k.id.label("key_id"),
                k.user_id.label("key_user"),
                k.key_hash.label("key_hash"),
                k.is_active.label("key_active"),
                k.scopes.label("key_scopes"),
                k.expires_at.label("key_expiry"),
                revoked.label("revoked"),
                ended.label("ended"),
            )
            .select_from(User.__table__)
            .outerjoin(SSOProvider.__table__, p.id == a.sso_provider_id)
            .outerjoin(APIKey.__table__, k.id == self.key_id if self.key_id else false())
            .where(a.id == self.actor_id)
        )

    @complete_before_cancellation
    async def _read(self) -> RowMapping | None:
        deadline = anyio.current_time() + 5
        try:
            async with AsyncExitStack() as cleanup:
                with anyio.fail_after(5):
                    db = await cleanup.enter_async_context(sessions.security_session_factory())
                    row = (await db.execute(self.statement())).mappings().one_or_none()
            if anyio.current_time() >= deadline:
                raise TimeoutError("Release authority read exceeded its bound")
            return row
        except Exception:
            await anyio.lowlevel.checkpoint()
            raise _ended(503) from None

    def validate(self, row: RowMapping | None) -> None:
        now = datetime.now(UTC)
        if row is None:
            raise _ended()
        account = {name: row["a_" + name] for name in _ACCOUNT_FIELDS}
        if (
            account["id"] != self.actor_id
            or account["organization_id"] != self.organization_id
            or account["role"] != self.role
            or account["is_active"] is not True
            or account["deleted_at"] is not None
            or not hmac.compare_digest(
                signing_commitment(account, key=self.secret_key, domain="account"),
                self.actor_digest,
            )
        ):
            raise _ended()
        permissions = DEFAULT_ROLE_PERMISSIONS.get(
            self.role or "viewer", DEFAULT_ROLE_PERMISSIONS["viewer"]
        )
        scoped = False
        if self.key_id is not None:
            if (
                row["key_id"] != self.key_id
                or row["key_user"] != self.actor_id
                or row["key_active"] is not True
                or type(row["key_hash"]) is not str
                or self.key_digest is None
                or not hmac.compare_digest(row["key_hash"], self.key_digest)
                or (row["key_expiry"] is not None and row["key_expiry"] <= now)
            ):
                raise _ended()
            if row["key_scopes"]:
                scoped = True
                permissions = [
                    s for s in row["key_scopes"] if _permission_granted_by(s, permissions)
                ]
            if self.key_state_digest is not None and not hmac.compare_digest(
                self._key_state(row), self.key_state_digest
            ):
                raise _ended()
        elif (
            self.expiry is None or now.timestamp() >= self.expiry or row["revoked"] or row["ended"]
        ):
            raise _ended()
        # This unbound User is only the role/identity view of the checked scalar
        # snapshot. It is never added to a Session or used to authenticate again.
        current = CurrentUser(
            User(id=self.actor_id, organization_id=self.organization_id, role=self.role),
            permissions,
            scoped=scoped,
        )
        if (
            scoped != self.scoped
            or tuple(sorted(permissions)) != self.permissions
            or not self._permission_allowed(current)
        ):
            raise _ended(403)
        mode = account["auth_provider"]
        if mode in (None, "local"):
            if account["sso_provider_id"] is not None or account["external_id"] is not None:
                raise _ended()
        elif mode in ("oidc", "ldap"):
            if (
                self.organization_id is None
                or not account["external_id"]
                or row["p_id"] != account["sso_provider_id"]
                or row["p_organization_id"] != self.organization_id
                or row["p_protocol"] != mode
                or row["p_status"] != "active"
                or row["p_deleted_at"] is not None
            ):
                raise _ended()
        else:
            raise _ended()
        if self.provider_digest is not None and not hmac.compare_digest(
            self._provider_digest(row), self.provider_digest
        ):
            raise _ended()

    def require_scope(self, organization_id: UUID | None) -> None:
        if self.role == "super_admin" and not self.scoped:
            return
        if self.organization_id is None or organization_id != self.organization_id:
            raise HTTPException(404, "Release not found")

    async def lock(self, session: AsyncSession) -> ReleaseMutationFence:
        """No caller commit or auth side effect; caller must roll back refusals."""
        if not session.in_transaction():
            raise RuntimeError("Release authority requires an owned transaction")
        transaction = session.get_transaction()
        if transaction is None:
            raise RuntimeError("Release authority requires an owned transaction")
        if not await try_share_user_lifecycle(session):
            raise HTTPException(409, "Account lifecycle busy; retry release operation")
        # The selected IDs establish locks only. fence.recheck() below reads
        # fresh state and validates User.deleted_at and SSOProvider.deleted_at
        # before returning authority; selecting an ID never grants permission.
        tracked: tuple[UUID, ...] = ()
        try:
            await session.execute(
                select(User.id).where(User.id == self.actor_id).with_for_update(nowait=True)
            )
            if self.key_id is not None:
                await session.execute(
                    select(APIKey.id)
                    .where(APIKey.id == self.key_id)
                    .with_for_update(read=True, nowait=True)
                )
            elif self.jti is not None:
                if not await try_share_token_authority(session, self.jti):
                    raise HTTPException(409, "Credential transition busy; retry release operation")
                c = UserSession.__table__.c
                rows = (
                    await session.execute(
                        select(c.id, c.user_id)
                        .where(c.access_jti == self.jti)
                        .limit(2)
                        .with_for_update(read=True, nowait=True)
                    )
                ).all()
                if len(rows) > 1 or any(row.user_id != self.actor_id for row in rows):
                    raise _ended()
                tracked = tuple(row.id for row in rows)
            row = (await session.execute(self.statement())).mappings().one_or_none()
            if row is not None and row["a_sso_provider_id"] is not None:
                await session.execute(
                    select(SSOProvider.id)
                    .where(SSOProvider.id == row["a_sso_provider_id"])
                    .with_for_update(read=True, nowait=True)
                )
            fence = ReleaseMutationFence(self, session, transaction, tracked)
            await fence.recheck()
            return fence
        except DBAPIError as error:
            if (
                getattr(error.orig, "sqlstate", None) or getattr(error.orig, "pgcode", None)
            ) == "55P03":
                raise HTTPException(409, "Release authority busy; retry operation") from None
            raise


@dataclass(frozen=True, repr=False)
class ReleaseMutationFence:
    authority: ReleaseMutationAuthority
    session: AsyncSession = field(repr=False)
    transaction: AsyncSessionTransaction = field(repr=False)
    session_ids: tuple[UUID, ...] = ()

    async def recheck(self) -> None:
        if self.session.get_transaction() is not self.transaction or not self.transaction.is_active:
            raise RuntimeError("Release authority transaction ended")
        self.authority.validate(
            (await self.session.execute(self.authority.statement())).mappings().one_or_none()
        )
        if self.session_ids:
            c = UserSession.__table__.c
            rows = (
                await self.session.execute(
                    select(c.id, c.user_id, c.access_jti, c.is_revoked, c.revoked_at).where(
                        c.id.in_(self.session_ids)
                    )
                )
            ).all()
            if len(rows) != len(self.session_ids) or any(
                row.user_id != self.authority.actor_id
                or row.access_jti != self.authority.jti
                or row.is_revoked
                or row.revoked_at is not None
                for row in rows
            ):
                raise _ended()
        # Expiry must be checked after the final awaited session lookup too.
        if (
            self.authority.expiry is not None
            and datetime.now(UTC).timestamp() >= self.authority.expiry
        ):
            raise _ended()
