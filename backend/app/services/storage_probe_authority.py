# SPDX-License-Identifier: AGPL-3.0-only
"""Copied storage-probe authority, rechecked without authentication side effects.

This is ordinary unscoped organization-admin permission, not vault export,
release publication, cross-tenant permission, or an operator recovery grant.
Checks do not undo remote bytes already sent or serialize arbitrary external
writers with a native protocol syscall.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from sqlalchemy import Select, exists, false, or_, select, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from app.core.agent_signing_binding import signing_commitment
from app.core.config import get_settings
from app.core.dependencies import CurrentUser, is_unscoped_org_admin
from app.core.owned_async import complete_before_cancellation
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User, UserSession
from app.models.sso import SSOProvider
from app.services.agent_signing_authority import _ACCOUNT_FIELDS, _PROVIDER_FIELDS

type ProbeRow = RowMapping | Mapping[str, Any]


def _ended(code: int = 401) -> HTTPException:
    return HTTPException(code, "Storage probe authorization changed; use current credentials")


def _check_browser_context(request: Request, user: CurrentUser) -> None:
    """Optional equality assertions for browser probes; never authority grants."""
    actors = request.headers.getlist("X-FreeSDN-Storage-Probe-Actor")
    organizations = request.headers.getlist("X-FreeSDN-Storage-Probe-Organization")
    if not actors and not organizations:
        return
    if len(actors) != 1 or len(organizations) != 1:
        raise HTTPException(400, "Complete storage probe browser context required")
    actor, organization = actors[0], organizations[0]
    try:
        for value in (actor, organization):
            if len(value) != 36 or str(UUID(value)) != value or UUID(value).int == 0:
                raise ValueError("Invalid browser identity")
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid storage probe browser context") from None
    if actor != str(user.id) or organization != str(user.organization_id):
        raise HTTPException(409, "Storage probe browser context changed; use the intended account")


@dataclass(frozen=True, repr=False)
class StorageProbeAuthority:
    engine: AsyncEngine = field(repr=False)
    actor_id: UUID
    organization_id: UUID
    actor_digest: str
    secret_key: bytes = field(repr=False)
    key_id: UUID | None = None
    key_digest: str | None = field(default=None, repr=False)
    jti: str | None = field(default=None, repr=False)
    expiry: float | None = None
    provider_digest: str | None = None
    key_state_digest: str | None = None

    @classmethod
    async def capture(
        cls, request: Request, user: CurrentUser, session: AsyncSession
    ) -> StorageProbeAuthority:
        if not is_unscoped_org_admin(user) or user.organization_id is None:
            raise _ended(403)
        _check_browser_context(request, user)
        engine = session.bind
        if isinstance(engine, AsyncConnection):
            engine = engine.engine
        if not isinstance(engine, AsyncEngine):
            raise _ended(503)
        raw_secret = get_settings().SECRET_KEY.encode()
        if not 32 <= len(raw_secret) <= 4096:
            raise _ended(503)
        key = hmac.digest(raw_secret, b"FreeSDN/storage-probe-authority/v1", "sha256")
        account = {name: getattr(user.user, name) for name in _ACCOUNT_FIELDS}
        version = account["token_version"]
        if type(version) is not int or not 0 <= version <= 2147483647:
            raise _ended()
        claims = user.token_claims
        key_id: UUID | None
        key_digest: str | None
        jti: str | None
        expiry: float | None
        key_id = key_digest = jti = expiry = None
        if claims.get("auth_method") == "api_key":
            try:
                key_id = UUID(claims["key_id"])
            except (ValueError, TypeError, KeyError, AttributeError):
                raise _ended() from None
            raw = request.headers.get("X-API-Key")
            if not raw or len(raw) > 1024:
                raise _ended()
            key_digest = hashlib.sha256(raw.encode()).hexdigest()
        else:
            jti, expiry = claims.get("jti"), claims.get("exp")
            if (
                claims.get("type") != "access"
                or claims.get("scope")
                or claims.get("sub") != str(user.id)
                or type(claims.get("tv", 0)) is not int
                or claims.get("tv", 0) != version
                or type(expiry) not in (float, int)
                or not math.isfinite(cast(float, expiry))
                or (jti is not None and (type(jti) is not str or not 1 <= len(jti) <= 1024))
            ):
                raise _ended()
        initial = cls(
            engine,
            user.id,
            user.organization_id,
            signing_commitment(account, key=key, domain="account"),
            key,
            key_id,
            key_digest,
            jti,
            expiry,
        )
        row = await initial._read()
        initial._validate(row)
        row = cast(ProbeRow, row)
        deadline = (
            row["key_expiry"].timestamp() if key_id and row["key_expiry"] is not None else expiry
        )
        result = replace(
            initial,
            expiry=deadline,
            provider_digest=initial._provider_state(row),
            key_state_digest=initial._key_state(row) if key_id else None,
        )
        result.check_deadline()
        return result

    def _provider_state(self, row: ProbeRow) -> str:
        return signing_commitment(
            {n: row["p_" + n] for n in _PROVIDER_FIELDS},
            key=self.secret_key,
            domain="provider",
        )

    def _key_state(self, row: ProbeRow) -> str:
        return signing_commitment(
            {
                n: row[n]
                for n in (
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

    def _statement(self) -> Select[*tuple[Any, ...]]:
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
                or_(
                    login.is_revoked.is_(True),
                    login.revoked_at.is_not(None),
                    login.user_id != self.actor_id,
                ),
            )
            if self.jti
            else false()
        )
        return (
            select(
                *(a[n].label("a_" + n) for n in _ACCOUNT_FIELDS),
                *(p[n].label("p_" + n) for n in _PROVIDER_FIELDS),
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
            .outerjoin(
                APIKey.__table__,
                k.id == self.key_id if self.key_id else false(),
            )
            .where(a.id == self.actor_id)
        )

    @complete_before_cancellation
    async def _read(self) -> ProbeRow | None:
        deadline = anyio.current_time() + 5
        try:
            # This connection is independent of the caller's transaction. Its
            # close is owned outside the expiring scope; no last_used/auth commit.
            async with AsyncExitStack() as cleanup:
                with anyio.fail_after(5):
                    db = await cleanup.enter_async_context(self.engine.connect())
                    await db.execute(text("SET LOCAL statement_timeout = '5s'"))
                    row = (await db.execute(self._statement())).mappings().one_or_none()
            if anyio.current_time() >= deadline:
                raise TimeoutError("Probe authority acceptance deadline exceeded")
            return row
        except Exception:
            await anyio.lowlevel.checkpoint()
            raise _ended(503) from None

    def _validate(self, row: ProbeRow | None) -> None:
        now = datetime.now(UTC)
        if row is None:
            raise _ended()
        account = {n: row["a_" + n] for n in _ACCOUNT_FIELDS}
        if (
            account["id"] != self.actor_id
            or account["organization_id"] != self.organization_id
            or account["role"] not in {"admin", "org_admin", "super_admin"}
            or account["is_active"] is not True
            or account["deleted_at"] is not None
            or not hmac.compare_digest(
                signing_commitment(account, key=self.secret_key, domain="account"),
                self.actor_digest,
            )
        ):
            raise _ended()
        if self.key_id:
            if (
                row["key_id"] != self.key_id
                or row["key_user"] != self.actor_id
                or row["key_active"] is not True
                or type(row["key_hash"]) is not str
                or self.key_digest is None
                or not hmac.compare_digest(row["key_hash"], self.key_digest)
                or row["key_scopes"] != []
                or (row["key_expiry"] is not None and row["key_expiry"] <= now)
                or (
                    self.key_state_digest is not None
                    and not hmac.compare_digest(self._key_state(row), self.key_state_digest)
                )
            ):
                raise _ended()
        elif (
            self.expiry is None or now.timestamp() >= self.expiry or row["revoked"] or row["ended"]
        ):
            raise _ended()
        mode = account["auth_provider"]
        if mode in (None, "local"):
            if account["sso_provider_id"] is not None or account["external_id"] is not None:
                raise _ended()
        elif mode in ("oidc", "ldap"):
            if (
                not account["external_id"]
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
            self._provider_state(row), self.provider_digest
        ):
            raise _ended()
        self.check_deadline()

    def check_deadline(self) -> None:
        # Safe in the native worker too, after the async recheck's handoff.
        if self.expiry is not None and datetime.now(UTC).timestamp() >= self.expiry:
            raise _ended()

    async def check(self) -> None:
        self._validate(await self._read())
