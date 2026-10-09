# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private platform signing authority and owned local-factor confirmation.

Not routed or a complete signing lifecycle. External accounts require separate
fresh provider confirmation; a local password cannot substitute for it. Receipts
remain internal and are not signed browser tokens or durably consumed grants.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import anyio
from fastapi import HTTPException, Request
from sqlalchemy import Select, Table, exists, false, or_, select, update
from sqlalchemy.engine import RowMapping

from app.core.agent_signing_binding import SigningCommand, signing_commitment
from app.core.owned_async import complete_before_cancellation
from app.core.security import verify_password, verify_totp_single_use
from app.core.security_utils import decrypt_field
from app.core.user_lifecycle import try_share_user_lifecycle
from app.db import session as sessions
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User, UserSession
from app.models.sso import SSOProvider
from app.services.backup_contributors.account_security_codec import (
    require_argon2_hash,
    require_backup_code_hashes,
    require_portable_seed,
)

if TYPE_CHECKING:
    from app.core.dependencies import CurrentUser

type SigningAuthorityRow = RowMapping | Mapping[str, Any]

_ACCOUNT_FIELDS = (
    "id",
    "organization_id",
    "role",
    "hashed_password",
    "token_version",
    "is_active",
    "is_verified",
    "deleted_at",
    "locked_until",
    "failed_login_attempts",
    "auth_provider",
    "sso_provider_id",
    "external_id",
    "mfa_enabled",
    "mfa_secret",
    "mfa_backup_codes",
    "mfa_pending_secret",
    "mfa_pending_backup_codes",
    "mfa_last_totp_step",
)
_PRESENTATION = {
    "name",
    "slug",
    "description",
    "icon_url",
    "display_order",
    "created_at",
    "updated_at",
    "created_by",
    "updated_by",
}
_PROVIDER_FIELDS = tuple(c.key for c in SSOProvider.__table__.columns if c.key not in _PRESENTATION)
_FACTOR_WORK = anyio.CapacityLimiter(2)
_ENDED = "Signing confirmation authorization changed; start a new confirmation"


def _commit(values: dict[str, Any], key: bytes) -> str:
    return signing_commitment(values, key=key, domain="account")


def _ended(status: int = 401) -> HTTPException:
    return HTTPException(status, _ENDED)


@dataclass(frozen=True, repr=False)
class SigningLifecycleAuthority:
    """Copied identifiers and keyed commitments, no ORM object or raw credential."""

    actor_id: UUID
    organization_id: UUID | None
    token_version: int
    command: SigningCommand
    command_digest: str
    actor_digest: str
    secret_key: bytes = field(repr=False)
    key_id: UUID | None = None
    key_digest: str | None = field(default=None, repr=False)
    jti: str | None = field(default=None, repr=False)
    expiry: float | None = None
    provider_digest: str | None = None

    @classmethod
    async def capture(
        cls, request: Request, user: CurrentUser, *, command: SigningCommand, secret_key: bytes
    ) -> SigningLifecycleAuthority:
        if user.is_scoped or user.role != "super_admin" or type(command) is not SigningCommand:
            raise _ended(403)
        if type(secret_key) is not bytes or not 32 <= len(secret_key) <= 4096:
            raise _ended(503)
        key = hmac.digest(secret_key, b"FreeSDN/agent-signing-credential/v1", "sha256")
        account = {name: getattr(user.user, name) for name in _ACCOUNT_FIELDS}
        version = account["token_version"]
        if type(version) is not int or not 0 <= version < 2147483647:
            raise _ended()
        claims = user.token_claims
        key_id: UUID | None
        key_digest: str | None
        jti: str | None
        expiry: float | None
        key_id, key_digest, jti, expiry = None, None, None, None
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
            expiry = claims.get("exp")
            jti = claims.get("jti")
            if (
                claims.get("type") != "access"
                or claims.get("scope")
                or claims.get("sub") != str(user.id)
                or type(claims.get("tv")) is not int
                or claims["tv"] != version
                or type(expiry) not in (int, float)
                or not math.isfinite(cast(float, expiry))
                or type(jti) is not str
                or not 1 <= len(jti) <= 1024
            ):
                # A legacy JWT without a JTI must be replaced by a current login.
                raise _ended()
        initial = cls(
            actor_id=UUID(str(user.id)),
            organization_id=UUID(str(user.organization_id))
            if user.organization_id is not None
            else None,
            token_version=version,
            command=command,
            command_digest=command.commitment(key=key),
            actor_digest=_commit(account, key),
            secret_key=key,
            key_id=key_id,
            key_digest=key_digest,
            jti=jti,
            expiry=expiry,
        )
        row = await initial._current()
        initial._validate(row)
        row = cast(SigningAuthorityRow, row)
        if key_id is not None and row["key_expiry"] is not None:
            expiry = row["key_expiry"].timestamp()
        return replace(initial, provider_digest=initial._provider_commit(row), expiry=expiry)

    def _statement(self) -> Select[*tuple[Any, ...]]:
        account, provider, api = User.__table__.c, SSOProvider.__table__.c, APIKey.__table__.c
        rev, login = TokenRevocation.__table__.c, UserSession.__table__.c
        jti_hash = hashlib.sha256(self.jti.encode()).hexdigest() if self.jti else None
        revoked = exists().where(rev.jti_hash == jti_hash) if jti_hash else false()
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
                *(account[name].label("a_" + name) for name in _ACCOUNT_FIELDS),
                *(provider[name].label("p_" + name) for name in _PROVIDER_FIELDS),
                api.id.label("key_id"),
                api.user_id.label("key_user"),
                api.key_hash.label("key_hash"),
                api.is_active.label("key_active"),
                api.scopes.label("key_scopes"),
                api.expires_at.label("key_expiry"),
                revoked.label("revoked"),
                ended.label("session_ended"),
            )
            .select_from(User.__table__)
            .outerjoin(SSOProvider.__table__, provider.id == account.sso_provider_id)
            .outerjoin(APIKey.__table__, api.id == self.key_id if self.key_id else false())
            .where(account.id == self.actor_id)
        )

    @staticmethod
    @complete_before_cancellation
    async def _read_owned(statement: Select[*tuple[Any, ...]]) -> SigningAuthorityRow | None:
        # Cleanup remains owned outside the acquisition/read deadline, matching
        # the W184 checkpoint contract. Stuck-driver close is a separate limit.
        end = anyio.current_time() + 5
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                db = await cleanup.enter_async_context(sessions.security_session_factory())
                row = (await db.execute(statement)).mappings().one_or_none()
        if anyio.current_time() >= end:
            raise TimeoutError("Signing authority deadline")
        return row

    async def _current(self) -> SigningAuthorityRow | None:
        try:
            return await self._read_owned(self._statement())
        except Exception:
            await anyio.lowlevel.checkpoint()
            raise _ended(503) from None

    @staticmethod
    def _account(row: SigningAuthorityRow) -> dict[str, Any]:
        return {name: row["a_" + name] for name in _ACCOUNT_FIELDS}

    def _provider_commit(self, row: SigningAuthorityRow) -> str:
        return signing_commitment(
            {name: row["p_" + name] for name in _PROVIDER_FIELDS},
            key=self.secret_key,
            domain="provider",
        )

    def _validate(self, row: SigningAuthorityRow | None) -> None:
        self.require_command(self.command)
        now = datetime.now(UTC)
        if row is None:
            raise _ended()
        account = self._account(row)
        if (
            account["id"] != self.actor_id
            or account["organization_id"] != self.organization_id
            or account["is_active"] is not True
            or account["is_verified"] is not True
            or account["deleted_at"] is not None
            or account["role"] != "super_admin"
            or (account["locked_until"] is not None and account["locked_until"] > now)
            or not hmac.compare_digest(_commit(account, self.secret_key), self.actor_digest)
        ):
            raise _ended()
        if self.key_id:
            if (
                row["key_id"] != self.key_id
                or row["key_user"] != self.actor_id
                or row["key_active"] is not True
                or row["key_scopes"]
                or type(row["key_hash"]) is not str
                or self.key_digest is None
                or not hmac.compare_digest(row["key_hash"], self.key_digest)
                or (row["key_expiry"] is not None and row["key_expiry"] <= now)
            ):
                raise _ended()
        elif (
            self.expiry is None
            or now.timestamp() >= self.expiry
            or row["revoked"]
            or row["session_ended"]
        ):
            raise _ended()
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
            raise _ended()  # SAML remains unsupported.
        if self.provider_digest is not None and not hmac.compare_digest(
            self._provider_commit(row), self.provider_digest
        ):
            raise _ended()

    async def check(self) -> None:
        self._validate(await self._current())

    def require_command(self, command: SigningCommand) -> None:
        if type(command) is not SigningCommand or not hmac.compare_digest(
            command.commitment(key=self.secret_key), self.command_digest
        ):
            raise _ended()

    @property
    def context(self) -> SigningAuthorityContext:
        if self.provider_digest is None:
            raise _ended()
        digest = signing_commitment(
            {
                "account": self.actor_digest,
                "provider": self.provider_digest,
                "credential": self.key_digest,
                "command": self.command_digest,
            },
            key=self.secret_key,
            domain="authority",
        )
        return SigningAuthorityContext(
            self.actor_id,
            self.organization_id,
            self.token_version,
            "api_key_id" if self.key_id else "access_jti",
            str(self.key_id) if self.key_id else cast(str, self.jti),
            self.command.action,
            self.command_digest,
            digest,
        )

    async def confirm_local(
        self, *, command: SigningCommand, password: str, code: str | None = None
    ) -> FreshSigningFactor:
        self.require_command(command)
        if command.action == "inspect":
            raise _ended(403)
        if type(password) is not str or not 1 <= len(password) <= 1024:
            raise _ended()
        if code is not None and (type(code) is not str or not 1 <= len(code) <= 10):
            raise _ended()
        started = int(time.time())
        try:
            _FACTOR_WORK.acquire_nowait()
        except anyio.WouldBlock:
            raise _ended(503) from None
        try:
            newer, accepted = await self._local_transaction(password, code)
        except HTTPException:
            raise
        except Exception:
            await anyio.lowlevel.checkpoint()
            raise _ended(503) from None
        finally:
            _FACTOR_WORK.release()
        if not accepted:
            raise HTTPException(401, "Fresh password or MFA confirmation was refused")
        await newer.check()
        expiry = min(started + 120, int(self.expiry)) if self.expiry is not None else started + 120
        if time.time() >= expiry:
            raise _ended()
        return FreshSigningFactor(newer, started, expiry)

    @complete_before_cancellation
    async def _local_transaction(
        self, password: str, code: str | None
    ) -> tuple[SigningLifecycleAuthority, bool]:
        deadline = anyio.current_time() + 5
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                db = await cleanup.enter_async_context(sessions.security_session_factory())
                async with db.begin():
                    if not await try_share_user_lifecycle(db):
                        raise _ended(409)
                    # Lifecycle before User, never API-key authentication/commit
                    # in this critical section. Fresh scalar snapshot follows wait.
                    await db.execute(
                        select(User.__table__.c.id)
                        .where(User.__table__.c.id == self.actor_id)
                        .with_for_update()
                    )
                    row = (await db.execute(self._statement())).mappings().one_or_none()
                    # This post-lock validator rejects User.deleted_at before
                    # password/MFA work or any factor/counter mutation.
                    self._validate(row)
                    row = cast(RowMapping, row)
                    account = self._account(row)
                    if account["auth_provider"] not in (None, "local"):
                        raise _ended()  # Local password is not fresh IdP authentication.
                    count = account["failed_login_attempts"]
                    if type(count) is not int or not 0 <= count <= 2147483646:
                        raise _ended()
                    phc = require_argon2_hash(account["hashed_password"])
                    valid = await anyio.to_thread.run_sync(partial(verify_password, password, phc))
                    changes: dict[str, int | str | datetime | None] = {}
                    if valid and account["mfa_enabled"]:
                        valid = False
                        if (
                            code is not None
                            and len(code) == 6
                            and code.isascii()
                            and code.isdigit()
                        ):
                            seed = require_portable_seed(decrypt_field(account["mfa_secret"]))
                            if seed is not None:
                                valid, step = verify_totp_single_use(
                                    seed, code, account["mfa_last_totp_step"]
                                )
                                if valid:
                                    changes["mfa_last_totp_step"] = step
                        elif code is not None and len(code) == 10:
                            hashes = require_backup_code_hashes(account["mfa_backup_codes"]) or []
                            for index, hashed in enumerate(hashes):
                                if await anyio.to_thread.run_sync(
                                    partial(verify_password, code, hashed)
                                ):
                                    hashes.pop(index)
                                    changes["mfa_backup_codes"] = json.dumps(hashes)
                                    valid = True
                                    break
                    if valid:
                        changes.update(failed_login_attempts=0, locked_until=None)
                    else:
                        changes["failed_login_attempts"] = count + 1
                        if count + 1 >= 5:
                            changes["locked_until"] = datetime.now(UTC) + timedelta(minutes=30)
                    await db.execute(
                        update(cast(Table, User.__table__))
                        .where(User.__table__.c.id == self.actor_id)
                        .values(**changes)
                    )
                    updated = replace(
                        self, actor_digest=_commit({**account, **changes}, self.secret_key)
                    )
                    # No secret collection/storage here. The independent commit
                    # persists failed attempts and successful factor consumption.
            # The transaction exits inside its deadline, session close stays owned.
        if anyio.current_time() >= deadline:
            raise _ended(503)
        return updated, valid


@dataclass(frozen=True, repr=False)
class SigningAuthorityContext:
    user_id: UUID
    organization_id: UUID | None
    token_version: int
    credential_kind: str
    credential_id: str
    action: str
    command_digest: str
    authority_digest: str


@dataclass(frozen=True, repr=False)
class FreshSigningFactor:
    """Internal local-factor receipt; never accept an HTTP-deserialized receipt.

    This is not a single-use bearer proof. Lifecycle orchestration still needs
    authenticated durable intent consumption and current-state acceptance after
    storage/SQL waits. It must not reuse an export proof or replace fresh IdP flow.
    """

    authority: SigningLifecycleAuthority
    authenticated_at: int
    expires_at: int
    confirmation_id: UUID = field(default_factory=uuid4)

    async def recheck(self, command: SigningCommand) -> None:
        self.authority.require_command(command)
        if time.time() >= self.expires_at:
            raise _ended()
        await self.authority.check()
        if time.time() >= self.expires_at:
            raise _ended()
