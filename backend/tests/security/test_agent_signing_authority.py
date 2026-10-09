"""AFTER-only PostgreSQL/current-auth probes for private signing confirmation.

The two owned HTTP routes are test harnesses, not published signing endpoints.
No account/factor/authentication/claim verifier is mocked. Owned row-lock waits
are proved with pg_blocking_pids on independent physical connections.
"""

import asyncio
import hashlib
import json
import secrets
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pyotp
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing_binding import SigningCommand
from app.core.config import settings
from app.core.dependencies import CurrentUser, get_current_user
from app.core.security import create_access_token, get_password_hash
from app.core.security_utils import encrypt_field
from app.db import session as sessions
from app.db.session import create_test_engine, get_session
from app.main import app as product_app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.services.agent_signing_authority import SigningLifecycleAuthority


@pytest_asyncio.fixture
async def owned_signing(monkeypatch, *, disposable_database=None):
    import app.core.token_blacklist as revocations

    engine = create_test_engine()
    if disposable_database is not None:
        # Only the enclosing per-test lifecycle fixture owns a whole database.
        # Its finally block drops that exact database without relaxing triggers.
        assert type(disposable_database) is str
        assert disposable_database.startswith("owned_signing_lifecycle_")
        assert engine.url.database == disposable_database
    f = SimpleNamespace(
        engine=engine,
        org=uuid4(),
        other_org=uuid4(),
        user=uuid4(),
        provider=uuid4(),
        key_id=uuid4(),
        seed=pyotp.random_base32(),
        pids=[],
        password="Owned!Aa7-" + uuid4().hex,
        recovery="AB12CD34EF",
        captured=asyncio.Event(),
        proceed=asyncio.Event(),
        pause=False,
        pause_after_factor=False,
        factor_done=asyncio.Event(),
        factor_proceed=asyncio.Event(),
        command=SigningCommand("initialize", uuid4(), uuid4(), 1),
        secret=secrets.token_bytes(32),
        token_hashes=set(),
    )
    raw, prefix, digest = generate_api_key()
    f.key = raw
    f.password_hash = get_password_hash(f.password)
    f.recovery_hash = get_password_hash(f.recovery)

    @asynccontextmanager
    async def security_session():
        async with engine.connect() as connection:
            pid = await connection.scalar(text("SELECT pg_backend_pid()"))
            await connection.rollback()
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                f.pids.append(pid)
                yield db

    async def request_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as db:
            yield db

    monkeypatch.setattr(sessions, "security_session_factory", security_session)
    monkeypatch.setattr(revocations, "security_session_factory", security_session)
    test_app = FastAPI(exception_handlers=product_app.exception_handlers)
    test_app.dependency_overrides[get_session] = request_session

    @test_app.post("/owned/confirm")
    async def confirm(request: Request, user: CurrentUser = Depends(get_current_user)):
        authority = await SigningLifecycleAuthority.capture(
            request, user, command=f.command, secret_key=f.secret
        )
        f.captured.set()
        if f.pause:
            await f.proceed.wait()
        body = await request.json()
        result = await authority.confirm_local(command=f.command, password=body["password"], code=body.get("code"))
        f.factor_done.set()
        if f.pause_after_factor:
            await f.factor_proceed.wait()
        await result.recheck(f.command)
        return {"actor": str(result.authority.context.user_id), "expiry": result.expires_at,
                "organization": str(result.authority.organization_id) if result.authority.organization_id else None}

    @test_app.get("/owned/check")
    async def check(request: Request, user: CurrentUser = Depends(get_current_user)):
        authority = await SigningLifecycleAuthority.capture(
            request, user, command=f.command, secret_key=f.secret
        )
        f.captured.set()
        if f.pause:
            await f.proceed.wait()
        await authority.check()
        return {"actor": str(authority.context.user_id)}

    try:
        async with AsyncSession(engine) as db:
            db.add_all(
                [
                    Organization(id=i, name="Owned export organization", slug=uuid4().hex)
                    for i in (f.org, f.other_org)
                ]
            )
            await db.flush()
            db.add(
                SSOProvider(
                    id=f.provider,
                    organization_id=f.org,
                    name="Owned provider",
                    slug=uuid4().hex,
                    protocol=SSOProtocol.OIDC,
                    status=SSOProviderStatus.ACTIVE,
                    oidc_issuer="https://idp.example.invalid",
                    oidc_client_id="owned-client",
                    oidc_client_secret=encrypt_field(secrets.token_urlsafe(32)),
                )
            )
            await db.flush()
            name = "owned-export-" + uuid4().hex
            db.add(
                User(
                    id=f.user,
                    organization_id=f.org,
                    username=name,
                    email=name + "@example.com",
                    hashed_password=f.password_hash,
                    role="super_admin",
                    is_active=True,
                    is_verified=True,
                    token_version=17,
                    mfa_enabled=False,
                    failed_login_attempts=0,
                )
            )
            await db.flush()
            db.add(
                APIKey(
                    id=f.key_id,
                    user_id=f.user,
                    name="Owned export key",
                    key_prefix=prefix,
                    key_hash=digest,
                    scopes=[],
                    is_active=True,
                )
            )
            await db.commit()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=test_app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            f.client = client
            yield f
    finally:
        f.proceed.set()
        f.factor_proceed.set()
        try:
            if disposable_database is None:
                async with AsyncSession(engine) as db:
                    await db.execute(delete(UserSession).where(UserSession.user_id == f.user))
                    await db.execute(delete(APIKey).where(APIKey.user_id == f.user))
                    await db.execute(delete(User).where(User.id == f.user))
                    await db.execute(delete(SSOProvider).where(SSOProvider.id == f.provider))
                    await db.execute(delete(Organization).where(Organization.id.in_([f.org, f.other_org])))
                    if f.token_hashes:
                        await db.execute(
                            delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(f.token_hashes))
                        )
                    await db.commit()
        finally:
            await engine.dispose()
            engine = None
            # Cached fixture callbacks must not retain completed request resources.
            f = None


def credentials(f, kind, *, expires=120):
    if kind == "key":
        return {"X-API-Key": f.key}, None
    token = create_access_token(
        str(f.user), token_version=17, expires_delta=timedelta(seconds=expires)
    )
    claims = jwt.decode(
        token,
        settings.jwt_signing_key,
        algorithms=[settings.ALGORITHM],
        audience="freesdn-api",
        issuer="freesdn",
    )
    f.token_hashes.add(hashlib.sha256(claims["jti"].encode()).hexdigest())
    return {"Authorization": "Bearer " + token}, claims


async def state(f):
    async with AsyncSession(f.engine) as db:
        return dict(
            (await db.execute(select(User.__table__).where(User.id == f.user))).mappings().one()
        )


async def mutate(f, values):
    async with AsyncSession(f.engine) as db:
        await db.execute(update(User).where(User.id == f.user).values(**values))
        await db.commit()


async def real_wait(f, task, holder, *, count=1):
    async with AsyncSession(f.engine) as observer:
        async with asyncio.timeout(10):
            while True:
                assert not task.done(), "Request ended before the required genuine database wait"
                waiting = []
                for pid in set(f.pids):
                    # Tuple-lock queues can block the second request through
                    # the first. Follow actual PG edges; events alone are not
                    # evidence that both physical connections waited.
                    pending, visited = [pid], set()
                    while pending and holder not in visited:
                        current = pending.pop()
                        if current in visited:
                            continue
                        visited.add(current)
                        assert len(visited) <= 30, "Unexpected owned lock graph"
                        blockers = await observer.scalar(
                            text("SELECT pg_blocking_pids(:pid)"), {"pid": current}
                        )
                        pending.extend(blockers)
                    if holder in visited:
                        waiting.append(pid)
                if len(waiting) >= count:
                    return waiting
                await asyncio.sleep(0.02)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "factor", ["password", "totp", "recovery", "wrong_password", "wrong_code", "pending_seed"]
)
async def test_fresh_local_confirmation_consumes_only_valid_established_factors(
    owned_signing, kind, factor
):
    f = owned_signing
    enabled = factor in {"totp", "recovery", "wrong_code", "pending_seed"}
    if enabled:
        await mutate(
            f,
            {
                "mfa_enabled": True,
                "mfa_secret": encrypt_field(f.seed),
                "mfa_backup_codes": json.dumps([f.recovery_hash]),
                "mfa_last_totp_step": 123456,
                "mfa_pending_secret": encrypt_field(pyotp.random_base32())
                if factor == "pending_seed"
                else None,
            },
        )
    before = await state(f)
    headers, _ = credentials(f, kind)
    code = f.recovery if factor == "recovery" else pyotp.TOTP(f.seed).now()
    if factor == "wrong_code":
        code = "not-a-code"
    if factor == "pending_seed":
        from app.core.security_utils import decrypt_field

        code = pyotp.TOTP(decrypt_field(before["mfa_pending_secret"])).now()
        # A six-digit collision is possible even for unrelated random seeds.
        # Establish that this negative input differs from every accepted step.
        while pyotp.TOTP(f.seed).verify(code, valid_window=1):
            pending_seed = pyotp.random_base32()
            await mutate(f, {"mfa_pending_secret": encrypt_field(pending_seed)})
            before = await state(f)
            code = pyotp.TOTP(pending_seed).now()
    response = await f.client.post(
        "/owned/confirm",
        headers=headers,
        json={
            "password": "wrong-password" if factor == "wrong_password" else f.password,
            "code": code if enabled else None,
        },
    )
    after = await state(f)
    observed = {
        "status": response.status_code,
        "attempts": after["failed_login_attempts"],
        "consumed_step": after["mfa_last_totp_step"],
        "remaining_codes": after["mfa_backup_codes"],
    }
    good = factor in {"password", "totp", "recovery"}
    assert observed["status"] == (200 if good else 401), observed
    assert after["token_version"] == 17 and after["hashed_password"] == f.password_hash
    if factor == "totp":
        assert after["mfa_last_totp_step"] > before["mfa_last_totp_step"]
    elif factor == "recovery":
        assert json.loads(after["mfa_backup_codes"]) == []
    else:
        assert after["mfa_last_totp_step"] == before["mfa_last_totp_step"]
    assert after["failed_login_attempts"] == (0 if good else 1)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change",
    [
        "unchanged",
        "active",
        "deleted",
        "organization",
        "role",
        "password",
        "counter",
        "verified",
        "locked",
        "mfa_seed",
        "key_revoked",
        "key_scoped",
    ],
)
async def test_real_user_row_wait_rechecks_account_and_credential_before_factor_work(
    owned_signing, kind, change, request
):
    f = owned_signing
    await mutate(
        f, {"mfa_enabled": True, "mfa_secret": encrypt_field(f.seed), "mfa_last_totp_step": 123456}
    )
    headers, _ = credentials(f, kind)
    async with AsyncSession(f.engine) as holder:
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        task = asyncio.create_task(
            f.client.post(
                "/owned/confirm",
                headers=headers,
                json={"password": f.password, "code": pyotp.TOTP(f.seed).now()},
            )
        )
        try:
            waiting = await real_wait(f, task, holder_pid)
            values = {
                "active": {"is_active": False},
                "deleted": {"deleted_at": datetime.now(UTC)},
                "organization": {"organization_id": f.other_org},
                "role": {"role": "viewer"},
                "password": {"hashed_password": get_password_hash("Changed!Aa7-" + uuid4().hex)},
                "counter": {"token_version": 18},
                "verified": {"is_verified": False},
                "locked": {"locked_until": datetime.now(UTC) + timedelta(minutes=1)},
                "mfa_seed": {"mfa_secret": encrypt_field(pyotp.random_base32())},
            }
            if change in values:
                await holder.execute(update(User).where(User.id == f.user).values(**values[change]))
            elif change.startswith("key_"):
                await holder.execute(
                    update(APIKey)
                    .where(APIKey.id == f.key_id)
                    .values(
                        **(
                            {"is_active": False}
                            if change == "key_revoked"
                            else {"scopes": ["network:read"]}
                        )
                    )
                )
            await holder.commit()
            response = await asyncio.wait_for(task, 10)
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    after = await state(f)
    request.node.user_properties.append(("real_User_row_wait", bool(waiting)))
    permitted = change == "unchanged" or (kind == "jwt" and change.startswith("key_"))
    observed = {
        "status": response.status_code,
        "step": after["mfa_last_totp_step"],
        "waiters": len(waiting),
    }
    assert observed["status"] == (200 if permitted else 401), observed
    assert (after["mfa_last_totp_step"] > 123456) == permitted
    assert after["failed_login_attempts"] == 0


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change",
    ["unchanged", "provider_disabled", "provider_org", "provider_issuer", "subject", "local_mode"],
)
async def test_current_sso_binding_after_independent_commit(owned_signing, kind, change):
    f = owned_signing
    await mutate(
        f,
        {
            "auth_provider": "oidc",
            "sso_provider_id": f.provider,
            "external_id": "owned-subject",
            "hashed_password": "!SSO_MANAGED",
        },
    )
    headers, _ = credentials(f, kind)
    f.pause = True
    task = asyncio.create_task(f.client.get("/owned/check", headers=headers))
    try:
        await asyncio.wait_for(f.captured.wait(), 10)
        async with AsyncSession(f.engine) as writer:
            if change in {"provider_disabled", "provider_org", "provider_issuer"}:
                values = {
                    "provider_disabled": {"status": SSOProviderStatus.INACTIVE},
                    "provider_org": {"organization_id": f.other_org},
                    "provider_issuer": {"oidc_issuer": "https://other.example.invalid"},
                }[change]
                await writer.execute(
                    update(SSOProvider).where(SSOProvider.id == f.provider).values(**values)
                )
            elif change in {"subject", "local_mode"}:
                values = (
                    {"external_id": "other-subject"}
                    if change == "subject"
                    else {"auth_provider": "local"}
                )
                await writer.execute(update(User).where(User.id == f.user).values(**values))
            await writer.commit()
        f.proceed.set()
        response = await asyncio.wait_for(task, 10)
    finally:
        f.proceed.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert response.status_code == (200 if change == "unchanged" else 401), response.text


@pytest.mark.parametrize("factor", ["totp", "recovery"])
async def test_two_real_waiters_cannot_consume_the_same_factor(owned_signing, factor, request):
    f = owned_signing
    await mutate(
        f,
        {
            "mfa_enabled": True,
            "mfa_secret": encrypt_field(f.seed),
            "mfa_backup_codes": json.dumps([f.recovery_hash]),
            "mfa_last_totp_step": 123456,
        },
    )
    headers, _ = credentials(f, "jwt")
    code = pyotp.TOTP(f.seed).now() if factor == "totp" else f.recovery
    async with AsyncSession(f.engine) as holder:
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        tasks = [
            asyncio.create_task(
                f.client.post(
                    "/owned/confirm", headers=headers, json={"password": f.password, "code": code}
                )
            )
            for _ in range(2)
        ]
        all_tasks = asyncio.gather(*tasks)
        try:
            waiting = await real_wait(f, all_tasks, pid, count=2)
            await holder.commit()
            responses = await asyncio.wait_for(all_tasks, 10)
        finally:
            await holder.rollback()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    observed = sorted(r.status_code for r in responses)
    after = await state(f)
    request.node.user_properties.append(("two_real_User_row_waiters", len(waiting) == 2))
    assert observed == [200, 401], observed
    if factor == "totp":
        assert after["mfa_last_totp_step"] > 123456
    else:
        assert json.loads(after["mfa_backup_codes"]) == []


async def test_failed_attempts_are_durable_and_bound_further_confirmation(owned_signing):
    f = owned_signing
    headers, _ = credentials(f, "jwt")
    responses = []
    for _ in range(5):
        responses.append(
            await f.client.post("/owned/confirm", headers=headers, json={"password": "wrong"})
        )
    locked = await state(f)
    correct = await f.client.post("/owned/confirm", headers=headers, json={"password": f.password})
    after = await state(f)
    assert [r.status_code for r in responses] == [401] * 5
    assert correct.status_code == 401
    assert locked["failed_login_attempts"] == after["failed_login_attempts"] == 5
    assert after["locked_until"] > datetime.now(UTC)


async def test_jwt_expires_during_real_user_wait_before_factor_consumption(owned_signing, request):
    f = owned_signing
    headers, claims = credentials(f, "jwt", expires=4)
    async with AsyncSession(f.engine) as holder:
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(select(User.id).where(User.id == f.user).with_for_update())
        task = asyncio.create_task(
            f.client.post("/owned/confirm", headers=headers, json={"password": f.password})
        )
        try:
            waiting = await real_wait(f, task, pid)
            await asyncio.sleep(max(0, claims["exp"] - datetime.now(UTC).timestamp()) + 0.05)
            await holder.commit()
            response = await asyncio.wait_for(task, 10)
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    request.node.user_properties.append(("expiry_after_real_User_wait", bool(waiting)))
    after = await state(f)
    assert response.status_code == 401, response.text
    assert after["failed_login_attempts"] == 0


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("factor", ["password", "totp", "recovery"])
async def test_platform_superadmin_without_organization_can_confirm_local_factors(owned_signing, kind, factor):
    f = owned_signing
    await mutate(f, {"organization_id": None, "mfa_enabled": factor != "password",
                     "mfa_secret": encrypt_field(f.seed), "mfa_backup_codes": json.dumps([f.recovery_hash]),
                     "mfa_last_totp_step": 123456})
    headers, _ = credentials(f, kind)
    code = None if factor == "password" else (f.recovery if factor == "recovery" else pyotp.TOTP(f.seed).now())
    response = await f.client.post("/owned/confirm", headers=headers,
                                   json={"password": f.password, "code": code})
    after = await state(f)
    assert response.status_code == 200, response.text
    assert response.json()["organization"] is None and after["organization_id"] is None
    assert after["failed_login_attempts"] == 0 and after["token_version"] == 17
    if factor == "totp":
        assert after["mfa_last_totp_step"] > 123456
    if factor == "recovery":
        assert json.loads(after["mfa_backup_codes"]) == []


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("field", ["action", "operation_id", "installation_id", "identity_epoch", "expected_public_sha256"])
async def test_changed_signing_command_refuses_before_factor_consumption(owned_signing, kind, field):
    f = owned_signing
    f.command = replace(f.command, action="resume", expected_public_sha256="0" * 64)
    f.pause = True
    headers, _ = credentials(f, kind)
    before = await state(f)
    task = asyncio.create_task(f.client.post("/owned/confirm", headers=headers, json={"password": f.password}))
    try:
        await asyncio.wait_for(f.captured.wait(), 10)
        value = {"action": "cancel", "operation_id": uuid4(), "installation_id": uuid4(),
                 "identity_epoch": 2, "expected_public_sha256": "1" * 64}[field]
        f.command = replace(f.command, **{field: value})
        f.proceed.set()
        response = await asyncio.wait_for(task, 10)
    finally:
        f.proceed.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    after = await state(f)
    assert response.status_code == 401, response.text
    for name in ("failed_login_attempts", "locked_until", "mfa_last_totp_step", "mfa_backup_codes", "hashed_password", "token_version"):
        assert after[name] == before[name], name


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change", ["unchanged", "role", "counter", "key_revoked", "command"])
async def test_internal_factor_receipt_rechecks_after_later_owned_wait(owned_signing, kind, change):
    f = owned_signing
    f.pause_after_factor = True
    headers, _ = credentials(f, kind)
    task = asyncio.create_task(f.client.post("/owned/confirm", headers=headers, json={"password": f.password}))
    try:
        await asyncio.wait_for(f.factor_done.wait(), 10)
        if change in {"role", "counter"}:
            await mutate(f, {"role": "viewer"} if change == "role" else {"token_version": 18})
        elif change == "key_revoked":
            async with AsyncSession(f.engine) as db:
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
                await db.commit()
        elif change == "command":
            f.command = replace(f.command, operation_id=uuid4())
        f.factor_proceed.set()
        response = await asyncio.wait_for(task, 10)
    finally:
        f.factor_proceed.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    permitted = change == "unchanged" or (kind == "jwt" and change == "key_revoked")
    assert response.status_code == (200 if permitted else 401), response.text


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("protocol", ["oidc", "ldap"])
async def test_external_account_cannot_substitute_valid_local_password_for_fresh_provider_confirmation(
    owned_signing, kind, protocol,
):
    f = owned_signing
    async with AsyncSession(f.engine) as db:
        await db.execute(update(SSOProvider).where(SSOProvider.id == f.provider).values(protocol=protocol))
        await db.commit()
    # Keep the actual valid local hash deliberately: the provider binding must
    # refuse this path before verification, even for a legacy mixed record.
    await mutate(f, {"auth_provider": protocol, "sso_provider_id": f.provider,
                     "external_id": "owned-bound-subject"})
    before = await state(f)
    headers, _ = credentials(f, kind)
    response = await f.client.post("/owned/confirm", headers=headers, json={"password": f.password})
    after = await state(f)
    assert response.status_code == 401, response.text
    assert after["failed_login_attempts"] == before["failed_login_attempts"] == 0
    assert after["hashed_password"] == before["hashed_password"] == f.password_hash


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("role", ["org_admin", "operator", "viewer"])
async def test_tenant_roles_cannot_confirm_global_signing_lifecycle(owned_signing, kind, role):
    f = owned_signing
    await mutate(f, {"role": role})
    headers, _ = credentials(f, kind)
    response = await f.client.post("/owned/confirm", headers=headers, json={"password": f.password})
    assert response.status_code == 403, response.text
    assert (await state(f))["failed_login_attempts"] == 0
