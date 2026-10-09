"""Planned real-auth caller equality headers; not authority or runtime evidence."""

from contextlib import asynccontextmanager
from dataclasses import replace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import update

from app.models.api_keys import APIKey
from app.models.core import User
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_operator as operator_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def browser(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(operator_probes.operator.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(role="super_admin", organization_id=f.org))
        yield f


def context_headers(f):
    return {"X-FreeSDN-Release-Actor": str(f.user), "X-FreeSDN-Release-Organization": str(f.org)}


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("case,status", [
    ("actor", 409), ("organization", 409), ("missing-actor", 400), ("missing-organization", 400),
    ("duplicate-actor", 400), ("duplicate-organization", 400), ("zero", 400), ("invalid", 400),
])
async def test_mismatched_partial_duplicate_context_never_reads_or_reserves(browser, kind, case, status):
    f = browser
    credential = await lifecycle_probes.headers(f, kind)
    headers = context_headers(f)
    if case == "actor":
        headers["X-FreeSDN-Release-Actor"] = str(uuid4())
    elif case == "organization":
        headers["X-FreeSDN-Release-Organization"] = str(f.other_org)
    elif case.startswith("missing-"):
        headers.pop("X-FreeSDN-Release-Actor" if case == "missing-actor" else "X-FreeSDN-Release-Organization")
    elif case == "zero":
        headers["X-FreeSDN-Release-Actor"] = "00000000-0000-0000-0000-000000000000"
    elif case == "invalid":
        headers["X-FreeSDN-Release-Organization"] = "synthetic-not-a-UUID"
    pairs = [*credential.items(), *headers.items(), ("Content-Type", "application/json")]
    if case.startswith("duplicate-"):
        name = "X-FreeSDN-Release-Actor" if case == "duplicate-actor" else "X-FreeSDN-Release-Organization"
        pairs.append((name, headers[name]))
    received = False

    async def source():
        nonlocal received
        received = True
        yield b"deliberately-malformed-json-must-not-be-read"

    before = await deletion_probes.state(f)
    response = await f.operator_client.post(f"/release-operations/{f.publication.operation_id}/reserve", headers=pairs, content=source())
    assert response.status_code == status and not received
    assert await deletion_probes.state(f) == before
    assert response.headers["cache-control"] == "private, no-store"
    assert "synthetic-not-a-UUID" not in response.text


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("mode", ["same-org", "platform-other-target", "actor-null-org", "absent-backward-compatible"])
async def test_headers_compare_actor_not_destination_and_never_change_authority(browser, kind, mode):
    f = browser
    async with f.engine.begin() as db:
        await db.execute(update(User).where(User.id == f.user).values(role="super_admin", organization_id=f.org))
    headers = context_headers(f)
    if mode == "platform-other-target":
        f.publication = replace(f.publication, organization_id=f.other_org)
    elif mode == "actor-null-org":
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(organization_id=None))
        headers["X-FreeSDN-Release-Organization"] = "none"
    elif mode == "absent-backward-compatible":
        headers = {}
    credential = await lifecycle_probes.headers(f, kind)
    response = await operator_probes.call(f, credential, "reserve", extra_headers=headers)
    assert response.status_code == 200 and response.json()["result"]["created"] is True
    assert response.json()["authorization_granted"] is False


@pytest.mark.parametrize("case", ["viewer", "scoped-key", "no-auth"])
async def test_correct_context_headers_cannot_grant_permission(browser, case):
    f = browser
    async with f.engine.begin() as db:
        if case == "viewer":
            await db.execute(update(User).where(User.id == f.user).values(role="viewer"))
        elif case == "scoped-key":
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:read"]))
    credential = {} if case == "no-auth" else await lifecycle_probes.headers(f, "key" if case == "scoped-key" else "jwt")
    before = await deletion_probes.state(f)
    response = await operator_probes.call(f, credential, "reserve", extra_headers=context_headers(f))
    assert response.status_code in (401, 403) and await deletion_probes.state(f) == before
