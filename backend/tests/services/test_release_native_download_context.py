# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Proposed native-download equality contract through real app/auth/SQL/files.

This is an added optional browser protocol, not proof that the old API broke an
existing query contract. No browser save, network proxy or background lifespan
acceptance. Observe actual response and durable state before status assertions.
"""

from uuid import uuid4

import pytest
from sqlalchemy import update

from app.core.cookies import ACCESS_COOKIE
from app.models.core import User
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_delivery as readers
from tests.services import test_public_release_binary as binary
from tests.services.test_public_release_binary import public_reader as public_reader


@pytest.mark.parametrize("method", ("GET", "HEAD"))
@pytest.mark.parametrize("case,expected", (
    ("matched", 200), ("non-browser", 200), ("actor", 409), ("organization", 409),
    ("missing-actor", 400), ("missing-organization", 400),
    ("invalid-actor", 400), ("invalid-organization", 400), ("zero", 400),
    ("duplicate-actor", 400), ("duplicate-organization", 400),
    ("no-auth", 401), ("agent-with-context", 401), ("agent-without-context", 200),
    ("null-organization", 200), ("header-conflict", 409),
))
async def test_native_query_context_never_replaces_current_binary_authority(
    public_reader, method, case, expected, record_property,
):
    f = public_reader
    await binary.seed(f, "legacy-explicit", f.org)
    if case == "null-organization":
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(role="super_admin", organization_id=None))
    credential = await readers.credentials(f, "jwt")
    # Exercise the actual httpOnly-cookie fallback, not a dependency bypass.
    cookie = {ACCESS_COOKIE: credential["Authorization"].removeprefix("Bearer ")}
    f.public_client.cookies.update(cookie)
    headers = {}
    query = [("release_actor", str(f.user)), ("release_organization", "none" if case == "null-organization" else str(f.org))]
    if case == "actor":
        query[0] = ("release_actor", str(uuid4()))
    elif case == "organization":
        query[1] = ("release_organization", str(f.other_org))
    elif case.startswith("missing-"):
        query = [entry for entry in query if entry[0] != ("release_actor" if case == "missing-actor" else "release_organization")]
    elif case in ("invalid-actor", "invalid-organization", "zero"):
        position = 1 if case == "invalid-organization" else 0
        query[position] = (query[position][0], "00000000-0000-0000-0000-000000000000" if case == "zero" else "invalid-synthetic")
    elif case.startswith("duplicate-"):
        query.append(query[0 if case == "duplicate-actor" else 1])
    elif case == "header-conflict":
        headers = {"X-FreeSDN-Release-Actor": str(uuid4()), "X-FreeSDN-Release-Organization": str(f.org)}
    if case in ("non-browser", "agent-without-context"):
        query = []
    if case in ("no-auth", "agent-with-context", "agent-without-context"):
        f.public_client.cookies.clear()
    if case.startswith("agent-"):
        headers = await readers.credentials(f, "agent")
    before = dict(await binary.row(f))
    before_files = binary.files(f)
    response = await f.public_client.request(method, binary.path(f), params=query, headers=headers)
    after = dict(await binary.row(f))
    record_property("observed_status", response.status_code)
    record_property("expected_status", expected)
    record_property("binary_body_disclosed", response.content == f.data)
    record_property("counter_delta", after["download_count"] - before["download_count"])
    record_property("files_unchanged", binary.files(f) == before_files)
    assert response.status_code == expected
    assert binary.files(f) == before_files
    if expected == 200:
        assert response.content == (b"" if method == "HEAD" else f.data)
        assert response.headers["content-disposition"].startswith("attachment;")
        assert response.headers["content-type"] == "application/octet-stream"
        assert after["download_count"] == before["download_count"] + int(method == "GET")
        assert {k: v for k, v in after.items() if k != "download_count"} == {k: v for k, v in before.items() if k != "download_count"}
    else:
        assert response.content != f.data and after == before
        assert "invalid-synthetic" not in response.text and str(f.legacy_root) not in response.text
