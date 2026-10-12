# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Every module GET answers without a server error.

The ten module routers were unreachable from this harness until the
``_module_routes`` fixture was added, because ASGITransport does not run the
lifespan where main.py mounts them. So this surface -- most of the product --
had never been exercised over HTTP against a real database. The first sweep
found it healthy: 91 of 94 parameterless GETs answered 200 and the other three
answered 422 because they require query parameters.

This keeps it that way. It is a smoke test and says so: it asserts only that
nothing returns 5xx or raises, because a 200 is not required to be correct and
a 404 or 422 can be the right answer for an empty database or a missing
parameter. What it catches is the class no unit test can: an endpoint that
imports fine and explodes when a real request reaches it with a real session
behind it.

Parameterless GETs only. Nothing is created, changed or deleted, and no path
parameter has to be invented, which keeps the test from asserting things about
ids it made up.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any
from uuid import uuid4

import pytest

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

MODULE_IDS = frozenset(
    {
        "network",
        "firewall",
        "cameras",
        "voip",
        "hypervisor",
        "storage",
        "backup",
        "collector",
        "ai",
        "access_control",
    }
)
PASSWORD = "SmokeP@ssw0rd!"


def _module_get_paths() -> list[str]:
    """Parameterless module GETs, read from the generated schema.

    Taken from ``app.openapi()`` rather than ``app.routes``: since FastAPI
    0.137 ``include_router`` appends an opaque ``_IncludedRouter`` with no path,
    so walking app.routes finds nothing and a test built on it would sweep an
    empty list while appearing to pass.
    """
    from app.main import app

    paths = app.openapi().get("paths", {})
    return sorted(
        path
        for path, operations in paths.items()
        if "get" in operations
        and "{" not in path
        and path.startswith("/api/v1/")
        and path.split("/")[3] in MODULE_IDS
    )


async def _org_admin_headers(integration_db: Any, integration_client: Any) -> dict[str, str]:
    from app.core.security import get_password_hash
    from app.models.core import Organization, User, UserRole

    org = Organization(
        id=uuid4(),
        name="Smoke Org",
        slug=f"smoke-{uuid4().hex[:8]}",
        contact_email="smoke@example.com",
    )
    integration_db.add(org)
    await integration_db.flush()

    email = f"smoke-{uuid4().hex[:8]}@example.com"
    integration_db.add(
        User(
            id=uuid4(),
            email=email,
            username=f"smoke_{uuid4().hex[:8]}",
            full_name="Smoke Admin",
            hashed_password=get_password_hash(PASSWORD),
            role=UserRole.ORG_ADMIN,
            organization_id=org.id,
            is_active=True,
            is_verified=True,
        )
    )
    await integration_db.commit()

    login = await integration_client.post(
        "/api/v1/auth/login", json={"login": email, "password": PASSWORD}
    )
    assert login.status_code == 200, login.text
    token = login.cookies.get("freesdn_access") or login.json().get("access_token")
    assert token, login.text
    headers = {"Authorization": f"Bearer {token}"}
    csrf = login.cookies.get("freesdn_csrf")
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return headers


async def test_no_module_get_returns_a_server_error(
    integration_db: Any, integration_client: Any
) -> None:
    headers = await _org_admin_headers(integration_db, integration_client)
    paths = _module_get_paths()

    # If the fixture ever stops mounting the module routers, this sweep would
    # silently cover nothing. Fail instead.
    assert len(paths) > 50, (
        f"only {len(paths)} module GETs found; the module routers are probably "
        "not mounted, so this test would prove nothing"
    )

    seen: Counter[int] = Counter()
    broken: list[str] = []
    for path in paths:
        try:
            response = await integration_client.get(path, headers=headers)
        except Exception as exc:  # noqa: BLE001 - any raise is a failure here
            broken.append(f"{path} RAISED {type(exc).__name__}: {exc}")
            continue
        seen[response.status_code] += 1
        if response.status_code >= 500:
            body = re.sub(r"\s+", " ", response.text)[:200]
            broken.append(f"{path} -> {response.status_code} {body}")

    assert not broken, (
        f"{len(broken)} module endpoint(s) returned a server error "
        f"(status distribution {dict(sorted(seen.items()))}):\n  "
        + "\n  ".join(broken)
    )
