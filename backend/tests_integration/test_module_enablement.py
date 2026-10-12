# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The module toggle, proven against a running stack rather than a mock.

The unit tests around ``app/modules/enablement.py`` exercise the dependency in
isolation. They cannot tell you whether the gate is actually reached by a real
request: that depends on the router being mounted with the dependency, on the
caller's organization resolving, and on the row the API just wrote being visible
to the next request. All three have to hold at once, and only a real request
through the real app proves it.

That matters more than usual here, because the first version of the unit ratchet
passed happily with the gate deleted. A mock can agree with you about a world
that does not exist.

The module routers are mounted by the ``_module_routes`` fixture in conftest;
ASGITransport does not run the lifespan, where main.py registers them.

The caller is an ORG_ADMIN, not the ``super_admin`` fixture. The wizard creates
that admin with ``organization_id=None`` (see test_tenant_isolation), and a
principal with no organization is deliberately not gated: module enablement is
per organization, so for a global principal there is no answer to "enabled for
whom", and the gate does not invent one. Writing this test proved that property
rather than assuming it.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

# A cheap authenticated GET inside a module router. Any route under the module
# prefix exercises the gate, because the gate is mounted on the router rather
# than on individual endpoints.
MODULE_ID = "network"
MODULE_ENDPOINT = "/api/v1/network/stats/summary"
OTHER_ENDPOINT = "/api/v1/cameras/stats"
PASSWORD = "ModuleGateP@ssw0rd!"



async def _org_admin(integration_db: Any, integration_client: Any) -> dict[str, Any]:
    """An organization-scoped admin, created directly so the wizard stays out of it."""
    from app.core.security import get_password_hash
    from app.models.core import Organization, User, UserRole

    org = Organization(
        id=uuid4(),
        name="Module Gate Org",
        slug=f"module-gate-{uuid4().hex[:8]}",
        contact_email="admin@module-gate.example.com",
    )
    integration_db.add(org)
    await integration_db.flush()

    email = f"gate-admin-{uuid4().hex[:8]}@example.com"
    user = User(
        id=uuid4(),
        email=email,
        username=f"gate_admin_{uuid4().hex[:8]}",
        full_name="Module Gate Admin",
        hashed_password=get_password_hash(PASSWORD),
        role=UserRole.ORG_ADMIN,
        organization_id=org.id,
        is_active=True,
        is_verified=True,
    )
    integration_db.add(user)
    await integration_db.commit()

    login = await integration_client.post(
        "/api/v1/auth/login", json={"login": email, "password": PASSWORD}
    )
    assert login.status_code == 200, login.text
    token = login.cookies.get("freesdn_access") or login.json().get("access_token")
    assert token, f"no access token returned: {login.text}"

    # The client keeps the login cookies, so the request carries BOTH a bearer
    # token and a session cookie. CSRF is enforced in that case by design (a
    # forged "Authorization: Bearer garbage" must not strip CSRF while the
    # cookie quietly authenticates the victim), so send the header the browser
    # would send.
    headers = {"Authorization": f"Bearer {token}"}
    csrf = login.cookies.get("freesdn_csrf")
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return {"org_id": str(org.id), "headers": headers}


async def test_disabling_a_module_actually_closes_its_endpoints(
    integration_db: Any, integration_client: Any
) -> None:
    """Disable, confirm refusal, re-enable, confirm service.

    Step two is the one that silently did nothing for a module with no
    enablement row; step three is the one that was impossible before
    ``enablement.py`` existed.
    """
    admin = await _org_admin(integration_db, integration_client)
    headers, org_id = admin["headers"], admin["org_id"]

    # Any non-403 proves the gate is not refusing. Whether the route answers
    # 200, 404 or 422 is the route's business, not this test's.
    before = await integration_client.get(MODULE_ENDPOINT, headers=headers)
    assert before.status_code != 404, (
        f"{MODULE_ENDPOINT} does not exist, so this test would prove nothing: "
        f"{before.text}"
    )
    assert before.status_code != 403, (
        f"refused before anything was disabled: {before.text}"
    )

    disabled = await integration_client.post(
        f"/api/v1/modules/org/{org_id}/disable",
        headers=headers,
        json={"module_id": MODULE_ID},
    )
    assert disabled.status_code == 200, (
        "disabling must record the decision even with no enablement row yet: "
        f"{disabled.status_code} {disabled.text}"
    )
    assert disabled.json()["is_enabled"] is False

    after = await integration_client.get(MODULE_ENDPOINT, headers=headers)
    assert after.status_code == 403, (
        "a disabled module still answered. Hiding navigation while leaving every "
        f"endpoint callable is the defect this gate closed: {after.text}"
    )
    # The app wraps errors as {"error": {"code", "message"}}; FastAPI's own
    # shape is {"detail": ...}. Accept either so this asserts on the message
    # rather than on the envelope.
    body = after.json()
    detail = str(body.get("detail") or (body.get("error") or {}).get("message") or body)
    assert MODULE_ID in detail, f"the refusal does not name the module: {detail}"
    assert "Settings > Modules" in detail, (
        f"the refusal does not tell the operator how to undo it: {detail}"
    )

    enabled = await integration_client.post(
        f"/api/v1/modules/org/{org_id}/enable",
        headers=headers,
        json={"module_id": MODULE_ID},
    )
    assert enabled.status_code == 200, enabled.text

    restored = await integration_client.get(MODULE_ENDPOINT, headers=headers)
    assert restored.status_code != 403, (
        f"stayed refused after being re-enabled: {restored.text}"
    )


async def test_disabling_one_module_does_not_refuse_the_others(
    integration_db: Any, integration_client: Any
) -> None:
    """The gate is built per module id, and this is what proves it.

    ``register_routes`` builds one dependency per module inside a loop. A single
    shared dependency, or a closure capturing the loop variable, would refuse
    every module the moment any one of them was disabled. Nothing in the unit
    tests would notice, because each dependency is constructed in isolation
    there.
    """
    admin = await _org_admin(integration_db, integration_client)
    headers, org_id = admin["headers"], admin["org_id"]

    disabled = await integration_client.post(
        f"/api/v1/modules/org/{org_id}/disable",
        headers=headers,
        json={"module_id": MODULE_ID},
    )
    assert disabled.status_code == 200, disabled.text

    other = await integration_client.get(OTHER_ENDPOINT, headers=headers)
    assert other.status_code != 403, (
        f"disabling '{MODULE_ID}' also refused cameras; the gate is not per "
        f"module: {other.text}"
    )
