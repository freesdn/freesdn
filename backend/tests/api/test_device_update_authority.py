"""Device edits enforce both destination-site write caps and credential visibility.

Actual PostgreSQL rows and HTTP-ASGI routes; authentication context is synthetic.
No credential decryption or external device operation is exercised.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.v1.endpoints.devices import router
from app.core.crypto import encrypt_credential
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Credential, Organization, Site, User
from app.models.devices import Device


def authority_cases():
    cases = []
    for level in ["write", "admin", None]:
        for credential in ["a", "b", "global", "foreign", "deleted", "missing", "clear", "omitted"]:
            expected = 404 if credential in {"b", "foreign", "deleted", "missing"} else 200
            cases.append(
                {
                    "label": f"{level}-{credential}",
                    "level": level,
                    "credential": credential,
                    "expected": expected,
                    "old": 200 if credential == "b" else expected,
                }
            )
    for level in ["read", "invalid"]:
        for credential in ["a", "global", "b", "clear", "omitted"]:
            cases.append(
                {
                    "label": f"{level}-{credential}",
                    "level": level,
                    "credential": credential,
                    "expected": 403,
                    "old": 200,
                }
            )
    controls = [
        {"label": "org-admin-sibling", "role": "org_admin", "credential": "b", "expected": 200},
        {"label": "super-sibling", "role": "super_admin", "credential": "b", "expected": 200},
        {"label": "grantless-sibling", "grants": [], "credential": "b", "expected": 200},
        {"label": "both-granted", "grants": ["a", "b"], "credential": "b", "expected": 200},
        {"label": "missing-permission", "permissions": ["device:read"], "expected": 403},
        {
            "label": "super-read-key",
            "role": "super_admin",
            "scoped": True,
            "permissions": ["device:read"],
            "expected": 403,
        },
        {
            "label": "org-admin-read-key",
            "role": "org_admin",
            "scoped": True,
            "permissions": ["device:read"],
            "expected": 403,
        },
        {
            "label": "super-scoped-foreign-credential",
            "role": "super_admin",
            "scoped": True,
            "credential": "foreign",
            "expected": 404,
        },
        {
            "label": "org-admin-foreign-credential",
            "role": "org_admin",
            "credential": "foreign",
            "expected": 404,
        },
        {"label": "device-outside-grant", "device": "b", "expected": 404},
        {"label": "foreign-device", "device": "foreign", "expected": 403},
        {"label": "deleted-device", "device": "deleted", "expected": 404},
    ]
    for case in controls:
        case["old"] = case["expected"]
    return cases + controls


async def make_authority_fixture(db, case):
    org = Organization(name="Owned device audit", slug=uuid4().hex)
    foreign = Organization(name="Owned foreign audit", slug=uuid4().hex)
    db.add_all([org, foreign])
    await db.flush()
    sites = {}
    for name in ["a", "b", "foreign"]:
        site = Site(
            name=name, slug=uuid4().hex, organization_id=foreign.id if name == "foreign" else org.id
        )
        db.add(site)
        sites[name] = site
    await db.flush()
    credentials = {}
    for name in ["a", "b", "global", "foreign", "deleted"]:
        credential = Credential(
            organization_id=foreign.id if name == "foreign" else org.id,
            site_id=None if name == "global" else sites["a" if name == "deleted" else name].id,
            name=name,
            credential_type="basic_auth",
            encrypted_password=encrypt_credential("owned-synthetic-device-secret"),
            deleted_at=datetime.now(UTC) if name == "deleted" else None,
        )
        db.add(credential)
        credentials[name] = credential
    await db.flush()
    target = case.get("device", "a")
    device = Device(
        site_id=sites["a" if target == "deleted" else target].id,
        name="Before",
        device_type="switch",
        notes="Before notes",
        location="Before location",
        credential_id=credentials["a"].id,
        is_managed=False,
        deleted_at=datetime.now(UTC) if target == "deleted" else None,
    )
    user = User(
        username=uuid4().hex,
        email=uuid4().hex + "@owned.example.test",
        hashed_password="owned-synthetic",
        role=case.get("role", "operator"),
        organization_id=org.id,
        is_active=True,
    )
    db.add_all([device, user])
    await db.flush()
    grants = {sites[n].id for n in case.get("grants", ["a"])}
    principal = CurrentUser(
        user,
        permissions=case.get("permissions", ["device:update"]),
        accessible_site_ids=grants,
        site_access_levels={s: case.get("level", "write") for s in grants},
        scoped=case.get("scoped", False),
    )
    app = FastAPI()
    app.include_router(router, prefix="/devices")
    app.dependency_overrides[get_current_active_user] = lambda: principal

    async def session():
        yield db

    app.dependency_overrides[get_session] = session
    credential_name = case.get("credential", "a")
    data = {
        "name": "After",
        "notes": "After notes",
        "location": "After location",
        "is_managed": True,
    }
    if credential_name != "omitted":
        data["credential_id"] = (
            None
            if credential_name == "clear"
            else str(credentials[credential_name].id if credential_name in credentials else uuid4())
        )
    return SimpleNamespace(
        db=db,
        app=app,
        device_id=device.id,
        original_credential=credentials["a"].id,
        data=data,
        path=f"/devices/{device.id}",
    )


async def inspect_authority_response(f, response, expected):
    assert response.status_code == expected, response.text
    row = (
        await f.db.execute(
            select(Device).where(Device.id == f.device_id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    if expected == 200:
        assert (row.name, row.notes, row.location, row.is_managed) == (
            "After",
            "After notes",
            "After location",
            True,
        )
        assert (str(row.credential_id) if row.credential_id else None) == f.data.get(
            "credential_id", str(f.original_credential)
        )
        assert response.json()["credential_id"] == (
            str(row.credential_id) if row.credential_id else None
        )
    else:
        assert (row.name, row.notes, row.location, row.is_managed, row.credential_id) == (
            "Before",
            "Before notes",
            "Before location",
            False,
            f.original_credential,
        )
    assert "owned-synthetic-device-secret" not in response.text
    return {
        "status": response.status_code,
        "all_fields_unchanged_on_denial": expected != 200,
        "writes_verified_on_success": expected == 200,
        "secret_not_in_response": True,
    }


@pytest.mark.parametrize("case", authority_cases(), ids=lambda c: c["label"])
async def test_device_update_authority_with_real_rows(db_session, case):
    f = await make_authority_fixture(db_session, case)
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.patch(f.path, json=f.data)
    await inspect_authority_response(f, response, case["expected"])
