"""Credential default writes stay inside the owning org and exact site group.

Real PostgreSQL rows and HTTP-ASGI routes; authenticated principals are synthetic.
These are sequential requests, not a concurrent uniqueness or hardware test.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.v1.endpoints.credentials import router
from app.core.crypto import encrypt_credential
from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import Credential, Organization, Site, User


def default_cases():
    cases = []
    for method in ["post", "put"]:
        for site in ["a", "global"]:
            for vendor in [None, "omada"]:
                cases.append(
                    {
                        "label": f"{method}-{site}-{vendor}",
                        "method": method,
                        "site": site,
                        "vendor": vendor,
                        "kind": "promote",
                    }
                )
        for scope in ["vendor", "site", "device"]:
            cases.append(
                {
                    "label": f"{method}-scope-{scope}",
                    "method": method,
                    "scope": scope,
                    "kind": "promote",
                }
            )
    for site in ["foreign", "foreign-global"]:
        cases.append(
            {
                "label": f"super-promote-{site}",
                "site": site,
                "role": "super_admin",
                "kind": "promote",
            }
        )
    for label, start, changes in [
        ("move-site", {}, {"site_id": "b"}),
        ("move-to-global", {}, {"site_id": "global"}),
        ("move-from-global", {"site": "global"}, {"site_id": "a"}),
        ("move-scope", {}, {"scope": "vendor"}),
        ("move-vendor", {}, {"vendor": "omada"}),
        ("clear-vendor", {"vendor": "omada"}, {"vendor": None}),
        ("move-all", {}, {"site_id": "b", "scope": "device", "vendor": "omada"}),
    ]:
        cases.append(
            {
                "label": label,
                **start,
                "kind": "move",
                "changes": changes,
                "grants": ["a", "b"],
            }
        )
    cases += [
        {
            "label": "super-move-within-owner",
            "site": "foreign",
            "role": "super_admin",
            "kind": "move",
            "changes": {"site_id": "foreign-b"},
            "old_status": 404,
        },
        {
            "label": "super-reject-rehome-to-caller",
            "site": "foreign",
            "role": "super_admin",
            "kind": "deny",
            "changes": {"site_id": "a"},
            "status": 404,
            "old_status": 200,
        },
        {
            "label": "disable-while-moving",
            "kind": "disable",
            "changes": {"site_id": "b", "is_default": False},
            "grants": ["a", "b"],
        },
        {
            "label": "nondefault-move",
            "kind": "nondefault",
            "changes": {"site_id": "b"},
            "grants": ["a", "b"],
        },
        {
            "label": "default-description-edit",
            "kind": "metadata",
            "changes": {"description": "After"},
        },
        {
            "label": "default-unchanged-group",
            "kind": "metadata",
            "changes": {"site_id": "a", "scope": "global", "vendor": None},
        },
        {"label": "post-nondefault", "kind": "nondefault", "method": "post"},
        {
            "label": "post-invisible-site",
            "kind": "deny",
            "method": "post",
            "site": "b",
            "status": 404,
        },
        {
            "label": "post-foreign-site",
            "kind": "deny",
            "method": "post",
            "site": "foreign",
            "status": 404,
        },
        {
            "label": "post-deleted-site",
            "kind": "deny",
            "method": "post",
            "site": "deleted",
            "status": 404,
        },
        {
            "label": "post-missing-site",
            "kind": "deny",
            "method": "post",
            "site": "missing",
            "status": 404,
        },
        {
            "label": "put-invisible-credential",
            "kind": "deny",
            "site": "b",
            "status": 404,
        },
        {
            "label": "put-foreign-credential",
            "kind": "deny",
            "site": "foreign",
            "status": 404,
        },
        {
            "label": "scoped-super-foreign",
            "kind": "deny",
            "site": "foreign",
            "role": "super_admin",
            "scoped": True,
            "status": 404,
        },
        {
            "label": "put-no-permission",
            "kind": "deny",
            "permissions": ["settings:read"],
            "status": 403,
        },
        {
            "label": "post-no-permission",
            "kind": "deny",
            "method": "post",
            "permissions": ["settings:read"],
            "status": 403,
        },
        {
            "label": "put-destination-invisible",
            "kind": "deny",
            "changes": {"site_id": "b"},
            "status": 404,
        },
        {
            "label": "put-destination-foreign",
            "kind": "deny",
            "changes": {"site_id": "foreign"},
            "status": 404,
        },
    ]
    return cases


async def credential_rows(db, ids):
    rows = (
        (
            await db.execute(
                select(Credential)
                .where(Credential.id.in_(ids))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    # Every model column is checked, including encrypted secrets and audit metadata.
    return {
        str(row.id): {c.name: getattr(row, c.name) for c in Credential.__table__.columns}
        for row in rows
    }


async def make_default_fixture(db, case):
    orgs = [Organization(name="Owned credential audit", slug=uuid4().hex) for _ in range(2)]
    db.add_all(orgs)
    await db.flush()
    sites = {}
    for name in ["a", "b", "foreign", "foreign-b", "deleted"]:
        sites[name] = Site(
            name=name,
            slug=uuid4().hex,
            organization_id=orgs[int(name.startswith("foreign"))].id,
            deleted_at=datetime.now(UTC) if name == "deleted" else None,
        )
    db.add_all(sites.values())
    await db.flush()
    site_ids = {name: row.id for name, row in sites.items()}
    site_ids.update({"global": None, "foreign-global": None, "missing": uuid4()})
    # One default in each legal org/site/scope/vendor group, plus inactive/deleted controls.
    records = []
    for group_site in ["a", "b", "global", "foreign", "foreign-b", "foreign-global"]:
        for scope in ["global", "vendor", "site", "device"]:
            for vendor in [None, "omada"]:
                records.append(
                    Credential(
                        organization_id=orgs[int(group_site.startswith("foreign"))].id,
                        site_id=site_ids[group_site],
                        name=f"{group_site}-{scope}-{vendor}",
                        credential_type="basic_auth",
                        scope=scope,
                        vendor=vendor,
                        is_default=True,
                        encrypted_password=encrypt_credential("owned-credential-default-secret"),
                    )
                )
    target_site = case.get("site", "a")
    owner = orgs[int(target_site.startswith("foreign"))].id
    initial_default = case["kind"] in {"move", "disable", "metadata"}
    target = Credential(
        organization_id=owner,
        site_id=site_ids[target_site] if target_site != "missing" else None,
        name="Target",
        credential_type="basic_auth",
        scope=case.get("scope", "global"),
        vendor=case.get("vendor"),
        is_default=initial_default,
        encrypted_password=encrypt_credential("owned-credential-default-secret"),
    )
    # An inactive default is still demoted by the established policy; a deleted one is not.
    records += [
        Credential(
            organization_id=orgs[0].id,
            site_id=site_ids["a"],
            name=kind,
            credential_type="basic_auth",
            scope="global",
            is_default=True,
            is_active=kind != "inactive",
            deleted_at=datetime.now(UTC) if kind == "deleted" else None,
            encrypted_password=encrypt_credential("owned-credential-default-secret"),
        )
        for kind in ["inactive", "deleted"]
    ]
    # Avoid duplicate initial defaults for move controls, except metadata cases that must
    # not silently repair unrelated pre-existing rows.
    if initial_default and case["kind"] != "metadata":
        for row in records:
            if (row.organization_id, row.site_id, row.scope, row.vendor) == (
                owner,
                target.site_id,
                target.scope,
                target.vendor,
            ) and row.deleted_at is None:
                row.is_default = False
    user = User(
        username=uuid4().hex,
        email=uuid4().hex + "@owned.example.test",
        hashed_password="owned-synthetic",
        organization_id=orgs[0].id,
        role=case.get("role", "operator"),
        is_active=True,
    )
    db.add_all([*records, target, user])
    await db.commit()
    principal = CurrentUser(
        user,
        permissions=case.get("permissions", ["settings:write"]),
        accessible_site_ids={site_ids[s] for s in case.get("grants", ["a"])},
        scoped=case.get("scoped", False),
    )
    app = FastAPI()
    app.include_router(router, prefix="/credentials")
    app.dependency_overrides[get_current_active_user] = lambda: principal

    async def session():
        try:
            yield db
        except BaseException:
            await db.rollback()
            raise

    app.dependency_overrides[get_session] = session
    method = case.get("method", "put")
    if method == "post":
        payload = {
            "name": "New credential",
            "scope": case.get("scope", "global"),
            "vendor": case.get("vendor"),
            "site_id": str(site_ids[target_site]) if site_ids[target_site] else None,
            "is_default": case["kind"] != "nondefault",
            "password": "owned-credential-default-secret",
        }
    else:
        payload = dict(case.get("changes", {"is_default": True}))
        if "site_id" in payload:
            value = site_ids[payload["site_id"]]
            payload["site_id"] = str(value) if value else None
    ids = [r.id for r in [*records, target]]
    return SimpleNamespace(
        db=db,
        app=app,
        case=case,
        target_id=str(target.id),
        ids=ids,
        caller_org=orgs[0].id,
        payload=payload,
        method=method,
        path="/credentials/" if method == "post" else f"/credentials/{target.id}",
        before=await credential_rows(db, ids),
    )


async def inspect_default_response(f, response, *, before=False):
    c = f.case
    expected_status = (
        c.get("old_status", c.get("status", 201 if f.method == "post" else 200))
        if before
        else c.get("status", 201 if f.method == "post" else 200)
    )
    assert response.status_code == expected_status, response.text
    rows = await credential_rows(f.db, f.ids)
    expected = {key: dict(value) for key, value in f.before.items()}
    original = f.before[f.target_id]
    desired = dict(original)
    if expected_status < 300:
        for key, value in f.payload.items():
            if key in desired and key not in {"password"}:
                desired[key] = UUID(value) if key == "site_id" and value else value
        promoting = f.payload.get("is_default") is True
        group_changed = any(desired[key] != original[key] for key in ["site_id", "scope", "vendor"])
        demote = promoting or (not before and desired["is_default"] and group_changed)
        if demote:
            for key, row in expected.items():
                owner = f.caller_org if before or f.method == "post" else desired["organization_id"]
                if (
                    key != f.target_id
                    and row["organization_id"] == owner
                    and row["scope"] == desired["scope"]
                    and row["vendor"] == desired["vendor"]
                    and row["deleted_at"] is None
                    and (before or row["site_id"] == desired["site_id"])
                ):
                    row["is_default"] = False
        if f.method == "put":
            expected[f.target_id] = desired
        else:
            # Existing fixture target is an ordinary sibling during POST.
            row = expected[f.target_id]
            if (
                demote
                and row["organization_id"] == f.caller_org
                and row["scope"] == desired["scope"]
                and row["vendor"] == desired["vendor"]
                and row["deleted_at"] is None
                and (before or row["site_id"] == desired["site_id"])
            ):
                row["is_default"] = False
            new_id = UUID(response.json()["id"])
            new = (await credential_rows(f.db, [new_id]))[str(new_id)]
            assert new["organization_id"] == f.caller_org and new["site_id"] == desired["site_id"]
            assert new["is_default"] == f.payload["is_default"]
            assert (
                new["encrypted_password"]
                and "owned-credential-default-secret" not in new["encrypted_password"]
            )
    for key in rows:
        # SQLAlchemy maintains updated_at on actual writes; every other field is exact.
        found = {name: value for name, value in rows[key].items() if name != "updated_at"}
        wanted = {name: value for name, value in expected[key].items() if name != "updated_at"}
        assert found == wanted, f"Unexpected change to {f.before[key]['name']} in {c['label']}"
        if wanted == {name: value for name, value in f.before[key].items() if name != "updated_at"}:
            assert rows[key]["updated_at"] == f.before[key]["updated_at"]
            continue
        assert expected_status < 300
    assert "owned-credential-default-secret" not in response.text
    return {
        "status": response.status_code,
        "all_existing_rows_checked": len(rows),
        "encrypted_secret_columns_unchanged": True,
        "synthetic_principal": True,
    }


@pytest.mark.parametrize("case", default_cases(), ids=lambda c: c["label"])
async def test_credential_default_mutation_boundaries(db_session, case):
    f = await make_default_fixture(db_session, case)
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.request(f.method, f.path, json=f.payload)
    await inspect_default_response(f, response)
