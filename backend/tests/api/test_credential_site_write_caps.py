"""Credential writes enforce each site's permission cap before mutation or testing.

PostgreSQL and HTTP routes are real; users are synthetic. Credential tests stop
at an instrumented validation boundary, with no DNS, decryption or vendor I/O.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.dependencies import CurrentUser, get_current_active_user
from app.models.core import User
from tests.api.test_credential_default_scope import (
    credential_rows,
    inspect_default_response,
    make_default_fixture,
)


def write_cap_cases():
    cases = []
    for action in ["create", "update", "delete", "test"]:
        allowed = 201 if action == "create" else 400 if action == "test" else 200
        for level in ["read", "invalid", "write", "admin", "full", None]:
            cases.append(
                {
                    "label": f"{action}-{level}",
                    "action": action,
                    "level": level,
                    "status": 403 if level in {"read", "invalid"} else allowed,
                    "old_status": allowed,
                }
            )
        for label, extra, status in [
            ("global-read-grant", {"site": "global", "level": "read"}, allowed),
            ("org-admin-read-grant", {"role": "org_admin", "level": "read"}, allowed),
            ("super-admin-read-grant", {"role": "super_admin", "level": "read"}, allowed),
            ("grantless", {"grants": []}, allowed),
            ("no-write-permission", {"permissions": ["settings:read"]}, 403),
            (
                "scoped-super-read-key",
                {"role": "super_admin", "scoped": True, "permissions": ["settings:read"]},
                403,
            ),
            ("invisible-site", {"site": "b"}, 404),
            ("foreign-tenant", {"site": "foreign"}, 404),
        ]:
            cases.append(
                {
                    "label": f"{action}-{label}",
                    "action": action,
                    **extra,
                    "status": status,
                    "old_status": status,
                }
            )
    for label, origin, destination, levels, status, old in [
        ("read-to-write", "a", "b", {"a": "read", "b": "write"}, 403, 200),
        ("write-to-read", "a", "b", {"a": "write", "b": "read"}, 403, 200),
        ("write-to-invalid", "a", "b", {"a": "write", "b": "invalid"}, 403, 200),
        ("read-to-global", "a", "global", {"a": "read"}, 403, 200),
        ("global-to-read", "global", "a", {"a": "read"}, 403, 200),
        ("write-to-write", "a", "b", {"a": "write", "b": "write"}, 200, 200),
        ("write-to-global", "a", "global", {"a": "write"}, 200, 200),
        ("global-to-write", "global", "a", {"a": "write"}, 200, 200),
        ("write-to-foreign", "a", "foreign", {"a": "write"}, 404, 404),
        ("write-to-deleted", "a", "deleted", {"a": "write"}, 404, 404),
    ]:
        cases.append(
            {
                "label": label,
                "action": "move",
                "site": origin,
                "destination": destination,
                "levels": levels,
                "grants": ["a", "b"],
                "status": status,
                "old_status": old,
            }
        )
    return cases


async def make_cap_fixture(db, case):
    action = case["action"]
    default_case = {
        "label": case["label"],
        "kind": "move" if action == "move" else "promote",
        "method": "post" if action == "create" else "put",
        "site": case.get("site", "a"),
        "permissions": case.get("permissions", ["settings:read", "settings:write"]),
        "role": case.get("role", "operator"),
        "scoped": case.get("scoped", False),
        "grants": case.get("grants", ["a"]),
    }
    if action == "move":
        default_case["changes"] = {"site_id": case["destination"]}
    f = await make_default_fixture(db, default_case)
    original = f.app.dependency_overrides[get_current_active_user]()
    user_id = original.user.id
    grants = set(original.accessible_site_ids)
    site_ids = {
        row["name"].split("-global-")[0]: row["site_id"]
        for row in f.before.values()
        if "-global-" in row["name"]
    }
    levels = {identity: case.get("level", "write") for identity in grants}
    levels.update({site_ids[name]: value for name, value in case.get("levels", {}).items()})

    async def principal():
        user = await db.get(User, user_id, populate_existing=True)
        return CurrentUser(
            user,
            permissions=default_case["permissions"],
            accessible_site_ids=grants,
            site_access_levels=levels,
            scoped=case.get("scoped", False),
        )

    f.app.dependency_overrides[get_current_active_user] = principal
    f.cap_case = case
    if action == "delete":
        f.method, f.payload = "delete", None
    elif action == "test":
        f.method, f.path = "post", f.path + "/test"
        f.payload = {"target_ip": "192.0.2.1"}
    return f


async def inspect_cap_response(f, response, validation_calls, *, before=False):
    case = f.cap_case
    status = case["old_status"] if before else case["status"]
    assert response.status_code == status, response.text
    action = case["action"]
    if action in {"create", "update", "move"}:
        f.case["status"] = status
        await inspect_default_response(f, response)
    else:
        rows = await credential_rows(f.db, f.ids)
        for key, row in rows.items():
            ignored = (
                {"deleted_at", "updated_at"}
                if action == "delete" and status == 200 and key == f.target_id
                else set()
            )
            assert {k: v for k, v in row.items() if k not in ignored} == {
                k: v for k, v in f.before[key].items() if k not in ignored
            }, "Denied or read-only operation changed stored data"
            if ignored:
                assert row["deleted_at"] is not None and f.before[key]["deleted_at"] is None
    expected_calls = 1 if action == "test" and status == 400 else 0
    assert len(validation_calls) == expected_calls
    assert "owned-credential-default-secret" not in response.text
    return {
        "status": status,
        "validation_boundary_calls": len(validation_calls),
        "existing_credential_rows_checked": len(f.ids),
    }


@pytest.mark.parametrize("case", write_cap_cases(), ids=lambda c: c["label"])
async def test_credential_site_write_caps(db_session, monkeypatch, case):
    import app.core.security_utils as security

    f = await make_cap_fixture(db_session, case)
    calls = []

    def stop_at_validation(*args, **kwargs):
        calls.append(True)
        raise ValueError("Owned qualification boundary: no outgoing request")

    monkeypatch.setattr(security, "validate_target_host", stop_at_validation)
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.request(f.method, f.path, json=f.payload)
    await inspect_cap_response(f, response, calls)
