"""Credential requests must fail validation before invalid database writes.

PostgreSQL/HTTP integration with synthetic authenticated principals. In particular,
JSON null options must not be committed and then fail response serialization.
"""

from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.dependencies import CurrentUser, get_current_active_user
from app.models.core import Credential, User
from app.schemas.credentials import CredentialCreate, CredentialUpdate
from tests.api.test_credential_default_scope import credential_rows, make_default_fixture


def input_cases():
    cases = []
    for method in ["post", "put"]:
        success = 201 if method == "post" else 200
        for field in ["name", "credential_type", "scope", "is_default", "options"]:
            cases.append(
                {
                    "label": f"{method}-null-{field}",
                    "method": method,
                    "payload": {field: None},
                    "status": 422,
                    "old_status": 500 if method == "put" else 422,
                    "persisted_null": method == "put" and field == "options",
                }
            )
        for field, limit, old_limit in [("vendor", 100, 128), ("username", 255, 512)]:
            for length in [limit, limit + 1, old_limit, old_limit + 1]:
                cases.append(
                    {
                        "label": f"{method}-{field}-{length}",
                        "method": method,
                        "payload": {field: "x" * length},
                        "status": success if length == limit else 422,
                        "old_status": success
                        if length == limit
                        else 500
                        if length <= old_limit
                        else 422,
                    }
                )
        for label, payload, status in [
            ("omitted", {}, success),
            ("false-default", {"is_default": False}, success),
            ("options-dict", {"options": {"site_key": "owned"}}, success),
            ("options-list", {"options": []}, 422),
            ("invalid-default", {"is_default": "unknown"}, 422),
            ("empty-name", {"name": ""}, 422),
            ("long-name", {"name": "x" * 256}, 422),
        ]:
            cases.append(
                {
                    "label": f"{method}-{label}",
                    "method": method,
                    "payload": payload,
                    "status": status,
                    "old_status": status,
                }
            )
    for field, limit in [("vendor", 100), ("username", 255)]:
        for length in [limit, limit + 1]:
            cases.append(
                {
                    "label": f"put-unicode-{field}-{length}",
                    "method": "put",
                    "payload": {field: "é" * length},
                    "status": 200 if length == limit else 422,
                    "old_status": 200 if length == limit else 500,
                }
            )
    cases.append(
        {
            "label": "put-clear-nullable",
            "method": "put",
            "status": 200,
            "old_status": 200,
            "payload": {
                "vendor": None,
                "username": None,
                "description": None,
                "site_id": None,
                "password": None,
            },
        }
    )
    return cases


async def make_input_fixture(db, case):
    f = await make_default_fixture(
        db,
        {
            "label": "input-fixture",
            "kind": "nondefault",
            "permissions": ["settings:read", "settings:write"],
            "vendor": "omada",
        },
    )
    row = await db.get(Credential, UUID(f.target_id))
    row.username = "Before username"
    row.description = "Before description"
    await db.commit()
    f.before = await credential_rows(db, f.ids)
    original = f.app.dependency_overrides[get_current_active_user]()
    user_id = original.user.id
    grants = set(original.accessible_site_ids)

    async def principal():
        # A rejected request rolls back and expires ORM state. Real authentication
        # loads a user for each request; do the same for the synthetic principal.
        user = await db.get(User, user_id, populate_existing=True)
        return CurrentUser(
            user, permissions=["settings:read", "settings:write"], accessible_site_ids=grants
        )

    f.app.dependency_overrides[get_current_active_user] = principal
    f.input_case = case
    f.method = case["method"]
    f.path = "/credentials/" if f.method == "post" else f"/credentials/{f.target_id}"
    f.payload = (
        {"name": "Created"} | case["payload"] if f.method == "post" else dict(case["payload"])
    )
    return f


async def inspect_input_response(f, response, read_response, *, before=False):
    case = f.input_case
    status = case["old_status"] if before else case["status"]
    assert response.status_code == status, response.text
    found = await credential_rows(f.db, f.ids)
    expected = {k: dict(v) for k, v in f.before.items()}
    persisted_null = before and case.get("persisted_null", False)
    if persisted_null:
        expected[f.target_id]["options"] = None
    if status < 300 and f.method == "put":
        for key, value in f.payload.items():
            expected[f.target_id]["encrypted_password" if key == "password" else key] = value
    for key, row in found.items():
        actual = {k: v for k, v in row.items() if k != "updated_at"}
        wanted = {k: v for k, v in expected[key].items() if k != "updated_at"}
        assert actual == wanted, f"Unexpected mutation of {row['name']}"
        if wanted == {k: v for k, v in f.before[key].items() if k != "updated_at"}:
            assert row["updated_at"] == f.before[key]["updated_at"]
    if f.method == "post" and status == 201:
        created = (await credential_rows(f.db, [UUID(response.json()["id"])]))[
            response.json()["id"]
        ]
        for key, value in f.payload.items():
            assert created[key] == value
    # The follow-up request detects persistent corruption that a write-response-only
    # test could miss. All synthetic principals have read and write permissions.
    assert read_response.status_code == (500 if persisted_null else 200), read_response.text
    if not persisted_null:
        assert isinstance(read_response.json()["options"], dict)
    if status == 422:
        assert all(error["loc"][0] == "body" for error in response.json()["detail"])
    assert "owned-credential-default-secret" not in response.text
    assert "owned-credential-default-secret" not in read_response.text
    return {
        "write_status": status,
        "followup_read_status": read_response.status_code,
        "persisted_invalid_options": persisted_null,
        "all_existing_rows_checked": len(found),
    }


@pytest.mark.parametrize("case", input_cases(), ids=lambda c: c["label"])
async def test_credential_input_validation_preserves_database(db_session, case):
    f = await make_input_fixture(db_session, case)
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.request(f.method, f.path, json=f.payload)
        read_response = await client.get(f"/credentials/{f.target_id}")
    await inspect_input_response(f, response, read_response)


@pytest.mark.parametrize("field", ["name", "credential_type", "scope", "is_default", "options"])
def test_update_required_values_are_optional_but_non_null(field):
    schema = CredentialUpdate.model_json_schema(mode="validation")
    prop = schema["properties"][field]
    assert field not in schema.get("required", [])
    assert "default" not in prop and "anyOf" not in prop
    assert CredentialUpdate().model_dump(exclude_unset=True) == {}


@pytest.mark.parametrize("model", [CredentialCreate, CredentialUpdate])
@pytest.mark.parametrize("field,limit", [("vendor", 100), ("username", 255)])
def test_credential_schema_widths_match_storage(model, field, limit):
    prop = model.model_json_schema(mode="validation")["properties"][field]
    assert {"type": "null"} in prop["anyOf"]
    assert next(p for p in prop["anyOf"] if p["type"] == "string")["maxLength"] == limit


def test_nullable_credential_update_fields_remain_clearable():
    fields = [
        "vendor",
        "username",
        "description",
        "site_id",
        "password",
        "api_key",
        "token",
        "snmp_community",
        "ssh_private_key",
        "certificate",
    ]
    values = dict.fromkeys(fields)
    assert CredentialUpdate.model_validate(values).model_dump(exclude_unset=True) == values
    schema = CredentialUpdate.model_json_schema(mode="validation")
    assert all({"type": "null"} in schema["properties"][field]["anyOf"] for field in fields)
