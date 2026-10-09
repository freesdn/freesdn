"""Explicit nulls must be rejected before violating device database constraints."""

from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db import get_session
from app.models.devices import Device
from app.schemas.devices import DeviceUpdate
from tests.api.test_device_update_authority import make_authority_fixture

FIELDS = ("name", "location", "floor", "room", "notes", "is_active", "is_managed", "credential_id")


def update_cases():
    return [
        {"label": label, "payload": payload, "expected": expected, "old": old, "changes": changes}
        for label, payload, expected, old, changes in [
            ("null-name", {"name": None}, 422, 500, {}),
            ("null-active", {"is_active": None}, 422, 500, {}),
            ("null-managed", {"is_managed": None}, 422, 500, {}),
            ("mixed-null", {"name": "After", "notes": "After", "is_active": None}, 422, 500, {}),
            ("omitted", {}, 200, 200, {}),
            ("rename", {"name": "After"}, 200, 200, {"name": "After"}),
            ("max-name", {"name": "x" * 255}, 200, 200, {"name": "x" * 255}),
            (
                "clear-nullable",
                {
                    "location": None,
                    "floor": None,
                    "room": None,
                    "notes": None,
                    "credential_id": None,
                },
                200,
                200,
                {
                    "location": None,
                    "floor": None,
                    "room": None,
                    "notes": None,
                    "credential_id": None,
                },
            ),
            (
                "false-flags",
                {"is_active": False, "is_managed": False},
                200,
                200,
                {"is_active": False, "is_managed": False},
            ),
            ("boolean-string", {"is_active": "false"}, 200, 200, {"is_active": False}),
            ("boolean-number", {"is_active": 0}, 200, 200, {"is_active": False}),
            ("empty-name", {"name": ""}, 422, 422, {}),
            ("long-name", {"name": "x" * 256}, 422, 422, {}),
            ("invalid-flag", {"is_active": "unknown"}, 422, 422, {}),
            ("missing-credential", {"credential_id": "missing"}, 404, 404, {}),
        ]
    ]


async def make_null_fixture(db, case):
    f = await make_authority_fixture(db, {"level": "write", "credential": "omitted"})
    await db.commit()
    f.null_case = case
    f.payload = dict(case["payload"])
    if case["label"] == "missing-credential":
        f.payload["credential_id"] = str(uuid4())
    row = (await db.execute(select(Device).where(Device.id == f.device_id))).scalar_one()
    f.before = {name: getattr(row, name) for name in FIELDS}

    async def session():
        try:
            yield db
        except BaseException:
            await db.rollback()
            raise

    f.app.dependency_overrides[get_session] = session
    return f


async def inspect_null_response(f, response, *, before=False):
    case = f.null_case
    expected = case["old"] if before else case["expected"]
    assert response.status_code == expected, response.text
    row = (
        await f.db.execute(
            select(Device).where(Device.id == f.device_id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    found = {name: getattr(row, name) for name in FIELDS}
    assert found == f.before | case["changes"]
    if expected == 422:
        assert isinstance(response.json()["detail"], list)
        assert all(error["loc"][0] == "body" for error in response.json()["detail"])
    assert "owned-synthetic-device-secret" not in response.text
    return {
        "status": response.status_code,
        "database_state_verified": True,
        "no_partial_write_on_rejection": expected != 200,
    }


@pytest.mark.parametrize("case", update_cases(), ids=lambda c: c["label"])
async def test_device_update_null_and_omitted_semantics(db_session, case):
    f = await make_null_fixture(db_session, case)
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.patch(f.path, json=f.payload)
    await inspect_null_response(f, response)


@pytest.mark.parametrize("field", ["name", "is_active", "is_managed"])
def test_required_database_fields_are_optional_but_non_null_in_schema(field):
    schema = DeviceUpdate.model_json_schema(mode="validation")
    prop = schema["properties"][field]
    assert field not in schema.get("required", []) and "default" not in prop
    assert prop["type"] == ("string" if field == "name" else "boolean")
    assert "anyOf" not in prop
    if field == "name":
        assert prop["minLength"] == 1 and prop["maxLength"] == 255
    assert DeviceUpdate().model_dump(exclude_unset=True) == {}


def test_nullable_fields_keep_explicit_clear_and_schema():
    fields = ["location", "floor", "room", "notes", "credential_id"]
    values = dict.fromkeys(fields)
    assert DeviceUpdate.model_validate(values).model_dump(exclude_unset=True) == values
    schema = DeviceUpdate.model_json_schema(mode="validation")
    assert all({"type": "null"} in schema["properties"][name]["anyOf"] for name in fields)
