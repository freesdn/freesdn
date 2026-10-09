"""Accepted SNMP communities must survive encrypted PostgreSQL storage.

These requests use real routes and storage with synthetic authenticated users.
They establish persistence and redaction, not device/protocol compatibility.
"""

from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.models.core import Credential
from tests.api.test_credential_default_scope import credential_rows
from tests.api.test_credential_input_validation import make_input_fixture


def storage_cases():
    cases = []
    for method in ["post", "put"]:
        for kind, character, lengths in [
            ("ascii", "x", [127, 128, 255, 512, 513]),
            ("two-byte", "é", [63, 64, 512]),
            ("four-byte", "🔑", [31, 32, 512, 513]),
        ]:
            for length in lengths:
                value = character * length
                status = 422 if length > 512 else 201 if method == "post" else 200
                cases.append(
                    {
                        "label": f"{method}-{kind}-{length}",
                        "method": method,
                        "payload": {"snmp_community": value},
                        "status": status,
                        "old_status": 500
                        if status < 300 and len(encrypt_credential(value)) > 255
                        else status,
                    }
                )
        for label, payload in [
            ("null", {"snmp_community": None}),
            ("empty", {"snmp_community": ""}),
            ("omitted", {}),
        ]:
            status = 201 if method == "post" else 200
            cases.append(
                {
                    "label": f"{method}-{label}",
                    "method": method,
                    "payload": payload,
                    "status": status,
                    "old_status": status,
                }
            )
    return cases


async def make_storage_fixture(db, case):
    f = await make_input_fixture(db, case)
    target = await db.get(Credential, UUID(f.target_id))
    target.snmp_community = encrypt_credential("owned-previous-community")
    await db.commit()
    f.before = await credential_rows(db, f.ids)
    return f


async def inspect_storage_response(f, response, followup, *, before=False):
    case = f.input_case
    status = case["old_status"] if before else case["status"]
    assert response.status_code == status, response.text
    assert followup.status_code == 200, followup.text
    assert "snmp_community" not in followup.json()
    found = await credential_rows(f.db, f.ids)
    changed = status < 300 and f.method == "put" and "snmp_community" in f.payload
    for key, row in found.items():
        fields = {"snmp_community", "updated_at"} if changed and key == f.target_id else set()
        assert {k: v for k, v in row.items() if k not in fields} == {
            k: v for k, v in f.before[key].items() if k not in fields
        }, "Unexpected credential mutation"
    stored = None
    if status < 300:
        identity = response.json()["id"]
        stored = (await credential_rows(f.db, [UUID(identity)]))[identity]["snmp_community"]
        expected = f.payload.get(
            "snmp_community", "owned-previous-community" if f.method == "put" else None
        )
        if expected:
            assert is_encrypted(stored) and stored != expected
            assert decrypt_credential(stored) == expected
        else:
            assert stored is None
        assert "snmp_community" not in response.json()
    if status == 422:
        assert any(e["loc"] == ["body", "snmp_community"] for e in response.json()["detail"])
    if stored:
        assert stored not in response.text and stored not in followup.text
    # Validation responses can echo rejected input; successful storage/read responses
    # must never expose an accepted secret or ciphertext.
    value = f.payload.get("snmp_community")
    if value and status < 300:
        assert value not in response.text and value not in followup.text
    return {
        "write_status": status,
        "followup_read_status": followup.status_code,
        "stored_ciphertext_characters": len(stored) if stored else 0,
        "all_existing_rows_checked": len(found),
    }


@pytest.mark.parametrize("case", storage_cases(), ids=lambda c: c["label"])
async def test_snmp_storage_preserves_accepted_secrets(db_session, case):
    f = await make_storage_fixture(db_session, case)
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.request(f.method, f.path, json=f.payload)
        identity = response.json()["id"] if response.status_code < 300 else f.target_id
        followup = await client.get(f"/credentials/{identity}")
    await inspect_storage_response(f, response, followup)
