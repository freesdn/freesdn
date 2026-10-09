"""Regression checks for documented HTTP trust and response-size boundaries."""
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.core.security import create_access_token
from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService
from app.services.audit_chain import prune_prefix
from tests.security.audit_integrity.test_audit_http_verification import client
from tests.security.audit_integrity.test_audit_http_verification import (
    owned_http_database as owned_http_database,
)
from tests.security.audit_integrity.test_audit_legacy_retention_migration import (
    insert_old,
    old_schema,
    revision,
)


def headers(f, *, scope=None):
    return {"Authorization": "Bearer " + create_access_token(
        subject=str(f.user_id), token_version=17,
        extra_claims={"scope": scope} if scope is not None else None,
    )}


@pytest.mark.parametrize("scope", ["stream", "future-purpose"])
async def test_scoped_bearer_cannot_read_global_chain(owned_http_database, scope, record_property):
    async with client(headers(owned_http_database, scope=scope)) as http:
        response = await http.get("/api/v1/audit/validate")
    body = response.json()
    record_property("actual_scoped_bearer", json.dumps({"scope": scope, "status": response.status_code, "body": body}))
    assert response.status_code == 401
    assert not {"valid", "checked", "unsigned_history_rows", "retention_applied"} & body.keys()


@pytest.mark.parametrize("mutation", ["state_bytes", "state_signature", "missing_state"])
async def test_HTTP_never_certifies_invalid_local_state(owned_http_database, mutation, record_property):
    f = owned_http_database
    identity = uuid4()
    f.audit_ids.append(identity)
    await AuditService(f.db).persist_record(AuditLogRecord(
        id=identity, timestamp=datetime.now(UTC), action="owned_http_state", resource_type="owned_http",
        organization_id=f.org_ids[0],
    ))
    await f.db.commit()
    if mutation == "missing_state":
        # Privileged fixture adversary, not a claim that ordinary SQL users can
        # bypass the state DELETE/TRUNCATE guard. Recreated privately at teardown.
        await f.db.execute(text("DROP TABLE audit.audit_chain_state"))
        await f.db.execute(text("CREATE TABLE audit.audit_chain_state "
            "(id smallint PRIMARY KEY,revision bigint NOT NULL,state_bytes bytea NOT NULL,state_hmac varchar(64))"))
    elif mutation == "state_bytes":
        await f.db.execute(text("UPDATE audit.audit_chain_state SET revision=revision+1,state_bytes=convert_to('{}','UTF8')"))
    else:
        await f.db.execute(text("UPDATE audit.audit_chain_state SET revision=revision+1,state_hmac=repeat('0',64)"))
    await f.db.commit()
    async with client(headers(f)) as http:
        response = await http.get("/api/v1/audit/validate")
    body = response.json()
    record_property("actual_HTTP_state_failure", json.dumps({"mutation": mutation, "status": response.status_code, "body": body}))
    assert response.status_code == 200
    assert not body["valid"] and not body["complete"] and not body["retained_history_authenticated"]
    assert not body["state_authenticated"] and not body["boundary_verified"]
    assert not body["history_authenticated"] and not body["external_immutability_proven"]
    assert body["broken_reason"] and body["broken_at"] is None


async def test_HTTP_preserves_unsigned_legacy_uncertainty_after_retention(owned_http_database, record_property):
    f = owned_http_database
    identity, new_id = uuid4(), uuid4()
    f.audit_ids.extend([identity, new_id])
    old = AuditLogRecord(id=identity, timestamp=datetime.now(UTC) - timedelta(days=200),
                         action="owned_unsigned_legacy", resource_type="owned_http",
                         prev_hash=None, row_hmac=None)
    # Actual revisions over a reconstructed predecessor, not a shipped-version
    # installation. Original legacy migration helper bytes are retained.
    async with f.db.bind.begin() as connection:
        await old_schema(connection)
        await insert_old(connection, [old])
        await connection.run_sync(lambda c: revision(c, 29, "upgrade"))
        await connection.run_sync(lambda c: revision(c, 30, "upgrade"))
    async with client(headers(f)) as http:
        unsealed = await http.get("/api/v1/audit/validate")
        await AuditService(f.db).persist_record(AuditLogRecord(
            id=new_id, timestamp=datetime.now(UTC), action="owned_new_signed", resource_type="owned_http",
        ))
        await f.db.commit()
        sealed = await http.get("/api/v1/audit/validate")
        removed = await prune_prefix(f.db, datetime.now(UTC) - timedelta(days=90))
        await f.db.commit()
        retained = await http.get("/api/v1/audit/validate")
    bodies = [r.json() for r in (unsealed, sealed, retained)]
    record_property("actual_HTTP_legacy_states", json.dumps({"statuses": [r.status_code for r in (unsealed, sealed, retained)],
                    "bodies": bodies, "removed": removed}))
    assert all(r.status_code == 200 for r in (unsealed, sealed, retained))
    for body in bodies:
        assert body["valid"] and body["complete"]
        assert not body["retained_history_authenticated"] and not body["history_authenticated"]
        assert not body["external_immutability_proven"]
    assert not bodies[0]["state_authenticated"] and bodies[0]["unchained"] == 1
    assert bodies[0]["unsigned_history_rows"] is None
    assert bodies[1]["state_authenticated"] and bodies[1]["unsigned_history_rows"] == 1
    assert bodies[1]["unchained"] == 1 and bodies[1]["checked"] == 2
    assert removed == 1 and bodies[2]["retention_applied"] and bodies[2]["state_authenticated"]
    assert bodies[2]["unsigned_history_rows"] == 1 and bodies[2]["unchained"] == 0 and bodies[2]["checked"] == 1


async def test_HTTP_serialized_window_budget_requires_smaller_window(owned_http_database, record_property):
    f = owned_http_database
    payload = "owned-window-budget-" + "x" * (2 * 1024 * 1024)
    for number in range(4):
        identity = uuid4()
        f.audit_ids.append(identity)
        await AuditService(f.db).persist_record(AuditLogRecord(
            id=identity, timestamp=datetime.now(UTC) + timedelta(seconds=number), action="owned_window_budget",
            resource_type="owned_http", extra_metadata={"owned_payload": payload},
        ))
    await f.db.commit()
    async with client(headers(f)) as http:
        full = await http.get("/api/v1/audit/validate")
        partial = await http.get("/api/v1/audit/validate", params={"limit": 1})
    a, b = full.json(), partial.json()
    record_property("actual_HTTP_window_budget", json.dumps({"statuses": [full.status_code, partial.status_code],
                    "full": a, "partial": b, "fixture_payload_characters": len(payload)}))
    assert full.status_code == partial.status_code == 200
    assert not a["valid"] and not a["complete"] and not a["retained_history_authenticated"]
    assert "8 MiB" in a["broken_reason"]
    assert b["valid"] and b["checked"] == 1 and not b["complete"] and not b["retained_history_authenticated"]
    assert b["next_start_id"] == str(f.audit_ids[1])
    assert "owned-window-budget-" not in full.text + partial.text
