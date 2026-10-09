"""Real HTTP diagnostics preserve known rows without guessing state corruption."""
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, text

from app.models.security_audit import AuditLogRecord
from app.services.audit import AuditService
from tests.security.audit_integrity.test_audit_http_boundaries import headers
from tests.security.audit_integrity.test_audit_http_verification import client
from tests.security.audit_integrity.test_audit_http_verification import (
    owned_http_database as owned_http_database,
)


@pytest.mark.parametrize("mutation", [
    "tail_body", "tail_outside_window", "interior_body",
    "state_signature", "missing_tail", "tail_position",
])
async def test_HTTP_identifies_only_a_known_broken_row(owned_http_database, mutation, record_property):
    f = owned_http_database
    when = datetime.now(UTC)
    for number in range(2):
        identity = uuid4()
        f.audit_ids.append(identity)
        await AuditService(f.db).persist_record(AuditLogRecord(
            id=identity, timestamp=when + timedelta(seconds=number),
            action="owned_precise_diagnostic", resource_type="owned_http",
            resource_name="owned_original_name", organization_id=f.org_ids[0],
        ))
    await f.db.commit()
    expected_id = None
    if mutation in ("tail_body", "tail_outside_window", "interior_body"):
        identity = f.audit_ids[0 if mutation == "interior_body" else 1]
        await f.db.execute(text("UPDATE audit.audit_logs SET resource_name='owned_modified_body' WHERE id=:id"), {"id": identity})
        expected_id = str(identity)
    elif mutation == "state_signature":
        await f.db.execute(text("UPDATE audit.audit_chain_state SET revision=revision+1,state_hmac=repeat('0',64)"))
    elif mutation == "missing_tail":
        await f.db.execute(delete(AuditLogRecord).where(AuditLogRecord.id == f.audit_ids[1]))
    else:
        await f.db.execute(text("UPDATE audit.audit_logs SET timestamp=timestamp+INTERVAL '1 second' WHERE id=:id"), {"id": f.audit_ids[1]})
    await f.db.commit()
    async with client(headers(f)) as http:
        response = await http.get("/api/v1/audit/validate", params={"limit": 1} if mutation == "tail_outside_window" else {})
    body = response.json()
    record_property("actual_HTTP_precise_failure", json.dumps({
        "mutation": mutation, "status": response.status_code, "body": body,
        "expected_broken_id": expected_id,
    }))
    assert response.status_code == 200
    assert not body["valid"] and not body["complete"] and not body["retained_history_authenticated"]
    assert not body["history_authenticated"] and not body["external_immutability_proven"]
    assert body["broken_at"] == expected_id and body["broken_reason"]
    assert "owned_modified_body" not in response.text
    if mutation in ("state_signature", "missing_tail", "tail_position"):
        assert body["state_authenticated"] is False and body["checked"] == 0
