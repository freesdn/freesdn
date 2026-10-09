"""Refusal controls for the query double; no PostgreSQL durability claim."""
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.audit_state import decode_state
from app.models.core import User
from app.models.security_audit import AuditChainState, AuditLogRecord
from app.services.audit import AuditService, _compute_row_hmac, _resolve_hmac_key
from tests.services.gateway._audit_session import make_audit_session


@pytest.mark.parametrize("operation", ["execute", "scalar", "scalars"])
async def test_unknown_query_shape_is_not_a_success(operation):
    session = make_audit_session("unifi")
    with pytest.raises(AssertionError):
        await getattr(session, operation)(select(User))
    assert not session.add.called and session.audit_state_writes == 0


@pytest.mark.parametrize("malformed", ["unlocked", "wrong-id", "reversed", "incomplete"])
async def test_state_read_requires_the_actual_locked_singleton_shape(malformed):
    columns = [AuditChainState.id, AuditChainState.revision, AuditChainState.state_bytes, AuditChainState.state_hmac]
    if malformed == "reversed":
        columns.reverse()
    elif malformed == "incomplete":
        columns.pop()
    statement = select(*columns).where(AuditChainState.id == (2 if malformed == "wrong-id" else 1))
    if malformed != "unlocked":
        statement = statement.with_for_update()
    with pytest.raises(AssertionError):
        await make_audit_session("unifi").execute(statement)


@pytest.mark.parametrize("existing", [False, True])
async def test_actual_writer_advances_a_valid_seed_without_signature_bypass(existing):
    session = make_audit_session("unifi")
    prior = session.seed_audit_tail() if existing else None
    raw = session.audit_raw_state
    initial = decode_state(raw.revision, raw.state_bytes, raw.state_hmac, _resolve_hmac_key())
    assert initial["live_rows"] == int(existing)
    row = AuditLogRecord(id=uuid4(), timestamp=datetime.now(UTC), action="owned_double", resource_type="owned")
    await AuditService(session).persist_record(row)
    assert row.prev_hash == prior and row.append_sequence == 1 + int(existing)
    assert row.row_hmac == _compute_row_hmac(prior, row)
    assert session.audit_state_writes == 1 and session.audit_revision == 2
    assert session.audit_state["live_rows"] == 1 + int(existing)
    session.add.assert_called_once_with(row)
    session.flush.assert_awaited_once_with()
    session.commit.assert_not_awaited()


@pytest.mark.parametrize("corruption", ["tail-body", "state-signature"])
async def test_actual_verifier_refuses_corrupt_fixture_before_record_add(corruption):
    session = make_audit_session("unifi")
    session.seed_audit_tail()
    if corruption == "tail-body":
        session.audit_tail.action = "owned_corrupt"
    else:
        session.audit_raw_state.state_hmac = "0" * 64
    with pytest.raises(ValueError):
        await AuditService(session).persist_record(AuditLogRecord(action="owned_refused", resource_type="owned"))
    session.add.assert_not_called()
    assert session.audit_state_writes == 0


async def test_flush_failure_never_claims_a_state_update():
    session = make_audit_session("unifi")
    raw = session.audit_raw_state
    session.flush.side_effect = RuntimeError("owned fixture flush refusal")
    with pytest.raises(RuntimeError, match="owned fixture flush refusal"):
        await AuditService(session).persist_record(AuditLogRecord(action="owned_refused", resource_type="owned"))
    session.add.assert_called_once()
    session.flush.assert_awaited_once_with()
    assert session.audit_state_writes == 0 and session.audit_raw_state is raw
    session.commit.assert_not_awaited()
