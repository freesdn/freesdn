"""SQLAlchemy-shaped gateway double with real audit signatures, not SQL proof.

The session models only the explicitly used query/result shapes. It does not
simulate database locking, savepoint rollback or durable commits; the separate
PostgreSQL gateway cases provide those observations.
"""
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, AsyncSessionTransaction
from sqlalchemy.sql.dml import Update
from sqlalchemy.sql.elements import TextClause

from app.core.audit_state import decode_state, encode_state, sign_state
from app.models.core import Controller
from app.models.security_audit import AUDIT_APPEND_SEQUENCE, AuditChainState, AuditLogRecord
from app.models.staging import AdapterPendingChange
from app.services.audit import _compute_row_hmac, _resolve_hmac_key
from app.services.audit_chain import position


def make_audit_session(controller_type):
    """Keep transaction factories/result access sync and database calls async.

    Original tests can continue assigning execute.return_value for the pending
    change. Controller and audit-tail reads have different scalar contracts.
    Unknown statements fail explicitly instead of receiving the pending row.
    """
    session = MagicMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.flush = AsyncMock()
    session.add = MagicMock()
    transaction = MagicMock(spec=AsyncSessionTransaction)
    transaction.__aenter__ = AsyncMock(return_value=transaction)
    transaction.__aexit__ = AsyncMock(return_value=False)
    session.begin_nested = MagicMock(return_value=transaction)
    session.audit_tail = None
    session.audit_sequence = 0
    session.audit_revision = 1
    session.audit_state_writes = 0
    session.audit_state = {
        "v": 1, "epoch": str(uuid4()), "tail": None, "boundary": None,
        "live_rows": 0, "legacy_rows": 0, "unsigned_history_rows": 0,
    }

    def seal():
        payload = encode_state(session.audit_state)
        session.audit_raw_state = SimpleNamespace(
            id=1, revision=session.audit_revision, state_bytes=payload,
            state_hmac=sign_state(session.audit_revision, payload, _resolve_hmac_key()),
        )

    def seed_audit_tail():
        assert session.audit_tail is None and not session.add.called
        row = AuditLogRecord(
            id=uuid4(), timestamp=datetime.now(UTC), append_sequence=1,
            action="owned_fixture_tail", resource_type="owned_fixture",
            actor_type="user", status="success", tags=[], prev_hash=None,
        )
        row.row_hmac = _compute_row_hmac(None, row)
        session.audit_tail = row
        session.audit_sequence = 1
        session.audit_state.update(tail=position(row), live_rows=1)
        seal()
        return row.row_hmac

    session.seed_audit_tail = seed_audit_tail
    seal()

    async def execute(statement, parameters=None):
        if isinstance(statement, TextClause):
            if statement.text != "SELECT pg_advisory_xact_lock(:k)":
                raise AssertionError("Unexpected gateway fixture SQL text")
            return MagicMock()
        if isinstance(statement, Update):
            if statement.table.name != AuditChainState.__tablename__:
                raise AssertionError("Unexpected gateway fixture UPDATE table")
            values = statement.compile().params
            assert set(values) == {"revision", "state_bytes", "state_hmac", "id_1", "revision_1"}
            assert values["id_1"] == 1 and values["revision_1"] == session.audit_revision
            assert values["revision"] == session.audit_revision + 1
            state = decode_state(values["revision"], values["state_bytes"], values["state_hmac"], _resolve_hmac_key())
            assert state is not None and session.add.called
            row = session.add.call_args.args[0]
            assert isinstance(row, AuditLogRecord)
            assert state == {**session.audit_state, "tail": position(row), "live_rows": session.audit_state["live_rows"] + 1}
            assert row.row_hmac == _compute_row_hmac(row.prev_hash, row)
            session.audit_revision = values["revision"]
            session.audit_state = state
            session.audit_tail = row
            session.audit_state_writes += 1
            seal()
            return SimpleNamespace(rowcount=1)
        descriptions = statement.column_descriptions
        if [d["entity"] for d in descriptions] == [AuditChainState] * 4:
            assert [d["name"] for d in descriptions] == ["id", "revision", "state_bytes", "state_hmac"]
            assert statement._for_update_arg is not None
            assert statement.compile().params == {"id_1": 1}
            return SimpleNamespace(first=lambda: session.audit_raw_state)
        if len(descriptions) != 1:
            raise AssertionError("Unexpected gateway fixture SQL projection")
        column = descriptions[0]
        if column["entity"] is AdapterPendingChange:
            return session.execute.return_value
        if column["entity"] is Controller and column["name"] == "controller_type":
            return MagicMock(scalar_one_or_none=MagicMock(return_value=controller_type))
        raise AssertionError("Unexpected gateway fixture SQL query")

    async def scalar(statement, parameters=None):
        assert getattr(statement, "sequence", None) is AUDIT_APPEND_SEQUENCE
        assert parameters is None
        session.audit_sequence += 1
        return session.audit_sequence

    async def scalars(statement, parameters=None):
        descriptions = statement.column_descriptions
        assert len(descriptions) == 1 and descriptions[0]["entity"] is AuditLogRecord
        assert descriptions[0]["name"] == "AuditLogRecord"
        assert statement._for_update_arg is not None
        assert statement.get_execution_options().get("populate_existing") is True
        assert str(statement._limit_clause.value) == "1"
        assert parameters is None
        return SimpleNamespace(first=lambda: session.audit_tail)

    session.execute = AsyncMock(side_effect=execute)
    session.scalar = AsyncMock(side_effect=scalar)
    session.scalars = AsyncMock(side_effect=scalars)
    return session
