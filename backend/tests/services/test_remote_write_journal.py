"""Real PostgreSQL retained history; no remote I/O or auth integration claim."""

import asyncio
import hashlib
from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.remote_write_intent import InvalidRemoteIntent, RemoteWriteIntent
from app.db.session import create_test_engine
from app.models.core import Organization
from app.services.remote_write_journal import (
    RemoteIntentConflict,
    RemoteWriteJournal,
    operations,
)


def intent():
    operation, backup = uuid4(), uuid4()
    final = f"sftp://192.0.2.10:22/backups/2026/10/{backup}_fixture.fsdn"
    return RemoteWriteIntent(operation, backup, uuid4(), uuid4(), uuid4(), None,
                             False, final, final + ".partial-" + operation.hex,
                             "a" * 64, hashlib.sha256(b"synthetic archive").hexdigest(), 17)


@pytest.fixture
async def journal():
    engine = create_test_engine()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(lambda sync: operations.create(sync, checkfirst=True))
        # Synthetic append-only rows intentionally stay in the archived owned
        # database. No shared database/schema or preexisting history is removed.
        yield RemoteWriteJournal(engine)
    finally:
        await engine.dispose()


@pytest.mark.parametrize("field,value", [
    ("operation_id", "not-a-uuid"), ("organization_id", None),
    ("payload_size", True), ("payload_size", 0), ("payload_size", 200 * 1024**2 + 1),
    ("payload_sha256", "A" * 64), ("destination_binding", "raw credential"),
    ("requested_by", None), ("include_secrets", 1),
    ("final_location", "sftp://user:private@192.0.2.10:22/file"),
    ("final_location", "sftp://192.0.2.10:22/../file"),
    ("final_location", "sftp://192.0.2.10:22/a%2fb"),
    ("final_location", "sftp://192.0.2.10:22/file?token=private"),
    ("final_location", "sftp://192.0.2.10:22/a\nfile"),
    ("temporary_location", "sftp://192.0.2.10:22/unrelated"),
], ids=[f"invalid-{number}" for number in range(15)])
async def test_invalid_metadata_never_creates_history(journal, field, value):
    original = intent()
    with pytest.raises(InvalidRemoteIntent, match="^Invalid remote recovery metadata$"):
        await journal.reserve(replace(original, **{field: value}))
    assert await journal.inspect(original.organization_id, original.operation_id) is None


async def test_reservation_commits_independently_of_caller_rollback(journal, request):
    value = intent()
    async with journal.engine.connect() as caller:
        transaction = await caller.begin()
        await caller.execute(insert(Organization.__table__).values(
            id=value.organization_id, name="Uncommitted owned marker", slug=uuid4().hex,
        ))
        original_tx = await caller.scalar(text("SELECT txid_current()"))
        await journal.reserve(value)
        assert caller.in_transaction() and await caller.scalar(text("SELECT txid_current()")) == original_tx
        async with journal.engine.connect() as observer:
            observed = await observer.scalar(select(Organization.id).where(Organization.id == value.organization_id))
            retained = await observer.scalar(select(operations.c.intent_bytes).where(operations.c.operation_id == value.operation_id))
            distinct = await observer.scalar(text("SELECT pg_backend_pid()")) != await caller.scalar(text("SELECT pg_backend_pid()"))
        assert distinct and observed is None and retained == value.encoded()
        await transaction.rollback()
    history = await journal.inspect(value.organization_id, value.operation_id)
    assert history.intent_bytes == value.encoded() and history.phase == "reserved"
    request.node.user_properties.extend([
        ("independent_committed_intent_observed_before_outer_rollback", True),
        ("caller_transaction_not_committed", True), ("distinct_physical_connections", distinct),
    ])


@pytest.mark.parametrize("variant", ["same", "payload", "operation"])
async def test_duplicate_reservation_never_resets_or_grants_replay(journal, variant):
    value = intent()
    await journal.reserve(value)
    await journal.advance(value, "dispatch")
    changed = value
    if variant == "payload":
        changed = replace(value, payload_sha256="b" * 64)
    if variant == "operation":
        op = uuid4()
        changed = replace(value, operation_id=op, temporary_location=value.final_location + ".partial-" + op.hex)
    with pytest.raises(RemoteIntentConflict):
        await journal.reserve(changed)
    history = await journal.inspect(value.organization_id, value.operation_id)
    assert history.phase == "dispatched" and history.outcome_unknown
    assert history.intent_bytes == value.encoded()


@pytest.mark.parametrize("action", ["acknowledge", "unknown"])
async def test_transition_cannot_skip_dispatch(journal, action):
    value = intent()
    await journal.reserve(value)
    with pytest.raises(RemoteIntentConflict):
        await journal.advance(value, action)
    assert (await journal.inspect(value.organization_id, value.operation_id)).phase == "reserved"


@pytest.mark.parametrize("field", ["organization_id", "requested_by", "destination_binding", "payload_sha256"])
async def test_changed_scope_or_intent_cannot_dispatch(journal, field):
    value = intent()
    await journal.reserve(value)
    altered = replace(value, **{field: uuid4() if field.endswith("_id") or field == "requested_by" else "b" * 64})
    with pytest.raises(RemoteIntentConflict):
        await journal.advance(altered, "dispatch")
    assert (await journal.inspect(value.organization_id, value.operation_id)).phase == "reserved"
    assert await journal.inspect(uuid4(), value.operation_id) is None


async def test_acknowledgment_is_not_verification_or_replay_permission(journal):
    value = intent()
    await journal.reserve(value)
    await journal.advance(value, "dispatch")
    unknown = await journal.inspect(value.organization_id, value.operation_id)
    assert unknown.outcome_unknown and unknown.sequence == 1
    await journal.advance(value, "acknowledge")
    acknowledged = await journal.inspect(value.organization_id, value.operation_id)
    assert acknowledged.phase == "acknowledged" and acknowledged.sequence == 2
    for action in ("dispatch", "acknowledge", "cancel_before_dispatch", "verify"):
        with pytest.raises(RemoteIntentConflict):
            await journal.advance(value, action)
    assert (await journal.inspect(value.organization_id, value.operation_id)) == acknowledged


@pytest.mark.parametrize("second_action", ["dispatch", "cancel_before_dispatch"])
async def test_real_wait_has_exactly_one_winner(journal, second_action, request):
    value = intent()
    await journal.reserve(value)
    name = "owned-remote-intent-" + uuid4().hex
    workers = create_async_engine(journal.engine.url, hide_parameters=True, poolclass=NullPool,
                                 connect_args={"server_settings": {"application_name": name}})
    contender = RemoteWriteJournal(workers)
    tasks = []
    try:
        async with journal.engine.connect() as blocker:
            transaction = await blocker.begin()
            pid = await blocker.scalar(text("SELECT pg_backend_pid()"))
            await blocker.execute(select(operations).where(operations.c.operation_id == value.operation_id).with_for_update())
            tasks = [asyncio.create_task(contender.advance(value, action)) for action in ("dispatch", second_action)]
            waited = False
            for _ in range(200):
                async with journal.engine.connect() as observer:
                    rows = (await observer.execute(text(
                        "SELECT pid, pg_blocking_pids(pid) AS holders FROM pg_stat_activity "
                        "WHERE application_name=:name"), {"name": name})).all()
                # Two updates can form a transitive tuple-lock queue.
                waiting = {row.pid: row.holders for row in rows}
                def reaches_blocker(who, graph, seen=None):
                    seen = set() if seen is None else seen
                    if who == pid:
                        return True
                    if who in seen:
                        return False
                    seen.add(who)
                    return any(reaches_blocker(parent, graph, seen) for parent in graph.get(who, []))
                waited = len(waiting) == 2 and all(reaches_blocker(who, waiting) for who in waiting)
                if waited:
                    break
                await asyncio.sleep(.01)
            assert waited, "Two genuine independent PostgreSQL waits required"
            await transaction.commit()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        assert sum(x is None for x in outcomes) == 1
        assert sum(isinstance(x, RemoteIntentConflict) for x in outcomes) == 1
        state = await journal.inspect(value.organization_id, value.operation_id)
        assert state.phase in {"dispatched", "cancelled"} and state.sequence == 1
        request.node.user_properties.append(("two_genuine_pg_blocking_pids_waits_one_winner", True))
    finally:
        # Closing blocker above releases waits before draining owned tasks.
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await workers.dispose()


@pytest.mark.parametrize("mutation", ["intent", "rewind", "skip", "delete"])
async def test_database_rejects_history_rewrite_or_erasure(journal, mutation):
    value = intent()
    await journal.reserve(value)
    await journal.advance(value, "dispatch")
    original = await journal.inspect(value.organization_id, value.operation_id)
    changes = {"intent": {"payload_size": 18}, "rewind": {"phase": "reserved", "sequence": 0},
               "skip": {"phase": "acknowledged", "sequence": 3}}
    statement = delete(operations) if mutation == "delete" else update(operations).values(**changes[mutation])
    with pytest.raises(DBAPIError):
        async with journal.engine.begin() as connection:
            await connection.execute(statement.where(operations.c.operation_id == value.operation_id))
    assert await journal.inspect(value.organization_id, value.operation_id) == original


async def test_cancel_before_dispatch_is_terminal(journal):
    value = intent()
    await journal.reserve(value)
    await journal.advance(value, "cancel_before_dispatch")
    for action in ("dispatch", "acknowledge", "cancel_before_dispatch"):
        with pytest.raises(RemoteIntentConflict):
            await journal.advance(value, action)
    history = await journal.inspect(value.organization_id, value.operation_id)
    assert history.phase == "cancelled" and not history.outcome_unknown
