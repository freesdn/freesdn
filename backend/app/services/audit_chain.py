# SPDX-License-Identifier: AGPL-3.0-only
"""Transactional local audit anchors and one-statement verification snapshots.

Caller owns commit/rollback. Every writer/cleaner takes the shared advisory
lock after its caller-state autoflush, then locks state, tail and prefix rows.
An external immutable checkpoint is still needed to detect whole-DB rollback.
"""

from __future__ import annotations

import hmac
import json
from datetime import UTC, datetime
from typing import Any, cast, overload
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_state import (
    MAX_REVISION,
    AuditPosition,
    AuditState,
    decode_state,
    encode_state,
    sign_state,
)
from app.models.security_audit import AuditChainState, AuditLogRecord


class AuditSnapshotRowError(ValueError):
    """A specific row body failed after its snapshot position was authenticated."""

    def __init__(self, message: str, row: AuditLogRecord) -> None:
        super().__init__(message)
        self.row = row


@overload
def position(row: None) -> None: ...


@overload
def position(row: AuditLogRecord) -> AuditPosition: ...


def position(row: AuditLogRecord | None) -> AuditPosition | None:
    if row is None:
        return None
    return {
        "id": str(row.id),
        "sequence": row.append_sequence,
        "timestamp": row.timestamp.astimezone(UTC).isoformat(),
        "hash": row.row_hmac,
    }


@overload
def from_json(body: None) -> None: ...


@overload
def from_json(body: dict[str, Any]) -> AuditLogRecord: ...


def from_json(body: dict[str, Any] | None) -> AuditLogRecord | None:
    if body is None:
        return None
    fields = dict(body)
    fields["extra_metadata"] = fields.pop("metadata")
    for name in ("id", "organization_id", "site_id"):
        if fields[name] is not None:
            fields[name] = UUID(fields[name])
    fields["timestamp"] = datetime.fromisoformat(fields["timestamp"]).astimezone(UTC)
    if fields["response_time_ms"] is not None:
        fields["response_time_ms"] = float(fields["response_time_ms"])
    return AuditLogRecord(**fields)


def _key() -> bytes:
    from app.services.audit import _resolve_hmac_key

    return _resolve_hmac_key()


def verify_body(row: AuditLogRecord) -> None:
    from app.services.audit import _compute_row_hmac

    if row.row_hmac is None:
        if row.append_sequence is not None:
            raise ValueError("Unsigned sequenced audit row")
        return
    if not hmac.compare_digest(_compute_row_hmac(row.prev_hash, row), row.row_hmac):
        raise ValueError("Audit row body or position signature mismatch")


_CAPTURE = """
SELECT jsonb_build_object(
    'live_rows',count(*), 'legacy_rows',count(*) FILTER (WHERE append_sequence IS NULL),
    'unsigned_rows',count(*) FILTER (WHERE row_hmac IS NULL),
    'tail',(SELECT to_jsonb(a) FROM audit.audit_logs a
            ORDER BY COALESCE(append_sequence,0) DESC,timestamp DESC,id DESC LIMIT 1)
) AS value FROM audit.audit_logs
"""


def captured_state(capture: dict[str, Any]) -> AuditState:
    return {
        "v": 1,
        "epoch": str(uuid4()),
        "tail": position(from_json(capture["tail"])),
        "boundary": None,
        "live_rows": capture["live_rows"],
        "legacy_rows": capture["legacy_rows"],
        "unsigned_history_rows": capture["unsigned_rows"],
    }


async def load_locked_state(db: AsyncSession) -> tuple[int, AuditState]:
    raw = (
        await db.execute(
            select(
                AuditChainState.id,
                AuditChainState.revision,
                AuditChainState.state_bytes,
                AuditChainState.state_hmac,
            )
            .where(AuditChainState.id == 1)
            .with_for_update()
        )
    ).first()
    if raw is None:
        raise ValueError("Missing audit chain state; refusing silent genesis")
    state = decode_state(raw.revision, bytes(raw.state_bytes), raw.state_hmac, _key())
    if raw.revision == MAX_REVISION:
        raise ValueError("Audit state revision exhausted")
    if state is None:
        # A migration-created unsealed marker is not authentication of old
        # history. Preserve old fields/signatures and remember unsigned rows.
        state = captured_state(await db.scalar(text(_CAPTURE)))
    return raw.revision, state


async def check_locked_tail(db: AsyncSession, state: AuditState) -> None:
    row = (
        await db.scalars(
            select(AuditLogRecord)
            .order_by(
                func.coalesce(AuditLogRecord.append_sequence, 0).desc(),
                AuditLogRecord.timestamp.desc(),
                AuditLogRecord.id.desc(),
            )
            .limit(1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).first()
    if state["live_rows"]:
        if row is None or position(row) != state["tail"]:
            raise ValueError("Audit tail differs from authenticated state")
        verify_body(row)
    elif row is not None or state["tail"] != state["boundary"]:
        raise ValueError("Empty audit history differs from authenticated boundary")


async def store_locked_state(db: AsyncSession, revision: int, state: AuditState) -> None:
    payload = encode_state(state)
    signature = sign_state(revision + 1, payload, _key())
    result = await db.execute(
        update(AuditChainState)
        .where(
            AuditChainState.id == 1,
            AuditChainState.revision == revision,
        )
        .values(revision=revision + 1, state_bytes=payload, state_hmac=signature)
    )
    if cast(CursorResult[Any], result).rowcount != 1:
        raise ValueError("Audit state changed during serialized operation")


async def prune_prefix(db: AsyncSession, cutoff: datetime, *, batch_size: int = 1000) -> int:
    """Delete at most one eligible append prefix and atomically seal its boundary."""
    from app.services.audit import _AUDIT_CHAIN_LOCK_KEY

    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError("Invalid audit retention batch size")
    async with db.begin_nested():
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_CHAIN_LOCK_KEY})
        revision, state = await load_locked_state(db)
        await check_locked_tail(db, state)
        actual = await db.scalar(select(func.count()).select_from(AuditLogRecord))
        if actual != state["live_rows"]:
            raise ValueError("Audit retention refuses an unaccounted row-count change")
        rows = list(
            (
                await db.scalars(
                    select(AuditLogRecord)
                    .order_by(
                        func.coalesce(AuditLogRecord.append_sequence, 0),
                        AuditLogRecord.timestamp,
                        AuditLogRecord.id,
                    )
                    .limit(batch_size + 1)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).all()
        )
        expected = state["boundary"]["hash"] if state["boundary"] is not None else None
        saw_signature = expected is not None
        chosen = []
        for row in rows[:batch_size]:
            if row.timestamp >= cutoff:
                break
            verify_body(row)
            if row.prev_hash != expected:
                raise ValueError("Audit retention would hide a broken link")
            if row.row_hmac is None and saw_signature:
                raise ValueError("Audit retention would hide an unsigned interior row")
            if row.row_hmac is not None:
                saw_signature = True
            expected = row.row_hmac
            chosen.append(row)
        if not chosen:
            return 0
        if len(chosen) > state["live_rows"]:
            raise ValueError("Audit retention count differs from authenticated state")
        if len(chosen) < len(rows):
            following = rows[len(chosen)]
            verify_body(following)
            if saw_signature and (following.row_hmac is None or following.prev_hash != expected):
                raise ValueError("Audit retention boundary does not link to the retained row")
        elif len(chosen) != state["live_rows"] or position(chosen[-1]) != state["tail"]:
            raise ValueError("Audit retention tail/count differs from authenticated state")
        state["boundary"] = position(chosen[-1])
        state["live_rows"] -= len(chosen)
        state["legacy_rows"] -= sum(row.append_sequence is None for row in chosen)
        result = await db.execute(
            delete(AuditLogRecord).where(
                AuditLogRecord.id.in_([row.id for row in chosen]),
            )
        )
        if cast(CursorResult[Any], result).rowcount != len(chosen):
            raise ValueError("Audit retention delete count changed")
        await store_locked_state(db, revision, state)
        return len(chosen)


_SNAPSHOT = """
WITH start_row AS (SELECT * FROM audit.audit_logs WHERE id=CAST(:start_id AS uuid)),
end_row AS (SELECT * FROM audit.audit_logs WHERE id=CAST(:end_id AS uuid)),
picked AS MATERIALIZED (
 SELECT a.* FROM audit.audit_logs a
 WHERE (CAST(:start_id AS uuid) IS NULL OR EXISTS (
   SELECT 1 FROM start_row s WHERE
   (COALESCE(a.append_sequence,0),a.timestamp,a.id) >=
   (COALESCE(s.append_sequence,0),s.timestamp,s.id)))
 AND (CAST(:end_id AS uuid) IS NULL OR EXISTS (
   SELECT 1 FROM end_row e WHERE
   (COALESCE(a.append_sequence,0),a.timestamp,a.id) <=
   (COALESCE(e.append_sequence,0),e.timestamp,e.id)))
 ORDER BY COALESCE(a.append_sequence,0),a.timestamp,a.id LIMIT :fetch
), first_row AS (
 SELECT * FROM picked ORDER BY COALESCE(append_sequence,0),timestamp,id LIMIT 1
), previous_row AS (
 SELECT a.* FROM audit.audit_logs a WHERE EXISTS (
 SELECT 1 FROM first_row f WHERE
 (COALESCE(a.append_sequence,0),a.timestamp,a.id) <
 (COALESCE(f.append_sequence,0),f.timestamp,f.id))
 ORDER BY COALESCE(a.append_sequence,0) DESC,a.timestamp DESC,a.id DESC LIMIT 1
), stats AS (
 SELECT count(*) AS live_rows,count(*) FILTER(WHERE append_sequence IS NULL) AS legacy_rows,
        count(*) FILTER(WHERE row_hmac IS NULL) AS unsigned_rows FROM audit.audit_logs
)
SELECT 0 AS kind,0::bigint AS ordinal,jsonb_build_object(
 'anchor',(SELECT jsonb_build_object('revision',revision,'bytes',encode(state_bytes,'hex'),
                                   'signature',state_hmac) FROM audit.audit_chain_state WHERE id=1),
 'stats',(SELECT to_jsonb(stats) FROM stats),
 'tail',(SELECT to_jsonb(a) FROM audit.audit_logs a
         ORDER BY COALESCE(append_sequence,0) DESC,timestamp DESC,id DESC LIMIT 1),
 'previous',(SELECT to_jsonb(previous_row) FROM previous_row),
 'start_exists',CAST(:start_id AS uuid) IS NULL OR EXISTS(SELECT 1 FROM start_row),
 'end_exists',CAST(:end_id AS uuid) IS NULL OR EXISTS(SELECT 1 FROM end_row),
 'bounds_ordered',CAST(:start_id AS uuid) IS NULL OR CAST(:end_id AS uuid) IS NULL OR EXISTS (
   SELECT 1 FROM start_row s CROSS JOIN end_row e WHERE
   (COALESCE(s.append_sequence,0),s.timestamp,s.id) <=
   (COALESCE(e.append_sequence,0),e.timestamp,e.id))
) AS value
UNION ALL SELECT 1,row_number() OVER(ORDER BY COALESCE(p.append_sequence,0),p.timestamp,p.id),
                      to_jsonb(p) FROM picked p
ORDER BY kind,ordinal
"""


async def snapshot(
    db: AsyncSession,
    start_id: UUID | None,
    end_id: UUID | None,
    size: int,
) -> tuple[dict[str, Any], list[AuditLogRecord]]:
    """One PostgreSQL statement/snapshot, including the caller's flushed writes."""
    cursor = await db.stream(
        text(_SNAPSHOT).execution_options(yield_per=50),
        {
            "start_id": start_id,
            "end_id": end_id,
            "fetch": size + 1,
        },
    )
    meta: dict[str, Any] | None = None
    rows: list[AuditLogRecord] = []
    used = 0
    try:
        async for result in cursor:
            # These JSON objects are emitted by the fixed _SNAPSHOT query; row
            # values are mapped back through the model before HMAC validation.
            body = cast(dict[str, Any], result.value)
            used += len(json.dumps(body, separators=(",", ":")).encode())
            if used > 8 * 1024 * 1024:
                raise ValueError("Audit verification window exceeds 8 MiB; choose a smaller window")
            if result.kind == 0:
                if meta is not None:
                    raise ValueError("Duplicate audit verification metadata")
                meta = body
            else:
                rows.append(from_json(body))
    finally:
        await cursor.close()
    if meta is None:
        raise ValueError("Missing audit verification metadata")
    return meta, rows


def verified_snapshot_state(meta: dict[str, Any]) -> AuditState | None:
    raw = meta["anchor"]
    if raw is None:
        raise ValueError("Missing audit chain state")
    state = decode_state(raw["revision"], bytes.fromhex(raw["bytes"]), raw["signature"], _key())
    if state is None:
        return None
    if (
        meta["stats"]["live_rows"] != state["live_rows"]
        or meta["stats"]["legacy_rows"] != state["legacy_rows"]
    ):
        raise ValueError("Retained audit row count differs from authenticated state")
    if meta["stats"]["unsigned_rows"] > state["unsigned_history_rows"]:
        raise ValueError("Audit history contains unexpected unsigned records")
    tail = from_json(meta["tail"])
    if state["live_rows"]:
        if tail is None or position(tail) != state["tail"]:
            raise ValueError("Audit tail differs from authenticated state")
        try:
            verify_body(tail)
        except ValueError as exc:
            # Preserve the known row for diagnostics without accepting its body.
            # Earlier state/count/position failures do not identify a bad row.
            raise AuditSnapshotRowError(str(exc), tail) from exc
    elif tail is not None or state["tail"] != state["boundary"]:
        raise ValueError("Empty retained audit history differs from authenticated boundary")
    return state
