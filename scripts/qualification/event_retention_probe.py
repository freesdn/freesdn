"""Real SQL acceptance inside a disposable, isolated qualification database.

Invoked only by check_event_retention.py. Never point this at existing data:
it creates and truncates events.event_records in its fresh test database.
"""

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import uuid4

from app.models.events import EventRecord
from app.services import event_retention
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def main():
    assert os.environ.get("FREESDN_RETENTION_FIXTURE") == "isolated-disposable"
    engine = create_async_engine(os.environ["LOGDB_URL"])
    factory = async_sessionmaker(engine, expire_on_commit=False)
    cases = []
    cutoff = datetime.now(UTC) - timedelta(days=90)
    original_cutoff = event_retention.retention_cutoff

    def fixed_cutoff(days):
        original_cutoff(days)
        return cutoff

    event_retention.retention_cutoff = fixed_cutoff

    def case(name, **details):
        cases.append({"case": name, **details})

    async def count():
        async with factory() as session:
            return await session.scalar(
                text("SELECT count(*) FROM events.event_records")
            )

    async def seed(total, days=5):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO events.event_records (id,event_type,timestamp,payload) "
                    "SELECT gen_random_uuid(),'retention-fixture', "
                    "CAST(:cutoff AS timestamptz) - make_interval(days => :days), "
                    "jsonb_build_object('n',n) FROM generate_series(1,:total) n"
                ),
                {"cutoff": cutoff, "days": days, "total": total},
            )

    async def reset():
        async with engine.begin() as connection:
            await connection.execute(text("TRUNCATE events.event_records"))

    try:
        async with engine.connect() as connection:
            extension = await connection.scalar(
                text("SELECT extversion FROM pg_extension WHERE extname='timescaledb'")
            )
            assert extension
            assert await count() == 0
        case(
            "shipped LogDB migration initialized empty hypertable",
            timescaledb=extension,
        )

        result = await event_retention.prune_event_history(factory)
        assert result["deleted"] == 0 and result["complete"]
        case("empty database completes")

        # Reproduce the old implementation's missing batch limit without
        # committing its destructive statement, even inside this disposable DB.
        await seed(2501)
        async with factory() as session:
            old = await session.execute(
                delete(EventRecord)
                .where(EventRecord.timestamp < cutoff)
                .returning(EventRecord.id)
            )
            old_count = len(old.scalars().all())
            assert old_count == 2501
            await session.rollback()
        assert await count() == 2501
        case(
            "old delete exceeds intended batch; negative control rolled back",
            rows_in_one_statement=old_count,
        )

        shared = uuid4()
        async with engine.begin() as connection:
            await connection.execute(
                EventRecord.__table__.insert(),
                [
                    {
                        "id": shared,
                        "timestamp": cutoff - timedelta(days=15),
                        "event_type": "shared-old",
                    },
                    {
                        "id": shared,
                        "timestamp": cutoff + timedelta(days=15),
                        "event_type": "shared-recent",
                    },
                    {"id": uuid4(), "timestamp": cutoff, "event_type": "boundary"},
                ],
            )
        result = await event_retention.prune_event_history(factory)
        assert (
            result["deleted"] == 2502 and result["batches"] == 3 and result["complete"]
        )
        async with factory() as session:
            assert set(
                (await session.scalars(select(EventRecord.event_type))).all()
            ) == {"shared-recent", "boundary"}
        case(
            "bounded multi-batch delete preserves cutoff and shared UUID in newer chunk",
            **result,
        )

        await reset()
        await seed(2001)
        async with factory() as locked:
            await locked.execute(
                select(EventRecord.id)
                .order_by(EventRecord.id)
                .limit(1)
                .with_for_update()
            )
            result = await event_retention.prune_event_history(factory)
            assert (
                result["deleted"] == 2000
                and not result["complete"]
                and await count() == 1
            )
            await locked.rollback()
        result2 = await event_retention.prune_event_history(factory)
        assert result2["deleted"] == 1 and result2["complete"]
        case(
            "locked row survives with incomplete result; next sweep drains it",
            deleted_while_locked=result["deleted"],
        )

        await reset()
        await seed(5007)
        results = await asyncio.gather(
            *[event_retention.prune_event_history(factory) for _ in range(3)]
        )
        assert sum(r["deleted"] for r in results) == 5007 and await count() == 0
        case(
            "three overlapping sweepers neither double-count nor lose rows",
            deleted=sum(r["deleted"] for r in results),
        )

        await reset()
        await seed(2501)
        async with engine.begin() as connection:
            compressed = (
                await connection.execute(
                    text(
                        "SELECT compress_chunk(c) FROM show_chunks('events.event_records') c"
                    )
                )
            ).all()
            assert compressed
        result = await event_retention.prune_event_history(factory)
        assert result["deleted"] == 2501 and result["complete"] and await count() == 0
        case(
            "compressed Timescale chunks support bounded cleanup",
            compressed_chunks=len(compressed),
            **result,
        )

        await reset()
        await seed(100007)
        started = monotonic()
        result = await event_retention.prune_event_history(factory)
        assert result["deleted"] == 100000 and result["batches"] == 100
        assert (
            result["remaining_expired"]
            and not result["complete"]
            and await count() == 7
        )
        followup = await event_retention.prune_event_history(factory)
        assert followup["deleted"] == 7 and followup["complete"]
        case(
            "default 100-batch cap leaves backlog explicit; safe follow-up drains it",
            first_deleted=result["deleted"],
            first_batches=result["batches"],
            remainder=7,
            seconds=round(monotonic() - started, 3),
        )

        # Force a real SQL failure after one committed batch. The second batch
        # rolls back; a later run resumes instead of discarding committed progress.
        await reset()
        await seed(2001)
        async with engine.begin() as connection:
            await connection.execute(
                text("CREATE SEQUENCE public.retention_delete_calls")
            )
            await connection.execute(
                text(
                    "CREATE FUNCTION public.retention_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('public.retention_delete_calls') > 1000 THEN RAISE EXCEPTION 'qualification injected failure'; END IF; RETURN OLD; END $$"
                )
            )
            await connection.execute(
                text(
                    "CREATE TRIGGER retention_fault BEFORE DELETE ON events.event_records FOR EACH ROW EXECUTE FUNCTION public.retention_fault()"
                )
            )
        try:
            await event_retention.prune_event_history(factory)
        except DBAPIError as error:
            assert "qualification injected failure" in str(error)
        else:
            raise AssertionError("Injected failure was swallowed")
        assert await count() == 1001
        async with engine.begin() as connection:
            await connection.execute(
                text("DROP TRIGGER retention_fault ON events.event_records")
            )
        result = await event_retention.prune_event_history(factory)
        assert result["deleted"] == 1001 and result["complete"]
        case(
            "real SQL failure rolls back current batch and preserves previous commit",
            remaining_after_failure=1001,
        )
        print(
            "EVENT_RETENTION_RESULT=" + json.dumps({"passed": True, "cases": cases}),
            flush=True,
        )
    finally:
        event_retention.retention_cutoff = original_cutoff
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
