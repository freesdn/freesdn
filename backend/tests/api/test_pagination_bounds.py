# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Regression tests for out-of-range pagination on list endpoints.

The defect: no list endpoint bounded its ``page``/``offset``/``skip`` query
parameter, so ``(page - 1) * per_page`` was bound into SQL as
``OFFSET $n::BIGINT`` and asyncpg raised ``DataError: value out of int64
range`` while *encoding* the parameter. Nothing caught it, so it fell through
to the generic 500 handler -- including on ``/api/v1/marketplace/plugins``,
which takes no auth dependency, and every hit wrote a full SELECT plus an
asyncpg traceback to the log.

Two independent guards are covered here, because either one alone leaves a
hole:

* the ``le=MAX_PAGE`` bound on the route (rejects it at the edge, 422), and
* the shared ``DBAPIError`` handler in ``app.core.middleware`` (turns anything
  that still reaches the driver into a 400 instead of a 500).

The driver-level tests execute against the real Postgres the rest of the
suite uses -- no hand-built exception objects, because the exact shape is the
whole point: asyncpg raises before the statement is sent, SQLAlchemy wraps it
in the generic ``AsyncAdapt_asyncpg_dbapi.Error``, and the result is a bare
``sqlalchemy.exc.DBAPIError``, NOT ``sqlalchemy.exc.DataError``. A handler
registered on ``DataError`` would never fire; ``test_overflow_offset_is_not_
classified_as_sqlalchemy_dataerror`` pins that.
"""

from collections.abc import AsyncGenerator

import asyncpg
import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, Query
from httpx import ASGITransport
from sqlalchemy import text
from sqlalchemy.exc import DataError as SADataError
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.middleware import setup_exception_handlers
from app.core.query import MAX_PAGE, QueryBuilder
from app.db.session import create_test_engine
from app.models.core import Organization

# One past the largest value PostgreSQL's BIGINT can hold. asyncpg rejects the
# bind rather than the server rejecting the statement.
_INT64_OVERFLOW = 2**63

# The statement is deliberately trivial: this exercises parameter binding, not
# any particular table, so it runs against a bare connection.
_OFFSET_SQL = "SELECT 1 AS n OFFSET :o"


@pytest_asyncio.fixture
async def driver_error_client(db_session: AsyncSession) -> AsyncGenerator[httpx.AsyncClient]:
    """A minimal app wired to the real exception handlers and a real engine.

    Deliberately NOT the full FreeSDN app: the point is to prove the shared
    handler installed by ``setup_exception_handlers`` classifies a real driver
    error correctly, without a route's own validation getting in the way.
    """
    app = FastAPI()
    setup_exception_handlers(app)
    engine = create_test_engine()

    @app.get("/rows")
    async def rows(offset: int = Query(0)) -> dict[str, list[int]]:
        async with engine.connect() as conn:
            result = await conn.execute(text(_OFFSET_SQL), {"o": offset})
            return {"rows": [row.n for row in result]}

    @app.get("/missing-table")
    async def missing_table() -> dict[str, str]:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1 FROM freesdn_no_such_table_xyz"))
            return {"unreachable": "yes"}

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# The shared driver-level guard (app/core/middleware.py)
# ---------------------------------------------------------------------------


async def test_overflow_offset_is_not_classified_as_sqlalchemy_dataerror(
    db_session: AsyncSession,
) -> None:
    """Pin the exception shape the handler has to match.

    Mutation this catches: narrowing ``_is_client_value_error`` to
    ``isinstance(exc, sqlalchemy.exc.DataError)``, which reads like the obvious
    fix and would silently never fire on this stack.
    """
    engine = create_test_engine()
    try:
        with pytest.raises(DBAPIError) as caught:
            async with engine.connect() as conn:
                await conn.execute(text(_OFFSET_SQL), {"o": _INT64_OVERFLOW})
    finally:
        await engine.dispose()

    assert not isinstance(caught.value, SADataError), (
        "SQLAlchemy now classifies the asyncpg bind overflow as DataError; "
        "_is_client_value_error can be simplified, but verify it still fires."
    )
    assert isinstance(caught.value.orig.__cause__, asyncpg.exceptions.DataError)


async def test_offset_beyond_int64_returns_400_not_500(
    driver_error_client: httpx.AsyncClient,
) -> None:
    """A value the driver refuses to bind is a client error, not a server one.

    Mutation this catches: removing the ``@app.exception_handler(DBAPIError)``
    registration (back to 500), or breaking the ``orig.__cause__`` lookup.
    """
    resp = await driver_error_client.get("/rows", params={"offset": str(_INT64_OVERFLOW)})

    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["type"] == "invalid_value"


async def test_offset_within_range_still_succeeds(
    driver_error_client: httpx.AsyncClient,
) -> None:
    """Control: the same route works, so the 400 above is about the value.

    Mutation this catches: a handler that 400s every request to this route,
    which would make the previous test pass for the wrong reason.
    """
    resp = await driver_error_client.get("/rows", params={"offset": "0"})

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"rows": [1]}


async def test_400_body_leaks_no_sql_or_parameters(
    driver_error_client: httpx.AsyncClient,
) -> None:
    """The response must not echo the statement or the bound parameters.

    Mutation this catches: putting ``str(exc)`` in the message, which is how
    SQLAlchemy's own repr renders and would ship the full SELECT to any
    unauthenticated caller.
    """
    resp = await driver_error_client.get("/rows", params={"offset": str(_INT64_OVERFLOW)})

    body = resp.text
    assert "SELECT" not in body.upper()
    assert str(_INT64_OVERFLOW) not in body


async def test_non_data_driver_error_still_returns_500(
    driver_error_client: httpx.AsyncClient,
) -> None:
    """A missing table is a server fault and must not be laundered into a 4xx.

    Mutation this catches: mapping every ``DBAPIError`` to 400, which would
    hide connection loss, deadlocks and schema drift behind a client error.
    """
    resp = await driver_error_client.get("/missing-table")

    assert resp.status_code == 500, resp.text
    assert resp.json()["error"]["code"] == 500


# ---------------------------------------------------------------------------
# The edge bound on the pre-auth marketplace routes
# ---------------------------------------------------------------------------


async def test_marketplace_browse_rejects_page_above_max_unauthenticated(
    async_client: httpx.AsyncClient,
) -> None:
    """The public browse route must reject the overflow before it reaches SQL.

    No credentials are sent: this route has no auth dependency, which is what
    made the 500 reachable pre-auth in the first place.

    Mutation this catches: dropping ``le=MAX_PAGE`` from ``browse_plugins``
    (the request would reach the DB and 400 via the shared handler, not 422).
    """
    resp = await async_client.get(
        "/api/v1/marketplace/plugins",
        params={"page": str(MAX_PAGE + 1), "per_page": "10"},
    )

    assert resp.status_code == 422, resp.text
    fields = [d["field"] for d in resp.json()["error"]["details"]]
    assert "query.page" in fields


async def test_marketplace_browse_rejects_the_reported_overflow_page(
    async_client: httpx.AsyncClient,
) -> None:
    """The literal request that returned an unauthenticated 500 in the field.

    Mutation this catches: any regression that lets a >2**63 page reach SQL --
    dropping ``le=MAX_PAGE``, or setting MAX_PAGE so high the product still
    overflows. Without the bound this is a 500, not a 422.
    """
    resp = await async_client.get(
        "/api/v1/marketplace/plugins",
        params={"page": "999999999999999999999999", "per_page": "10"},
    )

    assert resp.status_code == 422, resp.text


async def test_marketplace_browse_accepts_max_page(
    async_client: httpx.AsyncClient,
) -> None:
    """Control: MAX_PAGE itself is a legal offset, so the bound is not too tight.

    Mutation this catches: an off-by-one ``lt=MAX_PAGE``, or a MAX_PAGE so
    large that the resulting offset overflows anyway (the request would 400
    from the driver handler instead of 200).
    """
    resp = await async_client.get(
        "/api/v1/marketplace/plugins",
        params={"page": str(MAX_PAGE), "per_page": "10"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["plugins"] == []


async def test_marketplace_reviews_rejects_page_above_max(
    async_client: httpx.AsyncClient,
) -> None:
    """The other unauthenticated marketplace list route carries the same bound.

    Mutation this catches: fixing only ``browse_plugins`` and leaving
    ``list_reviews`` unbounded.
    """
    resp = await async_client.get(
        "/api/v1/marketplace/plugins/does-not-exist/reviews",
        params={"page": str(MAX_PAGE + 1)},
    )

    # 422 before the handler runs -- NOT the 404 an unknown slug would give.
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# The shared pagination helpers (app/core/query.py)
# ---------------------------------------------------------------------------


def test_max_page_offset_stays_inside_int64() -> None:
    """MAX_PAGE times the widest per_page in this codebase must fit in BIGINT.

    Mutation this catches: raising MAX_PAGE to something like 10**19 "because
    nobody paginates that far", which reintroduces the overflow.
    """
    widest_per_page = 1000
    assert (MAX_PAGE - 1) * widest_per_page < 2**63


def test_query_builder_paginate_clamps_page_at_max() -> None:
    """``QueryBuilder.paginate`` clamped only the low end before this fix.

    Mutation this catches: reverting ``min(MAX_PAGE, max(1, page))`` to
    ``max(1, page)``.
    """
    builder: QueryBuilder[Organization] = QueryBuilder(Organization, None)  # type: ignore[arg-type]
    builder.paginate(page=_INT64_OVERFLOW, per_page=20)

    assert builder._page == MAX_PAGE


def test_query_builder_paginate_keeps_low_bound() -> None:
    """Control: the pre-existing lower clamp is untouched.

    Mutation this catches: replacing the two-sided clamp with a bare
    ``min(MAX_PAGE, page)``, which would let ``page=0`` produce OFFSET -20.
    """
    builder: QueryBuilder[Organization] = QueryBuilder(Organization, None)  # type: ignore[arg-type]
    builder.paginate(page=0, per_page=20)

    assert builder._page == 1
