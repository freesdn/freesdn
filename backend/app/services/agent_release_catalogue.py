# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded scoped catalogue query and encoding, without committing caller work.

The caller must capture actual authority before this read and revalidate it after
encoding, immediately before returning the bytes. These functions do not grant
authority. Existing PostgreSQL/driver limits are not changed or increased.
"""

import asyncio
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import Select, and_, false, func, or_, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, is_unscoped_superuser
from app.core.owned_async import complete_before_cancellation
from app.models.agents import AgentRelease
from app.schemas.agent_release_catalogue import (
    CataloguePage,
    CatalogueRecord,
    LegacyCatalogueRecord,
)

MAX_ROWS = 100
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
QUERY_SECONDS = 5
NO_STORE = {"Cache-Control": "private, no-store", "Pragma": "no-cache"}
_FIELDS = (
    "id",
    "organization_id",
    "version",
    "platform",
    "agent_type",
    "download_url",
    "checksum_sha256",
    "signature",
    "file_size",
    "release_notes",
    "min_backend_version",
    "is_latest",
    "is_prerelease",
    "published_at",
    "download_count",
)
_LEGACY = TypeAdapter(list[LegacyCatalogueRecord])


def catalogue_statement(
    user: CurrentUser,
    *,
    platform: str | None,
    agent_type: str | None,
    limit: int,
    before_published_at: datetime | None = None,
    before_id: UUID | None = None,
) -> Select[*tuple[Any, ...]]:
    if type(limit) is not int or not 1 <= limit <= MAX_ROWS:
        raise HTTPException(400, "Catalogue limit must be between 1 and 100", headers=NO_STORE)
    if (before_published_at is None) != (before_id is None):
        raise HTTPException(400, "Supply both catalogue cursor components", headers=NO_STORE)
    if before_published_at is not None and (
        not isinstance(before_published_at, datetime)
        or before_published_at.utcoffset() is None
        or not isinstance(before_id, UUID)
    ):
        raise HTTPException(
            400, "A timezone-aware timestamp and UUID cursor are required", headers=NO_STORE
        )
    c = AgentRelease.__table__.c
    columns = []
    for name in _FIELDS:
        column = c[name]
        # Text has no database field-width bound. The extra character detects
        # an incompatible row without ever materializing the entire value.
        if name == "release_notes":
            column = func.left(column, 20001).label(name)
        elif name == "signature":
            column = func.left(column, 4097).label(name)
        columns.append(column)
    q = select(*columns)
    if not is_unscoped_superuser(user):
        q = q.where(
            false()
            if user.organization_id is None
            else or_(c.organization_id == user.organization_id, c.organization_id.is_(None))
        )
    for name, value in (("platform", platform), ("agent_type", agent_type)):
        if value is not None:
            if type(value) is not str or len(value) > 50:
                raise HTTPException(400, "Invalid catalogue filter", headers=NO_STORE)
            if value:
                q = q.where(c[name] == value.lower())
    if before_published_at is not None:
        q = q.where(
            or_(
                c.published_at < before_published_at,
                and_(c.published_at == before_published_at, c.id < before_id),
            )
        )
    return q.order_by(c.published_at.desc(), c.id.desc()).limit(limit + 1)


@complete_before_cancellation
async def catalogue_rows(
    session: AsyncSession, statement: Select[*tuple[Any, ...]]
) -> Sequence[RowMapping]:
    # Keep the session exclusively owned until this finite query has drained.
    # A single asyncio deadline cancellation lets SQLAlchemy/asyncpg finish
    # cancellation and graceful close. An enclosing cancelled AnyIO scope must
    # not repeatedly interrupt that close or release the session underneath it.
    # This does not promise server cleanup during network/process failure.
    try:
        async with asyncio.timeout(QUERY_SECONDS):
            return (await session.execute(statement)).mappings().all()
    except (TimeoutError, DBAPIError):
        raise HTTPException(
            503, "Catalogue query could not complete within service limits", headers=NO_STORE
        ) from None


def _bounded(content: bytes) -> bytes:
    if len(content) > MAX_RESPONSE_BYTES:
        raise HTTPException(503, "Catalogue response exceeds its size bound", headers=NO_STORE)
    return content


def encode_legacy_catalogue(rows: Sequence[RowMapping | Mapping[str, Any]]) -> bytes:
    if len(rows) > MAX_ROWS:
        raise HTTPException(
            413,
            "Legacy catalogue exceeds 100 rows. Use /api/v1/agents/release-catalogue "
            "with explicit pagination; no records were silently omitted.",
            headers=NO_STORE,
        )
    try:
        records = [
            LegacyCatalogueRecord.model_validate(
                {name: row[name] for name in _FIELDS if name != "organization_id"}
            )
            for row in rows
        ]
        return _bounded(_LEGACY.dump_json(records))
    except (ValidationError, ValueError, TypeError):
        raise HTTPException(
            409,
            "Stored release metadata does not fit the bounded catalogue schema; "
            "repair the original metadata explicitly. No rows were altered.",
            headers=NO_STORE,
        ) from None


def encode_catalogue_page(rows: Sequence[RowMapping | Mapping[str, Any]], *, limit: int) -> bytes:
    if type(limit) is not int or not 1 <= limit <= MAX_ROWS or len(rows) > limit + 1:
        raise HTTPException(503, "Catalogue result is outside its declared bound", headers=NO_STORE)
    visible = rows[:limit]
    more = len(rows) > limit
    try:
        records = [CatalogueRecord.model_validate(dict(row)) for row in visible]
        last = records[-1] if more else None
        result = CataloguePage(
            items=records,
            limit=limit,
            has_more=more,
            next_published_at=last.published_at if last else None,
            next_id=last.id if last else None,
        )
        return _bounded(result.model_dump_json().encode("utf-8"))
    except (ValidationError, ValueError, TypeError):
        raise HTTPException(
            409,
            "Stored release metadata does not fit the bounded catalogue schema; "
            "repair the original metadata explicitly. No rows were altered.",
            headers=NO_STORE,
        ) from None
