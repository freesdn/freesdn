# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Query Utilities
============================

Reusable utilities for filtering, sorting, and pagination in SQLAlchemy queries.
"""

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeVar

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security_utils import escape_like

logger = logging.getLogger(__name__)

# Safe default allowlist that contains ONLY non-sensitive columns.
# Use this when a caller needs the most common sortable fields without
# authoring a bespoke allowlist. NEVER include password/secret columns.
DEFAULT_SAFE_SORT_FIELDS: list[str] = [
    "id",
    "name",
    "title",
    "slug",
    "status",
    "created_at",
    "updated_at",
]

# ===========================================
# Sorting
# ===========================================


class SortOrder(StrEnum):
    """Sort direction."""

    ASC = "asc"
    DESC = "desc"


@dataclass
class SortField:
    """A single sort field specification."""

    field: str
    order: SortOrder = SortOrder.ASC


class SortParams(BaseModel):
    """
    Sort query parameters.

    Usage in endpoint:
        sort_by: str | None = Query(None, description="Field to sort by")
        sort_order: SortOrder = Query(SortOrder.ASC, description="Sort direction")
    """

    sort_by: str | None = Field(None, description="Field to sort by")
    sort_order: SortOrder = Field(SortOrder.ASC, description="Sort direction")

    def apply(
        self,
        query: Select[Any],
        model: Any,
        allowed_fields: list[str] | None = None,
    ) -> Select[Any]:
        """
        Apply sorting to a SQLAlchemy query.

        SECURITY: ``allowed_fields`` MUST be an explicit
        non-empty list. Passing ``None`` or ``[]`` disables sorting
        entirely. This prevents side-channel extraction of secret
        columns (``hashed_password``, ``mfa_secret``, ``api_key``,
        ``token``, ``password``, ...) via pagination order observation.

        Callers should pass a minimal allowlist of genuinely-safe
        columns — typically ``["name", "created_at", "updated_at"]``.
        The module-level ``DEFAULT_SAFE_SORT_FIELDS`` constant provides
        a safe starting point.

        Args:
            query: SQLAlchemy Select query
            model: SQLAlchemy model class
            allowed_fields: Explicit allowlist of sortable field names.
                Must be non-empty; ``None`` or ``[]`` disables sorting.

        Returns:
            Modified query with sorting applied (or the original query
            if sorting was denied).
        """
        if not self.sort_by:
            return query

        # default-deny — require an explicit allowlist.
        if not allowed_fields:
            logger.debug(
                "SortParams.apply called without allowed_fields — sort disabled (field=%r)",
                self.sort_by,
            )
            return query

        if self.sort_by not in allowed_fields:
            return query

        # Get the model attribute
        if not hasattr(model, self.sort_by):
            return query

        column = getattr(model, self.sort_by)

        if self.sort_order == SortOrder.DESC:
            return query.order_by(desc(column))
        else:
            return query.order_by(asc(column))


# ===========================================
# Filtering
# ===========================================


class FilterOperator(StrEnum):
    """Supported filter operators."""

    EQ = "eq"  # Equal
    NE = "ne"  # Not equal
    GT = "gt"  # Greater than
    GE = "ge"  # Greater than or equal
    LT = "lt"  # Less than
    LE = "le"  # Less than or equal
    LIKE = "like"  # SQL LIKE (case-sensitive)
    ILIKE = "ilike"  # SQL ILIKE (case-insensitive)
    IN = "in"  # In list
    NOT_IN = "not_in"  # Not in list
    IS_NULL = "is_null"  # Is null
    NOT_NULL = "not_null"  # Is not null
    BETWEEN = "between"  # Between two values


@dataclass
class FilterCondition:
    """A single filter condition."""

    field: str
    operator: FilterOperator
    value: Any

    def to_sqlalchemy(self, model: Any) -> Any:
        """Convert to SQLAlchemy filter expression."""
        if not hasattr(model, self.field):
            return None

        column = getattr(model, self.field)

        match self.operator:
            case FilterOperator.EQ:
                return column == self.value
            case FilterOperator.NE:
                return column != self.value
            case FilterOperator.GT:
                return column > self.value
            case FilterOperator.GE:
                return column >= self.value
            case FilterOperator.LT:
                return column < self.value
            case FilterOperator.LE:
                return column <= self.value
            case FilterOperator.LIKE:
                return column.like(f"%{escape_like(self.value)}%", escape="\\")
            case FilterOperator.ILIKE:
                return column.ilike(f"%{escape_like(self.value)}%", escape="\\")
            case FilterOperator.IN:
                return column.in_(self.value if isinstance(self.value, list) else [self.value])
            case FilterOperator.NOT_IN:
                return column.not_in(self.value if isinstance(self.value, list) else [self.value])
            case FilterOperator.IS_NULL:
                return column.is_(None)
            case FilterOperator.NOT_NULL:
                return column.isnot(None)
            case FilterOperator.BETWEEN:
                if isinstance(self.value, (list, tuple)) and len(self.value) == 2:
                    return column.between(self.value[0], self.value[1])
                return None
            case _:
                return None


class FilterParams(BaseModel):
    """
    Base filter parameters.

    Subclass this to create specific filters for each model:

    class DeviceFilterParams(FilterParams):
        name: str | None = None
        status: str | None = None
        site_id: UUID | None = None
    """

    search: str | None = Field(None, description="Global search across searchable fields")

    def get_conditions(self) -> list[FilterCondition]:
        """
        Get filter conditions from model fields.

        Override in subclass to customize filtering logic.
        """
        conditions = []
        for field_name, value in self.model_dump(exclude={"search"}).items():
            if value is not None:
                conditions.append(
                    FilterCondition(
                        field=field_name,
                        operator=FilterOperator.EQ,
                        value=value,
                    )
                )
        return conditions

    def apply(
        self,
        query: Select[Any],
        model: Any,
        search_fields: list[str] | None = None,
    ) -> Select[Any]:
        """
        Apply filters to a SQLAlchemy query.

        Args:
            query: SQLAlchemy Select query
            model: SQLAlchemy model class
            search_fields: Fields to search when using global search

        Returns:
            Modified query with filters applied
        """
        # Apply specific field conditions
        for condition in self.get_conditions():
            filter_expr = condition.to_sqlalchemy(model)
            if filter_expr is not None:
                query = query.where(filter_expr)

        # Apply global search
        if self.search and search_fields:
            search_conditions = []
            for field_name in search_fields:
                if hasattr(model, field_name):
                    column = getattr(model, field_name)
                    search_conditions.append(
                        column.ilike(f"%{escape_like(self.search)}%", escape="\\")
                    )
            if search_conditions:
                query = query.where(or_(*search_conditions))

        return query


# ===========================================
# Combined Query Builder
# ===========================================

T = TypeVar("T")


@dataclass
class QueryBuilder[T]:
    """
    Fluent query builder for combining filtering, sorting, and pagination.

    Usage:
        builder = QueryBuilder(Device, session)
        results = await builder
            .filter(DeviceFilterParams(status="online"))
            .sort(
                SortParams(sort_by="name"),
                allowed_fields=["name", "created_at", "updated_at"],
            )
            .paginate(page=1, per_page=20)
            .execute()

    SECURITY: ``.sort()`` requires an explicit
    ``allowed_fields`` list. Passing ``None`` or ``[]`` silently
    disables sorting (default-deny) to prevent side-channel
    extraction of secret columns via pagination order observation.
    """

    model: type[T]
    session: AsyncSession
    _query: Select[Any] | None = None
    _filters: list[FilterParams] = field(default_factory=list)
    _sort: SortParams | None = None
    _page: int = 1
    _per_page: int = 20

    def __post_init__(self) -> None:
        self._query = select(self.model)

    def filter(
        self, params: FilterParams, search_fields: list[str] | None = None
    ) -> "QueryBuilder[T]":
        """Add filter parameters."""
        assert self._query is not None
        self._query = params.apply(self._query, self.model, search_fields)
        return self

    def where(self, *conditions: Any) -> "QueryBuilder[T]":
        """Add raw SQLAlchemy where conditions."""
        assert self._query is not None
        for condition in conditions:
            self._query = self._query.where(condition)
        return self

    def sort(
        self, params: SortParams, allowed_fields: list[str] | None = None
    ) -> "QueryBuilder[T]":
        """Add sort parameters."""
        assert self._query is not None
        self._query = params.apply(self._query, self.model, allowed_fields)
        return self

    def order_by(self, *columns: Any) -> "QueryBuilder[T]":
        """Add raw SQLAlchemy order_by columns."""
        assert self._query is not None
        self._query = self._query.order_by(*columns)
        return self

    def paginate(self, page: int = 1, per_page: int = 20) -> "QueryBuilder[T]":
        """Set pagination parameters."""
        self._page = max(1, page)
        self._per_page = min(100, max(1, per_page))
        return self

    async def count(self) -> int:
        """Get total count without pagination."""
        assert self._query is not None
        count_query = select(func.count()).select_from(self._query.subquery())
        result = await self.session.execute(count_query)
        return result.scalar() or 0

    async def execute(self) -> list[T]:
        """Execute query and return results."""
        assert self._query is not None
        offset = (self._page - 1) * self._per_page
        paginated_query = self._query.offset(offset).limit(self._per_page)
        result = await self.session.execute(paginated_query)
        return list(result.scalars().all())

    async def execute_with_count(self) -> tuple[list[T], int]:
        """Execute query and return results with total count."""
        total = await self.count()
        items = await self.execute()
        return items, total


# ===========================================
# Dependency helpers
# ===========================================


def pagination_params(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
) -> dict[str, int]:
    """FastAPI dependency for pagination parameters."""
    return {"page": page, "per_page": per_page}


def sort_params(
    sort_by: str | None = Query(None, description="Field to sort by"),
    sort_order: SortOrder = Query(SortOrder.ASC, description="Sort direction"),
) -> SortParams:
    """FastAPI dependency for sort parameters."""
    return SortParams(sort_by=sort_by, sort_order=sort_order)
