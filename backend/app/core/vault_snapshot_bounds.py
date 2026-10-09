"""Bound values returned by independent vault snapshot reads.

PostgreSQL evaluates this predicate before returning selected values to the
driver. The budget covers encoded scalar values, not protocol overhead, Python
objects, query work or memory on the database server. Callers still validate
JSON structure and field semantics. This does not bound initial authentication.
"""

from typing import cast as type_cast

from sqlalchemy import BigInteger, ColumnElement, Select, Text, cast, func

SNAPSHOT_VALUE_BYTES = 4 * 1024 * 1024


def bounded_snapshot[*Ts](statement: Select[*Ts]) -> Select[*Ts]:
    """Retain native column types; refuse an oversized aggregate without truncation."""
    columns = tuple(statement.selected_columns)
    if not columns or len(columns) > 128:
        raise ValueError("Unsupported vault snapshot shape")
    # BIGINT prevents aggregate INT4 overflow across large legacy values.
    lengths = [
        func.coalesce(cast(func.octet_length(cast(column, Text)), BigInteger), 0)
        for column in columns
    ]
    return statement.where(type_cast(ColumnElement[bool], sum(lengths) <= SNAPSHOT_VALUE_BYTES))
