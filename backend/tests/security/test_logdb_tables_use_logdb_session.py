# SPDX-License-Identifier: AGPL-3.0-only
"""Raw SQL against a LogDB table runs on a LogDB session.

The four LogBase tables live in the LogDB, a separate PostgreSQL server on
every installed tier. The test suite points LOGDB_URL at the main database, so a
query sent through the main session passes here and fails on every real
install with "relation does not exist" (the tunnel health history did, and the
event list did before it).

Every function under ``app/`` whose SQL text names a LogDB table must take or
open a LogDB session; the tunnel health-history endpoint must query through it.
"""

from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

APP = Path(__file__).resolve().parents[2] / "app"
LOGDB_TABLE_SQL = re.compile(
    r"(?is)\b(?:from|into|update|join)\s+"
    r"(?:vpn\.vpn_health_checks|analytics\.metric_data|agents\.agent_heartbeats|events\.event_records)\b"
)
LOGDB_SESSION_MARKERS = ("logdb", "LogDB", "get_logdb")
#: Service methods that run on the session they are given. Every caller passes a
#: LogDB session (checked 2026-11-14: endpoints/analytics.py, modules/network/api.py,
#: tasks/analytics.py, endpoints/vpn.py, tasks/vpn.py). Adding a name here needs
#: the same check of its callers.
SESSION_FROM_CALLER = frozenset(
    {
        "app/services/analytics.py:query_metrics",
        "app/services/analytics.py:get_latest_metric",
        "app/services/analytics.py:purge_old_metrics",
        "app/services/vpn_integration.py:get_health_history",
        "app/services/vpn_integration.py:purge_old_health_checks",
    }
)


def _sql_strings(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and LOGDB_TABLE_SQL.search(child.value)
    ]


def _offenders() -> list[str]:
    found: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not LOGDB_TABLE_SQL.search(source):
            continue
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Only the innermost function that holds the SQL is judged.
            inner = [
                child
                for child in ast.walk(node)
                if child is not node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            own_sql = [
                s for s in _sql_strings(node) if not any(s in _sql_strings(i) for i in inner)
            ]
            if not own_sql:
                continue
            rel = path.relative_to(APP.parent).as_posix()
            if f"{rel}:{node.name}" in SESSION_FROM_CALLER:
                continue
            text = ast.get_source_segment(source, node) or ""
            if not any(marker in text for marker in LOGDB_SESSION_MARKERS):
                found.append(f"{rel}:{node.lineno} {node.name}")
    return found


def test_every_function_querying_a_logdb_table_uses_a_logdb_session() -> None:
    assert _offenders() == []


async def test_tunnel_health_history_reads_the_logdb() -> None:
    from app.api.v1.endpoints import vpn_orchestration

    tunnel = SimpleNamespace(site_a_id=None, site_b_id=None)
    main = MagicMock()
    main.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=tunnel))
    )
    row = MagicMock(_mapping={"time": "t", "is_healthy": True})
    logdb = MagicMock()
    logdb.execute = AsyncMock(return_value=MagicMock(fetchall=MagicMock(return_value=[row])))
    user: Any = SimpleNamespace(
        organization_id=uuid.uuid4(), is_superuser=False, is_site_limited=False
    )
    vpn_orchestration_any: Any = vpn_orchestration
    original = vpn_orchestration_any._assert_tunnel_sites
    vpn_orchestration_any._assert_tunnel_sites = lambda *_a, **_k: None
    try:
        result = await vpn_orchestration.get_tunnel_health_history(
            tunnel_id=uuid.uuid4(), hours=24, limit=10, db=main, logdb=logdb, user=user
        )
    finally:
        vpn_orchestration_any._assert_tunnel_sites = original
    assert result == [{"time": "t", "is_healthy": True}]
    assert main.execute.await_count == 1  # the tunnel lookup only
    sql = str(logdb.execute.await_args.args[0])
    assert "vpn.vpn_health_checks" in sql


@pytest.mark.parametrize(
    "snippet", ["SELECT 1 FROM vpn.vpn_health_checks", "DELETE FROM events.event_records"]
)
def test_the_pattern_recognises_logdb_sql(snippet: str) -> None:
    assert LOGDB_TABLE_SQL.search(snippet)
