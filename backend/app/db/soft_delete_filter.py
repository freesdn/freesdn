# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Global soft-delete filter (Pattern 1 structural kill)
=====================================================

A single ``do_orm_execute`` listener that injects ``deleted_at IS NULL`` into
**every** ORM SELECT / ``Session.get()`` / relationship load against a
:class:`~app.db.base.SoftDeleteMixin` model -- retiring the entire
soft-delete-leak class at once instead of hand-filtering ~100 query sites.

Built on the SQLAlchemy 2.0 ``with_loader_criteria`` recipe. ``include_aliases``
covers aliased occurrences and ``propagate_to_loaders=True`` (the default) makes
the criteria follow lazy/relationship loads from objects loaded by the
statement, so we only attach it on the top-level SELECT.

Opt out per query when you GENUINELY need soft-deleted rows::

    select(User).execution_options(include_deleted=True)          # statement
    await session.get(User, uid, execution_options={"include_deleted": True})

Gated by ``settings.ENABLE_SOFT_DELETE_GLOBAL_FILTER`` (default OFF) and wired
in :mod:`app.db.session`. It is a broad behavioural change: enable it in a
real-Postgres staging environment and run the suite + smoke tests first.

KNOWN LIMITS (these are NOT covered by the listener -- keep explicit filters):
  * bulk ``update()`` / ``delete()`` statements bypass it entirely
  * PostgreSQL ``INSERT ... ON CONFLICT DO UPDATE`` (device re-adoption in
    ``services/device_sync.py``) is not a SELECT -- unaffected, still works

CANDIDATE OPT-OUT SITES to review when enabling (read of deleted rows is
intentional): forensic audit of a deleted user
(``api/v1/endpoints/audit.py`` get_user_audit_logs) and any future
restore/undelete endpoint. The CI guard's baseline
(``tests/soft_delete_guard_baseline.txt``) is the broader worklist this
listener retires.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import ORMExecuteState, Session, with_loader_criteria

from app.db.base import SoftDeleteMixin

#: Execution-option key that disables the filter for a single statement.
INCLUDE_DELETED_OPTION = "include_deleted"


def _add_soft_delete_criteria(state: ORMExecuteState) -> None:
    """Attach ``deleted_at IS NULL`` to eligible ORM SELECT statements."""
    # Only top-level ORM SELECTs. Column loads (refresh of a single attr) and
    # relationship loads are reached by propagate_to_loaders from the parent,
    # so attaching here too would be redundant.
    if not state.is_select or state.is_column_load or state.is_relationship_load:
        return
    # Explicit per-statement opt-out.
    if state.execution_options.get(INCLUDE_DELETED_OPTION):
        return
    state.statement = state.statement.options(
        with_loader_criteria(
            SoftDeleteMixin,
            lambda cls: cls.deleted_at.is_(None),
            include_aliases=True,
        )
    )


def register_soft_delete_filter(target: Any = Session) -> None:
    """Idempotently attach the listener to ``target`` (the global
    :class:`Session` class in production; a scoped sessionmaker in tests)."""
    if not event.contains(target, "do_orm_execute", _add_soft_delete_criteria):
        event.listen(target, "do_orm_execute", _add_soft_delete_criteria)


def unregister_soft_delete_filter(target: Any = Session) -> None:
    """Detach the listener from ``target`` (used by tests for clean teardown)."""
    if event.contains(target, "do_orm_execute", _add_soft_delete_criteria):
        event.remove(target, "do_orm_execute", _add_soft_delete_criteria)
