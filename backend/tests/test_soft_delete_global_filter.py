# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Mechanism tests for the global soft-delete filter
=================================================

Validates app/db/soft_delete_filter.py against an in-memory SQLite DB using
throwaway models that inherit the REAL app.db.base.SoftDeleteMixin (so the
with_loader_criteria(SoftDeleteMixin, ...) targeting matches). This exercises
the listener logic itself; full integration against Postgres + the app models
is a staging concern (the listener is default-OFF in app config).

Proves: SELECT, Session.get(), and relationship loads exclude soft-deleted
rows when the filter is registered; execution_options(include_deleted=True)
opts out; and without the filter the deleted rows are visible (control).
"""
from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

# When the global filter is force-enabled via env, app.db.session registers the
# listener on the global Session class at import — so even an "unregistered"
# sessionmaker inherits it, and the no-filter control below cannot hold.
_GLOBAL_FILTER_ON = os.getenv("ENABLE_SOFT_DELETE_GLOBAL_FILTER", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
from sqlalchemy import ForeignKey, String, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from app.db.base import SoftDeleteMixin
from app.db.soft_delete_filter import (
    register_soft_delete_filter,
    unregister_soft_delete_filter,
)


class _Base(DeclarativeBase):
    pass


class _Parent(_Base, SoftDeleteMixin):
    __tablename__ = "sdf_parent"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    children: Mapped[list[_Child]] = relationship(
        back_populates="parent", lazy="select"
    )


class _Child(_Base, SoftDeleteMixin):
    __tablename__ = "sdf_child"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    parent_id: Mapped[int] = mapped_column(ForeignKey("sdf_parent.id"))
    parent: Mapped[_Parent] = relationship(back_populates="children")


@pytest.fixture()
def maker():
    """A SQLite sessionmaker with the soft-delete filter scoped to it (so the
    global Session class is never touched, keeping other tests clean)."""
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    gone = datetime(2020, 1, 1, tzinfo=UTC)

    # Seed: one live parent (with a live + a deleted child), one deleted parent.
    with factory() as s:
        p_live = _Parent(id=1, name="live")
        p_dead = _Parent(id=2, name="dead", deleted_at=gone)
        s.add_all([p_live, p_dead])
        s.add_all(
            [
                _Child(id=1, name="c_live", parent_id=1),
                _Child(id=2, name="c_dead", parent_id=1, deleted_at=gone),
            ]
        )
        s.commit()

    register_soft_delete_filter(factory)
    try:
        yield factory
    finally:
        unregister_soft_delete_filter(factory)
        engine.dispose()


def test_select_excludes_soft_deleted(maker):
    with maker() as s:
        names = {p.name for p in s.scalars(select(_Parent))}
    assert names == {"live"}


def test_get_returns_none_for_soft_deleted(maker):
    with maker() as s:
        assert s.get(_Parent, 2) is None       # deleted -> filtered
        assert s.get(_Parent, 1) is not None   # live -> found


def test_relationship_load_excludes_soft_deleted(maker):
    with maker() as s:
        parent = s.get(_Parent, 1)
        child_names = {c.name for c in parent.children}  # lazy load
    assert child_names == {"c_live"}


def test_include_deleted_opt_out_select(maker):
    with maker() as s:
        names = {
            p.name
            for p in s.scalars(
                select(_Parent).execution_options(include_deleted=True)
            )
        }
    assert names == {"live", "dead"}


def test_include_deleted_opt_out_get(maker):
    with maker() as s:
        dead = s.get(_Parent, 2, execution_options={"include_deleted": True})
    assert dead is not None and dead.name == "dead"


@pytest.mark.skipif(
    _GLOBAL_FILTER_ON,
    reason="global soft-delete filter is force-enabled — no unfiltered baseline exists",
)
def test_control_without_filter_sees_deleted():
    """Without the listener, soft-deleted rows ARE returned (proves the filter
    is what excludes them, not the schema)."""
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as s:
        s.add_all(
            [_Parent(id=1, name="live"), _Parent(id=2, name="dead",
                                                 deleted_at=datetime(2020, 1, 1, tzinfo=UTC))]
        )
        s.commit()
    with factory() as s:
        names = {p.name for p in s.scalars(select(_Parent))}
    engine.dispose()
    assert names == {"live", "dead"}
