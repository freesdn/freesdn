# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The session reaper must delete dead rows and ONLY dead rows.

``app.tasks.maintenance.cleanup_orphan_sessions`` is the only thing in the tree
that deletes from ``core.user_sessions`` / ``core.sso_sessions``. Two problems
lived in its predicate:

1. It referenced ``UserSession.last_activity_at``. The model's column is
   ``last_used_at``; building the statement raised AttributeError before either
   DELETE was issued, and a ``# type: ignore[attr-defined]`` on the line hid it
   from mypy. Every test below would ERROR on that mutation, not just fail.

2. It deleted on 24-hour idleness alone. A revoked row is the ONLY record that
   a session was revoked -- ``app.core.session_revocation`` returns False for a
   missing row and ``/auth/refresh`` only blocks when it finds one -- so a
   revoked row deleted while its refresh token is still inside its 14- or
   30-day window silently un-revokes that token. Scheduling the task as
   written would have made "revoke this device" expire after a day.

The predicate is exercised against real ``UserSession`` rows in an in-memory
SQLite database (the model has no Postgres-only column types), so these are
assertions about which rows survive a real DELETE, not about SQL text.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base
from app.models import UserSession
from app.tasks.maintenance import _reapable_user_sessions

_NOW = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
_IDLE_HOURS = 24
_MAX_REFRESH_DAYS = max(
    settings.REFRESH_TOKEN_EXPIRE_DAYS,
    settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS,
)


@pytest.fixture()
def db() -> Iterator[Session]:
    """A real user_sessions table, minus the ``core`` schema SQLite lacks."""
    engine = create_engine("sqlite://").execution_options(schema_translate_map={"core": None})
    Base.metadata.create_all(engine, tables=[UserSession.__table__], checkfirst=False)
    factory = sessionmaker(engine)
    with factory() as session:
        yield session
    engine.dispose()


def _add(
    session: Session,
    label: str,
    *,
    expires_at: datetime | None,
    last_used_at: datetime | None,
    created_at: datetime | None = None,
    revoked: bool = False,
) -> None:
    session.add(
        UserSession(
            user_id=uuid4(),
            refresh_jti=label,
            access_jti=f"access-{label}",
            created_at=created_at or (last_used_at or _NOW),
            last_used_at=last_used_at,
            expires_at=expires_at,
            revoked_at=_NOW - timedelta(hours=1) if revoked else None,
            is_revoked=revoked,
        )
    )


def _reap(session: Session) -> set[str]:
    """Run the reaper's predicate; return the refresh_jti labels that SURVIVE."""
    session.execute(
        delete(UserSession).where(
            _reapable_user_sessions(
                _NOW,
                _NOW - timedelta(hours=_IDLE_HOURS),
                _NOW - timedelta(days=_MAX_REFRESH_DAYS),
            )
        )
    )
    session.commit()
    return {row.refresh_jti or "" for row in session.execute(select(UserSession)).scalars()}


def test_a_row_past_its_refresh_expiry_is_deleted(db: Session) -> None:
    """The core reap. Both tokens on the row are dead, so it can go."""
    _add(db, "expired", expires_at=_NOW - timedelta(hours=1), last_used_at=_NOW - timedelta(days=3))
    db.commit()
    assert _reap(db) == set()


def test_an_idle_but_unexpired_session_survives(db: Session) -> None:
    """The regression the original predicate would have caused.

    ``expires_at`` is 13 days out but the device has not been used for 5 days.
    The old ``last_activity_at < now - 24h`` half would delete this row, taking
    a live sign-in with it -- and, if it had been revoked, un-revoking it.
    """
    _add(
        db,
        "idle-but-live",
        expires_at=_NOW + timedelta(days=13),
        last_used_at=_NOW - timedelta(days=5),
    )
    db.commit()
    assert _reap(db) == {"idle-but-live"}


def test_a_revoked_row_outlives_the_refresh_token_it_revokes(db: Session) -> None:
    """A revoked legacy row (no expires_at) idle past the 24h window stays.

    Deleting it would restore the refresh token it revokes: both revocation
    checks treat a missing row as NOT revoked. Mutation caught: dropping the
    ``revoked`` branch from the legacy predicate.
    """
    _add(
        db,
        "revoked-recent",
        expires_at=None,
        last_used_at=_NOW - timedelta(hours=25),
        revoked=True,
    )
    db.commit()
    assert _reap(db) == {"revoked-recent"}


def test_a_revoked_row_leaves_once_its_token_cannot_be_presented(db: Session) -> None:
    """...but it does not stay forever, or the table still grows without bound."""
    _add(
        db,
        "revoked-ancient",
        expires_at=None,
        last_used_at=_NOW - timedelta(days=_MAX_REFRESH_DAYS + 1),
        revoked=True,
    )
    db.commit()
    assert _reap(db) == set()


def test_an_expired_row_is_reaped_even_when_revoked(db: Session) -> None:
    """Expiry is authoritative: nothing can present the token, so nothing to lose."""
    _add(
        db,
        "expired-revoked",
        expires_at=_NOW - timedelta(minutes=5),
        last_used_at=_NOW - timedelta(minutes=10),
        revoked=True,
    )
    db.commit()
    assert _reap(db) == set()


def test_a_legacy_row_with_no_last_used_at_is_still_reachable(db: Session) -> None:
    """``last_used_at`` is nullable and ``NULL < cutoff`` is NULL, which would
    exempt such a row from every sweep forever. The predicate coalesces to
    ``created_at``. Mutation caught: dropping the coalesce.
    """
    _add(
        db,
        "no-last-used",
        expires_at=None,
        last_used_at=None,
        created_at=_NOW - timedelta(hours=25),
    )
    db.commit()
    assert _reap(db) == set()


def test_a_freshly_used_legacy_row_survives(db: Session) -> None:
    """The idle window must still bound something."""
    _add(db, "fresh-legacy", expires_at=None, last_used_at=_NOW - timedelta(hours=1))
    db.commit()
    assert _reap(db) == {"fresh-legacy"}


def test_the_predicate_names_columns_the_model_actually_has(db: Session) -> None:
    """Direct pin on defect (1).

    ``_reapable_user_sessions`` raises AttributeError -- not a failed
    assertion -- if it reaches for a column that does not exist, which is
    exactly how the shipped predicate failed. Compiling it proves every name
    resolved.
    """
    compiled = str(
        _reapable_user_sessions(_NOW, _NOW - timedelta(hours=1), _NOW - timedelta(days=30))
    )
    assert "last_activity_at" not in compiled
    assert "last_used_at" in compiled
