# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""``GET /auth/sessions`` must list live sessions, not a login archive.

The endpoint's docstring said "active sessions for a manage-sessions UI" and
the query was ``WHERE user_id = :me ORDER BY created_at DESC`` -- every row the
user had ever produced, with no expiry test and no limit. A session from six
months ago whose refresh token died in week two came back indistinguishable
from the laptop in front of you, because the payload carries ``is_revoked`` but
carries nothing at all about expiry. Nothing trimmed the table either: the only
deleter of ``core.user_sessions`` (``cleanup_orphan_sessions``) had no beat
entry until this pass, so the dev database held 135 rows going back to
2026-06-16 with none ever pruned.

"Live" means the refresh token bound to the row could still be presented:
``expires_at`` while it is set, and ``last activity + the longest refresh
window`` for the legacy rows written before that column was populated. Revoked
rows inside that window stay listed on purpose -- the row IS the revocation
record (``session_revocation`` reads a missing row as not-revoked), and the
payload's ``is_revoked`` is what a UI renders as "signed out on this device".

These run the real endpoint against real ``UserSession`` rows in an in-memory
SQLite database, so they assert which rows a real SELECT returns.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import list_sessions
from app.core.config import settings
from app.models import UserSession

_MAX_REFRESH_DAYS = max(
    settings.REFRESH_TOKEN_EXPIRE_DAYS,
    settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS,
)
_USER_ID = uuid4()
_OTHER_USER_ID = uuid4()


async def _seed_users(session: AsyncSession) -> None:
    """Real user rows for the two ids these tests attach sessions to.

    The original fixture built an isolated in-memory SQLite engine holding ONLY
    user_sessions, so the fk_user_sessions_user_id_users constraint was never
    created and never enforced. Against the real database it is, and every case
    failed with ForeignKeyViolationError -- so the sqlite shortcut had also been
    hiding whether these rows were even insertable.
    """
    from app.models import User

    for uid, handle in ((_USER_ID, "liveness-me"), (_OTHER_USER_ID, "liveness-other")):
        if await session.get(User, uid) is None:
            session.add(
                User(
                    id=uid,
                    email=f"{handle}@example.invalid",
                    username=handle,
                    hashed_password="x",
                    is_active=True,
                )
            )
    # flush, NOT commit: db_session wraps each test in a transaction that is
    # rolled back afterwards, and a commit escapes it -- rows then leak into the
    # next test and its expected list. The original in-memory SQLite fixture got
    # isolation for free by building a fresh engine per test.
    await session.flush()


@pytest.fixture()
async def db(db_session: AsyncSession) -> AsyncSession:
    """The project's real Postgres session.

    This fixture originally built its own in-memory engine with
    ``sqlite+aiosqlite://``. aiosqlite is present in a local dev environment as a
    transitive package but is NOT declared in pyproject, so the test passed here
    and every case ERRORed inside the CI container with
    ``ModuleNotFoundError: No module named 'aiosqlite'``. Using the suite's own
    fixture keeps the assertions honest against the database the product
    actually runs on, and removes an undeclared dependency.
    """
    await _seed_users(db_session)
    return db_session


async def _add(
    session: AsyncSession,
    label: str,
    *,
    expires_at: datetime | None,
    last_used_at: datetime | None = None,
    created_at: datetime | None = None,
    revoked: bool = False,
    user_id: UUID | None = None,
) -> None:
    now = datetime.now(UTC)
    session.add(
        UserSession(
            user_id=user_id or _USER_ID,
            refresh_jti=label,
            access_jti=f"access-{label}",
            user_agent=label,
            created_at=created_at or last_used_at or now,
            last_used_at=last_used_at,
            expires_at=expires_at,
            revoked_at=now - timedelta(hours=1) if revoked else None,
            is_revoked=revoked,
        )
    )
    await session.flush()


async def _listed(session: AsyncSession, **kwargs: Any) -> list[str]:
    """User-agent labels of the sessions the endpoint returns, in order."""
    me = SimpleNamespace(id=_USER_ID)
    body = await list_sessions(current_user=me, session=session, **kwargs)  # type: ignore[arg-type]
    return [row["user_agent"] for row in body["sessions"]]


async def test_a_session_whose_refresh_token_expired_is_not_listed(db: AsyncSession) -> None:
    """The defect: a dead session presented as a live device.

    Mutation this catches: drop the ``still_usable`` clause from the WHERE and
    "expired-last-month" comes back, which is exactly what the manage-sessions
    UI was being handed.
    """
    now = datetime.now(UTC)
    await _add(db, "live-laptop", expires_at=now + timedelta(days=7))
    await _add(db, "expired-last-month", expires_at=now - timedelta(days=30))

    assert await _listed(db) == ["live-laptop"]


async def test_legacy_rows_are_kept_only_while_their_token_could_survive(
    db: AsyncSession,
) -> None:
    """``expires_at`` is NULL on rows predating the column; bound them by activity.

    The upper bound has to be the longest refresh window, not the reaper's
    24-hour idle heuristic: a remember-me token from three days ago is idle but
    perfectly usable, and hiding it would hide a real signed-in device from the
    only screen that can revoke it.
    """
    now = datetime.now(UTC)
    await _add(db, "legacy-idle-3d", expires_at=None, last_used_at=now - timedelta(days=3))
    await _add(
        db,
        "legacy-ancient",
        expires_at=None,
        last_used_at=now - timedelta(days=_MAX_REFRESH_DAYS + 5),
    )
    # Never refreshed at all, so last_used_at is NULL and created_at is the floor.
    await _add(
        db,
        "legacy-never-used",
        expires_at=None,
        created_at=now - timedelta(days=_MAX_REFRESH_DAYS + 5),
    )

    assert await _listed(db) == ["legacy-idle-3d"]


async def test_revoked_but_unexpired_sessions_stay_visible(db: AsyncSession) -> None:
    """Revoking must not make the row vanish from the list.

    The row is the revocation record -- ``session_revocation`` treats a MISSING
    row as not-revoked -- so it has to survive until its token dies anyway. The
    payload flags it instead.
    """
    now = datetime.now(UTC)
    await _add(db, "signed-out-phone", expires_at=now + timedelta(days=7), revoked=True)

    me = SimpleNamespace(id=_USER_ID)
    body = await list_sessions(current_user=me, session=db)  # type: ignore[arg-type]
    assert [r["user_agent"] for r in body["sessions"]] == ["signed-out-phone"]
    assert body["sessions"][0]["is_revoked"] is True


async def test_another_users_live_session_is_never_listed(db: AsyncSession) -> None:
    """The user_id scope must survive the new WHERE clause."""
    now = datetime.now(UTC)
    await _add(db, "mine", expires_at=now + timedelta(days=7))
    await _add(db, "theirs", expires_at=now + timedelta(days=7), user_id=_OTHER_USER_ID)

    assert await _listed(db) == ["mine"]


async def test_the_result_is_bounded(db: AsyncSession) -> None:
    """Unbounded was the other half of the finding.

    Every login mints a row and each one stays live for the whole refresh
    window, so a scripted login loop makes this response grow without limit.
    """
    now = datetime.now(UTC)
    for i in range(5):
        await _add(
            db,
            f"device-{i}",
            expires_at=now + timedelta(days=7),
            created_at=now - timedelta(minutes=i),
        )

    assert await _listed(db, limit=2) == ["device-0", "device-1"]
    assert len(await _listed(db)) == 5  # default limit is well above 5
