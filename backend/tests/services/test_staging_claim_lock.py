# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The staged-apply "atomic claim" must actually see the locked row's real status.

Background
----------
``apply_change`` and ``discard`` both claim a row with

    select(AdapterPendingChange).where(id == ...).with_for_update()

and then re-check ``change.status != "pending"``. The lock is correct. The
re-check was not, and the reason is a SQLAlchemy default rather than anything
visible in the query: when the row is ALREADY in the session's identity map,
``populate_existing`` defaults to False, so the ORM returns that same Python
object with its ORIGINAL attribute values and never overwrites them from the
freshly-locked row.

The row is always already in the identity map. The endpoint calls
``staging.get(change_id)`` immediately before ``staging.apply_change(...)``, on
the same session.

So the sequence was:

    request A  load (pending) -> lock -> status="applying" -> COMMIT
    request B  load (pending) -> lock BLOCKS -> acquires -> reads its OWN stale
               copy, still "pending" -> proceeds -> applies the SAME change to
               the live device a second time

A duplicate firewall rule, a duplicate VLAN, a duplicate PBX extension -- from
two operators with the drawer open, two tabs, or any client/proxy retry. The
discard path carried a comment claiming this lock had fixed exactly this race;
it had not.

``.execution_options(populate_existing=True)`` is what makes the lock mean
something. These tests exercise it against a real Postgres session, because the
whole defect lives in ORM identity-map behaviour that a mock cannot reproduce.
"""

from __future__ import annotations

import inspect
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app.models.staging import AdapterPendingChange
from app.services import adapter_staging


@pytest_asyncio.fixture
async def org_id(db_session):
    """A real organization row; adapter_pending_changes.organization_id is a FK."""
    oid = uuid.uuid4()
    await db_session.execute(
        text(
            "INSERT INTO core.organizations (id, name, slug, settings, is_active) "
            "VALUES (:id, :name, :slug, '{}'::jsonb, true)"
        ),
        {"id": oid, "name": f"claim-test-{oid.hex[:8]}", "slug": f"claim-{oid.hex[:8]}"},
    )
    await db_session.commit()
    return oid


@pytest_asyncio.fixture
async def change_id(db_session, org_id):
    row = AdapterPendingChange(
        organization_id=org_id,
        feature="test.claim.lock",
        operation="create",
        payload={"marker": "claim-lock-test"},
        status="pending",
    )
    db_session.add(row)
    await db_session.commit()
    return row.id


def _claim(change_id_):
    """The exact statement shape both claim sites use."""
    return (
        select(AdapterPendingChange)
        .where(AdapterPendingChange.id == change_id_)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


# ── The regression, against a real session ───────────────────────


@pytest.mark.asyncio
async def test_claim_sees_a_status_written_by_another_session(db_session, change_id):
    """
    The core property. Load the row (populating the identity map), have another
    connection flip it to "applying", then claim it. The claim MUST observe
    "applying" -- if it reports "pending" the second apply proceeds and the
    device takes the write twice.
    """
    preloaded = await db_session.get(AdapterPendingChange, change_id)
    assert preloaded.status == "pending"

    # Another transaction wins the race and claims the change.
    await db_session.execute(
        text("UPDATE core.adapter_pending_changes SET status = 'applying' WHERE id = :id"),
        {"id": change_id},
    )
    await db_session.commit()

    claimed = (await db_session.execute(_claim(change_id))).scalar_one_or_none()
    assert claimed is not None
    assert claimed.status == "applying", (
        "the claim returned a stale identity-mapped copy; the status re-check "
        "would pass and the change would be applied to the device twice"
    )


@pytest.mark.asyncio
async def test_without_populate_existing_the_claim_is_stale(db_session, change_id):
    """
    Negative control, and the reason the option is not optional. This is the
    pre-fix statement; it must demonstrably return the stale value, otherwise
    the test above proves nothing about why populate_existing is there.
    """
    preloaded = await db_session.get(AdapterPendingChange, change_id)
    assert preloaded.status == "pending"

    await db_session.execute(
        text("UPDATE core.adapter_pending_changes SET status = 'applying' WHERE id = :id"),
        {"id": change_id},
    )
    await db_session.commit()

    stale_stmt = (
        select(AdapterPendingChange).where(AdapterPendingChange.id == change_id).with_for_update()
    )
    stale = (await db_session.execute(stale_stmt)).scalar_one_or_none()
    assert stale is not None
    assert stale.status == "pending", (
        "SQLAlchemy no longer returns the stale identity-mapped instance. If "
        "this fails, the underlying behaviour changed and the comments in "
        "adapter_staging.py should be revisited -- but keep populate_existing."
    )


@pytest.mark.asyncio
async def test_claim_is_still_correct_when_the_row_was_never_preloaded(db_session, change_id):
    """populate_existing must not disturb the simple path."""
    claimed = (await db_session.execute(_claim(change_id))).scalar_one_or_none()
    assert claimed is not None
    assert claimed.status == "pending"


# ── Both claim sites must carry it ───────────────────────────────


def test_every_for_update_claim_uses_populate_existing() -> None:
    """
    There are two claim sites -- apply and discard -- and the discard one was
    added specifically to fix a race it did not actually fix. A future third
    claim site must not repeat that.
    """
    src = inspect.getsource(adapter_staging)
    locks = src.count(".with_for_update()")
    populated = src.count("populate_existing=True")
    assert locks >= 2, "expected at least the apply + discard claim sites"
    assert populated == locks, (
        f"{locks} FOR UPDATE claim(s) but only {populated} use populate_existing; "
        "a claim without it re-reads a stale identity-mapped row and the lock "
        "protects nothing"
    )
