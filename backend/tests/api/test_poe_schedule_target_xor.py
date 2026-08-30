# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A PoE schedule must carry exactly one target, and say so at the API edge.

``devices.poe_schedules`` has a CHECK constraint requiring one of ``device_id`` /
``device_group_id`` and not the other (``app/models/poe.py``; back-filled onto
upgraded appliances by alembic 010). Nothing above the database enforced it:
both fields were plain ``str | None`` with no cross-field validator, and the
handler validated ownership only ``if`` a field had been supplied.

That left two bad outcomes depending on which database an operator has:

* No constraint (any appliance upgraded before 2026-06-22, until 010 runs) --
  ``POST /api/v1/poe/schedules`` with no target at all returns **201**. The
  schedule lists as enabled and never fires, because ``app/tasks/poe.py``
  resolves ``device_ids`` from one of the two fields and then hits
  ``if not device_ids: continue``. Lights or APs the operator believes are on a
  schedule are silently never switched.
* Constraint present -- the same request is a ``CheckViolation`` raised out of
  ``session.commit()`` with no handler around it: a **500**.

010 closes the silent-201. These tests cover the other half: the refusal has to
be a well-formed 422 that names the field, on both kinds of database.

Pure-unit -- no database. The schema validators are the create-side gate (a
FastAPI body model rejects before the handler runs at all), and the update-side
resulting-state check is exercised against a mocked session.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.endpoints.poe import PoEScheduleCreateIn, PoEScheduleUpdateIn

_DEVICE = "11111111-1111-1111-1111-111111111111"
_GROUP = "22222222-2222-2222-2222-222222222222"


def _create_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "night shutdown",
        "power_off_time": "22:00",
        "power_on_time": "06:00",
    }
    body.update(overrides)
    return body


# ── create: exactly one ──────────────────────────────────────────────


class TestCreateRequiresExactlyOneTarget:
    def test_no_target_is_rejected(self) -> None:
        """The silent-201 case: this used to build a schedule that can never fire."""
        with pytest.raises(ValidationError) as ei:
            PoEScheduleCreateIn(**_create_body())
        assert "exactly one of device_id or device_group_id" in str(ei.value)

    def test_both_targets_are_rejected(self) -> None:
        """The 500 case: the row violates the CHECK constraint at commit."""
        with pytest.raises(ValidationError) as ei:
            PoEScheduleCreateIn(**_create_body(device_id=_DEVICE, device_group_id=_GROUP))
        assert "exactly one of device_id or device_group_id" in str(ei.value)

    def test_device_only_is_accepted(self) -> None:
        model = PoEScheduleCreateIn(**_create_body(device_id=_DEVICE))
        assert model.device_id == _DEVICE
        assert model.device_group_id is None

    def test_group_only_is_accepted(self) -> None:
        model = PoEScheduleCreateIn(**_create_body(device_group_id=_GROUP))
        assert model.device_group_id == _GROUP
        assert model.device_id is None

    def test_a_blank_target_counts_as_no_target(self) -> None:
        """A cleared form field submits ``""``, not ``null``.

        Left as ``""`` it is falsy for the XOR test but not-None for the
        handler's ``is not None`` ownership branch, so validation would pass with
        no usable target and the handler would then compare a uuid column against
        an empty string.
        """
        with pytest.raises(ValidationError):
            PoEScheduleCreateIn(**_create_body(device_id="", device_group_id="   "))

        model = PoEScheduleCreateIn(**_create_body(device_id="", device_group_id=_GROUP))
        assert model.device_id is None

    @pytest.mark.parametrize(
        ("device_id", "device_group_id", "constraint_holds"),
        [
            (None, None, False),
            (_DEVICE, None, True),
            (None, _GROUP, True),
            (_DEVICE, _GROUP, False),
        ],
    )
    def test_the_validator_matches_the_check_constraint(
        self, device_id: str | None, device_group_id: str | None, constraint_holds: bool
    ) -> None:
        """The API rule and the DB rule must agree on all four combinations.

        ``constraint_holds`` is the truth table of
        ``(device_id IS NOT NULL AND device_group_id IS NULL)
          OR (device_id IS NULL AND device_group_id IS NOT NULL)``.
        Anything the API accepts but PostgreSQL refuses is a 500; anything the API
        refuses but PostgreSQL accepts is a rule the DB is not backing.
        """
        body = _create_body(device_id=device_id, device_group_id=device_group_id)
        if constraint_holds:
            PoEScheduleCreateIn(**body)
        else:
            with pytest.raises(ValidationError):
                PoEScheduleCreateIn(**body)


# ── update: at most one ──────────────────────────────────────────────


class TestUpdateAllowsAtMostOneTarget:
    def test_both_targets_are_rejected(self) -> None:
        with pytest.raises(ValidationError) as ei:
            PoEScheduleUpdateIn(device_id=_DEVICE, device_group_id=_GROUP)
        assert "at most one of device_id or device_group_id" in str(ei.value)

    def test_neither_target_is_fine_because_this_is_a_partial_update(self) -> None:
        """The create rule must NOT be copied here.

        ``None`` means "field not supplied", so requiring exactly one would reject
        every ordinary rename -- a strictly worse bug than the one being fixed.
        """
        model = PoEScheduleUpdateIn(name="renamed")
        assert model.device_id is None and model.device_group_id is None

    @pytest.mark.parametrize("field", ["device_id", "device_group_id"])
    def test_one_target_is_accepted(self, field: str) -> None:
        model = PoEScheduleUpdateIn(**{field: _DEVICE})
        assert getattr(model, field) == _DEVICE


# ── update handler: the resulting row must satisfy the constraint ────


def _admin(org_id: UUID) -> SimpleNamespace:
    from app.models.core import UserRole

    return SimpleNamespace(
        organization_id=org_id,
        role=UserRole.ORG_ADMIN,
        is_scoped=False,
    )


def _schedule(org_id: UUID, *, device_id: object = None, device_group_id: object = None):
    """A stored PoESchedule row, as ``scalar_one_or_none()`` would hand it back."""
    return SimpleNamespace(
        id=uuid4(),
        organization_id=org_id,
        name="night shutdown",
        enabled=True,
        device_id=device_id,
        device_group_id=device_group_id,
        port_numbers=[1],
        power_off_time="22:00",
        power_on_time="06:00",
        days_of_week=[0, 1, 2, 3, 4, 5, 6],
        timezone="UTC",
        last_action=None,
        last_action_at=None,
        created_at=None,
        updated_at=None,
        deleted_at=None,
    )


def _session(*results: object) -> MagicMock:
    """Successive ``execute()`` calls return ``results`` in order."""
    session = MagicMock()
    session.execute = AsyncMock(side_effect=list(results))
    session.commit = AsyncMock()
    return session


def _found(value: object) -> MagicMock:
    res = MagicMock()
    res.scalar_one_or_none.return_value = value
    return res


class TestUpdateHandlerKeepsTheRowValid:
    @pytest.mark.asyncio
    async def test_retargeting_to_a_device_clears_the_group(self) -> None:
        """Assigning without clearing leaves BOTH set -> CheckViolation -> 500.

        The update schema cannot spell "clear this field" (``None`` means "not
        supplied"), so implying the clear is also the only way an operator can
        move a group schedule onto a single device at all.
        """
        from app.api.v1.endpoints import poe

        org = uuid4()
        stored = _schedule(org, device_group_id=_GROUP)
        session = _session(_found(stored), _found(_DEVICE))

        out = await poe.update_poe_schedule(
            schedule_id=str(stored.id),
            data=PoEScheduleUpdateIn(device_id=_DEVICE),
            session=session,
            _user=_admin(org),
        )

        assert stored.device_id == _DEVICE
        assert stored.device_group_id is None
        assert out.device_id == _DEVICE
        assert out.device_group_id is None
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_retargeting_to_a_group_clears_the_device(self) -> None:
        from app.api.v1.endpoints import poe

        org = uuid4()
        stored = _schedule(org, device_id=_DEVICE)
        session = _session(_found(stored), _found(_GROUP))

        await poe.update_poe_schedule(
            schedule_id=str(stored.id),
            data=PoEScheduleUpdateIn(device_group_id=_GROUP),
            session=session,
            _user=_admin(org),
        )

        assert stored.device_group_id == _GROUP
        assert stored.device_id is None

    @pytest.mark.asyncio
    async def test_a_rename_leaves_the_target_alone(self) -> None:
        """The clearing rule must only fire when a target was actually supplied."""
        from app.api.v1.endpoints import poe

        org = uuid4()
        stored = _schedule(org, device_id=_DEVICE)
        session = _session(_found(stored))

        await poe.update_poe_schedule(
            schedule_id=str(stored.id),
            data=PoEScheduleUpdateIn(name="renamed"),
            session=session,
            _user=_admin(org),
        )

        assert stored.name == "renamed"
        assert stored.device_id == _DEVICE
        assert stored.device_group_id is None

    @pytest.mark.asyncio
    async def test_updating_a_legacy_targetless_row_is_a_422_not_a_500(self) -> None:
        """An appliance that carried a targetless row before 010 ran.

        010 adds the constraint NOT VALID there, and PostgreSQL enforces a NOT
        VALID CHECK on every subsequent UPDATE -- so even a plain rename of that
        row raises CheckViolation out of ``commit()``. Refuse it here, naming what
        is actually wrong, instead of returning a 500 about a constraint the
        operator has never heard of.
        """
        from app.api.v1.endpoints import poe

        org = uuid4()
        stored = _schedule(org)  # neither target: only possible pre-010
        session = _session(_found(stored))

        with pytest.raises(HTTPException) as ei:
            await poe.update_poe_schedule(
                schedule_id=str(stored.id),
                data=PoEScheduleUpdateIn(name="renamed"),
                session=session,
                _user=_admin(org),
            )

        assert ei.value.status_code == 422
        assert "no target" in str(ei.value.detail)
        session.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_legacy_targetless_row_can_be_repaired(self) -> None:
        """The 422 above must be an instruction that works, not a dead end."""
        from app.api.v1.endpoints import poe

        org = uuid4()
        stored = _schedule(org)
        session = _session(_found(stored), _found(_DEVICE))

        await poe.update_poe_schedule(
            schedule_id=str(stored.id),
            data=PoEScheduleUpdateIn(device_id=_DEVICE),
            session=session,
            _user=_admin(org),
        )

        assert stored.device_id == _DEVICE
        assert stored.device_group_id is None
        session.commit.assert_awaited_once()
