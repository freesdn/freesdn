# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The device-type guard in actions.py must work on a DB-LOADED Device.

Found by sweeping all 572 parameterized GET endpoints against the owner's live
fleet with real ids:

    GET /api/v1/actions/camera/{real_device_id}/rtsp  ->  500
    "'str' object has no attribute 'value'"  at actions.py:106

``Device.device_type`` advertises an enum but is stored as a bare string::

    device_type: Mapped[DeviceType] = mapped_column(String(50), nullable=False)

There is no SQLAlchemy ``Enum()`` on the column, so the ORM round-trips a plain
``str``. mypy trusts the annotation and accepts ``.value``; at runtime the
attribute is a ``str`` and ``.value`` raises AttributeError.

The timing is what hid it: a freshly CONSTRUCTED Device still holds the enum
member the caller assigned, so ``.value`` works there -- which is why discovery
(construct, flush, read back in-session) never tripped it. Only a row LOADED
from the database carries the plain string, and that is the only thing this
endpoint ever sees.

So these tests set ``device_type`` to a plain ``str``, which is exactly what
the ORM hands back, rather than to a DeviceType member -- a test written with
the enum passes against the broken code and proves nothing.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import actions
from app.models import Device


def _loaded_device(device_type: str) -> Device:
    """A Device shaped like one the ORM just returned: device_type is a str."""
    d = Device()
    d.id = uuid4()
    d.site_id = uuid4()
    d.name = "front-door"
    # NOT DeviceType.CAMERA -- a loaded row carries the raw column value.
    d.device_type = device_type
    assert isinstance(d.device_type, str) and not hasattr(d.device_type, "value")
    return d


def _session_returning(device: Device) -> MagicMock:
    session = MagicMock()

    async def execute(_query):
        result = MagicMock()
        result.scalar_one_or_none.return_value = device
        return result

    session.execute = execute
    return session


@pytest.fixture(autouse=True)
def _bypass_access_checks(monkeypatch):
    """Isolate the type guard; tenancy and site grants have their own suites."""
    monkeypatch.setattr(actions, "is_unscoped_superuser", lambda _u: True)
    monkeypatch.setattr(actions, "assert_can_access_site", lambda *_a, **_k: None)


async def test_matching_type_on_a_loaded_row_does_not_crash():
    """The live 500: `.value` on a str. Must return the device instead."""
    device = _loaded_device("camera")
    got = await actions.get_device_with_access(
        device_id=device.id,
        current_user=MagicMock(organization_id=uuid4()),
        session=_session_returning(device),
        device_type="camera",
    )
    assert got is device


async def test_mismatched_type_still_refused_with_400():
    """The guard must keep REFUSING, not just stop crashing."""
    device = _loaded_device("switch")
    with pytest.raises(HTTPException) as ei:
        await actions.get_device_with_access(
            device_id=device.id,
            current_user=MagicMock(organization_id=uuid4()),
            session=_session_returning(device),
            device_type="camera",
        )
    assert ei.value.status_code == 400


async def test_legacy_spelling_is_accepted_as_the_canonical_type():
    """A row holding the legacy "ap" IS an access_point.

    These rows exist -- folding them is the whole reason
    ``normalize_device_type`` was written -- and an access check that compared
    the raw column would refuse a device the operator can legitimately act on.
    """
    device = _loaded_device("ap")
    got = await actions.get_device_with_access(
        device_id=device.id,
        current_user=MagicMock(organization_id=uuid4()),
        session=_session_returning(device),
        device_type="access_point",
    )
    assert got is device


async def test_no_requested_type_skips_the_guard_entirely():
    device = _loaded_device("whatever-the-vendor-said")
    got = await actions.get_device_with_access(
        device_id=device.id,
        current_user=MagicMock(organization_id=uuid4()),
        session=_session_returning(device),
    )
    assert got is device
