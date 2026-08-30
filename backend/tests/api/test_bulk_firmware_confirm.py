# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""on the bulk path: a fleet flash needs explicit confirmation.

Three firmware endpoints have always enforced this -- ``devices.upgrade_firmware``,
``devices.batch_firmware_upgrade`` and ``controllers.batch_firmware_upgrade`` all
refuse with 409 unless ``confirm`` is set. The bulk-operations endpoint did not,
and nobody noticed, because the executor demanded a ``firmware_url`` the shipped
UI cannot produce: a bulk firmware job raised before it ever reached an adapter.

Removing that stale requirement was right -- ``firmware_url`` was never part of
``BaseAdapter.upgrade_firmware(device_id)`` -- but it turned a dead endpoint into
a live one-click fleet flash whose only brake had been a leftover argument check.
The brake now has to be the deliberate one.

These call the endpoint function directly. The confirm gate runs before any DB
access, so no session is needed, and calling production rather than re-deriving
the rule is the point.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.enterprise import create_bulk_operation
from app.schemas.enterprise import BulkOperationCreate, BulkTarget


class _User:
    """An operator holding every bulk-op permission."""

    def __init__(self, *, permissions: set[str] | None = None) -> None:
        self._perms = (
            permissions
            if permissions is not None
            else {
                "device:reboot",
                "config:push",
                "firmware:upgrade",
            }
        )

    def has_permission(self, perm: str) -> bool:
        return perm in self._perms


def _payload(operation: str, *, confirm: bool | None = None) -> BulkOperationCreate:
    kwargs: dict = {
        "operation": operation,
        "target": BulkTarget(scope="site", scope_id=uuid4()),
    }
    if confirm is not None:
        kwargs["confirm"] = confirm
    return BulkOperationCreate(**kwargs)


async def test_bulk_firmware_without_confirm_is_refused() -> None:
    """The core regression. Fails before the fix: the job is accepted."""
    with pytest.raises(HTTPException) as excinfo:
        await create_bulk_operation(_payload("firmware_update"), db=None, user=_User())

    assert excinfo.value.status_code == 409, (
        "an irreversible fleet firmware flash must be refused without explicit "
        f"confirmation; got {excinfo.value.status_code}"
    )
    assert "confirm=true" in str(excinfo.value.detail)


async def test_confirm_defaults_to_false() -> None:
    """A caller that omits the field must not be treated as having confirmed."""
    assert _payload("firmware_update").confirm is False


async def test_bulk_firmware_with_confirm_passes_the_gate() -> None:
    """confirm=true must get PAST the gate.

    Otherwise the UI path is still dead -- it just fails with a 409 instead of a
    ValueError, which is not a fix. db=None means it fails later, on the database;
    what matters is that it is no longer the confirmation that stops it.
    """
    with pytest.raises(Exception) as excinfo:  # noqa: PT011 - any later failure
        await create_bulk_operation(
            _payload("firmware_update", confirm=True), db=None, user=_User()
        )

    if isinstance(excinfo.value, HTTPException):
        assert excinfo.value.status_code != 409, (
            "confirm=true was sent and the request was still refused as "
            "unconfirmed -- the gate is unsatisfiable and the operation is dead"
        )


@pytest.mark.parametrize("operation", ["reboot", "push_config"])
async def test_reversible_operations_do_not_require_confirmation(operation: str) -> None:
    """The gate must be scoped to the irreversible operation only.

    A reboot is disruptive but recoverable, and requiring a confirm for it here
    while the reboot endpoints do not would be a silent behaviour change for
    existing API callers.
    """
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        await create_bulk_operation(_payload(operation), db=None, user=_User())

    if isinstance(excinfo.value, HTTPException):
        assert excinfo.value.status_code != 409, f"{operation} must not be gated on confirm"


async def test_the_permission_gate_still_runs_first() -> None:
    """An operator without firmware:upgrade gets 403, not a confirm hint.

    Answering 409 first would tell an unprivileged caller exactly how to retry.
    """
    user = _User(permissions={"device:reboot"})
    with pytest.raises(HTTPException) as excinfo:
        await create_bulk_operation(_payload("firmware_update"), db=None, user=user)

    assert excinfo.value.status_code == 403
