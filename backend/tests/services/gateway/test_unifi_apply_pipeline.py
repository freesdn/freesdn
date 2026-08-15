# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""UniFi catastrophic staged write through the FULL apply_change pipeline.

Locks the apply-path fix for the two HIGH findings from the UniFi review:

* (#1/#11) No staged-write UI ever put ``confirmed=true`` IN the payload, so a
  catastrophic UniFi op (any delete, client forget, device restart/disable/
  upgrade) could be STAGED but never APPLIED — the vendor pre-flight 409'd it
  forever. Confirmation is an APPLY-TIME decision (the Pending-Changes drawer);
  ``apply_change(confirmed=True)`` now merges the flag into a pre-flight-only
  payload view so the gate passes WITHOUT mutating the stored payload.
* (#6) ``unifi.devices.upgrade`` joined the catastrophic set.

This exercises the change through the real
``AdapterStagingService.apply_change`` orchestration (dual-gate, atomic claim,
pre-flights, status transitions) with only the applier faked — mirroring
``test_freepbx_apply_pipeline``.

Session is mocked (no DB); the row is a real model.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.models.staging import AdapterPendingChange
from app.services import adapter_staging
from app.services.adapter_staging import AdapterStagingService


def _make_session(change: AdapterPendingChange):
    """A mocked AsyncSession whose every ``execute`` resolves to ``change``.

    The SELECT-FOR-UPDATE claim and the Omada controller-type lookup both call
    ``.scalar_one_or_none()``; returning the change for both is harmless — the
    Omada pre-flight is keyed on controller_type, which is not 'omada' here, so
    it no-ops, exactly like the FreePBX pipeline test.
    """
    from unittest.mock import AsyncMock, MagicMock

    s = AsyncMock()
    s.commit = AsyncMock()
    s.refresh = AsyncMock()
    s.execute = AsyncMock(
        return_value=MagicMock(
            scalar_one_or_none=MagicMock(return_value=change)
        )
    )
    s.get = AsyncMock(return_value=None)
    return s


def _forget_change() -> AdapterPendingChange:
    """A catastrophic UniFi client-forget, staged WITHOUT confirmation."""
    return AdapterPendingChange(
        id=uuid4(),
        organization_id=uuid4(),
        controller_id=uuid4(),
        site_id=None,
        feature="unifi.clients.forget",
        operation="delete",
        target_id="aa:bb:cc:dd:ee:ff",
        payload={"site": "default"},  # NOTE: no "confirmed"
        status="pending",
        notes=None,
    )


class _RecApplier:
    """Records whether the applier was reached, and the payload it saw."""

    def __init__(self) -> None:
        self.called = False
        self.seen_payload: dict | None = None

    async def __call__(self, change: AdapterPendingChange) -> AdapterResult:
        self.called = True
        self.seen_payload = dict(change.payload or {})
        return AdapterResult.ok(data={"ok": True}, message="forgotten")


@pytest.fixture(autouse=True)
def _env_open(monkeypatch):
    # Open the env half of the dual-gate so apply reaches the pre-flights.
    monkeypatch.setattr(
        adapter_staging.AdapterStagingService,
        "is_read_only",
        staticmethod(lambda: False),
    )


@pytest.mark.asyncio
async def test_catastrophic_unifi_apply_without_confirmed_is_blocked():
    """force=true alone is NOT enough for a catastrophic op: the UniFi pre-flight
    409s, the applier is never reached, and the row stays 'pending' (refusal
    happens BEFORE the claim flips it to 'applying')."""
    change = _forget_change()
    session = _make_session(change)
    applier = _RecApplier()

    with pytest.raises(HTTPException) as ei:
        await AdapterStagingService(session).apply_change(
            change.id, force=True, confirmed=False, applier=applier
        )

    assert ei.value.status_code == 409
    assert "confirmed=true" in ei.value.detail
    assert applier.called is False
    assert change.status == "pending"  # never flipped to applying


@pytest.mark.asyncio
async def test_catastrophic_unifi_apply_with_confirmed_reaches_applier():
    """The operator's apply-time confirmed sign-off clears the gate; the change
    routes through to the applier (forced) and lands 'applied'."""
    change = _forget_change()
    session = _make_session(change)
    applier = _RecApplier()

    result = await AdapterStagingService(session).apply_change(
        change.id, force=True, confirmed=True, applier=applier
    )

    assert result.status == "applied"
    assert applier.called is True


@pytest.mark.asyncio
async def test_apply_time_confirmed_does_not_mutate_stored_payload():
    """The confirmation is merged into a pre-flight-ONLY view: the stored
    ``change.payload`` must NOT gain a ``confirmed`` key (no DB write, nothing
    leaks into the applier body or a future re-apply)."""
    change = _forget_change()
    session = _make_session(change)
    applier = _RecApplier()

    await AdapterStagingService(session).apply_change(
        change.id, force=True, confirmed=True, applier=applier
    )

    # Stored payload is untouched — confirmation lived only in the pre-flight view.
    assert "confirmed" not in (change.payload or {})
    assert (applier.seen_payload or {}).get("confirmed") is None


@pytest.mark.asyncio
async def test_non_catastrophic_unifi_apply_needs_no_confirmation():
    """A safe UniFi op (a network create) applies with force alone — the
    apply-time confirmed flag stays False and the pre-flight no-ops."""
    change = AdapterPendingChange(
        id=uuid4(),
        organization_id=uuid4(),
        controller_id=uuid4(),
        site_id=None,
        feature="unifi.networks.create",
        operation="create",
        target_id=None,
        payload={"site": "default", "name": "vlan-50"},
        status="pending",
        notes=None,
    )
    session = _make_session(change)
    applier = _RecApplier()

    result = await AdapterStagingService(session).apply_change(
        change.id, force=True, confirmed=False, applier=applier
    )

    assert result.status == "applied"
    assert applier.called is True
