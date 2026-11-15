# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
AdapterStagingService.apply_now: a configuration write made by the request,
recorded in the staging ledger (STAGING-MIGRATION option 2).

The endpoints that write to a device when called with ``force=true`` used to
call the adapter directly, so the pending-change ledger was not a record of
what FreeSDN did to a device. apply_now stages the write as a ``direct.*`` row
and applies it through apply_change in the same request: the read-only and
force gates refuse first, the row records who, what, when and the result, and
the caller gets the adapter's own answer back.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.staging import AdapterPendingChange
from app.services.adapter_staging import AdapterStagingService, redact_for_ledger


@pytest.fixture
def writable(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def scope(db_session):
    org = Organization(name="apply-now", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="c", site_id=site.id, controller_type="unifi", host="127.0.0.1", port=443
    )
    db_session.add(ctrl)
    await db_session.commit()
    return SimpleNamespace(org=org, site=site, ctrl=ctrl)


def _kwargs(scope, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "organization_id": scope.org.id,
        "controller_id": scope.ctrl.id,
        "site_id": scope.site.id,
        "feature": "unifi.wlans.password",
        "operation": "update",
        "target_id": "wlan-1",
        "payload": {"site": "default", "wlan_id": "wlan-1", "new_psk": "correct horse"},
        "force": True,
        "actor_id": None,
    }
    base.update(over)
    return base


async def _rows(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.%"))
            )
        ).scalars()
    )


async def test_the_write_is_recorded_with_its_result(db_session, scope, writable) -> None:
    calls: list[str] = []

    async def _perform() -> dict[str, Any]:
        calls.append("write")
        return {"wlan": "wlan-1", "changed": True}

    out = await AdapterStagingService(db_session).apply_now(**_kwargs(scope), perform=_perform)

    assert out == {"wlan": "wlan-1", "changed": True}
    assert calls == ["write"]
    (row,) = await _rows(db_session)
    assert row.feature == "direct.unifi.wlans.password"
    assert row.status == "applied"
    assert row.applied_at is not None
    assert row.applied_response == {"wlan": "wlan-1", "changed": True}
    # The ledger records that the PSK changed, never the PSK.
    assert row.payload["new_psk"] == "***"
    assert "correct horse" not in str(row.payload)


async def test_read_only_mode_refuses_before_anything_is_recorded(
    db_session, scope, writable
) -> None:
    writable["read_only"] = True

    async def _perform() -> None:
        raise AssertionError("the device must not be contacted")

    with pytest.raises(HTTPException) as refused:
        await AdapterStagingService(db_session).apply_now(**_kwargs(scope), perform=_perform)
    assert refused.value.status_code == 403
    assert "force=true alone does not lift read-only mode" in str(refused.value.detail)
    assert await _rows(db_session) == []


async def test_force_is_required(db_session, scope, writable) -> None:
    async def _perform() -> None:
        raise AssertionError("the device must not be contacted")

    with pytest.raises(HTTPException) as refused:
        await AdapterStagingService(db_session).apply_now(
            **_kwargs(scope, force=False), perform=_perform
        )
    assert refused.value.status_code == 403
    assert await _rows(db_session) == []


async def test_an_adapter_error_keeps_its_meaning_and_is_recorded(
    db_session, scope, writable
) -> None:
    class _Boom(RuntimeError):
        pass

    async def _perform() -> None:
        raise _Boom("controller said no")

    with pytest.raises(_Boom):
        await AdapterStagingService(db_session).apply_now(**_kwargs(scope), perform=_perform)
    (row,) = await _rows(db_session)
    assert row.status == "failed"


async def test_a_refused_result_is_recorded_and_raised_as_mapped(
    db_session, scope, writable
) -> None:
    async def _perform() -> AdapterResult:
        return AdapterResult.fail("no such wlan", error_code="NOT_FOUND")

    with pytest.raises(Exception) as raised:
        await AdapterStagingService(db_session).apply_now(**_kwargs(scope), perform=_perform)
    assert "no such wlan" in str(raised.value)
    (row,) = await _rows(db_session)
    assert row.status == "failed"
    assert "no such wlan" in (row.failure_reason or "")


async def test_a_refused_result_can_be_returned_to_the_caller(db_session, scope, writable) -> None:
    refused = AdapterResult.fail("busy", error_code="BUSY")

    async def _perform() -> AdapterResult:
        return refused

    out = await AdapterStagingService(db_session).apply_now(
        **_kwargs(scope), perform=_perform, return_failed_result=True
    )
    assert out is refused
    (row,) = await _rows(db_session)
    assert row.status == "failed"


async def test_a_refusal_before_the_device_is_not_left_pending(
    db_session, scope, writable, monkeypatch
) -> None:
    import app.services.adapter_preflight_common as common

    def _refuse(_payload: Any) -> bool:
        raise HTTPException(409, detail="preflight said no")

    monkeypatch.setattr(common, "payload_confirmed", _refuse)

    async def _perform() -> None:
        raise AssertionError("the device must not be contacted")

    with pytest.raises(HTTPException):
        await AdapterStagingService(db_session).apply_now(
            **_kwargs(scope, operation="delete"), perform=_perform
        )
    (row,) = await _rows(db_session)
    assert row.status == "failed"
    assert "refused before the device was contacted" in (row.failure_reason or "")


async def test_a_direct_row_cannot_be_applied_from_the_queue(db_session, scope, writable) -> None:
    async def _perform() -> dict[str, Any]:
        return {}

    staging = AdapterStagingService(db_session)
    with pytest.raises(HTTPException) as refused:
        await staging.stage_change(
            organization_id=scope.org.id,
            controller_id=scope.ctrl.id,
            feature="direct.unifi.wlans.password",
            operation="update",
            payload={},
        )
    assert refused.value.status_code == 400

    await staging.apply_now(**_kwargs(scope), perform=_perform)
    (row,) = await _rows(db_session)
    row.status = "pending"  # even if one were somehow left pending
    await db_session.commit()
    with pytest.raises(HTTPException) as again:
        await staging.apply_change(row.id, force=True, confirmed=True, applier=_perform)
    assert again.value.status_code == 409
    assert "cannot be applied from the pending-change queue" in str(again.value.detail)


async def test_a_direct_write_needs_no_controller(db_session, scope, writable) -> None:
    """Cameras, phones and PBXs are not controller rows."""

    async def _perform() -> str:
        return "ok"

    assert (
        await AdapterStagingService(db_session).apply_now(
            **_kwargs(scope, controller_id=None, feature="camera.motion"), perform=_perform
        )
        == "ok"
    )


def test_the_ledger_redaction_masks_more_than_the_read_path() -> None:
    masked = redact_for_ledger(
        {
            "new_psk": "a",
            "new_password": "b",
            "secret_key": "c",
            "snmp": {"community": "d"},
            "items": [{"admin_password": "e", "name": "keep"}],
            "vlan_id": 10,
        }
    )
    assert masked == {
        "new_psk": "***",
        "new_password": "***",
        "secret_key": "***",
        "snmp": {"community": "***"},
        "items": [{"admin_password": "***", "name": "keep"}],
        "vlan_id": 10,
    }
