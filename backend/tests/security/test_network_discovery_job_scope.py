# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Task IDs alone must never authorize discovery result reads or publication."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.modules.network import api
from app.tasks import base, discovery
from tests.security.test_pentest_network_queued_job_sitegrant import _make_current_user


@pytest.fixture
def state(monkeypatch):
    org, other, site, sibling, task_id = [uuid4() for _ in range(5)]
    caller = _make_current_user(org, role="org_admin")
    scope = SimpleNamespace(task_id=task_id, organization_id=org, site_id=site)
    read_scope = AsyncMock(return_value=scope)
    read_status = MagicMock(
        return_value={"task_id": str(task_id), "status": "success", "devices_found": 77}
    )
    raw_backend = MagicMock()
    raw_backend.return_value.state = "SUCCESS"
    raw_backend.return_value.result = {"devices_found": 77}
    monkeypatch.setattr(api, "get_discovery_scope", read_scope, raising=False)
    monkeypatch.setattr(api, "discovery_status", read_status, raising=False)
    monkeypatch.setattr("celery.result.AsyncResult", raw_backend)
    monkeypatch.setattr(base, "get_task_progress", MagicMock(return_value=None))
    db = SimpleNamespace(
        execute=AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=site)))
    )
    return SimpleNamespace(
        org=org,
        other=other,
        site=site,
        sibling=sibling,
        task_id=task_id,
        caller=caller,
        scope=scope,
        read_scope=read_scope,
        read_status=read_status,
        raw_backend=raw_backend,
        db=db,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        "unowned",
        "other-organization",
        "site-limited-global",
        "sibling-site",
        "deleted-site",
        "missing-organization",
    ],
)
async def test_unauthorized_status_does_not_reach_task_payload(state, invalid):
    expected = 404
    if invalid == "unowned":
        state.read_scope.return_value = None
    elif invalid == "other-organization":
        state.scope.organization_id = state.other
    elif invalid == "site-limited-global":
        state.scope.site_id = None
        state.caller = _make_current_user(state.org, role="operator", site_grants=[state.site])
    elif invalid == "sibling-site":
        state.caller = _make_current_user(state.org, role="operator", site_grants=[state.sibling])
    elif invalid == "deleted-site":
        state.db.execute.return_value.scalar_one_or_none.return_value = None
    else:
        state.caller = _make_current_user(None, role="operator")
        expected = 400
    with pytest.raises(HTTPException) as error:
        await api.get_discovery_status(state.db, state.caller, task_id=str(state.task_id))
    assert error.value.status_code == expected
    state.read_status.assert_not_called()
    state.raw_backend.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy", ["other-tenant", "unscoped", "different-task-kind"])
async def test_progress_record_cannot_bypass_the_discovery_scope_store(state, monkeypatch, legacy):
    state.read_scope.return_value = None
    progress = base.TaskProgress(
        task_id=str(state.task_id),
        task_name="app.tasks.discovery.discover_all_devices",
        organization_id=str(state.org),
        status=base.TaskStatus.SUCCESS,
        result={"devices_found": 99},
    )
    if legacy == "other-tenant":
        progress.organization_id = str(state.other)
    elif legacy == "unscoped":
        progress.organization_id = None
    else:
        progress.task_name = "backup.run_scheduled"
    monkeypatch.setattr(base, "get_task_progress", lambda _: progress)
    with pytest.raises(HTTPException) as error:
        await api.get_discovery_status(state.db, state.caller, task_id=str(state.task_id))
    assert error.value.status_code == 404
    state.read_status.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("limited", [False, True])
async def test_current_authorized_owner_can_read_discovery(state, limited):
    if limited:
        state.caller = _make_current_user(state.org, role="operator", site_grants=[state.site])
    result = await api.get_discovery_status(state.db, state.caller, task_id=str(state.task_id))
    assert result["status"] == "success" and result["devices_found"] == 77


@pytest.mark.asyncio
async def test_scope_store_failure_is_bounded_and_does_not_read_results(state):
    error_class = getattr(api, "DiscoveryScopeUnavailable", RuntimeError)
    state.read_scope.side_effect = error_class("synthetic-private-store-location")
    with pytest.raises(HTTPException) as error:
        await api.get_discovery_status(state.db, state.caller, task_id=str(state.task_id))
    assert error.value.status_code == 503 and "synthetic-private" not in str(error.value.detail)
    state.read_status.assert_not_called()
    state.raw_backend.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["start_discovery", "refresh_topology"])
@pytest.mark.parametrize(
    "mode", ["success", "reserve-refused", "uncertain-before", "uncertain-after"]
)
async def test_submission_owns_exact_identity_before_publish_and_keeps_uncertain_scope(
    state, monkeypatch, route, mode
):
    records, events = {}, []

    async def reserve(scope):
        events.append("reserve")
        if mode == "reserve-refused":
            return False
        records[str(scope.task_id)] = scope
        return True

    def publish(*args, **kwargs):
        events.append("publish")
        identity = kwargs.get("task_id", str(state.task_id))
        if mode.startswith("uncertain"):
            if mode == "uncertain-after":
                events.append("accepted")
            raise RuntimeError("synthetic-private-broker-location")
        return SimpleNamespace(id=identity)

    reserve_mock = AsyncMock(side_effect=reserve)
    publish_mock = MagicMock(side_effect=publish)
    monkeypatch.setattr(api, "reserve_discovery_scope", reserve_mock, raising=False)
    monkeypatch.setattr(discovery.discover_all_devices, "delay", publish_mock)
    monkeypatch.setattr(discovery.discover_all_devices, "apply_async", publish_mock)
    endpoint = getattr(api, route)
    if mode == "success":
        result = await endpoint(state.db, state.caller, site_id=state.site)
        assert events == ["reserve", "publish"]
        identity = result["task_id"]
    else:
        with pytest.raises(HTTPException) as error:
            await endpoint(state.db, state.caller, site_id=state.site)
        assert error.value.status_code == 503 and "synthetic-private" not in str(error.value.detail)
        if mode == "reserve-refused":
            publish_mock.assert_not_called()
            assert records == {}
            return
        identity = error.value.detail["task_id"]
        assert events == ["reserve", "publish"] + (
            ["accepted"] if mode == "uncertain-after" else []
        )
    assert len(records) == 1 and records[identity].organization_id == state.org
    assert records[identity].site_id == state.site
    assert records[identity].task_name == "app.tasks.discovery.discover_all_devices"
    assert publish_mock.call_count == 1 and publish_mock.call_args.kwargs["task_id"] == identity
    assert publish_mock.call_args.kwargs["kwargs"] == {
        "organization_id": str(state.org),
        "site_id": str(state.site),
    }
