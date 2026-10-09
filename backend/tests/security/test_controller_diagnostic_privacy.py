# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Provider diagnostics and legacy stored errors are not public controller data."""

import copy
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.adapters.proxmox.client import ProxmoxApiError
from app.adapters.registry import adapter_registry
from app.api.v1.endpoints import controllers
from app.core.dependencies import CurrentUser
from app.models.core import Controller, Site, User
from app.schemas.core import ControllerProbe, ControllerResponse, ControllerWithStats

MARKER = "owned-private-provider-response-marker"


@pytest.fixture
def owned():
    org, site_id, controller_id = uuid4(), uuid4(), uuid4()
    site = Site(id=site_id, name="Owned site", slug=site_id.hex, organization_id=org)
    controller = Controller(
        id=controller_id,
        name="Owned controller",
        controller_type="omada",
        site_id=site_id,
        site=site,
        host="192.0.2.10",
        port=8043,
        use_ssl=True,
        verify_ssl=True,
        status="error",
        last_sync=None,
        last_error=MARKER,
        config={
            "error_history": [
                {"timestamp": "2026-09-24T00:00:00+00:00", "error": MARKER, "private": MARKER}
            ],
            "preserve_setting": "owned",
        },
        sync_enabled=True,
        sync_interval_seconds=300,
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    user = CurrentUser(
        user=User(
            id=uuid4(),
            email="owned@example.invalid",
            organization_id=org,
            role="org_admin",
            hashed_password="owned",
            is_active=True,
        ),
        permissions=["controller:read", "controller:update", "controller:create"],
        accessible_site_ids=set(),
    )
    return SimpleNamespace(controller=controller, user=user)


@pytest.mark.parametrize("schema", [ControllerResponse, ControllerWithStats])
@pytest.mark.parametrize("field", ["last_error", "history"])
def test_schema_hides_legacy_diagnostic_without_mutating_model(owned, schema, field):
    row = owned.controller
    original = copy.deepcopy(row.config)
    result = schema.model_validate(row).model_dump(mode="json")
    exposed = result["last_error"] if field == "last_error" else result["config"]["error_history"]
    assert MARKER not in json.dumps(exposed)
    assert row.config == original and row.last_error == MARKER
    assert result["config"]["preserve_setting"] == "owned"


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["last_error", "error_history"])
async def test_metadata_hides_legacy_diagnostic_without_writing(owned, field):
    row = owned.controller
    original = copy.deepcopy(row.config)
    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=lambda: row),
            MagicMock(scalars=lambda: SimpleNamespace(all=lambda: [])),
        ]
    )
    session.commit = AsyncMock()
    result = await controllers.get_controller_metadata(row.id, owned.user, session)
    assert MARKER not in json.dumps(result["sync"][field])
    assert row.config == original and row.last_error == MARKER
    session.commit.assert_not_awaited()


@pytest.mark.parametrize("status", [0, 400, 404, 429, 500, MARKER])
def test_proxmox_hint_never_copies_provider_text_or_untyped_status(status):
    result = controllers._build_error_hint(ProxmoxApiError(MARKER, status_code=status))
    assert MARKER not in result


def test_unknown_hint_does_not_log_exception_body(caplog):
    result = controllers._build_error_hint(RuntimeError(MARKER))
    assert MARKER not in result + caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("success", [False, True])
@pytest.mark.parametrize("route", ["saved", "precreation"])
async def test_connection_result_has_only_safe_diagnostic_fields(
    owned, monkeypatch, success, route
):
    row = owned.controller
    adapter = MagicMock()
    adapter.__aenter__ = AsyncMock(return_value=adapter)
    adapter.__aexit__ = AsyncMock(return_value=False)
    adapter.test_connection = AsyncMock(
        return_value=SimpleNamespace(
            success=success,
            message=MARKER,
            error=MARKER,
            data={"version": "1.2", "controller_name": "Owned controller", "mode": "local"},
        )
    )
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    if route == "saved":
        session = MagicMock()
        session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: row))
        session.commit = AsyncMock()
        result = await controllers.test_controller_connection(row.id, owned.user, session)
        assert row.last_error is None if success else MARKER not in (row.last_error or "")
    else:
        probe = ControllerProbe(
            controller_type="omada",
            host="192.0.2.10",
            port=8043,
            username="owned",
            password="owned",
        )
        result = await controllers.test_connection_precreation(probe, owned.user)
    assert result["success"] is success
    assert MARKER not in json.dumps({name: result.get(name) for name in ["message", "error"]})
    assert result["details"]["controller_version"] == "1.2"
    adapter.test_connection.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["saved", "precreation"])
async def test_connection_exception_has_safe_storage_result_and_log(
    owned, monkeypatch, caplog, route
):
    row = owned.controller

    def unavailable(**_kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(adapter_registry, "create_adapter", unavailable)
    if route == "saved":
        session = MagicMock()
        session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: row))
        session.commit = AsyncMock()
        result = await controllers.test_controller_connection(row.id, owned.user, session)
        assert MARKER not in (row.last_error or "")
    else:
        probe = ControllerProbe(
            controller_type="omada",
            host="192.0.2.10",
            port=8043,
            username="owned",
            password="owned",
        )
        result = await controllers.test_connection_precreation(probe, owned.user)
    assert result["success"] is False
    assert MARKER not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("schema", [ControllerResponse, ControllerWithStats])
def test_empty_diagnostics_and_existing_secret_redaction_remain_compatible(owned, schema):
    owned.controller.last_error = None
    owned.controller.config = {"error_history": [], "password": MARKER, "preserve_setting": "owned"}
    result = schema.model_validate(owned.controller).model_dump(mode="json")
    assert result["last_error"] is None and result["config"]["error_history"] == []
    assert result["config"]["password"] == "***REDACTED***"
    assert result["config"]["preserve_setting"] == "owned"


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["create", "fetch"])
@pytest.mark.parametrize("route", ["saved-sites", "precreation-sites"])
async def test_controller_site_probe_diagnostics_are_safe(owned, monkeypatch, caplog, stage, route):
    from fastapi import HTTPException

    adapter = MagicMock()
    adapter.__aenter__ = AsyncMock(return_value=adapter)
    adapter.__aexit__ = AsyncMock(return_value=False)
    adapter.get_sites = AsyncMock(side_effect=RuntimeError(MARKER))

    def create(**_kwargs):
        if stage == "create":
            raise RuntimeError(MARKER)
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: owned.controller))
    with pytest.raises(HTTPException) as caught:
        if route == "saved-sites":
            await controllers.get_controller_remote_sites(owned.controller.id, owned.user, session)
        else:
            probe = ControllerProbe(
                controller_type="omada",
                host="192.0.2.10",
                port=8043,
                username="owned",
                password="owned",
            )
            await controllers.probe_remote_sites(probe, owned.user, session)
    assert caught.value.status_code == 502
    assert MARKER not in str(caught.value.detail) + caplog.text
