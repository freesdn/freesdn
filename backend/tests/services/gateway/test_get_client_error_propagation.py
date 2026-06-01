# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway service ``_get_client`` error propagation
=================================================

Regression guard for the offline-controller **500-vs-502** bug.

``GatewayServiceBase._get_client`` builds the vendor adapter via the shared
pool. When the controller is unreachable the pool's ``get_or_create_shared``
raises ``AdapterConnectionError``. That typed exception MUST propagate so the
central handler in ``app.core.middleware`` maps it to **502 Bad Gateway**
(``tests/test_adapter_exception_mapping.py`` locks that status mapping).

The historical bug: a broad ``except Exception`` swallowed the
``AdapterConnectionError`` and the fallback path then called the *async*
``get_adapter`` synchronously with a mis-named ``controller_type=`` kwarg —
raising ``TypeError`` → the generic handler → an opaque **500** for *every*
offline controller (the gateway UI showed only "could not load" blobs). The
fallback was therefore dead code that fired on every unreachable connect.

These tests pin the fix:

1. A typed ``AdapterError`` from the pool re-raises unchanged (→ 502/504).
2. The pool-internal-bug fallback awaits ``get_adapter(adapter_type=...)``
   with the correct signature (and never the old ``controller_type=``).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.adapters.exceptions import AdapterConnectionError
from app.adapters.pool import adapter_pool
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase


def _omada_controller() -> Controller:
    """A minimal, local-mode Omada controller (creds in the config JSONB)."""
    return Controller(
        id=uuid4(),
        site_id=uuid4(),
        name="omada-down",
        controller_type="omada",
        host="10.0.0.1",
        port=443,
        use_ssl=True,
        verify_ssl=False,
        status="unknown",
        config={
            "username": "admin",
            "password": "plain-pw",
            "connection_mode": "local",
        },
    )


def _service() -> GatewayServiceBase:
    svc = GatewayServiceBase.__new__(GatewayServiceBase)
    svc.db = MagicMock()
    svc.staging = MagicMock()
    # Isolate the unit from host DNS / SSRF pinning — irrelevant to the
    # exception-propagation behaviour under test, and keeps it offline.
    svc._pin_controller_host = lambda controller: controller.host  # type: ignore[assignment]
    return svc


@pytest.mark.asyncio
async def test_unreachable_controller_reraises_adapter_connection_error(monkeypatch) -> None:
    """Pool raises ``AdapterConnectionError`` (offline controller) → it must
    propagate unchanged so the central handler returns 502 — NOT be swallowed
    by the broad ``except`` and turned into a TypeError-driven 500."""
    svc = _service()

    async def _boom(**kwargs):
        raise AdapterConnectionError("controller unreachable", adapter_id="omada")

    monkeypatch.setattr(adapter_pool, "get_or_create_shared", _boom)

    with pytest.raises(AdapterConnectionError):
        await svc._get_client(_omada_controller())


@pytest.mark.asyncio
async def test_pool_internal_bug_falls_back_with_correct_get_adapter_signature(
    monkeypatch,
) -> None:
    """A NON-adapter error from the pool (a genuine pool bug) falls back to a
    direct adapter. The fallback must AWAIT ``app.adapters.get_adapter`` and
    pass ``adapter_type=`` — never the historical, guaranteed-TypeError
    ``controller_type=``."""
    svc = _service()

    async def _pool_bug(**kwargs):
        raise RuntimeError("pool machinery exploded")

    monkeypatch.setattr(adapter_pool, "get_or_create_shared", _pool_bug)
    monkeypatch.setattr(adapter_pool, "adopt", AsyncMock())

    fake_client = SimpleNamespace(tag="fallback-client")
    fake_adapter = SimpleNamespace(_connected=True, client=fake_client)
    get_adapter_mock = AsyncMock(return_value=fake_adapter)
    monkeypatch.setattr("app.services.adapter_base.get_adapter", get_adapter_mock)

    client = await svc._get_client(_omada_controller())

    assert client is fake_client
    get_adapter_mock.assert_awaited_once()
    kwargs = get_adapter_mock.await_args.kwargs
    assert kwargs["adapter_type"] == "omada"
    assert "controller_type" not in kwargs
