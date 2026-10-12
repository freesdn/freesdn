# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Settings > Modules toggle must actually close a module's endpoints.

Before ``app/modules/enablement.py`` existed, disabling a module hid its
navigation and nothing else: ``ModuleRegistry.require_enabled`` had no callers
and ``ModuleLoader.register_routes`` mounted every module router with no
dependency, so a "disabled" module answered every request from anyone holding
valid credentials.

The gate is deliberately asymmetric and these tests pin both halves:

* an EXPLICIT ``is_enabled=False`` row refuses, because that is an operator
  decision the product promised to honour;
* a MISSING row does not refuse, because no module declares ``is_core`` and
  ``ModuleService.is_module_enabled`` treats absence as disabled. A gate that
  refused on absence would 403 the whole product for any organization whose
  rows were never written, which is a lockout rather than a feature.

The last test is the one that matters a year from now: it asserts the gate is
mounted on every module router, so a module added later cannot arrive ungated.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from app.modules.enablement import (
    is_module_explicitly_disabled,
    module_enabled_dependency,
)


class _Result:
    """Stand-in for the scalar result of the enablement lookup."""

    def __init__(self, value: bool | None) -> None:
        self._value = value

    def scalar_one_or_none(self) -> bool | None:
        return self._value


class _Session:
    def __init__(self, value: bool | None) -> None:
        self._value = value
        self.executed = 0

    async def execute(self, _stmt: object) -> _Result:
        self.executed += 1
        return _Result(self._value)


ORG = uuid.uuid4()


@pytest.mark.parametrize(
    ("row_value", "expected"),
    [
        (False, True),  # explicit "off" -> refuse
        (True, False),  # explicit "on"  -> allow
        (None, False),  # no row at all  -> allow (see module docstring)
    ],
)
async def test_only_an_explicit_false_counts_as_disabled(
    row_value: bool | None, expected: bool
) -> None:
    session = _Session(row_value)
    assert await is_module_explicitly_disabled(session, ORG, "cameras") is expected


async def test_disabled_module_is_refused_with_an_actionable_message() -> None:
    enforce = module_enabled_dependency("cameras")
    user = SimpleNamespace(organization_id=ORG)

    with pytest.raises(Exception) as excinfo:  # noqa: PT011 - HTTPException
        await enforce(user=user, session=_Session(False))

    exc = excinfo.value
    assert getattr(exc, "status_code", None) == 403
    detail = str(getattr(exc, "detail", ""))
    # The operator has to be able to act on this without reading the source.
    assert "cameras" in detail
    assert "Settings > Modules" in detail


async def test_enabled_and_unconfigured_modules_are_allowed() -> None:
    enforce = module_enabled_dependency("cameras")
    user = SimpleNamespace(organization_id=ORG)

    assert await enforce(user=user, session=_Session(True)) is None
    assert await enforce(user=user, session=_Session(None)) is None


async def test_gate_does_not_impose_authentication_or_invent_an_org() -> None:
    """No caller, or a caller with no organization, is not this gate's business.

    Resolving the user optionally keeps a public module route public. Refusing a
    principal with no organization would make a routing gate answer a question
    the tenancy layer already answers, and the two would eventually disagree.
    """
    enforce = module_enabled_dependency("cameras")

    anonymous = _Session(False)
    assert await enforce(user=None, session=anonymous) is None
    assert anonymous.executed == 0, "must not query for an unauthenticated caller"

    orgless = _Session(False)
    assert (
        await enforce(user=SimpleNamespace(organization_id=None), session=orgless)
        is None
    )
    assert orgless.executed == 0, "must not query without an organization"


async def test_every_module_router_is_mounted_behind_the_gate() -> None:
    """RATCHET: a module added later must not arrive ungated.

    The gate is applied in ``register_routes`` rather than on each endpoint
    precisely so it cannot be forgotten. This asserts that property against the
    real loader, so moving the mount or adding a second one re-opens the hole
    loudly instead of silently.

    It inspects the ``include_router`` CALL rather than ``app.routes``. Since
    FastAPI 0.137 ``include_router`` appends an opaque ``_IncludedRouter`` with
    no ``path`` and no ``dependencies``, so a version of this test that walked
    app.routes matched nothing, found nothing ungated, and passed happily with
    the gate deleted. Checking the call is also the honest subject: the contract
    is "every module router is mounted WITH this dependency".
    """
    from app.modules.loader import ModuleLoader

    # Mirror app/main.py's startup sequence exactly, so this ratchet exercises
    # the path that actually mounts routes in production. discover_modules()
    # must run first; without it the registry stays empty.
    loader = ModuleLoader()
    discovered = loader.discover_modules()
    assert discovered, "no modules discovered; this test would prove nothing"
    await loader.load_all_modules()

    app = FastAPI()
    mounts: list[dict] = []
    real_include = app.include_router

    def _spy(router, **kwargs):
        mounts.append(kwargs)
        return real_include(router, **kwargs)

    app.include_router = _spy  # type: ignore[method-assign]
    loader.register_routes(app, prefix="/api/v1")

    assert mounts, "register_routes mounted nothing; this test would prove nothing"

    ungated = [
        kwargs.get("prefix", "<unknown>")
        for kwargs in mounts
        if not any(
            getattr(getattr(dep, "dependency", None), "__name__", "").endswith("_enabled")
            for dep in (kwargs.get("dependencies") or [])
        )
    ]
    assert not ungated, (
        f"{ungated} are mounted without the enablement gate. Disabling those "
        "modules would hide their navigation while leaving every endpoint "
        "callable, which is the exact defect app/modules/enablement.py closed."
    )

async def test_disabling_a_never_enabled_module_records_the_decision() -> None:
    """The toggle must work for a module that has no row yet.

    This was the hole left by the gate's absence-is-permitted rule. A module
    nobody explicitly enabled is SERVING, so Disable is a real request with a
    real effect -- but ``disable_module`` returned None when it found no row and
    the API turned that into 404 "Module not found for organization", writing
    nothing. The toggle was inert for exactly the modules most likely to be in
    that state.
    """
    from app.modules.service import ModuleService

    added: list[object] = []

    class _DB:
        def add(self, obj: object) -> None:
            added.append(obj)

        async def commit(self) -> None:
            return None

        async def refresh(self, _obj: object) -> None:
            return None

    service = ModuleService.__new__(ModuleService)
    service.db = _DB()
    service.registry = SimpleNamespace(get_module_or_none=lambda _id: None)

    async def _no_row(*_a: object, **_k: object) -> None:
        return None

    async def _noop_event(**_k: object) -> None:
        return None

    service.get_org_module = _no_row  # type: ignore[method-assign]
    service._log_event = _noop_event  # type: ignore[method-assign]

    result = await service.disable_module(
        organization_id=ORG, module_id="cameras", user_id=None
    )

    assert result is not None, "disable must not silently do nothing"
    assert added, "a row recording the decision must be persisted"
    row = added[0]
    assert row.module_id == "cameras"
    assert row.is_enabled is False
    assert row.disabled_at is not None
    # And the gate must now refuse it, which is the whole point.
    assert await is_module_explicitly_disabled(_Session(False), ORG, "cameras") is True

