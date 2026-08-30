# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The event-driven half of the per-user site-grant gap, left open by the
earlier fix.

``POST /fabric/invoke`` threads ``accessible_site_ids``, and the AI tool
bridge was fixed to match. Two paths
were left: the Fabric negotiator (a Connection firing on an event) and the
automation engine (a rule running on a schedule). Both build the same
``OperationContext`` and both left the field ``None`` -- which the field's own
docstring documents as "unrestricted".

Neither has a live principal to take the grant from. What they DO have is the
``actor_id`` recorded when the Connection or rule was authored, so the grant is
resolved from that. Both paths already re-check the author's PERMISSION at run
time; what was missing was the narrowing, so a site-limited author's automation
could act on any site in the org while the same operation through the API could
not.

The resolver returns ``None`` -- unrestricted -- rather than an empty set for a
super_admin / org_admin and for an actor with no grants at all. That is not
laxness: it mirrors ``CurrentUser.is_site_limited`` exactly, and the hybrid
model in says zero grants means unrestricted, not denied.
Returning an empty set for those would be fail-CLOSED and would silently break
every existing automation rule -- a different outage, not a fix.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.site_access import current_user_var, resolve_actor_site_grants

SITE_A, SITE_B = uuid4(), uuid4()


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


class _Session:
    """Returns one user row for the actor lookup."""

    def __init__(self, user) -> None:
        self._user = user
        self.raises = False

    async def execute(self, _query):
        if self.raises:
            raise RuntimeError("database is unhappy")
        user = self._user
        return SimpleNamespace(scalar_one_or_none=lambda: user)


def _user(role: str = "operator", sites: list | None = None):
    return SimpleNamespace(
        id=uuid4(),
        role=role,
        deleted_at=None,
        site_access=[SimpleNamespace(site_id=s) for s in (sites or [])],
    )


# ── the resolver ─────────────────────────────────────────────────


async def test_a_site_limited_author_is_narrowed_to_their_grants() -> None:
    """
    The regression. This is the value that was always None, so an automation
    authored by a site-limited operator ran unrestricted.
    """
    session = _Session(_user("operator", [SITE_A]))
    assert await resolve_actor_site_grants(session, uuid4()) == {SITE_A}


async def test_multiple_grants_all_come_through() -> None:
    session = _Session(_user("operator", [SITE_A, SITE_B]))
    assert await resolve_actor_site_grants(session, uuid4()) == {SITE_A, SITE_B}


@pytest.mark.parametrize("role", ["super_admin", "admin", "org_admin"])
async def test_an_admin_stays_unrestricted(role: str) -> None:
    """
    Mirrors ``CurrentUser.is_site_limited``, which returns False for these
    roles regardless of any grant rows they happen to have.
    """
    session = _Session(_user(role, [SITE_A]))
    assert await resolve_actor_site_grants(session, uuid4()) is None


async def test_an_actor_with_no_grants_is_unrestricted_not_denied() -> None:
    """
    FSDN-SEC-006's hybrid model: zero grants means unrestricted, for backwards
    compatibility. Returning an empty set here would be fail-CLOSED and would
    silently break every automation rule authored before site grants existed --
    an outage wearing a security fix's clothes.
    """
    session = _Session(_user("operator", []))
    assert await resolve_actor_site_grants(session, uuid4()) is None


async def test_a_missing_actor_does_not_disable_the_automation() -> None:
    """
    A deleted or unresolvable author. These paths re-check the author's
    PERMISSION separately; the grant is a narrowing, not the authorisation, so
    failing closed on a lookup miss would stop automations for the wrong
    reason.
    """
    assert await resolve_actor_site_grants(_Session(None), uuid4()) is None


async def test_no_actor_id_is_unrestricted() -> None:
    assert await resolve_actor_site_grants(_Session(_user()), None) is None


async def test_a_database_error_does_not_raise_into_the_caller() -> None:
    session = _Session(_user("operator", [SITE_A]))
    session.raises = True
    assert await resolve_actor_site_grants(session, uuid4()) is None


async def test_the_resolver_excludes_deleted_users() -> None:
    """A soft-deleted author must not resolve; the query has to say so."""
    assert "deleted_at.is_(None)" in _code(resolve_actor_site_grants)


def test_it_agrees_with_current_user_on_who_is_site_limited() -> None:
    """
    Two implementations of "is this principal site-limited" is how they drift.
    Pin the role set against the real property's source.
    """
    from app.core.dependencies import CurrentUser

    # is_site_limited is a property; getsource needs the underlying function.
    request_side = _code(CurrentUser.is_site_limited.fget)
    assert "is_superuser" in request_side and "is_org_admin" in request_side

    resolver = _code(resolve_actor_site_grants)
    for role in ("super_admin", "admin", "org_admin"):
        assert role in resolver, f"{role} is not treated as unrestricted"


# ── both call sites ──────────────────────────────────────────────


def test_the_negotiator_threads_the_authors_grant() -> None:
    # Imported by module path: ``app.core.fabric.negotiator`` is also the name
    # of a re-exported singleton, and the bare attribute resolves to that.
    import importlib

    code = _code(importlib.import_module("app.core.fabric.negotiator"))
    assert "resolve_actor_site_grants(db, conn.actor_id)" in code, (
        "a Connection still runs unrestricted regardless of its author's grants"
    )


def test_the_automation_engine_threads_the_authors_grant() -> None:
    from app.services import automation

    code = _code(automation)
    assert "resolve_actor_site_grants(db, rule_actor)" in code, (
        "an automation rule still runs unrestricted regardless of its author's grants"
    )


def test_the_automation_engine_still_rechecks_the_permission() -> None:
    """
    The grant narrows; it does not authorise. If the permission re-check ever
    goes away, resolving grants leniently on a lookup failure stops being safe.
    """
    from app.services import automation

    assert "no longer holds the required permission" in inspect.getsource(automation)


def test_every_operation_context_construction_now_passes_the_field() -> None:
    """
    Guard the class, not the two instances. A new OperationContext built
    without a grant is this bug again, and the field defaults to None --
    unrestricted -- so the omission is silent.
    """
    import ast
    import pathlib

    root = pathlib.Path(inspect.getfile(resolve_actor_site_grants)).parents[1]
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "OperationContext":
                continue
            if not any(kw.arg == "accessible_site_ids" for kw in node.keywords):
                offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, (
        f"OperationContext built without accessible_site_ids at {offenders} -- "
        "None means unrestricted, so this silently widens the operation"
    )


def test_the_field_still_means_unrestricted_when_none() -> None:
    """Premise. If None ever became fail-closed, all of the above inverts."""
    from app.core.fabric.execution import OperationContext

    assert "None = unrestricted" in inspect.getsource(OperationContext)


# ─────────────────────────────────────────────────────────────────
# F-02 — the executor's write plane never compared the target
# controller's site against anything
# ─────────────────────────────────────────────────────────────────
#
# The tests above prove ``accessible_site_ids`` is now POPULATED on every
# OperationContext. They do not prove anybody READS it, and the detector they
# end with cannot: it walks the AST for ``OperationContext(...)`` calls and
# checks the keyword is present at the construction site. Delete every
# downstream consumer and it stays green.
#
# It was green. ``app/core/fabric/executor.py`` -- the single chokepoint every
# native Fabric device write funnels through -- read the field zero times. It
# proved the controller was in the org and the site was in the org
# INDEPENDENTLY, and never that they had anything to do with each other. So a
# site_admin granted only Site A could invoke a write with
# ``controller_id`` = a controller living in Site B and ``site_id`` = their own
# Site A: the staging chokepoint's contextvar guard saw Site A and passed, the
# row landed as (controller B, site A), and at apply time the site-grant assert
# read the stored Site A while the applier drove controller B. The
# controller-site fallback that would have caught it is skipped precisely
# BECAUSE ``change.site_id`` is non-NULL.
#
# The tests below are behavioural at that chokepoint, which is where the reach
# comes from: they run the real executor, and one of them runs EVERY native
# write operation the shipped modules advertise through it.
#
# One thing the fix deliberately does NOT do: force the staged ``site_id`` to
# the controller's own ``site_id``. One physical controller legitimately fronts
# several FreeSDN sites through ``Controller.site_mappings``, and the Omada bulk
# applier resolves the Omada-side site from the staged ``site_id`` through it
# (``services/adapter_omada_bulk.py:73``).

import uuid as _uuid

from app.core.fabric.execution import OperationContext
from app.core.fabric.executor import OperationExecutor, _controller_in_org
from app.core.fabric.operations import Operation, OperationTier
from app.models.core import Controller, Site

ORG = _uuid.uuid4()
OTHER_ORG = _uuid.uuid4()


class _Result:
    def __init__(self, obj):
        self._obj = obj

    def scalar_one_or_none(self):
        return self._obj


class _FleetSession:
    """A real two-site fleet the executor's own queries are answered from.

    Not a stub that says yes: it holds ``Controller`` / ``Site`` rows and
    answers by matching the statement's bind parameters against them, so a
    query about a controller/site pair the fleet does not contain gets
    ``None`` -- the same answer Postgres would give.
    """

    def __init__(self, sites, controllers):
        self.sites = {s.id: s for s in sites}
        self.controllers = {c.id: c for c in controllers}

    async def execute(self, stmt):
        bound = set(stmt.compile().params.values())
        entity = stmt.column_descriptions[0]["entity"]
        if entity is Controller:
            for ctrl in self.controllers.values():
                site = self.sites.get(ctrl.site_id)
                if site is None:
                    continue
                if ctrl.id in bound and site.organization_id in bound:
                    return _Result(ctrl)
            return _Result(None)
        if entity is Site:
            for site in self.sites.values():
                if site.id in bound and site.organization_id in bound:
                    return _Result(site)
            return _Result(None)
        raise AssertionError(f"unexpected query against {entity!r}")


class _Fleet:
    """Site A, Site B, one controller in each, all inside ORG."""

    def __init__(self, *, b_maps_a: bool = False):
        self.site_a = Site(id=_uuid.uuid4(), organization_id=ORG, name="A")
        self.site_b = Site(id=_uuid.uuid4(), organization_id=ORG, name="B")
        self.ctrl_a = Controller(id=_uuid.uuid4(), site_id=self.site_a.id, name="ctrl-a", config={})
        # site_mappings is {omada_site_id: freesdn_site_uuid}; with b_maps_a set,
        # ctrl_b legitimately fronts Site A as well as its own Site B.
        self.ctrl_b = Controller(
            id=_uuid.uuid4(),
            site_id=self.site_b.id,
            name="ctrl-b",
            config={"site_mappings": {"omada-a": str(self.site_a.id)}} if b_maps_a else {},
        )
        self.session = _FleetSession([self.site_a, self.site_b], [self.ctrl_a, self.ctrl_b])


def _write_op() -> Operation:
    """A native write op shaped like the real ``firewall.block_ip``."""
    return Operation(
        id="firewall.block_ip",
        title="block",
        write=True,
        feature="opnsense.firewall.rule",
        permission="firewall.manage_rules",
        handler=None,
        tier=OperationTier.NATIVE,
        provider_id="firewall",
    )


def _staging_recorder(monkeypatch) -> dict:
    staged: dict = {}

    async def _stage(self, **kw):
        staged.update(kw)
        return SimpleNamespace(id=uuid4())

    monkeypatch.setattr("app.services.adapter_staging.AdapterStagingService.stage_change", _stage)
    return staged


async def _invoke(fleet, params, grants):
    return await OperationExecutor().execute(
        _write_op(),
        OperationContext(
            organization_id=ORG,
            params=params,
            db=fleet.session,
            actor_id=uuid4(),
            accessible_site_ids=grants,
        ),
    )


async def test_a_sibling_site_controller_with_the_callers_own_site_id_is_refused(
    monkeypatch,
) -> None:
    """
    The finding, end to end. Granted Site A only; target a controller that
    lives in Site B; declare site_id = Site A.

    Before the fix this returned success and wrote (controller B, site A) --
    a row whose stored site is a site the write will never touch.
    """
    fleet = _Fleet()
    staged = _staging_recorder(monkeypatch)

    res = await _invoke(
        fleet,
        {
            "controller_id": str(fleet.ctrl_b.id),
            "site_id": str(fleet.site_a.id),
            "source_net": "0.0.0.0/0",
        },
        {fleet.site_a.id},
    )

    assert res.success is False, "a Site B controller was accepted on a Site A grant"
    assert res.error_code == "CROSS_SITE_TARGET"
    assert staged == {}, "the refused write still reached the staging table"


async def test_a_site_limited_caller_cannot_target_a_controller_outside_their_grants(
    monkeypatch,
) -> None:
    """
    The same escalation with the site_id omitted. Every non-Fabric stage path
    already refuses this -- they go through ``GatewayServiceBase.stage_change``
    -> ``_resolve_controller_or_gateway``, which asserts the grant on the
    controller's own site. The Fabric calls ``AdapterStagingService.stage_change``
    directly and so skipped it.
    """
    fleet = _Fleet()
    staged = _staging_recorder(monkeypatch)

    res = await _invoke(
        fleet,
        {"controller_id": str(fleet.ctrl_b.id), "source_net": "0.0.0.0/0"},
        {fleet.site_a.id},
    )

    assert res.success is False
    assert res.error_code == "SITE_NOT_GRANTED"
    assert staged == {}


async def test_the_legitimate_single_site_write_still_stages(monkeypatch) -> None:
    """
    The case that must NOT break: granted Site A, controller in Site A,
    site_id = Site A. A guard that refuses whenever a grant is present would
    take every site-limited operator's automation offline.
    """
    fleet = _Fleet()
    staged = _staging_recorder(monkeypatch)

    res = await _invoke(
        fleet,
        {
            "controller_id": str(fleet.ctrl_a.id),
            "site_id": str(fleet.site_a.id),
            "source_net": "203.0.113.7/32",
        },
        {fleet.site_a.id},
    )

    assert res.success is True, res.error
    assert staged["controller_id"] == fleet.ctrl_a.id
    assert staged["site_id"] == fleet.site_a.id
    assert staged["payload"] == {"source_net": "203.0.113.7/32"}


async def test_a_controller_that_fronts_several_sites_still_stages_for_a_mapped_site(
    monkeypatch,
) -> None:
    """
    The trap in the obvious fix. "Reject a supplied site_id that differs from
    the controller's site_id" reads correct and would break every multi-site
    Omada write: ``Controller.site_mappings`` exists precisely so one physical
    controller fronts several FreeSDN sites, and the bulk applier resolves the
    Omada-side site from the staged ``site_id`` through it.

    So the invariant is "served by", not "equal to" -- and the staged site_id
    stays the caller's, not the controller's.
    """
    fleet = _Fleet(b_maps_a=True)
    staged = _staging_recorder(monkeypatch)

    res = await _invoke(
        fleet,
        {"controller_id": str(fleet.ctrl_b.id), "site_id": str(fleet.site_a.id)},
        None,  # unrestricted author -- isolates the served-by rule from the grant rule
    )

    assert res.success is True, res.error
    assert staged["controller_id"] == fleet.ctrl_b.id
    assert staged["site_id"] == fleet.site_a.id, (
        "the staged site was rewritten to the controller's own site -- the Omada "
        "bulk applier resolves the Omada-side site from this value"
    )


async def test_a_caller_granted_both_sites_may_use_the_multi_site_controller(
    monkeypatch,
) -> None:
    """Same fleet, site-limited caller holding both sites: still allowed."""
    fleet = _Fleet(b_maps_a=True)
    staged = _staging_recorder(monkeypatch)

    res = await _invoke(
        fleet,
        {"controller_id": str(fleet.ctrl_b.id), "site_id": str(fleet.site_a.id)},
        {fleet.site_a.id, fleet.site_b.id},
    )

    assert res.success is True, res.error
    assert staged["site_id"] == fleet.site_a.id


async def test_an_unrestricted_author_is_not_narrowed(monkeypatch) -> None:
    """
    ``accessible_site_ids is None`` means unrestricted (super_admin / org_admin
    / grant-less author). Nothing about this fix may fail those closed -- that
    would be an outage wearing a security fix's clothes, the same mistake
    ``resolve_actor_site_grants`` was written to avoid.
    """
    fleet = _Fleet()
    staged = _staging_recorder(monkeypatch)

    res = await _invoke(
        fleet, {"controller_id": str(fleet.ctrl_b.id), "source_net": "10.0.0.0/8"}, None
    )

    assert res.success is True, res.error
    assert staged["controller_id"] == fleet.ctrl_b.id
    assert staged["site_id"] is None


async def test_a_cross_org_controller_is_still_refused(monkeypatch) -> None:
    """
    Regression on the org gate itself. The fix changed ``_controller_in_org``
    from returning a bool to returning the row; a caller testing ``is not None``
    instead of truthiness would silently invert the meaning of the ``False``
    the existing executor tests stub it with.
    """
    fleet = _Fleet()
    staged = _staging_recorder(monkeypatch)

    res = await OperationExecutor().execute(
        _write_op(),
        OperationContext(
            organization_id=OTHER_ORG,  # the fleet belongs to ORG
            params={"controller_id": str(fleet.ctrl_a.id)},
            db=fleet.session,
            actor_id=uuid4(),
            accessible_site_ids=None,
        ),
    )

    assert res.success is False
    assert res.error_code == "CROSS_TENANT_TARGET"
    assert staged == {}


async def test_the_org_gate_returns_the_controller_row_not_a_bare_id() -> None:
    """
    Pin the contract the site checks stand on. If this ever goes back to
    ``select(Controller.id)`` the executor gets a UUID with no ``.site_id``,
    every site-limited write fails closed with SITE_UNRESOLVED, and the outage
    looks like a permissions bug.
    """
    fleet = _Fleet()

    row = await _controller_in_org(fleet.session, fleet.ctrl_b.id, ORG)
    assert getattr(row, "site_id", None) == fleet.site_b.id

    assert await _controller_in_org(fleet.session, fleet.ctrl_b.id, OTHER_ORG) is None


async def test_every_advertised_native_write_op_is_gated_the_same_way(monkeypatch) -> None:
    """
    Reach. The construction detector above pins four call sites; this pins the
    whole write catalogue. Every native write operation the shipped modules
    advertise runs through ``_execute_native_write``, so drive each of them at a
    controller outside the caller's grants and require a refusal. A new write op
    cannot opt out: it does not get to choose its executor path.

    ``overlay.*`` is excluded by design -- appliance-local daemon writes with no
    controller at all; a site-limited operator is blocked from APPLYING one in
    ``adapter_omada_vpn.apply_change``.
    """
    import importlib
    import pathlib

    from app.modules.base import BaseModule

    fleet = _Fleet()
    staged = _staging_recorder(monkeypatch)

    root = pathlib.Path(inspect.getfile(BaseModule)).parent
    assert root.name == "modules", root

    write_ops: list[Operation] = []
    seen: set[str] = set()
    for pkg in sorted(p.name for p in root.iterdir() if (p / "module.py").is_file()):
        mod = importlib.import_module(f"app.modules.{pkg}.module")
        for attr in vars(mod).values():
            if not (
                isinstance(attr, type) and issubclass(attr, BaseModule) and attr is not BaseModule
            ):
                continue
            for op in attr().get_operations() or []:
                if (
                    op.write
                    and op.tier is OperationTier.NATIVE
                    and not (op.feature or "").startswith("overlay.")
                    and op.id not in seen
                ):
                    seen.add(op.id)
                    write_ops.append(op)
    assert len(write_ops) >= 3, f"the write catalogue looks empty: {sorted(seen)}"

    leaked = []
    for op in write_ops:
        res = await OperationExecutor().execute(
            op,
            OperationContext(
                organization_id=ORG,
                params={"controller_id": str(fleet.ctrl_b.id)},
                db=fleet.session,
                actor_id=uuid4(),
                accessible_site_ids={fleet.site_a.id},  # granted A; ctrl_b lives in B
            ),
        )
        if res.success or res.error_code != "SITE_NOT_GRANTED":
            leaked.append(f"{op.id} -> {res.error_code}")
    assert not leaked, f"native write ops not gated on the caller's site grant: {leaked}"
    assert staged == {}, "a refused write still reached the staging table"


# ─────────────────────────────────────────────────────────────────
# F-02, apply side — a stored (controller, site) mismatch must not
# be applicable, however it got there
# ─────────────────────────────────────────────────────────────────


def _apply_user(org_id, *, role="site_admin", grants=(), permissions=("network:write",)):
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    return CurrentUser(
        user=User(
            id=uuid4(),
            email=f"{uuid4().hex[:8]}@example.com",
            organization_id=org_id,
            role=role,
            hashed_password="x",
            is_active=True,
        ),
        permissions=list(permissions),
        accessible_site_ids=set(grants),
    )


class _ReachedTheApplier(Exception):
    """Raised by the stubbed apply so we can tell "allowed" from "blocked"."""


def _pending(*, controller_id, site_id, feature="bulk.device.block"):
    return SimpleNamespace(
        id=uuid4(),
        organization_id=ORG,
        controller_id=controller_id,
        site_id=site_id,
        feature=feature,
        operation="create",
        status="pending",
        payload={"macs": ["aa:bb:cc:dd:ee:ff"]},
        target_id=None,
        omada_site_id=None,
    )


async def _apply(fleet, change, user, monkeypatch):
    from app.api.v1.endpoints import adapter_omada_vpn as ep
    from app.schemas.gateway_vpn import ApplyPendingChangeRequest

    async def _get(self, change_id):
        return change

    async def _apply_change(self, change_id, **kw):
        raise _ReachedTheApplier(str(change_id))

    monkeypatch.setattr("app.services.adapter_staging.AdapterStagingService.get", _get)
    monkeypatch.setattr(
        "app.services.adapter_staging.AdapterStagingService.apply_change", _apply_change
    )
    # The request-scoped principal, exactly as the auth dependency sets it in
    # production. Several guards on this path (``_resolve_controller_or_gateway``,
    # the staging chokepoint) read the contextvar rather than the ``user``
    # argument, and no-op when it is unset -- so a test that leaves it unset
    # would fabricate a precondition that is false in production and silently
    # stop exercising them.
    token = current_user_var.set(user)
    try:
        return await ep.apply_change(
            change.id,
            ApplyPendingChangeRequest(force=True, confirmed=True),
            user,
            fleet.session,
        )
    finally:
        current_user_var.reset(token)


async def test_apply_refuses_a_row_whose_controller_does_not_serve_its_site(
    monkeypatch,
) -> None:
    """
    The already-written row. ``assert_can_access_site`` reads Site A and passes,
    and because site_id is non-NULL the controller-grant fallback is skipped --
    so before the fix this reached the applier and drove the Site B controller.
    """
    from fastapi import HTTPException

    fleet = _Fleet()
    change = _pending(controller_id=fleet.ctrl_b.id, site_id=fleet.site_a.id)
    user = _apply_user(ORG, grants=[fleet.site_a.id])

    with pytest.raises(HTTPException) as exc:
        await _apply(fleet, change, user, monkeypatch)
    assert exc.value.status_code == 404, "a (controller B, site A) row was applicable"


async def test_apply_still_allows_a_row_for_a_site_the_controller_fronts(
    monkeypatch,
) -> None:
    """
    The multi-site Omada row the guard must not break: ctrl_b fronts Site A
    through site_mappings and the operator holds Site A, so the apply proceeds.

    Reaching the applier is the assertion -- ``_ReachedTheApplier`` is raised
    only past every authorisation gate on the endpoint.
    """
    fleet = _Fleet(b_maps_a=True)
    change = _pending(controller_id=fleet.ctrl_b.id, site_id=fleet.site_a.id)
    user = _apply_user(ORG, grants=[fleet.site_a.id])

    with pytest.raises(_ReachedTheApplier):
        await _apply(fleet, change, user, monkeypatch)


async def test_apply_still_allows_the_ordinary_same_site_row(monkeypatch) -> None:
    """The overwhelmingly common shape: controller and site are the same site."""
    fleet = _Fleet()
    change = _pending(controller_id=fleet.ctrl_a.id, site_id=fleet.site_a.id)
    user = _apply_user(ORG, grants=[fleet.site_a.id])

    with pytest.raises(_ReachedTheApplier):
        await _apply(fleet, change, user, monkeypatch)


async def test_apply_still_falls_back_to_the_controller_for_a_siteless_row(
    monkeypatch,
) -> None:
    """
    The pre-existing branch must survive: site_id NULL still resolves the
    controller so a site-limited operator cannot apply a sibling controller's
    queued change. The new guard is an ``elif`` -- if it ever became an ``if``
    that ran first, this branch would stop firing.
    """
    from fastapi import HTTPException

    fleet = _Fleet()
    change = _pending(controller_id=fleet.ctrl_b.id, site_id=None)
    user = _apply_user(ORG, grants=[fleet.site_a.id])

    with pytest.raises(HTTPException) as exc:
        await _apply(fleet, change, user, monkeypatch)
    assert exc.value.status_code == 404
