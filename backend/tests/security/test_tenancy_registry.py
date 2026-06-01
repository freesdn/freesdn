# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""CI anti-drift gate for application-layer tenant isolation.

The root cause of the repeated cross-tenant findings was that org/site scoping was
hand-rolled per endpoint, so a forgotten copy silently leaked. ``app.core.tenancy``
centralizes the rule; THIS test is the gate that keeps the registry honest:

* every mapped ORM model that carries an ``organization_id`` / ``site_id`` column is
  handled automatically by ``tenant_filter`` (column introspection);
* every mapped model that carries NEITHER column must be explicitly classified in
  ``TENANT_EXEMPT`` (global / user-scoped / scope-via-parent) — otherwise this test
  FAILS, so a new tenant-ambiguous table cannot merge without a human deciding how it
  is scoped. That converts "forgot to scope -> silent leak" into "forgot to classify
  -> red CI".
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.tenancy import (
    TENANT_EXEMPT,
    UnregisteredTenantModel,
    tenant_filter,
)


def _all_mapped_classes() -> dict[str, type]:
    """Every ORM model mapped on the main DB (Base) and the time-series DB (LogBase).

    DETERMINISTIC COMPLETENESS: some module models (firewall / voip / access_control
    / gateway children) register only when their module is imported, so relying on
    test-ordering would make this gate flaky (pass in isolation, fail in CI). We
    force-import every ``app.models.*`` and ``app.modules.*.models`` module so the
    registry is always the FULL set regardless of which tests ran first.
    """
    import importlib
    import pkgutil

    import app.main  # noqa: F401  (loads core + eager module models)
    import app.models
    import app.modules

    for _finder, name, _ispkg in pkgutil.iter_modules(app.models.__path__, "app.models."):
        importlib.import_module(name)
    for _finder, mod, _ispkg in pkgutil.iter_modules(app.modules.__path__, "app.modules."):
        # module model classes live in app.modules.<mod>.models (skip absent ones)
        try:
            importlib.import_module(f"{mod}.models")
        except ModuleNotFoundError:
            pass

    from app.db.base import Base, LogBase

    classes: dict[str, type] = {}
    for base in (Base, LogBase):
        for mapper in base.registry.mappers:
            cls = mapper.class_
            classes[f"{cls.__module__}:{cls.__name__}"] = cls
    return classes


def _cols(cls: type) -> set[str]:
    return {c.name for c in cls.__table__.columns}


def _is_tenant_columned(cls: type) -> bool:
    cols = _cols(cls)
    return "organization_id" in cols or "site_id" in cols


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
def test_every_model_with_no_tenant_column_is_classified():
    """A mapped model with no organization_id/site_id column MUST be in
    TENANT_EXEMPT — else a new tenant-ambiguous table slipped through unclassified."""
    unclassified = []
    for qual, cls in _all_mapped_classes().items():
        if _is_tenant_columned(cls):
            continue
        if qual not in TENANT_EXEMPT:
            unclassified.append(f"{qual} ({cls.__table__.schema}.{cls.__tablename__})")
    assert not unclassified, (
        "These mapped models declare no organization_id/site_id column and are not "
        "classified in app.core.tenancy.TENANT_EXEMPT. Decide how each is scoped "
        "(global / user-scoped / scope-via-parent) and add it (or add the missing "
        "tenant column):\n  - " + "\n  - ".join(sorted(unclassified))
    )


def test_no_stale_or_wrong_exempt_entries():
    """Every TENANT_EXEMPT entry resolves to a real mapped model that genuinely has
    no org/site column (a model that GAINED a tenant column must be removed so it is
    actually filtered)."""
    classes = _all_mapped_classes()
    for qual in TENANT_EXEMPT:
        assert qual in classes, (
            f"TENANT_EXEMPT lists {qual!r} which is not a currently-mapped model "
            f"(stale entry — remove it)."
        )
        assert not _is_tenant_columned(classes[qual]), (
            f"TENANT_EXEMPT lists {qual!r} but it now has an organization_id/site_id "
            f"column — remove it from TENANT_EXEMPT so tenant_filter actually scopes it."
        )


# ---------------------------------------------------------------------------
# tenant_filter behavior (principal matrix)
# ---------------------------------------------------------------------------
def _principal(
    *, superuser: bool, org, scoped: bool = False, site_limited: bool = False, grants=None
):
    return SimpleNamespace(
        is_superuser=superuser,
        organization_id=org,
        _scoped=scoped,
        is_site_limited=site_limited,
        accessible_site_ids=set(grants or []),
        role="super_admin" if superuser else "org_admin",
    )


class TestTenantFilterMatrix:
    def test_direct_org_for_org_user_is_org_equality(self):
        from app.models.sla import SLAPolicy

        org = uuid4()
        pred = str(tenant_filter(SLAPolicy, _principal(superuser=False, org=org)))
        assert "organization_id" in pred and "=" in pred

    def test_unscoped_super_is_unfiltered(self):
        from app.models.sla import SLAPolicy

        assert str(tenant_filter(SLAPolicy, _principal(superuser=True, org=None))) == "true"

    def test_scoped_super_no_org_fails_closed(self):
        from app.models.sla import SLAPolicy

        # scoped super_admin key (super role, _scoped, no org) -> see nothing.
        assert (
            str(tenant_filter(SLAPolicy, _principal(superuser=True, org=None, scoped=True)))
            == "false"
        )

    def test_via_site_reaches_org_through_site_subquery(self):
        from app.models.devices import Device

        pred = str(tenant_filter(Device, _principal(superuser=False, org=uuid4()))).lower()
        assert "site_id in" in pred and "sites" in pred

    def test_site_model_grant_is_on_primary_key(self):
        # Site has organization_id but NO site_id column; a site-limited user
        # listing Sites must still be confined to granted sites via Site.id.
        from app.models.core import Site

        grant = uuid4()
        user = _principal(superuser=False, org=uuid4(), site_limited=True, grants=[grant])
        pred = str(tenant_filter(Site, user)).lower()
        assert "organization_id" in pred and "sites.id in" in pred

    def test_exempt_model_is_unfiltered(self):
        from app.models.security_audit import FailedLoginRecord

        assert (
            str(tenant_filter(FailedLoginRecord, _principal(superuser=False, org=uuid4())))
            == "true"
        )

    def test_matches_hand_written_manual_filter(self):
        """DIFFERENTIAL / behavior-preserving proof: for the dominant case (an org
        user on a direct-org model) tenant_filter produces EXACTLY the predicate the
        ~120 hand-rolled ``where(Model.organization_id == current_user.organization_id)``
        sites produce — so the DRY refactor changes no behavior for legit principals."""
        from app.models.sla import SLAPolicy

        org = uuid4()
        auto = tenant_filter(SLAPolicy, _principal(superuser=False, org=org))
        manual = SLAPolicy.organization_id == org
        ck = {"literal_binds": True}
        assert str(auto.compile(compile_kwargs=ck)) == str(manual.compile(compile_kwargs=ck))

    def test_unregistered_no_column_model_raises(self):
        # a duck-typed model with no org/site column that is NOT in TENANT_EXEMPT
        # must raise — this is the runtime half of the merge-time gate.
        class _Table:
            columns: list = []

        class _Unregistered:
            __module__ = "tests.fake"
            __name__ = "_Unregistered"
            __table__ = _Table()

        with pytest.raises(UnregisteredTenantModel):
            tenant_filter(_Unregistered, _principal(superuser=False, org=uuid4()))
