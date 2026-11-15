# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""tenant_filter must scope a table by the column that actually owns it.

``tenant_filter`` classified models by column NAME: ``organization_id`` meant
"direct org", otherwise ``site_id`` meant "reach the org through the Site join".
``firewall.gateway_connections`` owns its rows with a foreign key named ``org_id``
and has a NULLABLE ``site_id``, so it was classified "site_id only":
``tenant_filter(GatewayConnection, org_user)`` became ``site_id IN (sites of the
org)``, and every gateway added without a site disappeared from its own
organization's queries. Nothing calls ``tenant_filter`` on that model yet, which
is exactly why it would bite: CLAUDE.md tells new code to adopt ``tenant_filter``,
and the first query migrated to it would have silently dropped rows.

The registry meta-test (``test_tenancy_registry``) cannot see this: it gates
"every model is classified", and GatewayConnection IS classified -- just wrongly.
These tests pin the classification itself to the schema's foreign keys.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from sqlalchemy.dialects import postgresql

from app.core.tenancy import TENANT_EXEMPT, tenant_filter

_ORGANIZATION_PK = "core.organizations.id"


def _org_user(org: Any, *, site_limited: bool = False, grants: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        is_superuser=False,
        organization_id=org,
        _scoped=False,
        is_site_limited=site_limited,
        accessible_site_ids=set(grants or []),
        role="org_admin",
    )


def _sql(predicate: Any) -> str:
    return str(predicate.compile(dialect=postgresql.dialect())).lower()


def _all_mapped_classes() -> dict[str, type]:
    """Every mapped model, force-imported so the result never depends on test order."""
    import app.main  # noqa: F401  (loads core + eager module models)
    import app.models
    import app.modules

    for _finder, name, _ispkg in pkgutil.iter_modules(app.models.__path__, "app.models."):
        importlib.import_module(name)
    for _finder, mod, _ispkg in pkgutil.iter_modules(app.modules.__path__, "app.modules."):
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


def _org_foreign_keys(cls: type) -> list[str]:
    table = cls.__table__  # type: ignore[attr-defined]
    return [
        c.name
        for c in table.columns
        if any(fk.target_fullname == _ORGANIZATION_PK for fk in c.foreign_keys)
    ]


class TestGatewayConnectionIsScopedByItsOwner:
    def test_org_user_predicate_is_the_org_id_column(self) -> None:
        from app.modules.firewall.models import GatewayConnection

        sql = _sql(tenant_filter(GatewayConnection, _org_user(uuid4())))

        assert "gateway_connections.org_id =" in sql, sql
        # A site-less gateway (site_id is nullable) must not be filtered out:
        # an org user who is not site-limited gets no site predicate at all.
        assert "site_id" not in sql, sql
        assert "core.sites" not in sql, sql

    def test_site_limited_user_still_gets_the_site_grant(self) -> None:
        from app.modules.firewall.models import GatewayConnection

        grant = uuid4()
        user = _org_user(uuid4(), site_limited=True, grants=[grant])
        sql = _sql(tenant_filter(GatewayConnection, user))

        assert "gateway_connections.org_id =" in sql, sql
        assert "gateway_connections.site_id in" in sql, sql


def test_every_single_org_foreign_key_is_what_tenant_filter_scopes_by() -> None:
    """A table owned through one organization foreign key is scoped by THAT column.

    Whatever the column is called. A table with several organization foreign keys
    must name its owner ``organization_id`` so the choice is not a guess.
    """
    wrong: list[str] = []
    ambiguous: list[str] = []
    for qual, cls in sorted(_all_mapped_classes().items()):
        owners = _org_foreign_keys(cls)
        if not owners or qual in TENANT_EXEMPT:
            continue
        columns = {c.name for c in cls.__table__.columns}  # type: ignore[attr-defined]
        if "organization_id" in columns:
            owner = "organization_id"
        elif len(owners) == 1:
            owner = owners[0]
        else:
            ambiguous.append(f"{qual}: {owners}")
            continue
        table = cls.__table__.name  # type: ignore[attr-defined]
        sql = _sql(tenant_filter(cls, _org_user(uuid4())))
        if f"{table}.{owner} =" not in sql:
            wrong.append(f"{qual}: scoped by {sql!r}, owner column is {owner!r}")

    assert not ambiguous, (
        "These tables carry more than one foreign key to core.organizations.id and "
        "none is named organization_id, so tenant_filter cannot tell which one owns "
        "the row. Name the owning column organization_id:\n  - " + "\n  - ".join(ambiguous)
    )
    assert not wrong, (
        "tenant_filter does not scope these tables by the column that owns them:\n  - "
        + "\n  - ".join(wrong)
    )


def test_no_exempt_model_is_owned_by_an_organization() -> None:
    """TENANT_EXEMPT means "no tenant column". An organization foreign key is one."""
    classes = _all_mapped_classes()
    owned = [
        f"{qual}: {_org_foreign_keys(classes[qual])}"
        for qual in sorted(TENANT_EXEMPT)
        if qual in classes and _org_foreign_keys(classes[qual])
    ]
    assert not owned, (
        "These TENANT_EXEMPT models carry a foreign key to core.organizations.id, so "
        "tenant_filter scopes them by it. Remove them from TENANT_EXEMPT:\n  - "
        + "\n  - ".join(owned)
    )
