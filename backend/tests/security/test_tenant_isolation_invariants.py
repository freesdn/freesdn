# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""DB / endpoint-level tenant-isolation invariants (core-verification Phase B).

These pin the #1 crown jewel — org A can never read/write/affect org B — plus the
over-the-wire regressions for the live-vuln fixes (TI-04 camera cross-org create,
TI-16 sibling-site flow read, WP-08 Proxmox catastrophic stage gate). A failure
here is a cross-tenant or privilege regression.

Uses the real ``db_session`` fixture (tests/conftest.py) and a real ``CurrentUser``
so can_access_site / has_min_role / has_permission behave exactly as in prod.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession


def _row_ids(items) -> set[str]:
    """Collect string ids from a list response whose items may be ORM objects,
    Pydantic models, or dicts."""
    out: set[str] = set()
    for it in items:
        rid = getattr(it, "id", None)
        if rid is None and isinstance(it, dict):
            rid = it.get("id")
        out.add(str(rid))
    return out


def _current_user(org_id, *, role="org_admin", grants=None, perms=("*",)):
    """A real CurrentUser bound to a (non-persisted) User row — gives faithful
    role/grant/permission semantics for the authz helpers under test."""
    from app.core.dependencies import CurrentUser
    from app.models.core import User

    user = User(
        id=uuid4(),
        email=f"{uuid4().hex[:10]}@example.com",
        organization_id=org_id,
        role=role,
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(
        user=user,
        permissions=list(perms),
        accessible_site_ids=set(grants or []),
    )


# ─────────────────────────────────────────────────────────────────────────────
# WP-08: stage-time catastrophic-role gate (no DB)
# ─────────────────────────────────────────────────────────────────────────────
class TestCatastrophicStageGate:
    @pytest.mark.asyncio
    async def test_low_role_blocked_on_catastrophic_feature(self):
        from app.api.v1.endpoints.staging_guards import enforce_catastrophic_stage_role

        operator = _current_user(uuid4(), role="operator")  # below site_admin
        with pytest.raises(HTTPException) as exc:
            await enforce_catastrophic_stage_role(operator, "proxmox.vm.destroy")
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_low_role_allowed_on_noncatastrophic_feature(self):
        from app.api.v1.endpoints.staging_guards import enforce_catastrophic_stage_role

        operator = _current_user(uuid4(), role="operator")
        # Non-catastrophic → no role gate (the endpoint's own perm check governs).
        await enforce_catastrophic_stage_role(operator, "proxmox.vm.start")

    @pytest.mark.asyncio
    async def test_site_admin_allowed_on_catastrophic_feature(self):
        from app.api.v1.endpoints.staging_guards import enforce_catastrophic_stage_role

        admin = _current_user(uuid4(), role="site_admin")
        await enforce_catastrophic_stage_role(admin, "proxmox.vm.destroy")

    @pytest.mark.asyncio
    async def test_noop_on_read_route_without_feature(self):
        from app.api.v1.endpoints.staging_guards import enforce_catastrophic_stage_role

        operator = _current_user(uuid4(), role="operator")
        await enforce_catastrophic_stage_role(operator, None)  # read route → no-op


# ─────────────────────────────────────────────────────────────────────────────
# TI-16: /flows/top-talkers — site-limited caller can't read a sibling site
# (the grant check fires before the DB query, so a mock session suffices)
# ─────────────────────────────────────────────────────────────────────────────
class TestTopTalkersSiteScoping:
    @pytest.mark.asyncio
    async def test_site_limited_user_blocked_on_non_granted_site(self):
        from app.modules.collector.api import top_talkers

        org_id = uuid4()
        granted = uuid4()
        sibling = uuid4()
        # Site-limited user: a grant for `granted`, role below admin.
        user = _current_user(
            org_id, role="operator", grants=[granted], perms=("collector.flows.read",)
        )
        assert user.is_site_limited is True
        # Called directly (not via FastAPI), so every Query-defaulted param must
        # be passed explicitly. The grant check fires before the DB query, so a
        # mock session is never touched.
        with pytest.raises(HTTPException) as exc:
            await top_talkers(
                user,
                MagicMock(spec=AsyncSession),
                hours=1,
                limit=10,
                sort_by="bytes",
                site_id=sibling,
            )
        # 404 (not 403): matches the canonical assert_can_access_site convention
        # used platform-wide — a site-limited caller can't even confirm the
        # sibling site exists (no existence oracle). The invariant (blocked from
        # a non-granted site) is preserved.
        assert exc.value.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Shared two-org DB fixture for the device/camera isolation tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def two_org_world(db_session: AsyncSession):
    """org A + org B, each with a site; an org-A device + camera to probe."""
    from app.models.core import Organization, Site
    from app.models.devices import Device

    org_a = Organization(name=f"A-{uuid4()}", slug=f"a-{uuid4().hex[:8]}")
    org_b = Organization(name=f"B-{uuid4()}", slug=f"b-{uuid4().hex[:8]}")
    db_session.add_all([org_a, org_b])
    await db_session.flush()

    site_a = Site(organization_id=org_a.id, name="sa", slug=f"sa-{uuid4().hex[:6]}")
    site_b = Site(organization_id=org_b.id, name="sb", slug=f"sb-{uuid4().hex[:6]}")
    db_session.add_all([site_a, site_b])
    await db_session.flush()

    dev_a = Device(site_id=site_a.id, name="dev-a", device_type="switch")
    db_session.add(dev_a)
    await db_session.flush()

    return SimpleNamespace(org_a=org_a, org_b=org_b, site_a=site_a, site_b=site_b, dev_a=dev_a)


# ─────────────────────────────────────────────────────────────────────────────
# TI-02: object-reference (IDOR) — org B cannot fetch org A's device
# ─────────────────────────────────────────────────────────────────────────────
class TestDeviceObjectIsolation:
    @pytest.mark.asyncio
    async def test_cross_org_get_device_denied(self, db_session, two_org_world):
        from app.api.v1.endpoints.devices import get_device

        w = two_org_world
        org_b_user = _current_user(w.org_b.id)
        with pytest.raises(HTTPException) as exc:
            await get_device(w.dev_a.id, org_b_user, db_session)
        # cross-org object reference must not resolve (403 or 404 — never the row)
        assert exc.value.status_code in (403, 404)

    @pytest.mark.asyncio
    async def test_same_org_get_device_allowed(self, db_session, two_org_world):
        from app.api.v1.endpoints.devices import get_device

        w = two_org_world
        org_a_user = _current_user(w.org_a.id)
        device = await get_device(w.dev_a.id, org_a_user, db_session)
        assert str(getattr(device, "id", "")) == str(w.dev_a.id)


# ─────────────────────────────────────────────────────────────────────────────
# TI-01: list is org-scoped — org B's list never contains org A's device
# ─────────────────────────────────────────────────────────────────────────────
class TestDeviceListIsolation:
    @pytest.mark.asyncio
    async def test_list_excludes_other_org_devices(self, db_session, two_org_world):
        from app.api.v1.endpoints.devices import list_devices

        w = two_org_world
        org_b_user = _current_user(w.org_b.id)
        # Pass every Query-defaulted param explicitly (direct call, not via FastAPI).
        result = await list_devices(
            current_user=org_b_user,
            session=db_session,
            site_id=None,
            controller_id=None,
            device_type=None,
            status=None,
            is_active=None,
            search=None,
            page=1,
            per_page=25,
        )
        items = getattr(result, "items", result)
        ids = {str(getattr(d, "id", "")) for d in items}
        assert str(w.dev_a.id) not in ids


# ─────────────────────────────────────────────────────────────────────────────
# TI-04: camera create rejects a cross-org site_id
# ─────────────────────────────────────────────────────────────────────────────
class TestCameraCreateCrossOrgFk:
    @pytest.mark.asyncio
    async def test_cross_org_site_id_rejected(self, db_session, two_org_world):
        from app.modules.cameras.api import create_camera
        from app.modules.cameras.schemas import CameraCreateRequest
        from app.modules.cameras.service import CameraService

        w = two_org_world
        org_a_user = _current_user(w.org_a.id)
        body = CameraCreateRequest(name="cam-x", site_id=w.site_b.id, ip_address="10.0.0.5")
        with pytest.raises(HTTPException) as exc:
            await create_camera(body, org_a_user, CameraService(db_session))
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_same_org_site_id_accepted(self, db_session, two_org_world):
        from app.modules.cameras.api import create_camera
        from app.modules.cameras.schemas import CameraCreateRequest
        from app.modules.cameras.service import CameraService

        w = two_org_world
        org_a_user = _current_user(w.org_a.id)
        body = CameraCreateRequest(name="cam-ok", site_id=w.site_a.id, ip_address="10.0.0.6")
        cam = await create_camera(body, org_a_user, CameraService(db_session))
        assert str(getattr(cam, "organization_id", "")) == str(w.org_a.id)


# ─────────────────────────────────────────────────────────────────────────────
# Phase-0 tenancy: crown-jewel runtime isolation through tenant_filter
# ─────────────────────────────────────────────────────────────────────────────
# These exercise app.core.tenancy.tenant_filter end-to-end against a real DB via
# the migrated list endpoints — the runtime backstop for the ~hundreds of scoping
# sites the merge-time registry gate cannot prove at runtime.


class TestSiteListIsolation:
    """direct-org model + the Site-PK grant: org B's site list never contains
    org A's site (tenant_filter(Site, user))."""

    @pytest.mark.asyncio
    async def test_list_excludes_other_org_sites(self, db_session, two_org_world):
        from app.api.v1.endpoints.sites import list_sites

        w = two_org_world
        org_b_user = _current_user(w.org_b.id)
        result = await list_sites(
            session=db_session,
            current_user=org_b_user,
            organization_id=None,
            search=None,
            is_active=None,
            page=1,
            per_page=50,
        )
        ids = _row_ids(getattr(result, "items", result))
        assert str(w.site_a.id) not in ids  # org A's site must NOT leak
        assert str(w.site_b.id) in ids  # org B sees its own site


@pytest_asyncio.fixture
async def org_two_sites(db_session: AsyncSession):
    """One org, TWO sites, a device on each — for the site-limited sibling test."""
    from app.models.core import Organization, Site
    from app.models.devices import Device

    org = Organization(name=f"OT-{uuid4()}", slug=f"ot-{uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()

    s1 = Site(organization_id=org.id, name="s1", slug=f"s1-{uuid4().hex[:6]}")
    s2 = Site(organization_id=org.id, name="s2", slug=f"s2-{uuid4().hex[:6]}")
    db_session.add_all([s1, s2])
    await db_session.flush()

    d1 = Device(site_id=s1.id, name="d1", device_type="switch")
    d2 = Device(site_id=s2.id, name="d2", device_type="switch")
    db_session.add_all([d1, d2])
    await db_session.flush()

    return SimpleNamespace(org=org, s1=s1, s2=s2, d1=d1, d2=d2)


class TestSiteLimitedSiblingIsolation:
    """The per-user site grant in tenant_filter: a site-limited operator granted
    ONLY site s1 must NOT see a device on sibling site s2 (same org)."""

    @pytest.mark.asyncio
    async def test_site_limited_user_excludes_sibling_site_device(self, db_session, org_two_sites):
        from app.api.v1.endpoints.devices import list_devices

        w = org_two_sites
        user = _current_user(w.org.id, role="operator", grants=[w.s1.id], perms=("device:read",))
        assert user.is_site_limited is True  # >=1 grant + sub-admin role
        result = await list_devices(
            current_user=user,
            session=db_session,
            site_id=None,
            controller_id=None,
            device_type=None,
            status=None,
            is_active=None,
            search=None,
            page=1,
            per_page=50,
        )
        ids = _row_ids(getattr(result, "items", result))
        assert str(w.d1.id) in ids  # granted site's device is visible
        assert str(w.d2.id) not in ids  # sibling site's device is hidden
