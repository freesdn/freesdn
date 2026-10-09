# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL regressions for missing versus measured health values."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.api.v1.endpoints.enterprise import (
    get_module_health,
    get_org_health,
    get_site_health,
    get_site_ranking,
    get_wan_health,
)
from app.core.dependencies import CurrentUser
from app.models.core import Organization, Site, User
from app.models.devices import Device
from app.models.enterprise import DeviceConfig, DeviceHealth, HealthStatus
from app.models.sla import SLAPolicy
from app.schemas.enterprise import DeviceHealthResponse
from app.services.enterprise import HealthService
from app.services.sla import SLAMonitoringService


async def fixture(db):
    org = Organization(name="Health truth fixture", slug="health-" + uuid4().hex)
    db.add(org)
    await db.flush()
    site = Site(organization_id=org.id, name="Health fixture", slug="health")
    db.add(site)
    await db.flush()
    user = CurrentUser(User(id=uuid4(), organization_id=org.id, role="org_admin"),
                       permissions=["device:read"])
    return org, site, user


async def device(db, site, *, score=None, status="unknown", kind="gateway"):
    dev = Device(site=site, name="Measured device", device_type=kind, status="unknown")
    db.add(dev)
    await db.flush()
    if score is not None:
        db.add(DeviceHealth(device_id=dev.id, site_id=site.id,
                            organization_id=site.organization_id, health_score=score,
                            health_status=status))
        await db.flush()
    return dev


@pytest.mark.parametrize("scope", ["site", "organization", "module", "ranking", "wan"])
@pytest.mark.parametrize("score,status,expected", [(0, "critical", 0), (100, "unknown", None)])
async def test_rollup_preserves_zero_and_excludes_unknown(db_session, scope, score, status, expected):
    _, site, user = await fixture(db_session)
    await device(db_session, site, score=score, status=status)
    if scope == "site":
        result = await get_site_health(site.id, db_session, user)
    elif scope == "organization":
        result = await get_org_health(None, db_session, user)
    elif scope == "module":
        result = next(r for r in await get_module_health(None, db_session, user)
                      if r.module == "Network")
    elif scope == "ranking":
        result = (await get_site_ranking(db_session, user))[0]
    else:
        result = (await get_wan_health(None, 100, db_session, user))[0]
    assert getattr(result, "health_score" if scope == "wan" else "avg_health_score") == expected
    if scope in {"site", "organization"}:
        assert result.health_status == status


async def test_empty_site_and_organization_are_unknown(db_session):
    _, site, user = await fixture(db_session)
    for result in [await get_site_health(site.id, db_session, user),
                   await get_org_health(None, db_session, user)]:
        assert result.avg_health_score is None
        assert result.health_status == "unknown"


async def test_unknown_devices_do_not_reweight_site_averages(db_session):
    org, site, user = await fixture(db_session)
    other = Site(organization_id=org.id, name="Other", slug="other")
    db_session.add(other)
    await db_session.flush()
    await device(db_session, site, score=0, status="critical")
    await device(db_session, other, score=100, status="healthy")
    for _ in range(3):
        await device(db_session, site, score=100, status="unknown")
    result = await get_org_health(None, db_session, user)
    assert result.device_count == 5
    assert result.avg_health_score == 50
    modules = await get_module_health(None, db_session, user)
    assert next(m for m in modules if m.module == "Network").avg_health_score == 50


async def test_site_aggregate_independently_enforces_organization(db_session):
    org, site, user = await fixture(db_session)
    foreign = Organization(name="Foreign", slug="foreign-" + uuid4().hex)
    db_session.add(foreign)
    await db_session.flush()
    dev = await device(db_session, site)
    db_session.add(DeviceHealth(device_id=dev.id, organization_id=foreign.id,
                                site_id=site.id, health_score=100, health_status="healthy"))
    await db_session.flush()
    result = await get_site_health(site.id, db_session, user)
    assert result.device_count == 0 and result.avg_health_score is None


@pytest.mark.parametrize("scope", ["site", "organization"])
async def test_sla_does_not_accept_unknown_health(db_session, scope):
    org, site, _ = await fixture(db_session)
    await device(db_session, site, score=100, status="unknown")
    policy = SLAPolicy(organization_id=org.id, scope=scope, scope_id=site.id, name="Missing")
    assert await SLAMonitoringService(db_session)._gather_health_data(policy) == {}


async def test_no_components_is_unknown_in_storage_api_and_history(db_session):
    _, site, _ = await fixture(db_session)
    dev = await device(db_session, site)
    health = await HealthService(db_session).compute_device_health(dev)
    await db_session.flush()
    assert health.health_status == HealthStatus.UNKNOWN
    assert health.score_history[-1]["s"] is None
    assert DeviceHealthResponse.model_validate(health).health_score is None


@pytest.mark.parametrize("known", [False, True])
async def test_periodic_job_does_not_fabricate_components(db_session, monkeypatch, known):
    from app.tasks.reconciliation import _recompute_device_health

    _, site, _ = await fixture(db_session)
    dev = await device(db_session, site, score=100, status="healthy")
    health = (await db_session.execute(select(DeviceHealth).where(
        DeviceHealth.device_id == dev.id))).scalar_one()
    health.firmware_score = health.error_score = health.drift_score = 100
    if known:
        dev.status = "offline"
        db_session.add(DeviceConfig(device_id=dev.id, organization_id=site.organization_id,
                                    has_drift=True,
                                    running_synced_at=datetime.now(UTC)))
    await db_session.flush()

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr("app.tasks.reconciliation.AsyncSessionLocal", session)
    result = await _recompute_device_health(str(dev.id))
    assert result["success"]
    assert health.firmware_score is None and health.error_score is None
    assert health.drift_score == (0 if known else None)
    assert result["health_score"] == (0 if known else None)
    assert result["health_status"] == ("critical" if known else "unknown")


@pytest.mark.parametrize("scorer,args", [("score_latency", (None,)), ("score_utilization", ())])
def test_missing_component_has_no_score(scorer, args):
    assert getattr(HealthService, scorer)(*args) is None


async def test_reachability_is_not_uptime_and_missing_history_is_not_stable(db_session):
    _, site, user = await fixture(db_session)
    dev = await device(db_session, site, score=100, status="healthy")
    health = (await db_session.execute(select(DeviceHealth).where(
        DeviceHealth.device_id == dev.id))).scalar_one()
    health.reachability_score = 100
    await db_session.flush()
    result = await get_org_health(None, db_session, user)
    assert result.sites[0].uptime_percent is None
    ranking = (await get_site_ranking(db_session, user))[0]
    assert ranking.uptime_percent is None
    assert ranking.trend == "unknown" and ranking.trend_delta is None
