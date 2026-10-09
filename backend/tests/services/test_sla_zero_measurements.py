# SPDX-License-Identifier: AGPL-3.0-only
"""Zero is a measured outage/failed target, never a synonym for missing data."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.enterprise import DeviceHealth, HealthStatus
from app.models.sla import SLABreach, SLAPolicy, SLASnapshot
from app.services.sla import SLAMonitoringService


@pytest.mark.parametrize("scope", ["site", "organization"])
async def test_zero_aggregate_is_not_discarded(scope):
    result = MagicMock()
    result.one_or_none.return_value = (0, 1, 0, 1) if scope == "site" else (0, 1)
    session = SimpleNamespace(execute=AsyncMock(return_value=result))
    policy = SLAPolicy(organization_id=uuid4(), scope=scope, scope_id=uuid4(), name="Zero")
    data = await SLAMonitoringService(session)._gather_health_data(policy)
    assert data["avg_health_score"] == 0
    assert data["total_devices"] == 1


@pytest.mark.parametrize("scope", ["site", "organization"])
async def test_null_aggregate_is_still_missing(scope):
    result = MagicMock()
    result.one_or_none.return_value = (None, 0, 0, 0) if scope == "site" else (None, 0)
    session = SimpleNamespace(execute=AsyncMock(return_value=result))
    policy = SLAPolicy(organization_id=uuid4(), scope=scope, scope_id=uuid4(), name="Missing")
    assert await SLAMonitoringService(session)._gather_health_data(policy) == {}


@pytest.mark.parametrize("scope", ["site", "organization"])
async def test_zero_health_creates_breach_snapshot_and_zero_dashboard(
    db_session, monkeypatch, scope,
):
    org = Organization(name="Zero health fixture", slug="zero-health-" + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(organization_id=org.id, name="Owned site", slug="zero")
    db_session.add(site)
    await db_session.flush()
    device = Device(site_id=site.id, name="Unhealthy device", device_type="switch")
    db_session.add(device)
    await db_session.flush()
    health = DeviceHealth(device_id=device.id, organization_id=org.id, site_id=site.id,
                          health_score=0, health_status=HealthStatus.CRITICAL)
    policy = SLAPolicy(organization_id=org.id, name="Availability health score", scope=scope,
                      scope_id=site.id if scope == "site" else None,
                      thresholds={"health_score_min": 80}, current_compliance_percent=100,
                      breach_after_consecutive=1)
    db_session.add_all([health, policy])
    await db_session.flush()
    # Only external event publication is replaced; evaluation and persistence
    # use the real PostgreSQL rows and actual reporting summary queries.
    publisher = SimpleNamespace(publish=AsyncMock())
    monkeypatch.setattr("app.services.sla.get_event_bus", lambda: publisher)
    service = SLAMonitoringService(db_session)
    outcome = await service._evaluate_policy(policy, datetime.now(UTC))
    await db_session.flush()
    assert outcome["breaches_created"] == 1
    assert policy.current_compliance_percent == 0
    breach = (await db_session.execute(select(SLABreach).where(
        SLABreach.policy_id == policy.id,
    ))).scalar_one()
    assert breach.actual_value == 0 and breach.status == "active"
    snapshot = (await db_session.execute(select(SLASnapshot).where(
        SLASnapshot.policy_id == policy.id,
    ))).scalar_one()
    assert snapshot.compliance_percent == 0 and snapshot.in_breach
    summary = await service.get_compliance_summary(org.id)
    assert summary["avg_compliance_percent"] == 0
    assert summary["active_breaches"] == 1
