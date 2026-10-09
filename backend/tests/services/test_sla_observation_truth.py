# SPDX-License-Identifier: AGPL-3.0-only
"""Missing observations must never turn into a successful SLA measurement."""
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.sla import SLAPolicy, SLASnapshot
from app.services.sla import SLAMonitoringService


@pytest.mark.parametrize('health,thresholds', [
    ({}, {'health_score_min': 80}),
    ({'avg_health_score': 100}, {'health_score_min': 80, 'latency_ms_max': 30}),
    ({'avg_health_score': 100}, {'latency_ms_max': 30}),
    ({'avg_health_score': 100}, {}),
    ({'avg_health_score': float('nan')}, {'health_score_min': 80}),
])
async def test_incomplete_observation_invalidates_old_compliance_without_success_snapshot(
    health, thresholds,
):
    result = MagicMock()
    result.scalars.return_value = []
    db = SimpleNamespace(execute=AsyncMock(return_value=result), add=MagicMock())
    service = SLAMonitoringService(db)
    service._gather_health_data = AsyncMock(return_value=health)
    policy = SLAPolicy(id=uuid4(), organization_id=uuid4(), name='Missing data',
                       scope='site', scope_id=uuid4(), thresholds=thresholds,
                       current_compliance_percent=100)
    now = datetime.now(UTC)
    await service._evaluate_policy(policy, now)
    assert policy.current_compliance_percent is None
    assert policy.last_evaluated_at == now
    assert not any(isinstance(c.args[0], SLASnapshot) for c in db.add.call_args_list)


@pytest.mark.parametrize('scope', ['site', 'organization'])
async def test_composite_health_score_is_not_claimed_as_measured_uptime(scope):
    result = MagicMock()
    result.one_or_none.return_value = (95, 1, 1, 0) if scope == 'site' else (95, 1)
    db = SimpleNamespace(execute=AsyncMock(return_value=result))
    service = SLAMonitoringService(db)
    policy = SLAPolicy(organization_id=uuid4(), name='Scope', scope=scope, scope_id=uuid4())
    data = await service._gather_health_data(policy)
    assert data['avg_health_score'] == 95
    assert service._extract_metric(data, 'uptime_percent_min') is None
    assert service._extract_metric(data, 'client_satisfaction_min') is None


@pytest.mark.parametrize('health_score', [0, 100])
async def test_partial_measurement_preserves_breach_state_and_resumes_with_complete_targets(
    db_session, monkeypatch, health_score,
):
    from sqlalchemy import func, select

    from app.models.core import Organization, Site
    from app.models.devices import Device
    from app.models.enterprise import DeviceHealth, HealthStatus
    from app.models.sla import SLABreach

    org = Organization(name='Observation fixture', slug='observations-' + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(organization_id=org.id, name='Owned site', slug='owned')
    db_session.add(site)
    await db_session.flush()
    device = Device(site_id=site.id, name='Health sensor', device_type='switch')
    db_session.add(device)
    await db_session.flush()
    policy = SLAPolicy(organization_id=org.id, name='Health and unavailable latency',
                       scope='site', scope_id=site.id,
                       thresholds={'health_score_min': 80, 'latency_ms_max': 30},
                       current_compliance_percent=100, breach_after_consecutive=1)
    health = DeviceHealth(organization_id=org.id, site_id=site.id, device_id=device.id,
                          health_score=health_score, health_status=HealthStatus.CRITICAL)
    db_session.add_all([policy, health])
    await db_session.flush()
    # An existing latency incident must not resolve when latency disappears.
    missing = SLABreach(policy_id=policy.id, organization_id=org.id, status='active',
                        severity='warning', violated_metric='latency_ms_max',
                        threshold_value=30, actual_value=90, deviation_percent=200)
    db_session.add(missing)
    await db_session.flush()
    monkeypatch.setattr('app.services.sla.get_event_bus',
                        lambda: SimpleNamespace(publish=AsyncMock()))
    service = SLAMonitoringService(db_session)
    outcome = await service._evaluate_policy(policy, datetime.now(UTC))
    await db_session.flush()
    await db_session.refresh(policy)
    assert policy.current_compliance_percent is None
    assert missing.status == 'active' and missing.resolved_at is None
    assert outcome['breaches_created'] == (1 if health_score == 0 else 0)
    assert (await db_session.scalar(select(func.count()).where(
        SLASnapshot.policy_id == policy.id))) == 0
    # A valid complete evaluation must still create its numeric history.
    policy.thresholds = {'health_score_min': 80}
    await service._evaluate_policy(policy, datetime.now(UTC))
    await db_session.flush()
    snapshot = (await db_session.execute(select(SLASnapshot).where(
        SLASnapshot.policy_id == policy.id))).scalar_one()
    assert snapshot.compliance_percent == health_score
    assert policy.current_compliance_percent == health_score


async def test_site_health_query_reasserts_organization_for_legacy_scope(db_session):
    from app.models.core import Organization, Site
    from app.models.devices import Device
    from app.models.enterprise import DeviceHealth, HealthStatus

    owner = Organization(name='Owner', slug='owner-' + uuid4().hex)
    other = Organization(name='Other', slug='other-' + uuid4().hex)
    db_session.add_all([owner, other])
    await db_session.flush()
    site = Site(organization_id=other.id, name='Foreign site', slug='foreign')
    db_session.add(site)
    await db_session.flush()
    device = Device(site_id=site.id, name='Foreign sensor', device_type='switch')
    db_session.add(device)
    await db_session.flush()
    db_session.add(DeviceHealth(organization_id=other.id, site_id=site.id, device_id=device.id,
                                health_score=100, health_status=HealthStatus.HEALTHY))
    await db_session.flush()
    legacy = SLAPolicy(organization_id=owner.id, name='Invalid legacy scope',
                       scope='site', scope_id=site.id)
    assert await SLAMonitoringService(db_session)._gather_health_data(legacy) == {}
