# SPDX-License-Identifier: AGPL-3.0-only
"""Acknowledgement is an operator action, not proof of incident recovery."""
import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db.session import create_test_engine
from app.models.core import Organization
from app.models.sla import SLABreach, SLAPolicy, SLASnapshot
from app.services.sla import SLAMonitoringService


@pytest.fixture
async def incident_policy(db_session, monkeypatch):
    org = Organization(name='Lifecycle fixture', slug='sla-lifecycle-' + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    policy = SLAPolicy(organization_id=org.id, name='Health', scope='organization',
                       thresholds={'health_score_min': 80}, breach_after_consecutive=1)
    db_session.add(policy)
    await db_session.flush()
    monkeypatch.setattr('app.services.sla.get_event_bus',
                        lambda: SimpleNamespace(publish=AsyncMock()))
    return policy


def incident(policy, status):
    return SLABreach(policy_id=policy.id, organization_id=policy.organization_id,
                     status=status, severity='critical', violated_metric='health_score_min',
                     threshold_value=80, actual_value=20, deviation_percent=75,
                     started_at=datetime.now(UTC) - timedelta(minutes=4),
                     acknowledged_at=datetime.now(UTC) if status == 'acknowledged' else None)


@pytest.mark.parametrize('score', [0, 100])
async def test_acknowledged_incident_is_updated_or_resolved_without_duplicate(
    db_session, incident_policy, score,
):
    breach = incident(incident_policy, 'acknowledged')
    db_session.add(breach)
    await db_session.flush()
    acknowledged_at = breach.acknowledged_at
    service = SLAMonitoringService(db_session)
    service._gather_health_data = AsyncMock(return_value={'avg_health_score': score})
    result = await service._evaluate_policy(incident_policy, datetime.now(UTC))
    await db_session.flush()
    assert result['breaches_created'] == 0
    assert result['breaches_resolved'] == (1 if score == 100 else 0)
    assert await db_session.scalar(select(func.count()).where(
        SLABreach.policy_id == incident_policy.id)) == 1
    await db_session.refresh(breach)
    assert breach.acknowledged_at == acknowledged_at
    assert breach.status == ('resolved' if score == 100 else 'acknowledged')
    if score == 0:
        assert breach.actual_value == 0
    summary = await service.get_compliance_summary(incident_policy.organization_id)
    assert summary['active_breaches'] == (0 if score == 100 else 1)


async def test_all_legacy_duplicate_incidents_resolve(db_session, incident_policy):
    breaches = [incident(incident_policy, status) for status in ['active', 'acknowledged']]
    db_session.add_all(breaches)
    await db_session.flush()
    service = SLAMonitoringService(db_session)
    service._gather_health_data = AsyncMock(return_value={'avg_health_score': 100})
    result = await service._evaluate_policy(incident_policy, datetime.now(UTC))
    await db_session.flush()
    assert result['breaches_resolved'] == 2
    assert all(b.status == 'resolved' and b.duration_minutes >= 4 for b in breaches)


async def test_acknowledging_resolved_incident_does_not_reopen_it(db_session, incident_policy):
    breach = incident(incident_policy, 'resolved')
    breach.resolved_at = datetime.now(UTC)
    db_session.add(breach)
    await db_session.flush()
    await SLAMonitoringService(db_session).acknowledge_breach(
        breach.id, uuid4(), organization_id=incident_policy.organization_id,
    )
    assert breach.status == 'resolved'
    assert breach.acknowledged_at is None


async def test_missing_observation_does_not_resolve_acknowledged_incident(
    db_session, incident_policy,
):
    breach = incident(incident_policy, 'acknowledged')
    db_session.add(breach)
    await db_session.flush()
    service = SLAMonitoringService(db_session)
    service._gather_health_data = AsyncMock(return_value={})
    await service._evaluate_policy(incident_policy, datetime.now(UTC))
    assert breach.status == 'acknowledged' and breach.resolved_at is None


async def test_overlapping_evaluators_skip_locked_policy_instead_of_duplicate_breaches(monkeypatch):
    engine = create_test_engine()
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    org_id, policy_id = uuid4(), uuid4()
    entered, release = asyncio.Event(), asyncio.Event()
    monkeypatch.setattr('app.services.sla.get_event_bus',
                        lambda: SimpleNamespace(publish=AsyncMock()))
    async def gather(self, policy):
        entered.set()
        await release.wait()
        return {'avg_health_score': 0}
    monkeypatch.setattr(SLAMonitoringService, '_gather_health_data', gather)
    tasks = []
    try:
        async with sessions() as db:
            db.add(Organization(id=org_id, name='Concurrent fixture', slug='concurrent-' + uuid4().hex))
            await db.flush()
            db.add(SLAPolicy(id=policy_id, organization_id=org_id, name='Serialized',
                             scope='organization', thresholds={'health_score_min': 80},
                             breach_after_consecutive=1))
            await db.commit()
        async def evaluate():
            async with sessions() as db:
                return await SLAMonitoringService(db).evaluate_all_policies(org_id)
        first = asyncio.create_task(evaluate())
        tasks.append(first)
        await asyncio.wait_for(entered.wait(), 5)
        second = asyncio.create_task(evaluate())
        tasks.append(second)
        # The second pass must finish without waiting on the first observation.
        result = await asyncio.wait_for(asyncio.shield(second), 3)
        assert result['policies_evaluated'] == 0
        release.set()
        assert (await asyncio.wait_for(first, 5))['breaches_created'] == 1
        async with sessions() as db:
            assert await db.scalar(select(func.count()).where(SLABreach.policy_id == policy_id)) == 1
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        async with sessions() as db:
            await db.execute(delete(SLABreach).where(SLABreach.policy_id == policy_id))
            await db.execute(delete(SLASnapshot).where(SLASnapshot.policy_id == policy_id))
            await db.execute(delete(SLAPolicy).where(SLAPolicy.id == policy_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.commit()
        await engine.dispose()
