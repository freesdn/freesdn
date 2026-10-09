# SPDX-License-Identifier: AGPL-3.0-only
"""The configured consecutive-violation gate must survive process boundaries."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.models.core import Organization
from app.models.sla import SLABreach, SLAPolicy, SLASnapshot
from app.services.sla import SLAMonitoringService


@pytest.fixture
async def consecutive_policy(db_session, monkeypatch):
    org = Organization(name='Consecutive fixture', slug='sla-consecutive-' + uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    policy = SLAPolicy(organization_id=org.id, name='Three observations', scope='organization',
                       thresholds={'health_score_min': 80}, breach_after_consecutive=3)
    db_session.add(policy)
    await db_session.flush()
    monkeypatch.setattr('app.services.sla.get_event_bus',
                        lambda: SimpleNamespace(publish=AsyncMock()))
    return policy


async def evaluate(db, policy, data, tick):
    # New service per pass: the counter must be in persisted observations.
    service = SLAMonitoringService(db)
    service._gather_health_data = AsyncMock(return_value=data)
    outcome = await service._evaluate_policy(policy, tick)
    await db.flush()
    await db.refresh(policy)
    return outcome


async def test_three_consecutive_complete_violations_create_one_incident(db_session, consecutive_policy):
    policy = consecutive_policy
    now = datetime.now(UTC)
    for i in range(4):
        result = await evaluate(db_session, policy, {'avg_health_score': 0}, now + timedelta(minutes=i))
        assert result['breaches_created'] == (1 if i == 2 else 0)
        assert policy.current_compliance_percent == 0
    assert await db_session.scalar(select(func.count()).where(SLABreach.policy_id == policy.id)) == 1
    rows = (await db_session.execute(select(SLASnapshot).where(
        SLASnapshot.policy_id == policy.id).order_by(SLASnapshot.recorded_at))).scalars().all()
    assert [r.in_breach for r in rows] == [False, False, True, True]
    assert [r.metrics['health_score_min']['consecutive_violations'] for r in rows] == [1, 2, 3, 3]


@pytest.mark.parametrize('interruption', ['healthy', 'missing', 'partial', 'changed_target'])
async def test_interrupted_observation_sequence_restarts_confirmation(
    db_session, consecutive_policy, interruption,
):
    policy = consecutive_policy
    now = datetime.now(UTC)
    for i in range(2):
        await evaluate(db_session, policy, {'avg_health_score': 0}, now + timedelta(minutes=i))
    if interruption == 'changed_target':
        await SLAMonitoringService(db_session).update_policy(policy.id, {
            'thresholds': {'health_score_min': 90},
        })
    else:
        if interruption == 'partial':
            policy.thresholds = {'health_score_min': 80, 'latency_ms_max': 20}
        data = {'avg_health_score': 100} if interruption == 'healthy' else (
            {'avg_health_score': 0} if interruption == 'partial' else {})
        await evaluate(db_session, policy, data, now + timedelta(minutes=2))
        policy.thresholds = {'health_score_min': 80}
    for i in range(3):
        result = await evaluate(db_session, policy, {'avg_health_score': 0}, now + timedelta(minutes=3+i))
        assert result['breaches_created'] == (1 if i == 2 else 0)


async def test_legacy_snapshot_without_confirmation_metadata_starts_a_new_sequence(
    db_session, consecutive_policy,
):
    policy = consecutive_policy
    now = datetime.now(UTC)
    policy.last_evaluated_at = now
    policy.current_compliance_percent = 0
    db_session.add(SLASnapshot(policy_id=policy.id, recorded_at=now, compliance_percent=0,
                               metrics={'health_score_min': {'threshold': 80, 'actual': 0}},
                               in_breach=False))
    await db_session.flush()
    result = await evaluate(db_session, policy, {'avg_health_score': 0}, now + timedelta(minutes=1))
    assert result['breaches_created'] == 0


async def test_disable_and_resume_clears_observation_sequence(db_session, consecutive_policy):
    policy = consecutive_policy
    now = datetime.now(UTC)
    for i in range(2):
        await evaluate(db_session, policy, {'avg_health_score': 0}, now + timedelta(minutes=i))
    service = SLAMonitoringService(db_session)
    await service.update_policy(policy.id, {'status': 'disabled'})
    assert policy.current_compliance_percent is None and policy.last_evaluated_at is None
    await service.update_policy(policy.id, {'status': 'active'})
    result = await evaluate(db_session, policy, {'avg_health_score': 0}, now + timedelta(minutes=3))
    assert result['breaches_created'] == 0


async def test_each_metric_confirms_and_recovers_independently(db_session, consecutive_policy):
    policy = consecutive_policy
    policy.breach_after_consecutive = 2
    policy.thresholds = {'health_score_min': 80, 'latency_ms_max': 30}
    now = datetime.now(UTC)
    first = await evaluate(db_session, policy, {'avg_health_score': 0, 'avg_latency_ms': 10}, now)
    assert first == {'breaches_created': 0, 'breaches_resolved': 0}
    second = await evaluate(db_session, policy, {'avg_health_score': 0, 'avg_latency_ms': 50},
                            now + timedelta(minutes=1))
    assert second == {'breaches_created': 1, 'breaches_resolved': 0}
    third = await evaluate(db_session, policy, {'avg_health_score': 100, 'avg_latency_ms': 50},
                           now + timedelta(minutes=2))
    assert third == {'breaches_created': 1, 'breaches_resolved': 1}
