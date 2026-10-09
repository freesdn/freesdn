# SPDX-License-Identifier: AGPL-3.0-only
"""Coverage denominators and missing historical observations stay inspectable."""

from datetime import UTC, date, datetime
from uuid import uuid4

import pytest

from app.api.v1.endpoints.enterprise import get_module_health, get_org_health, get_site_health
from app.schemas.enterprise import HealthDailySnapshotResponse
from app.services.enterprise import HealthService
from tests.services.test_health_measurement_truth import device, fixture


async def test_aggregate_coverage_reports_the_actual_denominator(db_session):
    _, site, user = await fixture(db_session)
    await device(db_session, site, score=0, status="critical")
    await device(db_session, site, score=100, status="unknown")
    results = [await get_site_health(site.id, db_session, user),
               await get_org_health(None, db_session, user)]
    results += [r for r in await get_module_health(None, db_session, user)
                if r.module == "Network"]
    for result in results:
        assert result.device_count == 2
        assert result.measured_device_count == 1
        assert result.avg_health_score == 0


@pytest.mark.parametrize("critical,expected", [(0, None), (1, 0)])
def test_daily_history_distinguishes_missing_from_measured_zero(critical, expected):
    snapshot = HealthDailySnapshotResponse(
        id=uuid4(), organization_id=uuid4(), snapshot_date=date.today(),
        avg_health_score=0, device_count=1, healthy_count=0, warning_count=0,
        degraded_count=0, critical_count=critical, created_at=datetime.now(UTC),
    )
    assert snapshot.avg_health_score == expected


async def test_partial_reconciliation_retains_observed_component(db_session):
    _, site, _ = await fixture(db_session)
    dev = await device(db_session, site)
    service = HealthService(db_session)
    health = await service.compute_device_health(dev, reachability_score=0)
    await db_session.flush()
    updated = await service.compute_device_health(dev, drift_score=100)
    assert updated.id == health.id
    assert updated.reachability_score == 0 and updated.drift_score == 100
    assert updated.measured_score == 40
