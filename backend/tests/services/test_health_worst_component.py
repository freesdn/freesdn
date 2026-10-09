# SPDX-License-Identifier: AGPL-3.0-only
"""Real DB issue summaries must not invent a perfect unknown component."""

import pytest
from sqlalchemy import select

from app.api.v1.endpoints.enterprise import get_top_issues
from app.models.enterprise import DeviceHealth
from tests.services.test_health_measurement_truth import device, fixture


@pytest.mark.parametrize(
    "components,expected_name,expected_score",
    [
        ({}, None, None),
        ({"reachability_score": 100}, "reachability", 100),
        ({"reachability_score": 100, "latency_score": 0}, "latency", 0),
        ({"drift_score": 25, "firmware_score": 100}, "drift", 25),
    ],
)
async def test_worst_component_uses_only_actual_observations(
    db_session, components, expected_name, expected_score
):
    _, site, user = await fixture(db_session)
    dev = await device(db_session, site, score=0, status="critical")
    health = (
        await db_session.execute(select(DeviceHealth).where(DeviceHealth.device_id == dev.id))
    ).scalar_one()
    for name, value in components.items():
        setattr(health, name, value)
    await db_session.flush()
    result = await get_top_issues(site.id, 10, db_session, user)
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.health_score == 0
    assert issue.worst_component == expected_name
    assert issue.worst_component_score == expected_score
    assert issue.model_dump()["worst_component_score"] == expected_score


async def test_unknown_aggregate_does_not_become_a_measured_top_issue(db_session):
    _, site, user = await fixture(db_session)
    await device(db_session, site, score=100, status="unknown")
    result = await get_top_issues(site.id, 10, db_session, user)
    assert result.issues == []
