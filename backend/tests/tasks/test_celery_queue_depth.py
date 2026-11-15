# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Celery backlog alert reads a queue depth that is actually measured.

``freesdn_celery_queue_depth`` was declared and written by nothing, so
FreeSDNCeleryQueueBacklog had to be commented out: it evaluated an empty family
forever. The depth is now read from the broker on every scrape. The only other
reader of queue lengths (the tasks page) asked Redis database 0, while the
shipped compose puts the broker in database 1, so it reported 0 pending tasks
in every queue, always.

Real Valkey; the broker is pointed at a scratch database so no real queue is
touched.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.core import celery_app as celery_module
from app.core import metrics
from app.core.config import settings


@pytest.mark.parametrize(
    ("url", "db"),
    [
        ("redis://:pw@redis:6379/1", 1),
        ("sentinel://:pw@10.0.0.1:26379/1;sentinel://:pw@10.0.0.2:26379/1", 1),
        ("redis://localhost:6379", 0),
        ("redis://localhost:6379/", 0),
    ],
)
def test_the_broker_database_is_read_from_the_broker_url(url, db):
    assert metrics.broker_db(url) == db


@pytest.fixture
def scratch_broker(monkeypatch):
    from app.core.redis_client import get_sync_redis

    db = 7
    monkeypatch.setattr(
        celery_module, "broker_url", f"redis://localhost:{settings.REDIS_PORT}/{db}"
    )
    client = get_sync_redis(db=db)
    client.delete("metrics", "default")
    try:
        yield client
    finally:
        client.delete("metrics", "default")
        client.close()


def test_queue_lengths_come_from_the_broker_database(scratch_broker):
    scratch_broker.rpush("metrics", "a", "b", "c")

    lengths = metrics.celery_queue_lengths()

    assert lengths["metrics"] == 3
    assert lengths["default"] == 0
    assert set(lengths) == {q.name for q in celery_module.task_queues}


async def test_a_scrape_reports_the_current_backlog(scratch_broker):
    from app.main import app

    if settings.ENVIRONMENT != "development" or not settings.ENABLE_METRICS:
        pytest.skip("this app instance serves /metrics only with a token")
    scratch_broker.rpush("default", *[str(i) for i in range(4)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.get("/metrics")
        scratch_broker.rpush("default", "late")
        second = await client.get("/metrics")

    assert first.status_code == 200
    assert 'freesdn_celery_queue_depth{queue="default"} 4.0' in first.text
    # Refreshed per scrape, not cached from the first one.
    assert 'freesdn_celery_queue_depth{queue="default"} 5.0' in second.text
