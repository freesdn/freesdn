# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Beat-driven recovery of committed in-app event publication."""

import asyncio

from app.core.celery_app import celery_app
from app.services.notification_outbox import publish_pending_notifications


def _publish_in_app_events() -> dict[str, int]:
    return asyncio.run(publish_pending_notifications())


# Keep the typed worker body separate from Celery's dynamic task registration.
publish_in_app_events = celery_app.task(
    name="notifications.publish_in_app_events", soft_time_limit=45, time_limit=60
)(_publish_in_app_events)
