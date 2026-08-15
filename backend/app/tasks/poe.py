# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - PoE Schedule Tasks
=================================

Celery tasks for evaluating PoE schedules and toggling port power
based on time-of-day rules.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True, base=FreeSDNTask, name="poe.evaluate_schedules", soft_time_limit=120, time_limit=180
)
def evaluate_poe_schedules(self) -> dict[str, Any]:
    """
    Every 1 minute: check all enabled PoE schedules against the
    current time and toggle port power accordingly.

    For each schedule:
        1. Determine the current local time in the schedule's timezone.
        2. Check if today's day-of-week is in the schedule's days_of_week list.
        3. Decide whether ports should be powered off or on.
        4. If the needed action differs from last_action, execute it
           via the device adapter and update the schedule.
    """

    async def _run() -> dict[str, Any]:
        from zoneinfo import ZoneInfo

        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from app.models.core import Site
        from app.models.devices import Device
        from app.models.poe import PoESchedule

        async with AsyncSessionLocal() as session:
            # Fetch all enabled, non-deleted schedules
            q = (
                select(PoESchedule)
                .where(
                    PoESchedule.enabled.is_(True),
                    PoESchedule.deleted_at.is_(None),
                )
                .with_for_update(skip_locked=True)
            )
            result = await session.execute(q)
            schedules = result.scalars().all()

            if not schedules:
                return {"evaluated": 0, "actions": 0}

            actions_taken = 0
            errors = 0

            for schedule in schedules:
                try:
                    # Determine local time for the schedule's timezone
                    try:
                        tz = ZoneInfo(schedule.timezone or "UTC")
                    except (KeyError, ValueError):
                        tz = ZoneInfo("UTC")

                    now_local = datetime.now(tz)
                    current_day = now_local.weekday()  # 0=Mon, 6=Sun
                    current_time = now_local.strftime("%H:%M")

                    # Check if today is a scheduled day
                    if schedule.days_of_week and current_day not in schedule.days_of_week:
                        continue

                    # Determine desired action based on current time
                    off_time = schedule.power_off_time  # e.g. "22:00"
                    on_time = schedule.power_on_time  # e.g. "06:00"

                    if off_time <= on_time:
                        # Same-day window: off at 08:00, on at 17:00
                        # Power is OFF between off_time and on_time
                        should_be_off = off_time <= current_time < on_time
                    else:
                        # Overnight window: off at 22:00, on at 06:00
                        # Power is OFF from off_time to midnight and midnight to on_time
                        should_be_off = current_time >= off_time or current_time < on_time

                    desired_action = "power_off" if should_be_off else "power_on"

                    # Skip if already in desired state
                    if schedule.last_action == desired_action:
                        continue

                    # Resolve target devices
                    device_ids: list = []
                    if schedule.device_id:
                        device_ids = [schedule.device_id]
                    elif schedule.device_group_id:
                        from app.models.enterprise import DeviceGroupMembership

                        member_q = select(DeviceGroupMembership.device_id).where(
                            DeviceGroupMembership.group_id == schedule.device_group_id,
                        )
                        member_result = await session.execute(member_q)
                        device_ids = list(member_result.scalars().all())

                    if not device_ids:
                        continue

                    # Load devices with controller relationship, scoped to org
                    dev_q = (
                        select(Device)
                        .options(selectinload(Device.controller))
                        .join(Site, Device.site_id == Site.id)
                        .where(
                            Device.id.in_(device_ids),
                            Site.organization_id == schedule.organization_id,
                            Device.deleted_at.is_(None),
                        )
                    )
                    dev_result = await session.execute(dev_q)
                    devices = dev_result.scalars().all()

                    poe_enabled = desired_action == "power_on"
                    any_device_succeeded = False

                    for device in devices:
                        if not device.controller:
                            logger.warning("Device %s has no controller, skipping", device.id)
                            continue
                        try:
                            from app.api.v1.endpoints.poe import _decrypt_if_needed
                            from app.services.adapter_factory import get_adapter

                            ctrl = device.controller
                            cloud_kwargs: dict = {}
                            if ctrl.connection_mode == "cloud":
                                cloud_kwargs = {
                                    "client_id": ctrl.client_id or "",
                                    "client_secret": _decrypt_if_needed(ctrl.client_secret),
                                    "omada_id": ctrl.omada_id or "",
                                    "cloud_region": ctrl.cloud_region or "us",
                                }
                            adapter = get_adapter(
                                controller_type=ctrl.controller_type,
                                host=ctrl.host,
                                username=ctrl.username or "",
                                password=_decrypt_if_needed(ctrl.password),
                                port=ctrl.port,
                                use_ssl=ctrl.use_ssl,
                                verify_ssl=ctrl.verify_ssl,
                                mode=ctrl.connection_mode or "local",
                                **cloud_kwargs,
                            )
                            async with adapter:
                                for port_num in schedule.port_numbers or []:
                                    config = {"poe": {"enable": poe_enabled}}
                                    await adapter.configure_switch_port(
                                        device.mac_address,
                                        port_num,
                                        config,
                                    )
                            any_device_succeeded = True
                        except Exception as e:
                            logger.warning(
                                "PoE schedule '%s' failed on device %s port(s) %s: %s",
                                schedule.name,
                                device.id,
                                schedule.port_numbers,
                                e,
                            )

                    # Update schedule status only if at least one device push succeeded
                    if any_device_succeeded:
                        schedule.last_action = desired_action
                        schedule.last_action_at = datetime.now(UTC)
                        actions_taken += 1

                except Exception as e:
                    logger.error(
                        "Error evaluating PoE schedule '%s' (%s): %s",
                        schedule.name,
                        schedule.id,
                        e,
                    )
                    errors += 1

            await session.commit()

            logger.info(
                "PoE schedule evaluation: %d schedules, %d actions, %d errors",
                len(schedules),
                actions_taken,
                errors,
            )
            return {
                "evaluated": len(schedules),
                "actions": actions_taken,
                "errors": errors,
            }

    return asyncio.run(_run())
