# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Zero-Touch Provisioning Service
=============================================

Evaluates newly discovered devices against adoption rules and
executes the multi-step adoption pipeline.
"""

import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.devices import Device, DeviceStatus
from app.models.enterprise import LifecycleState
from app.models.ztp import (
    AdoptionJob,
    AdoptionJobStatus,
    AdoptionTrigger,
    AutoAdoptionRule,
    MACPreRegistration,
    ProvisioningProfile,
)
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)


def _result_field(result: Any, name: str, default: Any = None) -> Any:
    from app.core.adapter_result import adapter_result_field

    return adapter_result_field(result, name, default)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dicts, override values take precedence."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


async def resolve_profile_config(
    db: AsyncSession, profile: ProvisioningProfile, device: Device
) -> dict[str, Any]:
    """The configuration a provisioning profile gives a device.

    The profile's own payload, merged over its linked configuration template
    when that template is live, active and meant for this kind of device.
    Template values are ``ConfigTemplate.config``. The merge used to read
    ``tpl.config_data``, an attribute the model does not have, so applying any
    profile with a template raised before anything was sent; and the adoption
    pipeline ignored the template altogether, so the two paths pushed different
    configurations for the same profile.
    """
    config: dict[str, Any] = dict(profile.config_payload or {})
    if not profile.config_template_id:
        return config
    from app.models.enterprise import ConfigTemplate

    tpl = (
        await db.execute(
            select(ConfigTemplate).where(
                ConfigTemplate.id == profile.config_template_id,
                ConfigTemplate.organization_id == profile.organization_id,
                ConfigTemplate.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if tpl is None or not tpl.is_active or not tpl.config:
        return config
    device_type = getattr(device.device_type, "value", device.device_type)
    if tpl.device_type and str(tpl.device_type) != str(device_type):
        return config
    return _deep_merge(dict(tpl.config), config)


def _decrypt_if_needed(value: str | None) -> str:
    """Return plaintext value for encrypted controller secrets."""
    if not value:
        return ""
    try:
        from app.core.crypto import decrypt_credential, is_encrypted

        if not is_encrypted(value):
            return value
        return decrypt_credential(value)
    except (ValueError, Exception):
        return value or ""


# =========================================================================
# ZTP Engine — rule evaluation
# =========================================================================


class ZTPEngine:
    """Evaluates newly discovered devices against adoption rules."""

    async def evaluate_device(
        self,
        device: Device,
        session: AsyncSession,
    ) -> AdoptionJob | None:
        """
        Called from discovery task after new device creation.

        1. Check MACPreRegistration for exact MAC match
        2. If no MAC match, evaluate AutoAdoptionRules (ordered by priority)
        3. If match found, create AdoptionJob and return it for dispatch
        """
        if not device.mac_address:
            return None

        # Already adopted — skip
        if device.is_adopted:
            return None

        # Check for existing active adoption job for this device
        existing = await session.execute(
            select(AdoptionJob).where(
                AdoptionJob.device_id == device.id,
                AdoptionJob.status.in_([AdoptionJobStatus.PENDING, AdoptionJobStatus.ADOPTING]),
            )
        )
        if existing.scalar_one_or_none():
            logger.info("Active adoption job already exists for device %s", device.name)
            return None

        org_id = await self._get_org_id(device, session)
        if not org_id:
            return None

        # 1. Check MAC pre-registration
        job = await self._check_mac_preregistration(device, org_id, session)
        if job:
            return job

        # 2. Evaluate adoption rules
        job = await self._evaluate_rules(device, org_id, session)
        if job:
            return job

        return None

    async def _get_org_id(self, device: Device, session: AsyncSession) -> UUID | None:
        """Get organization_id from device's site."""
        if not device.site_id:
            return None
        from app.models.core import Site

        result = await session.execute(
            select(Site.organization_id).where(Site.id == device.site_id)
        )
        return result.scalar_one_or_none()

    async def _check_mac_preregistration(
        self,
        device: Device,
        org_id: UUID,
        session: AsyncSession,
    ) -> AdoptionJob | None:
        """Check if device's MAC is pre-registered."""
        mac = device.mac_address.upper()
        result = await session.execute(
            select(MACPreRegistration).where(
                MACPreRegistration.mac_address == mac,
                MACPreRegistration.organization_id == org_id,
                # M1: `not MACPreRegistration.adopted` is a Python
                # bool-negation of an InstrumentedAttribute -> literal False,
                # which SQLAlchemy folds to `WHERE false`, so this query never
                # matched and MAC pre-registration adoption was permanently
                # dead. Use the column comparison the endpoint already uses.
                MACPreRegistration.adopted.is_(False),
            )
        )
        prereg = result.scalar_one_or_none()
        if not prereg:
            return None

        logger.info(
            "MAC pre-registration match for device %s (%s)",
            device.name,
            mac,
        )

        # Update device name if specified
        if prereg.device_name:
            device.name = prereg.device_name

        # Move to target site if specified
        if prereg.target_site_id:
            device.site_id = prereg.target_site_id

        # Create adoption job
        job = AdoptionJob(
            device_id=device.id,
            organization_id=org_id,
            status=AdoptionJobStatus.PENDING,
            current_step="validate",
            steps_completed=[],
            triggered_by=AdoptionTrigger.MAC_PREREGISTER,
            profile_id=prereg.provisioning_profile_id,
            started_at=datetime.now(UTC),
        )
        session.add(job)
        await session.flush()

        # Mark pre-registration as adopted
        prereg.adopted = True
        prereg.adopted_at = datetime.now(UTC)
        prereg.adopted_device_id = device.id

        return job

    async def _evaluate_rules(
        self,
        device: Device,
        org_id: UUID,
        session: AsyncSession,
    ) -> AdoptionJob | None:
        """Evaluate auto-adoption rules ordered by priority."""
        result = await session.execute(
            select(AutoAdoptionRule)
            .where(
                AutoAdoptionRule.organization_id == org_id,
                AutoAdoptionRule.enabled,
            )
            .order_by(AutoAdoptionRule.priority.asc())
        )
        rules = result.scalars().all()

        for rule in rules:
            if self._matches_rule(device, rule):
                logger.info(
                    "Auto-adoption rule '%s' matched device %s",
                    rule.name,
                    device.name,
                )

                # Apply rule actions
                if rule.target_site_id:
                    device.site_id = rule.target_site_id

                job = AdoptionJob(
                    device_id=device.id,
                    organization_id=org_id,
                    status=AdoptionJobStatus.PENDING,
                    current_step="validate",
                    steps_completed=[],
                    triggered_by=AdoptionTrigger.AUTO_RULE,
                    rule_id=rule.id,
                    profile_id=rule.provisioning_profile_id,
                    started_at=datetime.now(UTC),
                )
                session.add(job)
                await session.flush()
                return job

        return None

    @staticmethod
    def _matches_rule(device: Device, rule: AutoAdoptionRule) -> bool:
        """Check if a device matches all non-null criteria of a rule."""
        if rule.match_device_type and device.device_type != rule.match_device_type:
            return False
        if rule.match_manufacturer:
            dev_mfr = (device.manufacturer or "").lower()
            if rule.match_manufacturer.lower() not in dev_mfr:
                return False
        if rule.match_model_pattern:
            dev_model = device.model or ""
            # Simple LIKE-style match: % = wildcard
            import fnmatch

            pattern = rule.match_model_pattern.replace("%", "*")
            if not fnmatch.fnmatch(dev_model, pattern):
                return False
        if rule.match_controller_id and device.controller_id != rule.match_controller_id:
            return False
        return not (rule.match_site_id and device.site_id != rule.match_site_id)


# =========================================================================
# Adoption Orchestrator — multi-step pipeline
# =========================================================================


class AdoptionOrchestrator:
    """
    Executes the multi-step adoption pipeline:
    validate → adopt → firmware_check → provision → verify
    """

    STEPS = ["validate", "adopt", "firmware_check", "provision", "verify"]

    def __init__(
        self,
        ledger_session_factory: Callable[[], contextlib.AbstractAsyncContextManager[AsyncSession]]
        | None = None,
    ) -> None:
        # The staging ledger is written in its own transaction: the pipeline's
        # transaction rolls back on failure, and the record of a write the
        # device already took must survive that.
        self._ledger_session_factory = ledger_session_factory

    @contextlib.asynccontextmanager
    async def _ledger_session(self) -> AsyncIterator[AsyncSession]:
        factory = self._ledger_session_factory
        if factory is None:
            from app.db.session import celery_session_factory

            factory = celery_session_factory
        async with factory() as ledger:
            yield ledger

    async def _device_write(
        self,
        *,
        device: Device,
        organization_id: UUID,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        perform: Callable[[], Awaitable[Any]],
        notes: str,
        actor_id: UUID | None = None,
        force: bool = True,
    ) -> Any:
        """Make one device write through the staging chokepoint.

        Refused while read-only mode is on; otherwise recorded in the staging
        ledger (``direct.ztp.*``) and applied in the same call. Returns the
        adapter's result, a failed one included, so each step keeps deciding
        what a refusal means for the adoption.
        """
        from app.services.adapter_staging import AdapterStagingService

        async with self._ledger_session() as ledger:
            return await AdapterStagingService(ledger).apply_now(
                organization_id=organization_id,
                controller_id=device.controller_id,
                site_id=device.site_id,
                feature=f"ztp.{feature}",
                operation=operation,
                target_id=device.mac_address or str(device.id),
                payload=payload,
                perform=perform,
                # An adoption job is the explicit request: an administrator
                # started it, or an administrator's auto-adoption rule matched.
                # "Apply profile" passes the request's own force flag.
                force=force,
                actor_id=actor_id,
                notes=notes,
                return_failed_result=True,
            )

    @staticmethod
    def _job_note(job: AdoptionJob) -> str:
        return f"zero-touch adoption job {job.id} ({job.triggered_by})"

    async def execute(self, job_id: UUID, session: AsyncSession) -> dict[str, Any]:
        """Run adoption pipeline for a job."""
        result = await session.execute(
            select(AdoptionJob)
            .options(selectinload(AdoptionJob.device))
            .where(AdoptionJob.id == job_id)
            .with_for_update(skip_locked=True)
        )
        job = result.scalar_one_or_none()
        if not job:
            return {"success": False, "error": f"Job {job_id} not found"}

        # Only execute jobs that are still pending
        if job.status != AdoptionJobStatus.PENDING:
            return {"success": False, "error": "Job is not in pending state"}

        device = job.device
        if not device:
            return await self._fail_job(job, "Device not found", session)

        # Pre-load controller for pipeline steps
        self._cached_controller = None
        if device.controller_id:
            from app.models.core import Controller

            ctrl_result = await session.execute(
                select(Controller).where(
                    Controller.id == device.controller_id,
                    Controller.deleted_at.is_(None),
                )
            )
            self._cached_controller = ctrl_result.scalar_one_or_none()

        # Update status
        job.status = AdoptionJobStatus.ADOPTING
        device.status = DeviceStatus.ADOPTING
        device.lifecycle_state = LifecycleState.ADOPTING

        # Publish start event
        await self._publish_event(
            "adoption.started",
            device,
            job,
            data={"triggered_by": job.triggered_by},
        )

        steps_skipped: list[str] = []
        try:
            for step in self.STEPS:
                job.current_step = step
                await session.flush()

                step_method = getattr(self, f"_step_{step}")
                step_result = await step_method(device, job, session)

                if not step_result.get("success"):
                    return await self._fail_job(
                        job,
                        step_result.get("error", f"Step {step} failed"),
                        session,
                        device=device,
                    )

                # A step the device's adapter cannot perform does not fail the
                # adoption, but it did not happen either. It used to be listed in
                # steps_completed, so a profile no adapter can push read as applied.
                if step_result.get("skipped"):
                    steps_skipped.append(f"{step}: {step_result['skipped']}")
                    continue

                job.steps_completed = [*job.steps_completed, step]

                await self._publish_event(
                    "adoption.step_completed",
                    device,
                    job,
                    data={"step": step},
                )

            # Success
            job.status = AdoptionJobStatus.COMPLETED
            job.completed_at = datetime.now(UTC)
            if steps_skipped:
                job.error_message = "Adopted, but these steps did not run: " + "; ".join(
                    steps_skipped
                )
            device.is_adopted = True
            device.adopted_at = datetime.now(UTC)
            device.status = DeviceStatus.ONLINE
            device.lifecycle_state = LifecycleState.MANAGED

            await session.flush()

            await self._publish_event(
                "adoption.completed",
                device,
                job,
                data={"steps_completed": job.steps_completed, "steps_skipped": steps_skipped},
            )

            return {
                "success": True,
                "job_id": str(job.id),
                "device_id": str(device.id),
                "steps_completed": job.steps_completed,
                "steps_skipped": steps_skipped,
            }

        except Exception:
            logger.exception("Adoption pipeline error for job %s", job_id)
            return await self._fail_job(
                job, "Internal adoption pipeline error", session, device=device
            )

    # ---- Pipeline steps ----

    async def _step_validate(
        self,
        device: Device,
        job: AdoptionJob,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Validate device is reachable and controller is connected."""
        if not device.controller_id:
            return {"success": False, "error": "No controller assigned"}

        from app.models.core import Controller, ControllerStatus

        result = await session.execute(
            select(Controller).where(
                Controller.id == device.controller_id,
                Controller.deleted_at.is_(None),
            )
        )
        controller = result.scalar_one_or_none()
        if not controller:
            return {"success": False, "error": "Controller not found"}
        if controller.status == ControllerStatus.UNREACHABLE:
            return {"success": False, "error": "Controller is unreachable"}

        return {"success": True}

    async def _step_adopt(
        self,
        device: Device,
        job: AdoptionJob,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Call adapter.adopt_device() to claim the device."""
        adapter = await self._get_adapter(device, session)
        if not adapter:
            return {"success": False, "error": "Cannot create adapter"}

        mac = device.mac_address or ""

        async def _adopt() -> Any:
            async with adapter:
                return await adapter.adopt_device(mac)

        try:
            # adopt_device returns an AdapterResult dataclass (NOT a dict).
            # The old `result.get(...)` raised AttributeError that the broad
            # except below swallowed, so adoption ALWAYS failed, even for
            # Omada, the only adapter that implements it.
            result = await self._device_write(
                device=device,
                organization_id=job.organization_id,
                feature="adopt",
                operation="create",
                payload={"device_id": str(device.id), "mac": mac},
                perform=_adopt,
                notes=self._job_note(job),
            )
            if _result_field(result, "success", False):
                return {"success": True}
            # A base / non-adopting adapter returns AdapterResult.fail(
            # error_code="NOT_SUPPORTED") — treat that as a no-op skip (the
            # device just isn't controller-adoptable), not a hard failure.
            if _result_field(result, "error_code") == "NOT_SUPPORTED":
                logger.info(
                    "Adapter %s does not support device adoption — skipping",
                    type(adapter).__name__,
                )
                return {
                    "success": True,
                    "skipped": "this device's adapter cannot adopt devices",
                }
            return {
                "success": False,
                "error": _result_field(result, "error") or "Adoption failed",
            }
        except HTTPException as exc:
            # Read-only mode, or the staging chokepoint refused the write.
            return {"success": False, "error": str(exc.detail)}
        except Exception:
            logger.exception("Adapter adopt_device failed for device %s", device.id)
            return {"success": False, "error": "Device adoption failed"}

    async def _step_firmware_check(
        self,
        device: Device,
        job: AdoptionJob,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Check firmware and trigger upgrade via adapter if needed."""
        if not job.profile_id:
            return {"success": True}

        profile = await session.get(ProvisioningProfile, job.profile_id)
        if not profile:
            return {"success": True}
        if profile.deleted_at is not None:
            return {"success": False, "error": "Provisioning profile has been deleted"}

        if not (profile.auto_firmware_update and profile.target_firmware_version):
            return {"success": True}

        current = device.firmware_version or ""
        if current == profile.target_firmware_version:
            logger.info("Device %s firmware already at target %s", device.name, current)
            return {"success": True}

        logger.info(
            "Device %s needs firmware update: %s → %s",
            device.name,
            current,
            profile.target_firmware_version,
        )

        # Trigger firmware upgrade via adapter. A failure does not fail the
        # adoption, but it is reported as a skipped step, not a completed one.
        target = profile.target_firmware_version
        adapter = await self._get_adapter(device, session)
        if not adapter:
            logger.warning("Cannot create adapter for firmware upgrade — skipping")
            return {
                "success": True,
                "skipped": f"no adapter was available, so the upgrade to {target} was not started",
            }

        mac = device.mac_address or ""

        async def _upgrade() -> Any:
            async with adapter:
                return await adapter.upgrade_firmware(mac)

        try:
            result = await self._device_write(
                device=device,
                organization_id=job.organization_id,
                feature="firmware_upgrade",
                operation="update",
                payload={
                    "device_id": str(device.id),
                    "mac": mac,
                    "from_version": current,
                    "target_version": target,
                },
                perform=_upgrade,
                notes=self._job_note(job),
            )
            if _result_field(result, "success", True) is False:
                # Non-blocking: log but don't fail adoption
                reason = _result_field(result, "error") or "the adapter refused it"
                logger.warning(
                    "Firmware upgrade request failed for %s: %s — adoption continues",
                    device.name,
                    reason,
                )
                return {
                    "success": True,
                    "skipped": f"the upgrade to {target} was not started: {reason}",
                }
            logger.info(
                "Firmware upgrade initiated for device %s (%s → %s)",
                device.name,
                current,
                target,
            )
        except HTTPException as exc:
            return {
                "success": True,
                "skipped": f"the upgrade to {target} was not started: {exc.detail}",
            }
        except NotImplementedError:
            logger.info("Adapter does not support firmware upgrade — skipping")
            return {
                "success": True,
                "skipped": f"this device's adapter cannot upgrade firmware to {target}",
            }
        except Exception:
            logger.warning(
                "Firmware upgrade dispatch failed for %s — adoption continues",
                device.name,
                exc_info=True,
            )
            return {
                "success": True,
                "skipped": f"the request to upgrade firmware to {target} failed",
            }

        return {"success": True}

    async def _step_provision(
        self,
        device: Device,
        job: AdoptionJob,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Apply provisioning profile config."""
        if not job.profile_id:
            logger.info("No provisioning profile — skipping provision step")
            return {"success": True}

        profile = await session.get(ProvisioningProfile, job.profile_id)
        if not profile:
            return {"success": True}
        if profile.deleted_at is not None:
            return {"success": False, "error": "Provisioning profile has been deleted"}
        # The same configuration "apply profile" pushes: payload over template.
        config = await resolve_profile_config(session, profile, device)
        if not config:
            return {"success": True}

        adapter = await self._get_adapter(device, session)
        if not adapter:
            return {"success": False, "error": "Cannot create adapter"}

        mac = device.mac_address or device.external_id or ""

        async def _push() -> Any:
            async with adapter:
                return await adapter.push_full_config(mac, config)

        try:
            result = await self._device_write(
                device=device,
                organization_id=job.organization_id,
                feature="provision",
                operation="update",
                payload={"profile_id": str(profile.id), "config": config},
                perform=_push,
                notes=self._job_note(job),
            )
            if _result_field(result, "success", False):
                device.status = DeviceStatus.PROVISIONING
                device.lifecycle_state = LifecycleState.PROVISIONING
                return {"success": True}
            # No adapter implements full-config push yet — base returns
            # AdapterResult.fail(error_code="NOT_SUPPORTED"). Skip honestly
            # rather than hard-failing every profile-bearing adoption.
            if _result_field(result, "error_code") == "NOT_SUPPORTED":
                logger.info(
                    "Adapter %s does not support full-config push — skipping provision",
                    type(adapter).__name__,
                )
                return {
                    "success": True,
                    "skipped": "this device's adapter cannot push a full configuration, "
                    "so the provisioning profile was not applied",
                }
            return {
                "success": False,
                "error": _result_field(result, "error") or "Config push failed",
            }
        except HTTPException as exc:
            return {"success": False, "error": str(exc.detail)}
        except Exception:
            logger.exception("Provisioning failed for device %s", device.id)
            return {"success": False, "error": "Provisioning failed"}

    async def _step_verify(
        self,
        device: Device,
        job: AdoptionJob,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Verify the device actually came online after adoption.

        Honesty fix: this used to return success on EVERY branch (no adapter, no
        status data, exception), so a device that never came online was still
        marked adopted/ONLINE. Now it only succeeds when the device confirms
        online; otherwise it fails so the retry sweep re-verifies — a genuinely
        slow device gets retried, a dead one is honestly marked failed.
        """
        adapter = await self._get_adapter(device, session)
        if not adapter:
            return {
                "success": False,
                "error": "Cannot verify: no adapter for device's controller",
            }

        try:
            async with adapter:
                mac = device.mac_address or ""
                status = await adapter.get_device_status(mac)
                if status:
                    return {"success": True}
                return {
                    "success": False,
                    "error": "Device not yet reporting online (will retry)",
                }
        except Exception:
            logger.warning(
                "Verification failed for device %s — will retry",
                getattr(device, "name", None),
                exc_info=True,
            )
            return {"success": False, "error": "Verification failed"}

    # ---- Helpers ----

    async def _get_adapter(self, device: Device, session: AsyncSession) -> Any | None:
        """Create adapter instance for device's controller."""
        if not device.controller_id:
            return None

        # Use cached controller from execute() if available
        ctrl = getattr(self, "_cached_controller", None)
        if ctrl is None or ctrl.id != device.controller_id:
            from app.models.core import Controller

            result = await session.execute(
                select(Controller).where(
                    Controller.id == device.controller_id,
                    Controller.deleted_at.is_(None),
                )
            )
            ctrl = result.scalar_one_or_none()
        if not ctrl:
            return None

        kwargs: dict[str, Any] = {
            "port": ctrl.port,
            "use_ssl": ctrl.use_ssl,
            "verify_ssl": ctrl.verify_ssl,
            "mode": ctrl.connection_mode,
        }
        if ctrl.connection_mode == "cloud":
            kwargs["client_id"] = ctrl.client_id or ""
            kwargs["client_secret"] = _decrypt_if_needed(ctrl.client_secret)
            kwargs["omada_id"] = ctrl.omada_id or ""
            kwargs["cloud_region"] = ctrl.cloud_region or ""

        return get_adapter(
            ctrl.controller_type,
            host=ctrl.host,
            username=_decrypt_if_needed(ctrl.username),
            password=_decrypt_if_needed(ctrl.password),
            **kwargs,
        )

    async def _fail_job(
        self,
        job: AdoptionJob,
        error: str,
        session: AsyncSession,
        device: Device | None = None,
    ) -> dict[str, Any]:
        """Mark job as failed and update device state."""
        job.status = AdoptionJobStatus.FAILED
        job.error_message = error
        job.completed_at = datetime.now(UTC)

        if device:
            device.status = DeviceStatus.ADOPTION_FAILED
            device.lifecycle_state = LifecycleState.ERROR
            device.lifecycle_error = error

        await session.flush()

        if device:
            await self._publish_event(
                "adoption.failed",
                device,
                job,
                data={"error": error, "step": job.current_step},
            )

        return {"success": False, "error": error, "step": job.current_step}

    async def _publish_event(
        self,
        event_name: str,
        device: Device,
        job: AdoptionJob,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Publish adoption event via the event bus (org-scoped delivery).

        The previous implementation imported a ``connection_manager`` symbol
        from :mod:`app.services.websocket` that never existed — the module
        exposed ``websocket_manager`` instead, and that singleton has since
        been removed because its ``broadcast()`` helper
        did not filter by organization. This code path was therefore dead
        (every call fell into the ``except`` branch).

        It is now wired to the central event bus, which means the org-scoped
        WebSocket manager in :mod:`app.api.v1.endpoints.websocket` will
        forward the event only to clients belonging to ``job.organization_id``.
        """
        try:
            from app.core.events import (
                Event,
                EventCategory,
                EventPriority,
                get_event_bus,
            )

            payload: dict[str, Any] = {
                "organization_id": str(job.organization_id),
                "device_id": str(device.id),
                "device_name": device.name,
                "job_id": str(job.id),
                "status": job.status,
                "current_step": job.current_step,
                **(data or {}),
            }

            # Every caller already passes "adoption.<x>"; prefixing again published
            # "adoption.adoption.completed", which matched nothing the
            # integrations catalogue advertises.
            event = Event(
                event_type=event_name,
                payload=payload,
                category=EventCategory.SYSTEM,
                priority=EventPriority.NORMAL,
                source="ztp",
            )
            await get_event_bus().publish(event)
        except Exception:
            logger.debug("Failed to publish adoption event", exc_info=True)


# =========================================================================
# Provisioning Profile Service
# =========================================================================


class ProvisioningProfileService:
    """Service for managing provisioning profiles."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def apply_profile(
        self,
        device: Device,
        profile: ProvisioningProfile,
        *,
        force: bool = False,
        actor_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Apply a provisioning profile to an existing device.

        1. Resolve the configuration (profile payload over its linked template)
        2. Push it through the staging chokepoint: refused while read-only mode
           is on and without ``force``; recorded in the staging ledger
        3. Report what the device's adapter actually did
        """
        config = await resolve_profile_config(self.db, profile, device)
        if not config:
            return {"success": False, "error": "Profile has no configuration to apply"}

        orchestrator = AdoptionOrchestrator(
            ledger_session_factory=lambda: contextlib.nullcontext(self.db)
        )
        adapter = await orchestrator._get_adapter(device, self.db)
        if not adapter:
            return {"success": False, "error": "Cannot create adapter for device"}

        mac = device.mac_address or device.external_id or ""

        async def _push() -> Any:
            async with adapter:
                return await adapter.push_full_config(mac, config)

        try:
            result = await orchestrator._device_write(
                device=device,
                organization_id=profile.organization_id,
                feature="profile_apply",
                operation="update",
                payload={"profile_id": str(profile.id), "config": config},
                perform=_push,
                notes=f"provisioning profile {profile.id} applied",
                actor_id=actor_id,
                force=force,
            )
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to apply profile to device %s", device.id)
            return {"success": False, "error": "Failed to push configuration to device"}
        if _result_field(result, "success", False):
            return {"success": True, "config_pushed": True}
        # It used to answer "config_pushed: true" whatever the adapter said, and
        # no adapter implements a full-configuration push yet.
        if _result_field(result, "error_code") == "NOT_SUPPORTED":
            return {
                "success": False,
                "error": "this device's adapter cannot push a full configuration; "
                "nothing was changed on the device",
            }
        return {
            "success": False,
            "error": _result_field(result, "error") or "The device refused the configuration",
        }

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        """Deep merge two dicts, override values take precedence."""
        return _deep_merge(base, override)
