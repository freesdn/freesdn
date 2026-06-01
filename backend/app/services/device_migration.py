# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Device Migration Service
===================================

Moves a device from one site to another. Currently supports phone
migration (voip.phones); designed to extend to cameras, switches,
firewalls, and the generic ``devices.devices`` shadow row.

What follows the device when it moves:
  * The canonical row's ``site_id``  (voip.phones, cameras.cameras, etc.)
  * The shadow ``devices.devices`` row (synced inventory).
  * ``core.device_firmware_status`` rows (firmware history is site-scoped).

What gets UNLINKED on migration (because they're site-scoped and the
old links would point to resources in the wrong site):
  * ``voip.phones.pbx_id`` / ``extension_id`` / ``config_template_id``
    — operator runs ``/voip/phones/auto-link`` after migration to bind
    to the new site's PBX.
  * The operator can opt to "follow links" via ``follow_links=True``,
    in which case the service tries to find equivalent resources in
    the target site by extension number + PBX host match. Otherwise
    the links are cleared.

Audit:
  Every migration emits a ``device.migrated`` event on the event bus
  AND writes a ``DEVICE_MIGRATED`` audit log row so the operator can
  later answer "when did this phone move and who did it".

Idempotency:
  Migrating a device already at the target site is a no-op (returns
  ``{moved: 0, no_op: True}``) — safe to retry.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import Event, EventCategory, EventPriority, get_event_bus

logger = logging.getLogger(__name__)


class DeviceMigrationError(Exception):
    """Raised when a migration cannot proceed (missing site, etc.)."""


class DeviceMigrationService:
    """Cross-cutting service for moving a device from one site to another."""

    def __init__(self, db: AsyncSession, organization_id: UUID | None = None):
        self.db = db
        self.organization_id = organization_id

    # ── Phone migration ──────────────────────────────────────────────

    async def migrate_phone(
        self,
        phone_id: UUID,
        target_site_id: UUID,
        *,
        actor_id: UUID | None = None,
        follow_links: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Move a single phone (voip.phones row) to a new site.

        Steps:
          1. Validate target site exists + caller has org access.
          2. If the phone is already at the target site → no-op.
          3. Update voip.phones.site_id.
          4. Update the shadow ``devices.devices`` row (matched by
             ``external_id = "voip_phone:<phone_id>"``).
          5. Migrate firmware_status rows.
          6. ``follow_links=False`` (default): clear pbx_id,
             extension_id, config_template_id. ``follow_links=True``:
             try to find equivalent resources in the target site.
          7. Emit ``device.migrated`` event + write audit log.

        ``dry_run=True`` returns the planned actions without writing.
        """
        from app.models.core import Site
        from app.models.devices import Device
        from app.modules.voip.models import (
            PBX,
            Extension,
            Phone,
        )

        # 1. Validate target site (org-scoped).
        target = await self._get_site(target_site_id)
        if not target:
            raise DeviceMigrationError(f"Target site {target_site_id} not found or not in your org")

        # 2. Load the phone, org-scoped.
        phone_q = select(Phone).where(
            Phone.id == phone_id,
            Phone.deleted_at.is_(None),
        )
        if self.organization_id:
            phone_q = phone_q.where(
                Phone.site_id.in_(
                    select(Site.id).where(Site.organization_id == self.organization_id)
                )
            )
        phone = (await self.db.execute(phone_q)).scalar_one_or_none()
        if not phone:
            raise DeviceMigrationError(f"Phone {phone_id} not found")

        source_site_id = phone.site_id

        # Idempotent no-op if already there.
        if source_site_id == target_site_id:
            return {
                "phone_id": str(phone_id),
                "source_site_id": str(source_site_id),
                "target_site_id": str(target_site_id),
                "no_op": True,
                "moved": 0,
                "message": "Phone is already at the target site",
            }

        # 3. Decide what to do with link references.
        plan: dict[str, Any] = {
            "phone_id": str(phone_id),
            "phone_ip": phone.ip_address,
            "source_site_id": str(source_site_id),
            "target_site_id": str(target_site_id),
            "target_site_name": target.name,
            "shadow_device_updated": False,
            "firmware_records_updated": 0,
            "pbx_unlinked": False,
            "pbx_rebound": False,
            "extension_unlinked": False,
            "extension_rebound": False,
            "template_unlinked": False,
        }

        # Decide what to do with the FreePBX link.
        new_pbx_id: UUID | None = None
        new_extension_id: UUID | None = None
        if phone.pbx_id and follow_links:
            # Try to find a PBX at the target site with the same host.
            old_pbx = await self.db.get(PBX, phone.pbx_id)
            if old_pbx:
                match_q = select(PBX).where(
                    PBX.site_id == target_site_id,
                    PBX.deleted_at.is_(None),
                    PBX.ip_address == old_pbx.ip_address,
                )
                new_pbx = (await self.db.execute(match_q)).scalar_one_or_none()
                if new_pbx:
                    new_pbx_id = new_pbx.id
                    plan["pbx_rebound"] = True
                    # If the new PBX has the same extension number, rebind it too.
                    if phone.extension_id:
                        old_ext = await self.db.get(Extension, phone.extension_id)
                        if old_ext:
                            ext_q = select(Extension).where(
                                Extension.pbx_id == new_pbx.id,
                                Extension.extension_number == old_ext.extension_number,
                                Extension.deleted_at.is_(None),
                            )
                            new_ext = (await self.db.execute(ext_q)).scalar_one_or_none()
                            if new_ext:
                                new_extension_id = new_ext.id
                                plan["extension_rebound"] = True

        if phone.pbx_id and not new_pbx_id:
            plan["pbx_unlinked"] = True
        if phone.extension_id and not new_extension_id:
            plan["extension_unlinked"] = True

        # Config templates are site-scoped; never auto-follow — always
        # require the operator to pick a new template after migration.
        if phone.config_template_id:
            plan["template_unlinked"] = True

        # Pre-flight the shadow device.
        shadow_q = select(Device).where(
            Device.external_id == f"voip_phone:{phone_id}",
            Device.deleted_at.is_(None),
        )
        shadow = (await self.db.execute(shadow_q)).scalar_one_or_none()
        if shadow:
            plan["shadow_device_updated"] = True

        # Firmware status records — count up-front for the plan.
        # Lives in app.models.firmware (not app.models.core).
        from app.models.firmware import DeviceFirmwareStatus

        fw_records: list[Any] = []
        if shadow:
            fw_q = select(DeviceFirmwareStatus).where(
                DeviceFirmwareStatus.device_id == shadow.id,
            )
            fw_records = list((await self.db.execute(fw_q)).scalars())
            plan["firmware_records_updated"] = len(fw_records)

        if dry_run:
            plan["status"] = "dry_run"
            plan["message"] = (
                f"Would move phone {phone.ip_address} from site "
                f"{source_site_id} to {target_site_id} ({target.name})"
            )
            return plan

        # ── Actually move things. ──────────────────────────────────
        phone.site_id = target_site_id
        if not new_pbx_id:
            phone.pbx_id = None
        else:
            phone.pbx_id = new_pbx_id
        if not new_extension_id:
            phone.extension_id = None
        else:
            phone.extension_id = new_extension_id
        if plan["template_unlinked"]:
            phone.config_template_id = None
        phone.updated_at = datetime.now(UTC)

        if shadow:
            shadow.site_id = target_site_id
            shadow.updated_at = datetime.now(UTC)

        for fw in fw_records:
            fw.site_id = target_site_id

        await self.db.commit()
        await self.db.refresh(phone)

        # Audit log — best effort. Don't roll back the migration if the
        # audit write fails.
        try:
            await self._write_audit_log(
                actor_id=actor_id,
                action="device.migrated",
                resource_type="voip.phone",
                resource_id=str(phone_id),
                details={
                    "phone_ip": phone.ip_address,
                    "source_site_id": str(source_site_id),
                    "target_site_id": str(target_site_id),
                    "target_site_name": target.name,
                    "follow_links": follow_links,
                    "pbx_rebound": plan["pbx_rebound"],
                    "extension_rebound": plan["extension_rebound"],
                },
            )
        except Exception as exc:
            logger.warning(
                "Audit log write failed for phone migration %s: %s",
                phone_id,
                exc,
            )

        # Event-bus emission — fan out to WebSocket subscribers so the
        # source-site UI can refresh "phone disappeared from here" and
        # the target-site UI can refresh "phone appeared here".
        try:
            await get_event_bus().publish(
                Event(
                    event_type="device.migrated",
                    category=EventCategory.DEVICE,
                    priority=EventPriority.NORMAL,
                    organization_id=str(self.organization_id) if self.organization_id else None,
                    payload={
                        "device_type": "voip.phone",
                        "device_id": str(phone_id),
                        "phone_ip": phone.ip_address,
                        "source_site_id": str(source_site_id),
                        "target_site_id": str(target_site_id),
                    },
                )
            )
        except Exception as exc:
            logger.debug("event-bus publish failed for device.migrated: %s", exc)

        plan["status"] = "success"
        plan["moved"] = 1
        plan["message"] = f"Phone {phone.ip_address} moved to {target.name}" + (
            ", PBX/extension rebound."
            if plan["pbx_rebound"]
            else " — links were cleared, run auto-link to bind to the new site's PBX."
        )
        return plan

    # ── Internals ────────────────────────────────────────────────────

    async def _get_site(self, site_id: UUID) -> Any:
        from app.models.core import Site

        q = select(Site).where(
            Site.id == site_id,
            Site.deleted_at.is_(None),
        )
        if self.organization_id:
            q = q.where(Site.organization_id == self.organization_id)
        return (await self.db.execute(q)).scalar_one_or_none()

    async def _write_audit_log(
        self,
        *,
        actor_id: UUID | None,
        action: str,
        resource_type: str,
        resource_id: str,
        details: dict[str, Any],
    ) -> None:
        """Append to audit.audit_logs — best effort.

        Schema lives in app.models.security_audit. The AuditLogRecord
        has a fixed schema with no JSONB "details" column — we stash
        the structured info into the ``metadata_json`` field.
        """
        from app.models.security_audit import AuditLogRecord

        log = AuditLogRecord(
            timestamp=datetime.now(UTC),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_id=str(actor_id) if actor_id else None,
            actor_type="user",
            organization_id=self.organization_id,
            site_id=UUID(details["target_site_id"]) if details.get("target_site_id") else None,
            status="success",
            extra_metadata=details,
        )
        self.db.add(log)
        await self.db.commit()
