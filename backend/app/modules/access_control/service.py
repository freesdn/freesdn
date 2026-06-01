# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Access Control Module Service
===========================================

Business logic for access control management.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import desc, func, select, text
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession

# stable transaction-advisory-lock key that serializes writers of
# the single global access-event tamper-evidence chain. pg_advisory_xact_lock
# auto-releases at transaction end. (Arbitrary constant within signed bigint.)
_ACCESS_EVENT_CHAIN_LOCK_KEY = 779_001_438

from app.core.config import settings
from app.core.security_utils import escape_like

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class AccessControlError(Exception):
    """Base access control error."""

    pass


class DoorNotFoundError(AccessControlError):
    """Door not found."""

    def __init__(self, door_id: UUID):
        super().__init__(f"Door not found: {door_id}")


class CredentialNotFoundError(AccessControlError):
    """Credential not found."""

    def __init__(self, credential_id: UUID):
        super().__init__(f"Credential not found: {credential_id}")


class CardholderNotFoundError(AccessControlError):
    """Cardholder not found."""

    def __init__(self, cardholder_id: UUID):
        super().__init__(f"Cardholder not found: {cardholder_id}")


class ScheduleNotFoundError(AccessControlError):
    """Schedule not found."""

    def __init__(self, schedule_id: UUID):
        super().__init__(f"Schedule not found: {schedule_id}")


class AccessControllerNotFoundError(AccessControlError):
    """Access controller not found."""

    def __init__(self, controller_id: UUID):
        super().__init__(f"Access controller not found: {controller_id}")


class EventNotFoundError(AccessControlError):
    """Access event not found."""

    def __init__(self, event_id: UUID):
        super().__init__(f"Access event not found: {event_id}")


class CrossTenantError(AccessControlError):
    """Caller attempted to reference a resource outside their org."""

    pass


class DoorControlUnavailableError(AccessControlError):
    """No hardware adapter is registered for the door's controller (C4)."""

    pass


# =============================================================================
# Hash chain helpers (H1) — mirrors app.services.audit
# =============================================================================


# NOTE (H1): Use AUDIT_HMAC_KEY where available so all tamper-evident chains
# in FreeSDN share a single secret. Fall back to SECRET_KEY if unset.
def _resolve_hmac_key() -> bytes:
    raw = getattr(settings, "AUDIT_HMAC_KEY", None) or settings.SECRET_KEY or ""
    if not raw:
        logger.error(
            "AUDIT_HMAC_KEY and SECRET_KEY are both empty; access-event chain "
            "HMAC is effectively public. This is a misconfiguration."
        )
        raw = "freesdn-access-fallback-key"
    if isinstance(raw, str):
        return raw.encode("utf-8")
    return raw


def _canonical_event_json(event: Any) -> bytes:
    """Deterministic JSON encoding of an AccessEvent (excludes chain cols)."""
    payload = {
        "id": str(event.id) if event.id else None,
        "door_id": str(event.door_id) if event.door_id else None,
        "credential_id": str(event.credential_id) if event.credential_id else None,
        "cardholder_id": str(event.cardholder_id) if event.cardholder_id else None,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "card_number": event.card_number,
        "description": event.description,
        "metadata_json": event.metadata_json,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _compute_event_hmac(prev_hash: str | None, event: Any) -> str:
    key = _resolve_hmac_key()
    msg = (prev_hash or "").encode("utf-8") + _canonical_event_json(event)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# =============================================================================
# Access Control Service
# =============================================================================

# NOTE (C1): These whitelists back the explicit field copies in
# create_/update_ methods. Pydantic schemas already enforce ``extra=forbid``,
# but we filter again defensively in case the service is invoked from
# non-API call sites with a raw dict (e.g. an internal Celery task).
_DOOR_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "door_number",
        "unlock_time",
        "held_open_time",
        "default_schedule_id",
        "location",
        "floor",
        "settings",
    }
)


# Maps the stored AccessEvent.event_type values to dotted Fabric bus event types
# (the Fabric source surface declared by AccessControlModule.get_emitted_events).
_ACCESS_BUS_EVENT_TYPE = {
    "access_granted": "access.door.granted",
    "access_denied": "access.door.denied",
    "door_forced": "access.door.forced",
    "door_held_open": "access.door.held_open",
    "door_unlocked": "access.door.unlocked",
    "door_locked": "access.door.locked",
    "alarm": "access.door.alarm",
}


class AccessControlService:
    """Service for access control management."""

    def __init__(
        self,
        db: AsyncSession,
        organization_id: UUID,
        accessible_site_ids: set[UUID] | None = None,
    ):
        self.db = db
        self.organization_id = organization_id
        # when set (site-limited caller), the org-sites scope
        # below is intersected with these grants — site-scoping EVERY read/list
        # that routes through _sites_for_org (doors, cardholders, credentials,
        # events, schedules) in one place. None = no per-site restriction.
        self.accessible_site_ids = accessible_site_ids

    def _sites_for_org(self):
        """Subquery of site IDs for the current organization (∩ site grants)."""
        from app.models.core import Site

        q = select(Site.id).where(
            Site.organization_id == self.organization_id,
            Site.deleted_at.is_(None),
        )
        if self.accessible_site_ids is not None:
            q = q.where(Site.id.in_(self.accessible_site_ids))
        return q.subquery()

    async def _assert_site_in_org(self, site_id: UUID) -> None:
        """NOTE (C1): Reject any site_id that doesn't belong to caller's org.

        also reject a non-granted site for a site-limited caller.
        """
        from app.models.core import Site

        result = await self.db.execute(
            select(Site.id).where(
                Site.id == site_id,
                Site.organization_id == self.organization_id,
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"site_id {site_id} is not in your organization")
        if self.accessible_site_ids is not None and site_id not in self.accessible_site_ids:
            raise CrossTenantError(f"site_id {site_id} is not in your accessible sites")

    async def _assert_controller_in_org(self, controller_id: UUID) -> None:
        """NOTE (C1): Reject any access-controller_id outside caller's org."""
        from app.modules.access_control.models import AccessController

        result = await self.db.execute(
            select(AccessController.id).where(
                AccessController.id == controller_id,
                AccessController.deleted_at.is_(None),
                AccessController.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"controller_id {controller_id} is not in your organization")

    async def _assert_cardholder_in_org(self, cardholder_id: UUID) -> None:
        """NOTE (C1): Reject any cardholder_id outside caller's org."""
        from app.modules.access_control.models import Cardholder

        result = await self.db.execute(
            select(Cardholder.id).where(
                Cardholder.id == cardholder_id,
                Cardholder.deleted_at.is_(None),
                Cardholder.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"cardholder_id {cardholder_id} is not in your organization")

    async def _assert_schedule_in_org(self, schedule_id: UUID) -> None:
        from app.modules.access_control.models import AccessSchedule

        result = await self.db.execute(
            select(AccessSchedule.id).where(
                AccessSchedule.id == schedule_id,
                AccessSchedule.deleted_at.is_(None),
                AccessSchedule.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"schedule_id {schedule_id} is not in your organization")

    async def _assert_user_in_org(self, user_id: UUID) -> None:
        """NOTE: reject a cardholder user_id outside caller's org.

        Cardholder.user_id is an FK to core.users; without this a tenant could
        stamp a foreign platform-user UUID into its own access records (audit-
        trail/referential-hygiene flaw). Mirrors the CameraAccessGrant precedent.
        """
        from app.models.core import User

        result = await self.db.execute(
            select(User.id).where(
                User.id == user_id,
                User.organization_id == self.organization_id,
                User.deleted_at.is_(None),
            )
        )
        if result.scalar_one_or_none() is None:
            raise CrossTenantError(f"user_id {user_id} is not in your organization")

    # -------------------------------------------------------------------------
    # Door Management
    # -------------------------------------------------------------------------

    async def list_doors(
        self,
        site_id: UUID | None = None,
        controller_id: UUID | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """List doors with optional filters."""
        from app.modules.access_control.models import Door

        query = select(Door).where(
            Door.deleted_at.is_(None),
            Door.site_id.in_(select(self._sites_for_org().c.id)),
        )

        if site_id:
            query = query.where(Door.site_id == site_id)
        if controller_id:
            query = query.where(Door.controller_id == controller_id)
        if status:
            query = query.where(Door.status == status)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(Door.name).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_door(self, door_id: UUID) -> Any:
        """Get a door by ID."""
        from app.modules.access_control.models import Door

        result = await self.db.execute(
            select(Door).where(
                Door.id == door_id,
                Door.deleted_at.is_(None),
                Door.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        door = result.scalar_one_or_none()

        if not door:
            raise DoorNotFoundError(door_id)

        return door

    async def create_door(self, data: dict[str, Any]) -> Any:
        """Create a new door.

        NOTE (C1): caller-supplied site_id + controller_id are validated
        against the org before insert; any non-whitelisted key in ``data``
        is silently dropped.
        """
        from app.modules.access_control.models import Door

        site_id = data.get("site_id")
        controller_id = data.get("controller_id")
        if site_id is None or controller_id is None:
            raise ValueError("site_id and controller_id are required")

        await self._assert_site_in_org(site_id)
        await self._assert_controller_in_org(controller_id)
        if data.get("default_schedule_id"):
            await self._assert_schedule_in_org(data["default_schedule_id"])

        allowed_create = _DOOR_MUTABLE_FIELDS | {"site_id", "controller_id"}
        filtered = {k: v for k, v in data.items() if k in allowed_create}

        door = Door(**filtered)
        self.db.add(door)
        await self.db.commit()
        await self.db.refresh(door)

        return door

    async def update_door(self, door_id: UUID, data: dict[str, Any]) -> Any:
        """Update a door."""
        door = await self.get_door(door_id)

        if data.get("default_schedule_id"):
            await self._assert_schedule_in_org(data["default_schedule_id"])

        for key, value in data.items():
            if key in _DOOR_MUTABLE_FIELDS and hasattr(door, key):
                setattr(door, key, value)

        await self.db.commit()
        await self.db.refresh(door)

        return door

    async def delete_door(self, door_id: UUID) -> bool:
        """Soft delete a door."""
        door = await self.get_door(door_id)
        door.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    async def _get_door_adapter(self, door: Any) -> Any | None:
        """
        Attempt to resolve an access control adapter for the door's controller.

        Returns an adapter instance that supports door control, or ``None``
        if no adapter is available for the controller's vendor type.

        NOTE (C4): All currently registered adapters (omada, hikvision, etc.)
        target network/camera/PBX devices — none implement lock_door /
        unlock_door. To avoid silently no-op'ing destructive requests, the
        unlock/lock endpoints now refuse with HTTP 501 instead of updating
        DB state without issuing hardware commands.

        Implementing this for real means writing an access-control adapter
        (HID Mercury, Axis A1601, Honeywell Pro-Watch, ZKTeco BioStar, or a
        generic SSH/script bridge). When added, register it in
        ``app.services.adapter_factory`` and ensure the class exposes
        ``async lock_door(door_number)`` and
        ``async unlock_door(door_number, duration)``.
        """
        from app.services.adapter_factory import AdapterNotFoundError, get_adapter_class

        controller = door.controller
        if controller is None:
            return None

        vendor = (controller.vendor or "").lower().strip()
        if not vendor:
            return None

        try:
            adapter_cls = get_adapter_class(vendor)
        except AdapterNotFoundError:
            return None

        # Adapter classes for non-access-control vendors don't have door
        # control methods. Probe for the API surface explicitly.
        if not hasattr(adapter_cls, "lock_door") or not hasattr(adapter_cls, "unlock_door"):
            return None

        # Future: instantiate with controller credentials. For now, no
        # door-capable adapters are registered, so we return None and the
        # caller refuses with 501.
        return None

    async def lock_door(self, door_id: UUID, actor_id: UUID | None = None) -> dict[str, Any]:
        """Lock a door remotely via its access controller adapter.

        NOTE (C4): If no hardware adapter is available we refuse the
        request rather than updating DB state.

        Audit log: every successful lock writes an AccessEvent of type
        ``remote_lock`` with the actor user_id and door_id so there's
        a forensic trail of physical-state changes.
        """
        door = await self.get_door(door_id)

        adapter = await self._get_door_adapter(door)
        if adapter is None:
            raise DoorControlUnavailableError(
                "No door controller adapter is registered for this door's "
                "controller. Hardware lock/unlock is not implemented. "
                "DB state was NOT changed."
            )

        try:
            await adapter.lock_door(door.door_number)
        except Exception as exc:
            logger.error("Adapter lock_door failed for door %s: %s", door_id, exc)
            raise AccessControlError(f"Failed to lock door via controller: {exc}") from exc

        door.is_locked = True
        door.status = "locked"
        door.last_status_change = datetime.now(UTC)
        await self.db.commit()

        # Audit log entry — physical security state change MUST be
        # recorded with actor_id (regulatory + forensic requirement).
        try:
            await self._store_event(
                {
                    "door_id": door_id,
                    "event_type": "remote_lock",
                    "description": f"Door locked by user {actor_id}" if actor_id else "Door locked",
                    "metadata_json": {"actor_user_id": str(actor_id) if actor_id else None},
                }
            )
        except Exception:
            logger.exception("Failed to log remote_lock audit event for door %s", door_id)

        return {
            "status": "ok",
            "door_id": str(door_id),
            "locked": True,
            "hardware_controlled": True,
        }

    async def unlock_door(
        self,
        door_id: UUID,
        duration: int | None = None,
        actor_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Unlock a door remotely via its access controller adapter.

        NOTE (C4 + H4): Refuses with 501-equivalent if no adapter; on
        success schedules a Celery re-lock so DB state matches the
        hardware after the unlock window elapses.

        Audit log: every successful unlock writes an AccessEvent of
        type ``remote_unlock`` with the actor user_id and door_id so
        there's a forensic trail of physical-state changes
        (regulatory + investigation requirement).
        """
        door = await self.get_door(door_id)

        unlock_time = duration or door.unlock_time

        adapter = await self._get_door_adapter(door)
        if adapter is None:
            raise DoorControlUnavailableError(
                "No door controller adapter is registered for this door's "
                "controller. Hardware lock/unlock is not implemented. "
                "DB state was NOT changed."
            )

        try:
            await adapter.unlock_door(door.door_number, duration=unlock_time)
        except Exception as exc:
            logger.error("Adapter unlock_door failed for door %s: %s", door_id, exc)
            raise AccessControlError(f"Failed to unlock door via controller: {exc}") from exc

        door.is_locked = False
        door.status = "unlocked"
        door.last_status_change = datetime.now(UTC)
        await self.db.commit()

        # Audit log entry — see comment on lock_door above.
        try:
            await self._store_event(
                {
                    "door_id": door_id,
                    "event_type": "remote_unlock",
                    "description": (
                        f"Door unlocked by user {actor_id} for {unlock_time}s"
                        if actor_id
                        else f"Door unlocked for {unlock_time}s"
                    ),
                    "metadata_json": {
                        "actor_user_id": str(actor_id) if actor_id else None,
                        "duration_seconds": int(unlock_time or 0),
                    },
                }
            )
        except Exception:
            logger.exception("Failed to log remote_unlock audit event for door %s", door_id)

        # NOTE (H4): Hardware controllers typically re-lock themselves
        # after their configured strike-time, but if the request used a
        # custom duration the DB state would drift until the next sync.
        # Schedule a Celery task to flip the row back. See
        # ``relock_door_after`` at the bottom of this module.
        try:
            relock_door_after.apply_async(
                args=[str(door_id)],
                countdown=max(int(unlock_time), 1),
                queue="default",
            )
        except Exception:
            logger.exception(
                "Failed to schedule re-lock for door %s; DB state may drift until next sync.",
                door_id,
            )

        return {
            "status": "ok",
            "door_id": str(door_id),
            "locked": False,
            "unlock_duration": unlock_time,
            "hardware_controlled": True,
        }

    async def get_door_stats(self, site_id: UUID | None = None) -> dict[str, int]:
        """Get door statistics."""
        from app.modules.access_control.models import Door, DoorStatus

        query = select(Door.status, func.count(Door.id)).where(
            Door.deleted_at.is_(None),
            Door.site_id.in_(select(self._sites_for_org().c.id)),
        )

        if site_id:
            query = query.where(Door.site_id == site_id)

        query = query.group_by(Door.status)

        result = await self.db.execute(query)
        stats = dict(result.all())

        return {
            "total": sum(stats.values()),
            "locked": stats.get(DoorStatus.LOCKED.value, 0),
            "unlocked": stats.get(DoorStatus.UNLOCKED.value, 0),
            "open": stats.get(DoorStatus.OPEN.value, 0),
            "offline": stats.get(DoorStatus.OFFLINE.value, 0),
        }

    # -------------------------------------------------------------------------
    # Credential Management
    # -------------------------------------------------------------------------

    async def list_credentials(
        self,
        cardholder_id: UUID | None = None,
        credential_type: str | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """List credentials."""
        from app.modules.access_control.models import AccessCredential, Cardholder

        query = (
            select(AccessCredential)
            .join(Cardholder, AccessCredential.cardholder_id == Cardholder.id)
            .where(
                AccessCredential.deleted_at.is_(None),
                Cardholder.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )

        if cardholder_id:
            query = query.where(AccessCredential.cardholder_id == cardholder_id)
        if credential_type:
            query = query.where(AccessCredential.credential_type == credential_type)
        if is_active is not None:
            query = query.where(AccessCredential.is_active == is_active)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(AccessCredential.created_at.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_credential(self, credential_id: UUID) -> Any:
        """Get a credential by ID."""
        from app.modules.access_control.models import AccessCredential, Cardholder

        result = await self.db.execute(
            select(AccessCredential)
            .join(Cardholder, AccessCredential.cardholder_id == Cardholder.id)
            .where(
                AccessCredential.id == credential_id,
                AccessCredential.deleted_at.is_(None),
                Cardholder.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        credential = result.scalar_one_or_none()

        if not credential:
            raise CredentialNotFoundError(credential_id)

        return credential

    async def create_credential(self, data: dict[str, Any]) -> Any:
        """Create a new credential.

        NOTE (C1 + C2): cardholder_id is validated against the org; PIN
        is Argon2id-hashed, card_number + facility_code are Fernet-encrypted
        before persistence.
        """
        from app.modules.access_control.models import AccessCredential

        cardholder_id = data.get("cardholder_id")
        if cardholder_id is None:
            raise ValueError("cardholder_id is required")
        await self._assert_cardholder_in_org(cardholder_id)

        allowed = {
            "cardholder_id",
            "credential_type",
            "is_active",
            "activation_date",
            "expiration_date",
            "settings",
        }
        scalar_args = {k: v for k, v in data.items() if k in allowed}

        credential = AccessCredential(**scalar_args)
        # Sensitive fields go through the encryption / hash helpers
        credential.set_card_number(data.get("card_number"))
        credential.set_facility_code(data.get("facility_code"))
        credential.set_pin(data.get("pin"))

        self.db.add(credential)
        await self.db.commit()
        await self.db.refresh(credential)

        return credential

    async def update_credential(self, credential_id: UUID, data: dict[str, Any]) -> Any:
        """Update a credential (excluding sensitive plaintext echo)."""
        credential = await self.get_credential(credential_id)

        mutable = {
            "credential_type",
            "is_active",
            "activation_date",
            "expiration_date",
            "settings",
        }
        for key, value in data.items():
            if key in mutable and hasattr(credential, key):
                setattr(credential, key, value)

        # Sensitive fields — only re-set when explicitly supplied (None
        # clears, missing leaves alone).
        if "card_number" in data:
            credential.set_card_number(data["card_number"])
        if "facility_code" in data:
            credential.set_facility_code(data["facility_code"])
        if "pin" in data:
            credential.set_pin(data["pin"])

        await self.db.commit()
        await self.db.refresh(credential)
        return credential

    async def revoke_credential(self, credential_id: UUID) -> bool:
        """Revoke a credential."""
        credential = await self.get_credential(credential_id)
        credential.is_active = False
        await self.db.commit()
        return True

    # -------------------------------------------------------------------------
    # Cardholder Management
    # -------------------------------------------------------------------------

    async def list_cardholders(
        self,
        site_id: UUID | None = None,
        is_active: bool | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """List cardholders."""
        from app.modules.access_control.models import Cardholder

        query = select(Cardholder).where(
            Cardholder.deleted_at.is_(None),
            Cardholder.site_id.in_(select(self._sites_for_org().c.id)),
        )

        if site_id:
            query = query.where(Cardholder.site_id == site_id)
        if is_active is not None:
            query = query.where(Cardholder.is_active == is_active)
        if search:
            escaped = escape_like(search)
            search_filter = f"%{escaped}%"
            query = query.where(
                (Cardholder.first_name.ilike(search_filter, escape="\\"))
                | (Cardholder.last_name.ilike(search_filter, escape="\\"))
                | (Cardholder.email.ilike(search_filter, escape="\\"))
                | (Cardholder.employee_id.ilike(search_filter, escape="\\"))
            )

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = (
            query.order_by(Cardholder.last_name, Cardholder.first_name).limit(limit).offset(offset)
        )

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_cardholder(self, cardholder_id: UUID) -> Any:
        """Get a cardholder by ID."""
        from app.modules.access_control.models import Cardholder

        result = await self.db.execute(
            select(Cardholder).where(
                Cardholder.id == cardholder_id,
                Cardholder.deleted_at.is_(None),
                Cardholder.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        cardholder = result.scalar_one_or_none()

        if not cardholder:
            raise CardholderNotFoundError(cardholder_id)

        return cardholder

    async def create_cardholder(self, data: dict[str, Any]) -> Any:
        """Create a new cardholder.

        NOTE (C1): site_id validated against caller's org.
        """
        from app.modules.access_control.models import Cardholder

        site_id = data.get("site_id")
        if site_id is None:
            raise ValueError("site_id is required")
        await self._assert_site_in_org(site_id)

        # validate the optional platform-user link too.
        user_id = data.get("user_id")
        if user_id is not None:
            await self._assert_user_in_org(user_id)

        allowed = {
            "site_id",
            "user_id",
            "first_name",
            "last_name",
            "email",
            "phone",
            "employee_id",
            "department",
            "title",
            "is_active",
            "activation_date",
            "expiration_date",
            "photo_url",
            "settings",
        }
        filtered = {k: v for k, v in data.items() if k in allowed}

        cardholder = Cardholder(**filtered)
        self.db.add(cardholder)
        await self.db.commit()
        await self.db.refresh(cardholder)
        return cardholder

    async def update_cardholder(self, cardholder_id: UUID, data: dict[str, Any]) -> Any:
        """Update a cardholder."""
        cardholder = await self.get_cardholder(cardholder_id)

        mutable = {
            "first_name",
            "last_name",
            "email",
            "phone",
            "employee_id",
            "department",
            "title",
            "is_active",
            "activation_date",
            "expiration_date",
            "photo_url",
            "settings",
        }
        for key, value in data.items():
            if key in mutable and hasattr(cardholder, key):
                setattr(cardholder, key, value)

        await self.db.commit()
        await self.db.refresh(cardholder)
        return cardholder

    async def delete_cardholder(self, cardholder_id: UUID) -> bool:
        """Soft delete a cardholder."""
        cardholder = await self.get_cardholder(cardholder_id)
        cardholder.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    # -------------------------------------------------------------------------
    # Schedule Management (H3)
    # -------------------------------------------------------------------------

    async def list_schedules(
        self,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        from app.modules.access_control.models import AccessSchedule

        query = select(AccessSchedule).where(
            AccessSchedule.deleted_at.is_(None),
            AccessSchedule.site_id.in_(select(self._sites_for_org().c.id)),
        )
        if site_id:
            query = query.where(AccessSchedule.site_id == site_id)
        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(AccessSchedule.name).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_schedule(self, schedule_id: UUID) -> Any:
        from app.modules.access_control.models import AccessSchedule

        result = await self.db.execute(
            select(AccessSchedule).where(
                AccessSchedule.id == schedule_id,
                AccessSchedule.deleted_at.is_(None),
                AccessSchedule.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        schedule = result.scalar_one_or_none()
        if not schedule:
            raise ScheduleNotFoundError(schedule_id)
        return schedule

    async def create_schedule(self, data: dict[str, Any]) -> Any:
        from app.modules.access_control.models import AccessSchedule

        site_id = data.get("site_id")
        if site_id is None:
            raise ValueError("site_id is required")
        await self._assert_site_in_org(site_id)

        allowed = {
            "site_id",
            "name",
            "description",
            "is_24_7",
            "intervals",
            "honor_holidays",
            "is_active",
        }
        filtered = {k: v for k, v in data.items() if k in allowed}

        schedule = AccessSchedule(**filtered)
        self.db.add(schedule)
        await self.db.commit()
        await self.db.refresh(schedule)
        return schedule

    async def update_schedule(self, schedule_id: UUID, data: dict[str, Any]) -> Any:
        schedule = await self.get_schedule(schedule_id)
        mutable = {
            "name",
            "description",
            "is_24_7",
            "intervals",
            "honor_holidays",
            "is_active",
        }
        for key, value in data.items():
            if key in mutable and hasattr(schedule, key):
                setattr(schedule, key, value)
        await self.db.commit()
        await self.db.refresh(schedule)
        return schedule

    async def delete_schedule(self, schedule_id: UUID) -> bool:
        schedule = await self.get_schedule(schedule_id)
        schedule.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    # -------------------------------------------------------------------------
    # Access Controller Management (H3)
    # -------------------------------------------------------------------------

    async def list_controllers(
        self,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        from app.modules.access_control.models import AccessController

        query = select(AccessController).where(
            AccessController.deleted_at.is_(None),
            AccessController.site_id.in_(select(self._sites_for_org().c.id)),
        )
        if site_id:
            query = query.where(AccessController.site_id == site_id)
        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(AccessController.name).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_controller(self, controller_id: UUID) -> Any:
        from app.modules.access_control.models import AccessController

        result = await self.db.execute(
            select(AccessController).where(
                AccessController.id == controller_id,
                AccessController.deleted_at.is_(None),
                AccessController.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        ctrl = result.scalar_one_or_none()
        if not ctrl:
            raise AccessControllerNotFoundError(controller_id)
        return ctrl

    async def create_controller(self, data: dict[str, Any]) -> Any:
        from app.modules.access_control.models import AccessController

        site_id = data.get("site_id")
        if site_id is None:
            raise ValueError("site_id is required")
        await self._assert_site_in_org(site_id)

        allowed = {
            "site_id",
            "device_controller_id",
            "name",
            "description",
            "ip_address",
            "port",
            "mac_address",
            "vendor",
            "model",
            "firmware_version",
            "serial_number",
            "door_capacity",
            "reader_capacity",
            "settings",
        }
        filtered = {k: v for k, v in data.items() if k in allowed}

        ctrl = AccessController(**filtered)
        self.db.add(ctrl)
        await self.db.commit()
        await self.db.refresh(ctrl)
        return ctrl

    async def update_controller(self, controller_id: UUID, data: dict[str, Any]) -> Any:
        ctrl = await self.get_controller(controller_id)
        mutable = {
            "name",
            "description",
            "ip_address",
            "port",
            "mac_address",
            "vendor",
            "model",
            "firmware_version",
            "serial_number",
            "door_capacity",
            "reader_capacity",
            "settings",
        }
        for key, value in data.items():
            if key in mutable and hasattr(ctrl, key):
                setattr(ctrl, key, value)
        await self.db.commit()
        await self.db.refresh(ctrl)
        return ctrl

    async def delete_controller(self, controller_id: UUID) -> bool:
        ctrl = await self.get_controller(controller_id)
        ctrl.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    # -------------------------------------------------------------------------
    # Access Events
    # -------------------------------------------------------------------------

    async def _store_event(self, event_data: dict[str, Any]) -> Any:
        """Persist an AccessEvent with tamper-evidence hash chain (H1).

        NOTE (H1 + R5): The chain is extended inside a SAVEPOINT. A
        transaction-scoped advisory lock serializes concurrent chain writers
        BEFORE the tail-read — `SELECT ... FOR UPDATE` alone is insufficient
        under READ COMMITTED, since it locks only the existing tail row and
        takes no gap lock, so two writers could both read the same tail and
        branch the chain (a false "tampering detected" at verify time). The
        advisory lock makes the read-then-append atomic across writers and
        auto-releases at transaction end. Falls back to "unchained" if the
        columns aren't present yet (migration not applied).
        """
        from app.modules.access_control.models import AccessEvent, Door

        # Validate door_id belongs to org if provided
        door_id = event_data.get("door_id")
        if door_id is not None:
            door_check = await self.db.execute(
                select(Door.id).where(
                    Door.id == door_id,
                    Door.site_id.in_(select(self._sites_for_org().c.id)),
                )
            )
            if door_check.scalar_one_or_none() is None:
                raise CrossTenantError(f"door_id {door_id} is not in your organization")

        allowed = {
            "door_id",
            "credential_id",
            "cardholder_id",
            "event_type",
            "timestamp",
            "card_number",
            "description",
            "metadata_json",
        }
        filtered = {k: v for k, v in event_data.items() if k in allowed}
        if "timestamp" not in filtered:
            filtered["timestamp"] = datetime.now(UTC)

        event = AccessEvent(**filtered)

        try:
            async with self.db.begin_nested():
                # Serialize chain writers before reading the tail. Best-effort:
                # suppressed on non-PostgreSQL backends (e.g. SQLite tests),
                # which are single-threaded so cannot branch anyway.
                with contextlib.suppress(Exception):
                    await self.db.execute(
                        text("SELECT pg_advisory_xact_lock(:k)"),
                        {"k": _ACCESS_EVENT_CHAIN_LOCK_KEY},
                    )

                prev_hmac: str | None = None
                try:
                    latest = await self.db.execute(
                        select(AccessEvent.row_hmac)
                        .order_by(desc(AccessEvent.timestamp), desc(AccessEvent.id))
                        .limit(1)
                        .with_for_update()
                    )
                    prev_hmac = latest.scalar_one_or_none()
                except (OperationalError, ProgrammingError):
                    prev_hmac = None

                event.prev_hash = prev_hmac
                try:
                    event.row_hmac = _compute_event_hmac(prev_hmac, event)
                except Exception:
                    logger.exception("access-event chain HMAC computation failed")
                    event.row_hmac = None

                self.db.add(event)
        except Exception:
            # If the savepoint itself blows up, fall back to unchained insert.
            logger.exception("access-event chain savepoint failed; inserting unchained")
            event.prev_hash = None
            event.row_hmac = None
            self.db.add(event)

        await self.db.commit()
        await self.db.refresh(event)

        # Fabric event source: surface the access event on the bus so an
        # operator can wire it (e.g. "door forced → cameras.snapshot →
        # storage.store_blob"). Best-effort — a publish failure must NEVER lose
        # the tamper-evident audit row that was just committed.
        try:
            from app.core.events import (
                Event,
                EventCategory,
                EventPriority,
                get_event_bus,
            )

            raw = getattr(event, "event_type", "")
            et = raw.value if hasattr(raw, "value") else str(raw or "")
            bus_type = _ACCESS_BUS_EVENT_TYPE.get(et)
            if bus_type:
                pri = (
                    EventPriority.HIGH
                    if et in ("door_forced", "door_held_open", "access_denied", "alarm")
                    else EventPriority.NORMAL
                )
                await get_event_bus().publish(
                    Event(
                        event_type=bus_type,
                        category=EventCategory.SECURITY,
                        priority=pri,
                        payload={
                            "door_id": str(event.door_id) if event.door_id else None,
                            "credential_id": (
                                str(event.credential_id)
                                if getattr(event, "credential_id", None)
                                else None
                            ),
                            "cardholder_id": (
                                str(event.cardholder_id)
                                if getattr(event, "cardholder_id", None)
                                else None
                            ),
                            "event_type": et,
                            "card_number": getattr(event, "card_number", None),
                            "description": getattr(event, "description", None),
                        },
                        organization_id=str(self.organization_id) if self.organization_id else None,
                        source="access_control",
                    )
                )
        except Exception:
            logger.debug("access-event bus publish skipped", exc_info=True)

        return event

    async def search_events(
        self,
        door_id: UUID | None = None,
        cardholder_id: UUID | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[Any]:
        """Search access events.

        NOTE (H2): If ``cardholder_id`` is supplied we pre-validate it
        belongs to caller's org. Without this, a caller could probe for
        the existence of arbitrary cardholder IDs by checking whether
        the query returns any events.
        """
        from app.modules.access_control.models import AccessEvent, Door

        if cardholder_id is not None:
            # Raises CardholderNotFoundError if outside org — let it bubble
            # up so the API can translate to 404.
            await self.get_cardholder(cardholder_id)

        org_sites = self._sites_for_org()
        query = (
            select(AccessEvent)
            .join(Door, AccessEvent.door_id == Door.id)
            .where(Door.site_id.in_(select(org_sites.c.id)))
        )

        if door_id:
            query = query.where(AccessEvent.door_id == door_id)
        if cardholder_id:
            query = query.where(AccessEvent.cardholder_id == cardholder_id)
        if event_type:
            query = query.where(AccessEvent.event_type == event_type)
        if start_time:
            query = query.where(AccessEvent.timestamp >= start_time)
        if end_time:
            query = query.where(AccessEvent.timestamp <= end_time)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(AccessEvent.timestamp.desc()).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def acknowledge_event(self, event_id: UUID, user_id: UUID) -> Any:
        """Acknowledge an access event (H3)."""
        from app.modules.access_control.models import AccessEvent, Door

        result = await self.db.execute(
            select(AccessEvent)
            .join(Door, AccessEvent.door_id == Door.id)
            .where(
                AccessEvent.id == event_id,
                Door.site_id.in_(select(self._sites_for_org().c.id)),
            )
        )
        event = result.scalar_one_or_none()
        if not event:
            raise EventNotFoundError(event_id)

        event.is_acknowledged = True
        event.acknowledged_by = user_id
        event.acknowledged_at = datetime.now(UTC)
        await self.db.commit()
        await self.db.refresh(event)
        return event

    async def validate_event_chain(
        self,
        door_id: UUID | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Walk the access-event hash chain and verify each row's HMAC (H1).

        Returns ``{"valid", "checked", "unchained", "broken_at",
        "broken_reason"}`` in the same shape used by the audit log
        validator. Tolerates pre-migration "unchained" rows.
        """
        from app.modules.access_control.models import AccessEvent, Door

        query = (
            select(AccessEvent)
            .join(Door, AccessEvent.door_id == Door.id)
            .where(Door.site_id.in_(select(self._sites_for_org().c.id)))
        )
        if door_id is not None:
            query = query.where(AccessEvent.door_id == door_id)
        if start_at is not None:
            query = query.where(AccessEvent.timestamp >= start_at)
        if end_at is not None:
            query = query.where(AccessEvent.timestamp <= end_at)
        query = query.order_by(AccessEvent.timestamp.asc(), AccessEvent.id.asc())

        result = await self.db.execute(query)
        rows = list(result.scalars().all())

        checked = 0
        unchained = 0
        last_seen_hmac: str | None = None
        for row in rows:
            checked += 1
            if row.row_hmac is None:
                unchained += 1
                last_seen_hmac = None
                continue

            if last_seen_hmac is not None and row.prev_hash != last_seen_hmac:
                return {
                    "valid": False,
                    "checked": checked,
                    "unchained": unchained,
                    "broken_at": str(row.id),
                    "broken_reason": (
                        f"prev_hash mismatch: expected {last_seen_hmac!r} got {row.prev_hash!r}"
                    ),
                }

            expected = _compute_event_hmac(row.prev_hash, row)
            if not hmac.compare_digest(expected, row.row_hmac):
                return {
                    "valid": False,
                    "checked": checked,
                    "unchained": unchained,
                    "broken_at": str(row.id),
                    "broken_reason": "row_hmac mismatch (row body modified)",
                }
            last_seen_hmac = row.row_hmac

        return {
            "valid": True,
            "checked": checked,
            "unchained": unchained,
            "broken_at": None,
            "broken_reason": None,
        }

    async def get_event_stats(
        self,
        site_id: UUID | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Get access event statistics."""
        from app.modules.access_control.models import AccessEvent, Door, EventType

        org_sites = self._sites_for_org()
        query = (
            select(AccessEvent.event_type, func.count(AccessEvent.id))
            .join(Door, AccessEvent.door_id == Door.id)
            .where(Door.site_id.in_(select(org_sites.c.id)))
        )

        if site_id:
            query = query.where(Door.site_id == site_id)
        if start_time:
            query = query.where(AccessEvent.timestamp >= start_time)
        if end_time:
            query = query.where(AccessEvent.timestamp <= end_time)

        query = query.group_by(AccessEvent.event_type)

        result = await self.db.execute(query)
        stats = dict(result.all())

        return {
            "total": sum(stats.values()),
            "granted": stats.get(EventType.ACCESS_GRANTED.value, 0),
            "denied": stats.get(EventType.ACCESS_DENIED.value, 0),
            "forced": stats.get(EventType.DOOR_FORCED.value, 0),
            "held_open": stats.get(EventType.DOOR_HELD_OPEN.value, 0),
        }


# =============================================================================
# Celery task: scheduled re-lock (H4)
# =============================================================================

# NOTE (H4): Defined here (rather than a dedicated tasks.py) because
# tasks.py is outside the allowed file scope for this fix. The task is
# wired into the celery worker via the module's ``get_tasks()`` method
# in ``module.py``, which also returns a reference to ``celery_app``'s
# task registry. The decorator runs at import time and registers the
# task in celery_app.
import asyncio  # noqa: E402

from app.core.celery_app import celery_app  # noqa: E402
from app.db.session import CelerySessionLocal as _AsyncSessionLocal  # noqa: E402


async def _do_relock(door_id: UUID) -> dict[str, Any]:
    """Flip a door's DB status back to locked after the unlock window."""
    from app.modules.access_control.models import Door

    async with _AsyncSessionLocal() as session:
        result = await session.execute(
            select(Door).where(Door.id == door_id, Door.deleted_at.is_(None))
        )
        door = result.scalar_one_or_none()
        if door is None:
            return {"success": False, "error": "door not found"}

        if door.is_locked:
            return {"success": True, "skipped": "already locked"}

        door.is_locked = True
        door.status = "locked"
        door.last_status_change = datetime.now(UTC)
        await session.commit()
        return {"success": True, "door_id": str(door_id)}


@celery_app.task(name="access_control.relock_door_after", queue="default")
def relock_door_after(door_id: str) -> dict[str, Any]:
    """Celery task — schedule the DB re-lock after an unlock window (H4)."""
    try:
        return asyncio.run(_do_relock(UUID(door_id)))
    except Exception as exc:
        logger.exception("Failed to re-lock door %s after unlock window", door_id)
        return {"success": False, "error": str(exc)}
