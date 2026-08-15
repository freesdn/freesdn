# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - RADIUS / 802.1X Service
=====================================

Business logic for RADIUS server profiles, 802.1X configuration
deployment, auth-event synchronisation, and health checking.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.crypto import decrypt_credential
from app.models.core import Controller, Site
from app.models.radius import Dot1xAuthEvent, Dot1xPortConfig, RadiusServerProfile
from app.services.adapter_factory import get_adapter

logger = logging.getLogger(__name__)


def _safe_decrypt(value: str | None) -> str:
    """Decrypt a credential, falling back to the raw value if not encrypted."""
    if not value:
        return ""
    try:
        return decrypt_credential(value)
    except Exception:
        logger.warning("Failed to decrypt credential value, returning raw value", exc_info=True)
        return value


class RadiusProfileService:
    """
    Service layer for RADIUS profiles, 802.1X config push,
    auth-event sync, and RADIUS server health checks.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # -----------------------------------------------------------------
    # Push 802.1X config to controller
    # -----------------------------------------------------------------

    async def push_dot1x_config(
        self, config_id: UUID, organization_id: UUID | None = None
    ) -> dict[str, Any]:
        """
        Push 802.1X settings to the target controller via its adapter.

        Loads the Dot1xPortConfig, its RadiusServerProfile, and the
        associated controller.  If the adapter exposes an
        ``update_dot1x_config()`` method the config is sent; otherwise
        the push is marked as unsupported.

        Parameters
        ----------
        config_id : UUID
            The Dot1xPortConfig to push.
        organization_id : UUID | None
            When provided, verifies the config belongs to this org
            by joining through Controller -> Site.
        """
        # Load config with org ownership verification
        query = select(Dot1xPortConfig).where(
            Dot1xPortConfig.id == config_id,
            Dot1xPortConfig.deleted_at.is_(None),
        )
        if organization_id:
            query = (
                query.join(Controller, Dot1xPortConfig.controller_id == Controller.id)
                .join(Site, Controller.site_id == Site.id)
                .where(Site.organization_id == organization_id)
            )
        result = await self.db.execute(query)
        config = result.scalar_one_or_none()
        if not config:
            return {"success": False, "error": "Dot1xPortConfig not found"}

        # Load RADIUS profile
        rp_result = await self.db.execute(
            select(RadiusServerProfile).where(
                RadiusServerProfile.id == config.radius_profile_id,
                RadiusServerProfile.deleted_at.is_(None),
            )
        )
        radius_profile = rp_result.scalar_one_or_none()
        if not radius_profile:
            config.push_status = "failed"
            await self.db.flush()
            return {"success": False, "error": "RADIUS profile not found"}

        # Load controller
        ctrl_result = await self.db.execute(
            select(Controller).where(
                Controller.id == config.controller_id,
                Controller.deleted_at.is_(None),
            )
        )
        controller = ctrl_result.scalar_one_or_none()
        if not controller:
            config.push_status = "failed"
            await self.db.flush()
            return {"success": False, "error": "Controller not found"}

        # Build adapter
        adapter_kwargs: dict[str, Any] = {
            "port": controller.port,
            "ssl": controller.use_ssl,
            "verify_ssl": controller.verify_ssl,
        }
        try:
            adapter = get_adapter(
                controller.controller_type,
                host=controller.host,
                username=_safe_decrypt(controller.username),
                password=_safe_decrypt(controller.password),
                **adapter_kwargs,
            )
        except Exception:
            logger.exception("Cannot create adapter for controller %s", controller.id)
            config.push_status = "failed"
            await self.db.flush()
            return {"success": False, "error": "Failed to initialize controller adapter"}

        # Push via adapter if method exists
        if not hasattr(adapter, "update_dot1x_config"):
            config.push_status = "failed"
            await self.db.flush()
            return {
                "success": False,
                "error": "Controller does not support 802.1X config push",
            }

        payload = {
            "auth_mode": config.auth_mode,
            "radius_host": radius_profile.host,
            "radius_port": radius_profile.port,
            "shared_secret": decrypt_credential(radius_profile.shared_secret_encrypted),
            "auth_protocol": radius_profile.auth_protocol,
            "guest_vlan_id": config.guest_vlan_id,
            "dynamic_vlan": config.dynamic_vlan,
            "reauthentication_interval": config.reauthentication_interval,
        }

        try:
            async with adapter:
                await adapter.update_dot1x_config(payload)

            config.push_status = "pushed"
            config.pushed_at = datetime.now(UTC)
            logger.info(
                "Pushed 802.1X config %s to controller %s",
                config_id,
                controller.id,
            )
            return {"success": True, "pushed_at": config.pushed_at.isoformat()}

        except Exception:
            logger.exception(
                "Failed to push 802.1X config %s",
                config_id,
            )
            config.push_status = "failed"
            await self.db.flush()
            return {"success": False, "error": "Failed to push 802.1X configuration to controller"}

    # -----------------------------------------------------------------
    # Sync auth events from controller
    # -----------------------------------------------------------------

    async def sync_auth_events(self, controller_id: UUID) -> dict[str, Any]:
        """
        Pull recent 802.1X authentication events from a controller.

        The adapter must expose ``get_dot1x_auth_events()`` returning a
        list of dicts with at least ``client_mac``, ``auth_result``, and
        ``timestamp``.
        """
        ctrl_result = await self.db.execute(
            select(Controller)
            .options(selectinload(Controller.site))
            .where(
                Controller.id == controller_id,
                Controller.deleted_at.is_(None),
            )
        )
        controller = ctrl_result.scalar_one_or_none()
        if not controller:
            return {"success": False, "error": "Controller not found", "synced": 0}

        adapter_kwargs: dict[str, Any] = {
            "port": controller.port,
            "ssl": controller.use_ssl,
            "verify_ssl": controller.verify_ssl,
        }
        try:
            adapter = get_adapter(
                controller.controller_type,
                host=controller.host,
                username=_safe_decrypt(controller.username),
                password=_safe_decrypt(controller.password),
                **adapter_kwargs,
            )
        except Exception:
            logger.exception("Cannot create adapter for controller %s", controller.id)
            return {
                "success": False,
                "error": "Failed to initialize controller adapter",
                "synced": 0,
            }

        if not hasattr(adapter, "get_dot1x_auth_events"):
            return {
                "success": False,
                "error": "Controller does not support auth-event sync",
                "synced": 0,
            }

        try:
            async with adapter:
                events: list[dict[str, Any]] = await adapter.get_dot1x_auth_events()
        except Exception:
            logger.exception(
                "Failed to fetch auth events from controller %s",
                controller.id,
            )
            return {
                "success": False,
                "error": "Failed to fetch auth events from controller",
                "synced": 0,
            }

        # Determine the organization_id from the controller's site
        org_id = getattr(controller, "organization_id", None)
        if not org_id and controller.site:
            org_id = getattr(controller.site, "organization_id", None)

        if not org_id:
            logger.warning(
                "Cannot determine org_id for controller %s, skipping sync", controller.id
            )
            return {
                "success": False,
                "error": "Cannot determine organization for controller",
                "synced": 0,
            }

        # Pre-load valid RADIUS profile IDs for this org to validate external data
        valid_profile_ids: set[UUID] = set()
        rp_result = await self.db.execute(
            select(RadiusServerProfile.id).where(
                RadiusServerProfile.organization_id == org_id,
                RadiusServerProfile.deleted_at.is_(None),
            )
        )
        valid_profile_ids = {row[0] for row in rp_result.all()}

        synced = 0
        for ev in events:
            try:
                # Validate radius_profile_id belongs to the org
                ev_radius_profile_id = ev.get("radius_profile_id")
                if ev_radius_profile_id and ev_radius_profile_id not in valid_profile_ids:
                    logger.warning(
                        "Skipping auth event with radius_profile_id %s not belonging to org %s",
                        ev_radius_profile_id,
                        org_id,
                    )
                    continue

                event = Dot1xAuthEvent(
                    organization_id=org_id,
                    controller_id=controller.id,
                    device_id=ev.get("device_id"),
                    client_mac=ev["client_mac"],
                    username=ev.get("username"),
                    auth_result=ev["auth_result"],
                    reject_reason=ev.get("reject_reason"),
                    assigned_vlan=ev.get("assigned_vlan"),
                    radius_profile_id=ev_radius_profile_id,
                    timestamp=ev.get(
                        "timestamp",
                        datetime.now(UTC),
                    ),
                )
                self.db.add(event)
                synced += 1
            except Exception as exc:
                logger.warning("Skipping malformed auth event: %s", exc)

        if synced:
            await self.db.flush()

        logger.info(
            "Synced %d auth events from controller %s",
            synced,
            controller.id,
        )
        return {"success": True, "synced": synced}

    # -----------------------------------------------------------------
    # RADIUS health check (TCP probe)
    # -----------------------------------------------------------------

    async def health_check(self, profile_id: UUID) -> dict[str, Any]:
        """
        TCP-connect to the RADIUS server's auth port to verify
        reachability.  Updates ``is_healthy`` and ``last_health_check``
        on the profile.
        """
        result = await self.db.execute(
            select(RadiusServerProfile).where(
                RadiusServerProfile.id == profile_id,
                RadiusServerProfile.deleted_at.is_(None),
            )
        )
        profile = result.scalar_one_or_none()
        if not profile:
            return {"success": False, "error": "RADIUS profile not found"}

        return await self.health_check_profile(profile)

    async def health_check_profile(self, profile: RadiusServerProfile) -> dict[str, Any]:
        """
        TCP-connect to the RADIUS server's auth port to verify
        reachability.  Accepts an already-loaded profile object to
        avoid redundant queries (N+1).

        Updates ``is_healthy`` and ``last_health_check`` on the profile.
        """
        is_healthy = False
        error_msg: str | None = None

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(profile.host, profile.port),
                timeout=profile.timeout_seconds,
            )
            writer.close()
            await writer.wait_closed()
            is_healthy = True
        except TimeoutError:
            error_msg = f"Connection timed out after {profile.timeout_seconds}s"
        except OSError:
            logger.exception("RADIUS health check connection error for profile %s", profile.id)
            error_msg = "Connection failed"

        now = datetime.now(UTC)
        profile.is_healthy = is_healthy
        profile.last_health_check = now

        logger.info(
            "RADIUS health check %s (%s:%d) -> %s",
            profile.name,
            profile.host,
            profile.port,
            "healthy" if is_healthy else error_msg,
        )

        return {
            "success": True,
            "profile_id": str(profile.id),
            "is_healthy": is_healthy,
            "checked_at": now.isoformat(),
            "error": error_msg,
        }
