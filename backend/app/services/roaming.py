# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Client Roaming Analytics Service
================================================

Analyses 802.11r/k/v roaming events, detects sticky clients,
and pushes roaming configuration to controllers.
"""

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import site_ids_for_request
from app.models.devices import Device
from app.modules.network.models import ClientRoamingEvent, WifiNetwork

logger = logging.getLogger(__name__)


def _granted_roaming_pred():
    """(R5)per-user site-grant predicate for roaming events.

    ``ClientRoamingEvent`` has no ``site_id`` column; its site dimension is the
    owning site of the from/to AP devices. When the request caller is
    site-limited, constrain events to those whose source OR target AP belongs to
    a granted site. Returns ``None`` for unrestricted / admin / background
    callers (``current_user_var`` unset) so the filter is a strict no-op there.
    """
    granted = site_ids_for_request()
    if granted is None:
        return None
    dev = select(Device.id).where(Device.site_id.in_(granted)).scalar_subquery()
    return or_(
        ClientRoamingEvent.from_device_id.in_(dev),
        ClientRoamingEvent.to_device_id.in_(dev),
    )


def _safe_decrypt(value: str | None) -> str:
    """Decrypt a credential, falling back to the raw value if not encrypted."""
    if not value:
        return ""
    try:
        from app.core.crypto import decrypt_credential, is_encrypted

        if not is_encrypted(value):
            return value
        return decrypt_credential(value)
    except Exception:
        logger.warning("Failed to decrypt credential value, returning raw value", exc_info=True)
        return value


class RoamingAnalyticsService:
    """Service for client roaming analytics and configuration."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ──────────────────────────────────────────────────────────────────────
    # Roaming Events (paginated)
    # ──────────────────────────────────────────────────────────────────────

    async def list_roaming_events(
        self,
        org_id: UUID,
        *,
        client_mac: str | None = None,
        device_id: UUID | None = None,
        hours: int = 24,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list, int]:
        """
        Return paginated roaming events for the organisation.

        Parameters
        ----------
        org_id : UUID
            Organisation scope.
        client_mac : str | None
            Optional filter by client MAC address.
        device_id : UUID | None
            Optional filter by AP device (either source or target).
        hours : int
            Look-back window in hours (default 24).
        limit, offset : int
            Pagination.

        Returns
        -------
        tuple[list, int]
            (events, total_count)
        """
        since = datetime.now(UTC) - timedelta(hours=hours)

        base = select(ClientRoamingEvent).where(
            ClientRoamingEvent.organization_id == org_id,
            ClientRoamingEvent.timestamp >= since,
        )

        if client_mac:
            base = base.where(ClientRoamingEvent.client_mac == client_mac)
        if device_id:
            base = base.where(
                (ClientRoamingEvent.from_device_id == device_id)
                | (ClientRoamingEvent.to_device_id == device_id)
            )
        _grant = _granted_roaming_pred()
        if _grant is not None:
            base = base.where(_grant)

        # Total count
        count_q = select(func.count()).select_from(base.subquery())
        total = (await self.db.execute(count_q)).scalar() or 0

        # Paginated results (newest first)
        q = base.order_by(ClientRoamingEvent.timestamp.desc()).offset(offset).limit(limit)
        result = await self.db.execute(q)
        events = list(result.scalars().all())

        return events, total

    # ──────────────────────────────────────────────────────────────────────
    # Aggregate Stats
    # ──────────────────────────────────────────────────────────────────────

    async def get_roaming_stats(
        self,
        org_id: UUID,
        hours: int = 24,
    ) -> dict:
        """
        Compute aggregate roaming statistics for the look-back period.

        Returns
        -------
        dict
            {
              "total_roams": int,
              "avg_roam_time_ms": float | None,
              "roam_type_breakdown": {"802.11r": int, ...},
              "per_ap_stats": [{"device_id": str, "roams_in": int, "roams_out": int}, ...],
            }
        """
        since = datetime.now(UTC) - timedelta(hours=hours)

        base_filter = [
            ClientRoamingEvent.organization_id == org_id,
            ClientRoamingEvent.timestamp >= since,
        ]
        _grant = _granted_roaming_pred()
        if _grant is not None:
            base_filter.append(_grant)

        # Total roams
        total_q = select(func.count()).where(*base_filter)
        total_roams = (await self.db.execute(total_q)).scalar() or 0

        # Average roam time
        avg_q = select(func.avg(ClientRoamingEvent.roam_time_ms)).where(*base_filter)
        avg_roam_time = (await self.db.execute(avg_q)).scalar()

        # Breakdown by roam type
        type_q = (
            select(
                ClientRoamingEvent.roam_type,
                func.count().label("count"),
            )
            .where(*base_filter)
            .group_by(ClientRoamingEvent.roam_type)
        )
        type_rows = (await self.db.execute(type_q)).all()
        roam_type_breakdown = {row[0] or "unknown": row[1] for row in type_rows}

        # Per-AP stats (roams out = from_device, roams in = to_device)
        out_q = (
            select(
                ClientRoamingEvent.from_device_id.label("device_id"),
                func.count().label("roams_out"),
            )
            .where(*base_filter, ClientRoamingEvent.from_device_id.isnot(None))
            .group_by(ClientRoamingEvent.from_device_id)
        )
        out_rows = {str(row[0]): row[1] for row in (await self.db.execute(out_q)).all()}

        in_q = (
            select(
                ClientRoamingEvent.to_device_id.label("device_id"),
                func.count().label("roams_in"),
            )
            .where(*base_filter, ClientRoamingEvent.to_device_id.isnot(None))
            .group_by(ClientRoamingEvent.to_device_id)
        )
        in_rows = {str(row[0]): row[1] for row in (await self.db.execute(in_q)).all()}

        all_device_ids = set(out_rows.keys()) | set(in_rows.keys())
        per_ap_stats = [
            {
                "device_id": did,
                "roams_in": in_rows.get(did, 0),
                "roams_out": out_rows.get(did, 0),
            }
            for did in sorted(all_device_ids)
        ]

        return {
            "total_roams": total_roams,
            "avg_roam_time_ms": round(avg_roam_time, 2) if avg_roam_time else None,
            "roam_type_breakdown": roam_type_breakdown,
            "per_ap_stats": per_ap_stats,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Sticky Client Detection
    # ──────────────────────────────────────────────────────────────────────

    async def get_sticky_clients(
        self,
        org_id: UUID,
        rssi_threshold: int = -75,
        hours: int = 24,
    ) -> list[dict]:
        """
        Detect sticky clients — clients that remain associated to an AP
        even when the signal is weak (below ``rssi_threshold``).

        A client is flagged as sticky if their most recent roaming event's
        ``from_rssi`` is below the threshold and no outbound roam occurred
        within the look-back period.

        Parameters
        ----------
        org_id : UUID
            Organisation scope.
        rssi_threshold : int
            RSSI value (dBm) below which a client is considered stuck
            on a weak AP.  Default -75 dBm.
        hours : int
            Look-back window.

        Returns
        -------
        list[dict]
            List of sticky client records.
        """
        since = datetime.now(UTC) - timedelta(hours=hours)

        # Find the latest roaming event per client in the window
        # where from_rssi is weak — these clients stayed on a weak AP
        subq = (
            select(
                ClientRoamingEvent.client_mac,
                func.max(ClientRoamingEvent.timestamp).label("last_roam"),
            )
            .where(
                ClientRoamingEvent.organization_id == org_id,
                ClientRoamingEvent.timestamp >= since,
            )
            .group_by(ClientRoamingEvent.client_mac)
            .subquery()
        )

        # Join back to get the actual event row
        q = (
            select(ClientRoamingEvent)
            .join(
                subq,
                (ClientRoamingEvent.client_mac == subq.c.client_mac)
                & (ClientRoamingEvent.timestamp == subq.c.last_roam),
            )
            .where(
                ClientRoamingEvent.organization_id == org_id,
                ClientRoamingEvent.to_rssi.isnot(None),
                ClientRoamingEvent.to_rssi < rssi_threshold,
            )
        )
        _grant = _granted_roaming_pred()
        if _grant is not None:
            q = q.where(_grant)
        q = q.limit(500)
        result = await self.db.execute(q)
        events = result.scalars().all()

        seen_macs = set()
        sticky = []
        for ev in events:
            if ev.client_mac in seen_macs:
                continue
            seen_macs.add(ev.client_mac)
            sticky.append(
                {
                    "client_mac": ev.client_mac,
                    "current_device_id": str(ev.to_device_id) if ev.to_device_id else None,
                    "current_bssid": ev.to_bssid,
                    "rssi": ev.to_rssi,
                    "last_roam_at": ev.timestamp.isoformat() if ev.timestamp else None,
                    "roam_type": ev.roam_type,
                }
            )

        return sticky

    # ──────────────────────────────────────────────────────────────────────
    # Push Roaming Configuration
    # ──────────────────────────────────────────────────────────────────────

    async def push_roaming_config(
        self,
        wifi_network_id: UUID,
        config: dict,
        organization_id: UUID | None = None,
    ) -> dict:
        """
        Update roaming settings (802.11r/k/v) on a WiFi network.

        Parameters
        ----------
        wifi_network_id : UUID
            The WiFi network to update.
        config : dict
            Keys may include:
            - ``roaming_protocol``: "802.11r", "802.11k", "802.11v", or None
            - ``minimum_rssi``: int (dBm threshold)
            - ``fast_roaming``: bool
        organization_id : UUID | None
            When provided, verifies the WiFi network belongs to this org
            by joining through Site.

        Returns
        -------
        dict
            Updated configuration summary.
        """
        from app.models.core import Site

        query = select(WifiNetwork).where(
            WifiNetwork.id == wifi_network_id,
            WifiNetwork.deleted_at.is_(None),
        )
        if organization_id:
            query = query.join(Site).where(Site.organization_id == organization_id)
        result = await self.db.execute(query)
        wifi = result.scalar_one_or_none()
        if not wifi:
            raise ValueError(f"WiFi network {wifi_network_id} not found")

        if "roaming_protocol" in config:
            wifi.roaming_protocol = config["roaming_protocol"]
        if "minimum_rssi" in config:
            wifi.minimum_rssi = config["minimum_rssi"]
        if "fast_roaming" in config:
            wifi.fast_roaming = config["fast_roaming"]

        await self.db.flush()

        logger.info(
            "Updated roaming config for WiFi network %s: protocol=%s, min_rssi=%s, fast_roaming=%s",
            wifi_network_id,
            wifi.roaming_protocol,
            wifi.minimum_rssi,
            wifi.fast_roaming,
        )

        # Push to controller via adapter if possible
        try:
            from app.models.core import Controller, Site
            from app.services.adapter_factory import get_adapter

            # Load the site + controller for this WiFi network
            site_q = await self.db.execute(select(Site).where(Site.id == wifi.site_id))
            site = site_q.scalar_one_or_none()
            if site:
                ctrl_q = await self.db.execute(
                    select(Controller).where(
                        Controller.site_id == site.id,
                        Controller.deleted_at.is_(None),
                    )
                )
                controller = ctrl_q.scalars().first()
                if controller and hasattr(controller, "host"):
                    try:
                        adapter = get_adapter(
                            controller.controller_type,
                            host=controller.host,
                            username=_safe_decrypt(controller.username),
                            password=_safe_decrypt(controller.password),
                            port=controller.port,
                            ssl=controller.use_ssl,
                            verify_ssl=controller.verify_ssl,
                        )
                        if hasattr(adapter, "update_ssid_config"):
                            roaming_payload = {
                                "fast_roaming": wifi.fast_roaming,
                                "roaming_protocol": wifi.roaming_protocol,
                                "minimum_rssi": wifi.minimum_rssi,
                            }
                            async with adapter:
                                await adapter.update_ssid_config(str(wifi.id), roaming_payload)
                            logger.info(
                                "Pushed roaming config to controller for WiFi %s", wifi_network_id
                            )
                    except Exception:
                        logger.warning(
                            "Failed to push roaming config to controller for WiFi %s — DB updated, device push pending",
                            wifi_network_id,
                            exc_info=True,
                        )
        except Exception:
            logger.debug("Roaming config push skipped — no controller available", exc_info=True)

        return {
            "wifi_network_id": str(wifi_network_id),
            "ssid": wifi.ssid,
            "roaming_protocol": wifi.roaming_protocol,
            "minimum_rssi": wifi.minimum_rssi,
            "fast_roaming": wifi.fast_roaming,
        }
