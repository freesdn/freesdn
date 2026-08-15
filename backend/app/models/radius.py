# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - RADIUS / 802.1X Models
====================================

SQLAlchemy models for RADIUS authentication and 802.1X port security:
- RadiusServerProfile: RADIUS server connection profile
- Dot1xPortConfig: 802.1X config applied to a switch port or SSID
- Dot1xAuthEvent: 802.1X authentication event synced from controller
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

# =============================================================================
# RADIUS Server Profile
# =============================================================================


class RadiusServerProfile(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    RADIUS server connection profile.

    Stores connection details for a RADIUS server used for 802.1X
    authentication.  The shared secret is stored encrypted at rest.
    """

    __tablename__ = "radius_server_profiles"
    __table_args__ = (
        Index("ix_radius_profiles_org_id", "organization_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Connection
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=1812)
    shared_secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)

    # Authentication protocol
    auth_protocol: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pap",
    )  # pap / mschapv2 / eap-tls / eap-peap

    # Timeouts & retries
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    # RADIUS Accounting
    accounting_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    accounting_port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1813,
    )

    # Health monitoring
    last_health_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    is_healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def __repr__(self) -> str:
        return f"<RadiusServerProfile {self.name} ({self.host}:{self.port})>"


# =============================================================================
# 802.1X Port / SSID Configuration
# =============================================================================


class Dot1xPortConfig(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    802.1X configuration applied to a switch port profile or WiFi SSID.

    Links a RADIUS profile to a port profile or WiFi network, and tracks
    the push status so the operator knows whether the config has been
    deployed to the target controller.
    """

    __tablename__ = "dot1x_port_configs"
    __table_args__ = (
        Index("ix_dot1x_cfg_controller", "controller_id"),
        Index("ix_dot1x_cfg_radius_profile", "radius_profile_id"),
        Index("ix_dot1x_cfg_controller_push_status", "controller_id", "push_status"),
        {"schema": "network"},
    )

    # Foreign Keys
    port_profile_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("network.port_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )
    wifi_network_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("network.wifi_networks.id", ondelete="SET NULL"),
        nullable=True,
    )
    controller_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="CASCADE"),
        nullable=False,
    )
    radius_profile_id: Mapped[UUID] = mapped_column(
        ForeignKey("network.radius_server_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )

    # 802.1X settings
    auth_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="port-based",
    )  # port-based / mac-based / multi-host
    guest_vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dynamic_vlan: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reauthentication_interval: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3600,
    )

    # Deployment status
    pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    push_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
    )  # pending / pushed / failed

    # Relationships (selectin for eager loading)
    radius_profile: Mapped["RadiusServerProfile"] = relationship(
        "RadiusServerProfile",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Dot1xPortConfig controller={self.controller_id} status={self.push_status}>"


# =============================================================================
# 802.1X Authentication Event
# =============================================================================


class Dot1xAuthEvent(Base, UUIDMixin, AuditMixin):
    """
    802.1X authentication event synced from a controller.

    Records every authentication attempt (success or failure) so
    operators can audit network access.
    """

    __tablename__ = "dot1x_auth_events"
    __table_args__ = (
        Index("ix_dot1x_events_timestamp", "timestamp"),
        Index("ix_dot1x_events_client_mac", "client_mac"),
        Index("ix_dot1x_events_org_id", "organization_id"),
        {"schema": "network"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    controller_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.controllers.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[UUID | None] = mapped_column(
        nullable=True,
    )
    radius_profile_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("network.radius_server_profiles.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Event data
    client_mac: Mapped[str] = mapped_column(String(17), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_result: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )  # success / reject / timeout
    reject_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assigned_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Dot1xAuthEvent {self.client_mac} {self.auth_result}>"
