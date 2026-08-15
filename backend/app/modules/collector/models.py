# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Collector Module Models
========================================

Database models for collected syslog messages, SNMP traps, NetFlow records,
and per-org collector configuration. Uses schema "collector".
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class AppCategory(StrEnum):
    """Application category for DPI classification."""

    WEB = "web"
    STREAMING = "streaming"
    CONFERENCING = "conferencing"
    EMAIL = "email"
    FILE_TRANSFER = "file_transfer"
    VPN_TUNNEL = "vpn_tunnel"
    DNS = "dns"
    DATABASE = "database"
    GAMING = "gaming"
    SOCIAL = "social"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    IOT = "iot"
    VOIP = "voip"
    OTHER = "other"


class CollectorLog(Base, UUIDMixin):
    """
    A single collected log entry — either a syslog message or SNMP trap.
    Indexed for efficient time-range and source queries.
    """

    __tablename__ = "collector_logs"
    __table_args__ = (
        Index("ix_collector_logs_timestamp", "timestamp"),
        Index("ix_collector_logs_source", "source_type", "source_ip"),
        Index("ix_collector_logs_device", "device_id"),
        Index("ix_collector_logs_severity", "severity"),
        {"schema": "collector"},
    )

    source_type: Mapped[str] = mapped_column(String(20))  # "snmp_trap" | "syslog"
    source_ip: Mapped[str] = mapped_column(String(45))
    device_id: Mapped[UUID | None] = mapped_column()
    organization_id: Mapped[UUID | None] = mapped_column()

    # Syslog-specific
    facility: Mapped[str | None] = mapped_column(String(20))
    severity: Mapped[str | None] = mapped_column(String(20))
    hostname: Mapped[str | None] = mapped_column(String(255))
    app_name: Mapped[str | None] = mapped_column(String(100))
    message: Mapped[str] = mapped_column(Text)

    # SNMP trap-specific
    enterprise_oid: Mapped[str | None] = mapped_column(String(200))
    trap_type: Mapped[str | None] = mapped_column(String(50))
    varbinds: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )
    raw_data: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:
        return f"<CollectorLog {self.source_type} from {self.source_ip}>"


class FlowRecord(Base, UUIDMixin):
    """
    Aggregated NetFlow record (1-minute bucket).
    Indexed for efficient time-range and source IP queries.
    """

    __tablename__ = "flow_records"
    __table_args__ = (
        Index("ix_flow_records_bucket", "bucket_time"),
        Index("ix_flow_records_src_ip", "source_ip"),
        Index("ix_flow_records_device", "device_id"),
        Index("ix_flow_records_app", "app_name", "app_category"),
        {"schema": "collector"},
    )

    device_id: Mapped[UUID | None] = mapped_column()
    organization_id: Mapped[UUID | None] = mapped_column()

    source_ip: Mapped[str] = mapped_column(String(45))
    dest_ip: Mapped[str] = mapped_column(String(45))
    source_port: Mapped[int | None] = mapped_column(Integer)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer)  # IP protocol number (6=TCP, 17=UDP)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)
    packets: Mapped[int] = mapped_column(BigInteger, default=0)
    bucket_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    # DPI classification
    app_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    app_category: Mapped[str | None] = mapped_column(String(50), nullable=True)

    def __repr__(self) -> str:
        return f"<FlowRecord {self.source_ip} -> {self.dest_ip}>"


class CollectorConfig(Base, UUIDMixin, AuditMixin):
    """Per-org collector service configuration."""

    __tablename__ = "collector_configs"
    __table_args__ = ({"schema": "collector"},)

    organization_id: Mapped[UUID] = mapped_column(unique=True)

    # SNMP trap
    snmp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    snmp_port: Mapped[int] = mapped_column(Integer, default=162)
    snmp_community: Mapped[str] = mapped_column(String(100), default="public")

    # Syslog
    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    syslog_port: Mapped[int] = mapped_column(Integer, default=514)

    # NetFlow
    netflow_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    netflow_port: Mapped[int] = mapped_column(Integer, default=2055)

    # Retention
    log_retention_days: Mapped[int] = mapped_column(Integer, default=30)
    flow_retention_days: Mapped[int] = mapped_column(Integer, default=7)

    # NOTE(C3): Allowlist of CIDRs from which UDP collector packets are
    # accepted. Empty list = block all (secure default). Per-org config
    # so multi-tenant deployments can constrain which devices may emit
    # traps/flows/syslog into their org bucket.
    allowed_source_ips: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(64)), nullable=True, default=list
    )

    def __repr__(self) -> str:
        return f"<CollectorConfig org={self.organization_id}>"


class ApplicationClassificationRule(Base, UUIDMixin, AuditMixin):
    """
    DPI classification rule — maps port/protocol to application name.

    System rules (is_system=True) are seeded automatically.
    Org-specific rules override system rules by priority.
    """

    __tablename__ = "app_classification_rules"
    __table_args__ = (
        Index("ix_app_rules_org", "organization_id"),
        Index("ix_app_rules_port", "protocol", "port"),
        {"schema": "collector"},
    )

    organization_id: Mapped[UUID | None] = mapped_column(nullable=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    app_category: Mapped[str] = mapped_column(String(50), nullable=False)

    # Match criteria
    protocol: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port_range_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port_range_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_ip_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Metadata
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<AppClassificationRule {self.name} proto={self.protocol} port={self.port}>"
