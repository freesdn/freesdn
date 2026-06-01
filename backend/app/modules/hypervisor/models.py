# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Hypervisor Module - Database Models
=============================================

SQLAlchemy models for hypervisor management.
Uses the ``hypervisor`` database schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ProxmoxNode(Base):
    """A physical Proxmox VE node in a cluster."""

    __tablename__ = "proxmox_nodes"
    __table_args__ = (
        Index("ix_proxmox_nodes_controller", "controller_id"),
        Index("ix_proxmox_nodes_site", "site_id"),
        Index("ix_proxmox_nodes_status", "status"),
        {"schema": "hypervisor"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    controller_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Identity
    node_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="unknown")
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Resources
    cpu_count: Mapped[int] = mapped_column(Integer, default=0)
    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0)
    memory_total: Mapped[int] = mapped_column(BigInteger, default=0)  # bytes
    memory_used: Mapped[int] = mapped_column(BigInteger, default=0)
    storage_total: Mapped[int] = mapped_column(BigInteger, default=0)
    storage_used: Mapped[int] = mapped_column(BigInteger, default=0)

    # Info
    pve_version: Mapped[str] = mapped_column(String(50), default="")
    kernel_version: Mapped[str] = mapped_column(String(100), default="")
    cpu_model: Mapped[str] = mapped_column(String(255), default="")
    uptime: Mapped[int] = mapped_column(BigInteger, default=0)  # seconds
    subscription_level: Mapped[str] = mapped_column(String(50), default="")

    # Metadata
    extra: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    virtual_machines: Mapped[list[VirtualMachine]] = relationship(
        "VirtualMachine", back_populates="node", cascade="all, delete-orphan"
    )


class VirtualMachine(Base):
    """A VM (QEMU) or container (LXC) on a Proxmox node."""

    __tablename__ = "virtual_machines"
    __table_args__ = (
        Index("ix_vms_node", "node_id"),
        Index("ix_vms_site", "site_id"),
        Index("ix_vms_status", "status"),
        Index("ix_vms_vmid_node", "vmid", "node_id", unique=True),
        Index("ix_vms_type", "vm_type"),
        {"schema": "hypervisor"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hypervisor.proxmox_nodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Proxmox identity
    vmid: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vm_type: Mapped[str] = mapped_column(String(10), nullable=False)  # "qemu" | "lxc"
    status: Mapped[str] = mapped_column(String(50), default="stopped")
    template: Mapped[bool] = mapped_column(Boolean, default=False)

    # Resources
    cpu_cores: Mapped[int] = mapped_column(Integer, default=1)
    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0)
    memory_mb: Mapped[int] = mapped_column(Integer, default=512)
    memory_used_mb: Mapped[int] = mapped_column(Integer, default=0)
    disk_gb: Mapped[float] = mapped_column(Float, default=0.0)
    disk_used_gb: Mapped[float] = mapped_column(Float, default=0.0)

    # Network
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    net_in: Mapped[int] = mapped_column(BigInteger, default=0)
    net_out: Mapped[int] = mapped_column(BigInteger, default=0)

    # Metadata
    os_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tags: Mapped[str] = mapped_column(Text, default="")
    uptime: Mapped[int] = mapped_column(BigInteger, default=0)
    ha_state: Mapped[str | None] = mapped_column(String(50), nullable=True)
    lock: Mapped[str | None] = mapped_column(String(50), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)

    # Timestamps
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    node: Mapped[ProxmoxNode] = relationship("ProxmoxNode", back_populates="virtual_machines")
