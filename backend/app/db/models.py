# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Database Models Re-export
=======================================

Re-exports models from app.models for backwards compatibility.
Use `from app.db.models import ...` or `from app.models import ...`
"""

# Re-export all models from app.models
# Also export base classes
from app.db.base import (
    AuditMixin,
    Base,
    LogBase,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDMixin,
)
from app.models.core import (
    Controller,
    ControllerStatus,
    ControllerType,
    Organization,
    Site,
    User,
    UserRole,
    UserSession,
)
from app.models.devices import (
    ConnectionType,
    Device,
    DeviceClient,
    DevicePort,
    DeviceStatus,
    DeviceType,
    PortStatus,
    PortType,
)
from app.modules.network.models import (
    LAGMode,
    LinkAggregationGroup,
    Network,
    PortProfile,
    TopologyLink,
    WifiBand,
    WifiNetwork,
    WifiSecurityType,
)

__all__ = [
    # Base
    "Base",
    "LogBase",
    "UUIDMixin",
    "TimestampMixin",
    "SoftDeleteMixin",
    "AuditMixin",
    # Core
    "Organization",
    "Site",
    "Controller",
    "ControllerType",
    "ControllerStatus",
    "User",
    "UserRole",
    "UserSession",
    # Devices
    "Device",
    "DeviceType",
    "DeviceStatus",
    "ConnectionType",
    "DevicePort",
    "PortType",
    "PortStatus",
    "DeviceClient",
    # Network
    "Network",
    "WifiNetwork",
    "WifiSecurityType",
    "WifiBand",
    "PortProfile",
    "LinkAggregationGroup",
    "LAGMode",
    "TopologyLink",
]
