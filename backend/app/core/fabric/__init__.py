# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — the universal app-interconnect (core engine).

The Fabric is the app-agnostic interconnect that lets any integrated app talk to
any other. It unifies FreeSDN's previously-fragmented "services" surfaces (AI
tools, automation actions, plugin bridges, staged writes) into ONE tier-tagged
**Operation** registry plus a normalized **Event** catalog, so a capability is
declared once and discovered everywhere.

This package provides the *declarative catalog*:
``operations`` (the Operation/EventSpec types + the two trust tiers) and
``registry`` (the FabricRegistry that discovers native operations from modules
and plugin operations from the plugin bridge), plus the execution layer — the
Negotiator, Connections, and Artifact Broker.

Trust tiers (honored end-to-end):
  - ``native``  — first-party in-tree modules; full trust.
  - ``plugin``  — external apps; SDK-bounded, permission-declared, namespaced.
"""

from app.core.fabric.artifact_broker import ArtifactBroker, ArtifactError, artifact_broker
from app.core.fabric.execution import ArtifactRef, OperationContext, OperationResult
from app.core.fabric.executor import OperationExecutor, operation_executor
from app.core.fabric.negotiator import Connection, ConnectionStep, Negotiator, negotiator
from app.core.fabric.operations import (
    EventSpec,
    Operation,
    OperationTier,
)
from app.core.fabric.registry import FabricRegistry, fabric_registry
from app.core.fabric.templating import resolve_template

__all__ = [
    "ArtifactBroker",
    "ArtifactError",
    "ArtifactRef",
    "Connection",
    "ConnectionStep",
    "EventSpec",
    "FabricRegistry",
    "Negotiator",
    "Operation",
    "OperationContext",
    "OperationExecutor",
    "OperationResult",
    "OperationTier",
    "artifact_broker",
    "fabric_registry",
    "negotiator",
    "operation_executor",
    "resolve_template",
]
