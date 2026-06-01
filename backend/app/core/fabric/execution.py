# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — runtime execution contracts.

Catalog vocabulary lives in ``operations.py``; this module holds the *runtime*
types the executor + negotiator pass around when a Connection actually fires:
the per-invocation context, the normalized result, and the artifact reference
that lets a producer hand binary data to a consumer through the Artifact Broker.

Kept separate from ``operations.py`` so the catalog stays import-light (no DB /
broker types) — modules import only ``Operation``/``EventSpec`` to *declare*
capabilities; the executor imports these to *run* them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    import logging

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.fabric.artifact_broker import ArtifactBroker


@dataclass(frozen=True)
class ArtifactRef:
    """A handle to a binary payload held by the Artifact Broker.

    Carries enough metadata for the negotiator to match producer→consumer
    (``media_type``) and for integrity/audit (``sha256``) without ever inlining
    the bytes into an event or a DB row.
    """

    handle: str
    media_type: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "media_type": self.media_type,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass
class OperationContext:
    """Everything an operation handler needs for one invocation.

    Org-scoped and actor-attributed: ``organization_id`` is the tenant the
    Connection belongs to (fail-closed), and ``actor_id`` is the human operator
    who authored the Connection — writes are staged/audited under that identity,
    never under a plugin's.
    """

    organization_id: UUID
    params: dict[str, Any]
    """Invocation params AFTER safe templating + schema validation."""
    trigger: dict[str, Any] = field(default_factory=dict)
    """The source event payload that fired the Connection (read-only context)."""
    actor_id: UUID | None = None
    db: AsyncSession | None = None
    artifacts: ArtifactBroker | None = None
    input_artifact: ArtifactRef | None = None
    """An artifact handed in from the trigger or a prior step (consumer side)."""
    logger: logging.Logger | None = None
    accessible_site_ids: set[UUID] | None = None
    """The caller's per-user site grant (None = unrestricted / org-admin). Handlers
    that resolve site-scoped resources (e.g. a target PBX/phone) MUST thread this
    into their service so a site-limited caller can't act on a sibling site via
    Fabric."""


@dataclass
class OperationResult:
    """Normalized outcome of an operation invocation."""

    success: bool
    output: dict[str, Any] = field(default_factory=dict)
    artifact: ArtifactRef | None = None
    error: str | None = None
    error_code: str | None = None
    # Set by the executor when a write operation was staged (not applied) and is
    # awaiting operator sign-off via the staged-change pipeline.
    staged_change_id: str | None = None

    @classmethod
    def ok(
        cls, output: dict[str, Any] | None = None, artifact: ArtifactRef | None = None
    ) -> OperationResult:
        return cls(success=True, output=output or {}, artifact=artifact)

    @classmethod
    def fail(cls, error: str, error_code: str | None = None) -> OperationResult:
        return cls(success=False, error=error, error_code=error_code)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "error": self.error,
            "error_code": self.error_code,
            "staged_change_id": self.staged_change_id,
        }
