# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned read-only signing inspection; no key-store access or lifecycle retry.

Inspection and preflight convey retained database state, never authorization to
mutate or proof that an empty installation is new. Authority is checked outside
the consistent read transaction again before any retained state is disclosed.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import exists, select, text
from sqlalchemy.exc import DBAPIError

from app.core.agent_signing_binding import SigningCommand
from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_signing import AgentSigningIdentity, AgentSigningIntent
from app.models.agents import AgentRelease, RemoteAgent
from app.services.agent_signing_authority import SigningLifecycleAuthority
from app.services.agent_signing_lifecycle import _same_operation
from app.services.release_signing import SigningKeyError, public_key_for_anchor

INSPECTION_COMMAND = SigningCommand("inspect", UUID(int=0), UUID(int=0), 1)
_READERS = threading.BoundedSemaphore(8)
_PUBLIC_OPERATION_FIELDS = (
    "operation_id",
    "installation_id",
    "identity_epoch",
    "kind",
    "state",
    "expected_public_sha256",
    "public_key_sha256",
    "created_at",
    "prepared_at",
    "closed_at",
    "requested_by",
    "closed_by",
)


def _public_operation(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    return {name: row[name] for name in _PUBLIC_OPERATION_FIELDS} if row else None


@dataclass(frozen=True, repr=False)
class SigningSnapshot:
    active: dict[str, Any] | None
    open_operation: dict[str, Any] | None
    selected: dict[str, Any] | None
    history_identity: tuple[UUID, int] | None
    agent_history: bool

    def public(self) -> dict[str, Any]:
        return {
            "state": "active"
            if self.active
            else "incomplete"
            if self.open_operation
            else "unconfigured",
            "active": (
                {
                    name: self.active[name]
                    for name in (
                        "operation_id",
                        "installation_id",
                        "identity_epoch",
                        "public_key_sha256",
                        "activated_at",
                    )
                }
                if self.active
                else None
            ),
            "open_operation": _public_operation(self.open_operation),
            "operation": _public_operation(self.selected),
            "retained_installation_id": self.history_identity[0] if self.history_identity else None,
            "retained_identity_epoch": self.history_identity[1] if self.history_identity else None,
            "has_agent_or_release_history": self.agent_history,
            "storage_checked": False,
            "authorization_granted": False,
            "empty_state_proves_new_installation": False,
        }


async def _read_snapshot(operation_id: UUID | None) -> SigningSnapshot:
    deadline = anyio.current_time() + 5
    async with AsyncExitStack() as cleanup:
        with anyio.fail_after(5):
            db = await cleanup.enter_async_context(sessions.security_session_factory())
            async with db.begin():
                # First SQL in a new owned transaction, not a session default.
                # No caller transaction is accepted or committed here.
                await db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                active = (
                    (await db.execute(select(AgentSigningIdentity.__table__).limit(2)))
                    .mappings()
                    .all()
                )
                opened = (
                    (
                        await db.execute(
                            select(AgentSigningIntent.__table__)
                            .where(AgentSigningIntent.state.in_(["pending", "prepared"]))
                            .limit(2)
                        )
                    )
                    .mappings()
                    .all()
                )
                activated = (
                    (
                        await db.execute(
                            select(AgentSigningIntent.__table__)
                            .where(AgentSigningIntent.state == "activated")
                            .limit(2)
                        )
                    )
                    .mappings()
                    .all()
                )
                history = (
                    await db.execute(
                        select(
                            AgentSigningIntent.installation_id, AgentSigningIntent.identity_epoch
                        )
                        .distinct()
                        .limit(2)
                    )
                ).all()
                selected = (
                    (
                        await db.execute(
                            select(AgentSigningIntent.__table__).where(
                                AgentSigningIntent.operation_id == operation_id
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                    if operation_id is not None
                    else None
                )
                agent_history = bool(
                    await db.scalar(
                        select(
                            exists().select_from(RemoteAgent) | exists().select_from(AgentRelease)
                        )
                    )
                )
    if anyio.current_time() >= deadline:
        raise TimeoutError("Signing inspection deadline")
    if (
        len(active) > 1
        or len(opened) > 1
        or len(activated) != len(active)
        or len(history) > 1
        or (active and opened)
    ):
        raise HTTPException(
            409, "Signing records require database recovery; no automatic initialization"
        )
    if active:
        identity, intent = active[0], activated[0]
        matching = (
            ("operation_id", "operation_id"),
            ("installation_id", "installation_id"),
            ("identity_epoch", "identity_epoch"),
            ("public_key_pem", "public_key_pem"),
            ("public_key_sha256", "public_key_sha256"),
            ("activated_at", "closed_at"),
            ("activated_by", "closed_by"),
        )
        if (
            identity["singleton_id"] != 1
            or identity["format_version"] != 1
            or identity["purpose"] != "agent-release"
            or any(identity[left] != intent[right] for left, right in matching)
        ):
            raise HTTPException(409, "Signing identity conflicts with retained operation history")
        public_key_for_anchor(
            anchor_public_pem=identity["public_key_pem"],
            anchor_sha256=identity["public_key_sha256"],
        )
    return SigningSnapshot(
        dict(active[0]) if active else None,
        dict(opened[0]) if opened else None,
        dict(selected) if selected else None,
        cast(tuple[UUID, int], tuple(history[0])) if history else None,
        agent_history,
    )


@complete_before_cancellation
async def inspect_signing_state(
    authority: SigningLifecycleAuthority,
    *,
    operation_id: UUID | None = None,
) -> SigningSnapshot:
    if type(authority) is not SigningLifecycleAuthority:
        raise HTTPException(403, "Current platform signing authority is required")
    if operation_id is not None and type(operation_id) is not UUID:
        raise HTTPException(422, "Invalid signing operation identity")
    await authority.check()
    if not _READERS.acquire(blocking=False):
        raise HTTPException(503, "Signing inspection capacity is busy")
    try:
        try:
            snapshot = await _read_snapshot(operation_id)
        except (DBAPIError, TimeoutError):
            await authority.check()
            raise HTTPException(
                503, "Signing state is unavailable; do not infer initialization"
            ) from None
        except SigningKeyError:
            await authority.check()
            raise HTTPException(409, "Stored signing identity requires database recovery") from None
        # Capture any query/refusal privately until the initiator is rechecked.
        except HTTPException:
            await authority.check()
            raise
        await authority.check()
        return snapshot
    finally:
        _READERS.release()


def preflight_signing_command(snapshot: SigningSnapshot, command: SigningCommand) -> dict[str, Any]:
    """Advisory SQL-only eligibility. The coordinator must repeat every check."""
    blockers = []
    row, active = snapshot.selected, snapshot.active
    if command.action == "inspect":
        blockers.append("inspection_is_not_a_mutation")
    elif row is not None:
        try:
            _same_operation(row, command)
        except HTTPException:
            blockers.append("command_does_not_match_retained_operation")
        if row["state"] == "cancelled":
            blockers.append("cancelled_operation_requires_a_new_explicit_operation")
        if row["state"] == "activated" and command.action == "cancel":
            blockers.append("active_identity_cannot_be_cancelled")
        if command.action == "recover" and row["state"] != "activated":
            blockers.append("recovery_requires_the_active_identity")
    elif command.action not in ("initialize", "adopt"):
        blockers.append("operation_not_found")
    else:
        if command.identity_epoch != 1:
            blockers.append("rotation_is_not_supported")
        if snapshot.open_operation:
            blockers.append("resolve_open_operation_first")
        if snapshot.history_identity and snapshot.history_identity != (
            command.installation_id,
            command.identity_epoch,
        ):
            blockers.append("installation_identity_conflicts_with_history")
        if command.action == "initialize" and snapshot.agent_history:
            blockers.append("existing_agents_or_releases_require_adoption_or_recovery")
    if active and active["operation_id"] != command.operation_id:
        blockers.append("another_identity_is_already_active")
    return {
        "database_eligible": not blockers,
        "blockers": blockers,
        "storage_checked": False,
        "authorization_granted": False,
        "fresh_confirmation_required": True,
        "independent_fingerprint_required": command.action in ("adopt", "recover"),
        "explicit_new_installation_acknowledgment_required": command.action == "initialize",
        "snapshot": snapshot.public(),
    }
