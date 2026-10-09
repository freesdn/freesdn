# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Observe independent release prerequisites without granting future authority.

Storage failure does not erase journal recovery or silently recreate a signing
identity. These are startup observations only: every action continues to attest
its current database/filesystem/credential state. There is no caller transaction
to commit, schema repair, implicit migration, or signing-key initialization here.
"""

import logging
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import anyio
from sqlalchemy import text

from app.core.agent_release_runtime_policy import ReleaseRuntimePolicy
from app.core.agent_release_storage_root import initialize_release_storage_root
from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.services.agent_release_reference_validation import validate_release_reference_installation
from app.services.agent_signing_identity import read_trusted_signing_identity

logger = logging.getLogger(__name__)
State = Literal["observed", "unavailable"]


@dataclass(frozen=True)
class ReleaseStartupObservation:
    checked_at: datetime
    storage: State
    reference_schema: State
    signing_identity: State

    @property
    def all_observed(self) -> bool:
        return (self.storage, self.reference_schema, self.signing_identity) == ("observed",) * 3

    def public(self) -> dict[str, str | bool]:
        # Deliberately no paths, key material, exception strings or capability.
        return {
            "checked_at": self.checked_at.isoformat(),
            "storage": self.storage,
            "reference_schema": self.reference_schema,
            "signing_identity": self.signing_identity,
            "observation_only": True,
            "actions_revalidate_current_state": True,
        }


async def _reference_schema() -> None:
    async with AsyncExitStack() as resources:
        with anyio.fail_after(5):
            connection = await resources.enter_async_context(sessions.security_engine.connect())
            async with connection.begin():
                await connection.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
                await connection.execute(text("SET LOCAL statement_timeout = '2500ms'"))
                await connection.execute(text("SET LOCAL lock_timeout = '500ms'"))
                await connection.execute(
                    text(
                        "LOCK TABLE agents.agent_release_operations, agents.agent_releases IN SHARE MODE NOWAIT"
                    )
                )
                await connection.run_sync(validate_release_reference_installation)


@complete_before_cancellation
async def observe_release_startup(policy: ReleaseRuntimePolicy) -> ReleaseStartupObservation:
    if type(policy) is not ReleaseRuntimePolicy:
        raise ValueError("Explicit deployment release policy required")
    storage: State = "unavailable"
    reference_schema: State = "unavailable"
    signing_identity: State = "unavailable"
    try:
        await anyio.to_thread.run_sync(
            initialize_release_storage_root, policy.managed_root, abandon_on_cancel=False
        )
        storage = "observed"
    except Exception as error:
        logger.warning(
            "Managed release storage startup unavailable (%s); no repair attempted",
            type(error).__name__,
        )
    try:
        await _reference_schema()
        reference_schema = "observed"
    except Exception as error:
        logger.warning(
            "Release reference startup unavailable (%s); no migration attempted",
            type(error).__name__,
        )
    try:
        await read_trusted_signing_identity()
        signing_identity = "observed"
    except Exception as error:
        logger.warning(
            "Release signing identity startup unavailable (%s); explicit recovery required",
            type(error).__name__,
        )
    return ReleaseStartupObservation(datetime.now(UTC), storage, reference_schema, signing_identity)
