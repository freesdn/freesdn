# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Select managed or verified legacy delivery from current retained SQL state.

Selection is not an authorization lease. Each reader validates its classification,
exact target, current credential and signing identity again after I/O. Failure in
managed history, storage or signing never invokes the legacy reader. Legacy reads
preserve files and metadata; unverified records need explicit operator recovery.
External publications are never fetched or redirected by this local endpoint.
"""

from __future__ import annotations

import json
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Literal, cast, overload
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import case, func, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_release_runtime_policy import ReleaseRuntimePolicy
from app.core.agent_release_storage_root import ReleaseStorageUnavailable
from app.core.owned_async import complete_before_cancellation
from app.db import session as sessions
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.services.agent_release_delete_request import DeletionMetadata, ReleaseDeletionRequest
from app.services.agent_release_delivery import (
    ManagedReleaseResponse,
    ReadAuthority,
    ReadIntent,
    ReleaseSnapshot,
    _current,
    _ReadStorage,
)
from app.services.agent_release_legacy_storage import (
    LegacyReleaseFile,
    LegacyReleaseLease,
    LegacyReleaseUnavailable,
    VerifiedLegacyFile,
)
from app.services.agent_release_promotion import lock_verified_identity
from app.services.agent_release_reference_validation import validate_release_reference_installation
from app.services.agent_signing_identity import TrustedSigningIdentity
from app.services.release_signing import build_release_manifest
from app.services.release_signing_async import InvalidReleaseSignature, verify_manifest_async


@dataclass(frozen=True)
class LegacyBinarySnapshot:
    file: LegacyReleaseFile
    target: ReleaseDeletionRequest

    def metadata(self) -> DeletionMetadata:
        # Preserve the signed version/platform/type spelling, not a normalized
        # replacement. The target codec independently bounds every field.
        return cast(DeletionMetadata, json.loads(self.target.metadata_bytes))


@overload
async def _observe_local(
    authority: ReadAuthority,
    release_id: UUID,
    *,
    classify: Literal[True],
    expected: ReleaseSnapshot | None = None,
    identity: TrustedSigningIdentity | None = None,
    attest: bool = False,
    count: bool = False,
) -> Literal["managed", "legacy"]: ...


@overload
async def _observe_local(
    authority: ReadAuthority,
    release_id: UUID,
    *,
    classify: Literal[False] = False,
    expected: ReleaseSnapshot | None = None,
    identity: TrustedSigningIdentity | None = None,
    attest: bool = False,
    count: bool = False,
) -> LegacyBinarySnapshot: ...


@complete_before_cancellation
async def _observe_local(
    authority: ReadAuthority,
    release_id: UUID,
    *,
    classify: bool = False,
    expected: ReleaseSnapshot | None = None,
    identity: TrustedSigningIdentity | None = None,
    attest: bool = False,
    count: bool = False,
) -> LegacyBinarySnapshot | Literal["managed", "legacy"]:
    deadline = anyio.current_time() + 5
    result: LegacyBinarySnapshot | Literal["managed", "legacy"]
    try:
        async with AsyncExitStack() as cleanup:
            with anyio.fail_after(5):
                connection = await cleanup.enter_async_context(sessions.security_engine.connect())
                db = await cleanup.enter_async_context(
                    AsyncSession(bind=connection, expire_on_commit=False, autoflush=False)
                )
                async with db.begin():
                    await db.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
                    await db.execute(text("SET LOCAL statement_timeout = '2500ms'"))
                    await db.execute(text("SET LOCAL lock_timeout = '500ms'"))
                    await db.execute(
                        text(
                            "LOCK TABLE agents.agent_release_operations, agents.agent_releases "
                            + (
                                "IN SHARE ROW EXCLUSIVE MODE NOWAIT"
                                if count
                                else "IN SHARE MODE NOWAIT"
                            )
                        )
                    )
                    fence = await authority.lock(db)
                    if identity is not None:
                        await lock_verified_identity(db, identity)
                    if attest:
                        await connection.run_sync(validate_release_reference_installation)
                    a = AgentRelease.__table__.c
                    release = (
                        (
                            await db.execute(
                                select(AgentRelease.__table__).where(
                                    a.id == release_id,
                                    func.length(a.release_notes) <= 20000,
                                    a.signature.is_(None) | (func.length(a.signature) <= 4096),
                                )
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if release is None:
                        raise HTTPException(404, "Release not found")
                    authority.require_scope(release["organization_id"])
                    await db.execute(
                        text("SELECT agents.assert_release_reference(:id)"), {"id": release_id}
                    )
                    c = AgentReleaseOperation.__table__.c
                    birth = (
                        (
                            await db.execute(
                                select(c.storage_kind, c.phase, c.decision).where(
                                    c.release_id == release_id,
                                    c.kind == "publish",
                                )
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if birth is not None:
                        if not (
                            classify
                            and birth["storage_kind"] == "owned"
                            and birth["phase"] == "decided"
                            and birth["decision"] == "published"
                        ):
                            raise HTTPException(
                                409,
                                "Release has managed or external history; legacy delivery is forbidden",
                            )
                        result = "managed"
                    elif classify:
                        result = "legacy"
                    else:
                        try:
                            target = ReleaseDeletionRequest.capture(
                                operation_id=release_id, release=release
                            )
                            file = LegacyReleaseFile(
                                release_id,
                                release["filename"],
                                release["checksum_sha256"],
                                release["file_size"],
                            )
                        except (ValueError, TypeError, LegacyReleaseUnavailable):
                            raise HTTPException(
                                409,
                                "Legacy release metadata needs explicit operator verification; existing data was preserved",
                            ) from None
                        if (
                            release["download_url"]
                            != f"/api/v1/agents/releases/{release_id}/binary"
                        ):
                            raise HTTPException(409, "Release is not a recorded local binary")
                        result = LegacyBinarySnapshot(file, target)
                        if expected is not None and result != expected:
                            raise HTTPException(409, "Legacy release changed during delivery")
                    if count:
                        await db.execute(
                            update(AgentRelease)
                            .where(a.id == release_id)
                            .values(
                                download_count=case(
                                    (
                                        a.download_count < 2147483647,
                                        func.greatest(a.download_count, 0) + 1,
                                    ),
                                    else_=2147483647,
                                )
                            )
                        )
                    await fence.recheck()
        if anyio.current_time() >= deadline:
            raise TimeoutError("Release observation exceeded its bound")
        await _current(authority)
        return result
    except HTTPException:
        await _current(authority)
        raise
    except (SQLAlchemyError, TimeoutError, RuntimeError, ValueError):
        await _current(authority)
        raise HTTPException(
            503, "Current release state unavailable; no fallback file is authorized"
        ) from None


class _LegacyReadStorage(_ReadStorage):
    def _acquire(self, root: str, expected: ReadIntent) -> VerifiedLegacyFile:
        # LegacyReleaseResponse selects this factory and supplies its validated
        # LegacyReleaseFile; the base wrapper owns the shared cancellation flow.
        self.lease = LegacyReleaseLease.acquire(root, cast(LegacyReleaseFile, expected))
        return self.lease.verified


class LegacyReleaseResponse(ManagedReleaseResponse):
    """Reuse the owned ASGI/range/cancellation lifetime, with strict legacy checks.

    Missing/invalid manifest signatures are never checksum-only installation
    approval. Existing records/files are kept for explicit signing recovery or a
    verified replacement publication. No repair occurs during a GET or HEAD.
    """

    _storage_errors = (
        *ManagedReleaseResponse._storage_errors,
        LegacyReleaseUnavailable,
        ReleaseStorageUnavailable,
    )

    def __init__(self, *, authority: ReadAuthority, release_id: UUID, root: str) -> None:
        super().__init__(authority=authority, release_id=release_id, root=root)
        self._storage = _LegacyReadStorage()

    async def _check(self, *, attest: bool = False) -> LegacyBinarySnapshot:
        return await _observe_local(
            self.authority,
            self.release_id,
            expected=self._snapshot,
            identity=self._identity,
            attest=attest,
        )

    async def _prepare(self) -> tuple[str, int, str, int]:
        self._snapshot = await _observe_local(self.authority, self.release_id, attest=True)
        metadata = self._snapshot.metadata()
        if not metadata["signature"]:
            raise HTTPException(
                409,
                "Legacy release lacks a verified manifest signature; recover its signing identity or publish a verified replacement",
            )
        # This response's constructor replaces the factory with the legacy one.
        prepared = cast(
            VerifiedLegacyFile, await self._storage.acquire(self.root, self._snapshot.file)
        )
        try:
            manifest = build_release_manifest(
                digest_hex=metadata["checksum_sha256"],
                version=metadata["version"],
                platform=metadata["platform"],
                agent_type=metadata["agent_type"],
                channel="prerelease" if metadata["is_prerelease"] else "stable",
            )
            self._identity = await verify_manifest_async(manifest, metadata["signature"])
        except (InvalidReleaseSignature, ValueError):
            await self._check()
            raise HTTPException(
                409, "Legacy release manifest signature is invalid; publish a verified replacement"
            ) from None
        await self._check(attest=True)
        await self._storage.read(0, 1)
        return (
            prepared.filename,
            prepared.expected.size,
            prepared.expected.sha256.lower(),
            prepared.file_state[7],
        )

    async def _record_download(self) -> None:
        await _observe_local(
            self.authority,
            self.release_id,
            expected=self._snapshot,
            identity=self._identity,
            count=True,
        )


async def create_release_binary_response(
    *, authority: ReadAuthority, release_id: UUID, policy: ReleaseRuntimePolicy
) -> ManagedReleaseResponse:
    """Choose from a current, attested row/history observation, never exceptions."""
    if type(policy) is not ReleaseRuntimePolicy:
        raise HTTPException(503, "Release storage policy is unavailable")
    kind = await _observe_local(authority, release_id, classify=True, attest=True)
    if kind == "managed":
        return ManagedReleaseResponse(
            authority=authority, release_id=release_id, root=policy.managed_root
        )
    return LegacyReleaseResponse(
        authority=authority, release_id=release_id, root=policy.legacy_root
    )
