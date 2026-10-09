# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private atomic publication; not a registered public upload/delivery route.

Publication couples release insertion/latest mutation to the retained decision.
Owned bytes are reverified under their exclusive lifetime before signing and
remain held through the SQL commit and worker drain. Failures never unlink.
Confirmed retries only observe history; they cannot recreate or repromote it.
Old writers, deletion, delivery, backup and supported API recovery still require
integration before this can be enabled against a deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from uuid import UUID

import anyio
from fastapi import HTTPException
from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.core import Organization
from app.services.agent_release_artifact_store import PreparedArtifact
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_cleanup import ReleaseOperationRecord, _record
from app.services.agent_release_preparation import (
    _intent,
    _PreparationStorage,
    _record_prepared,
)
from app.services.agent_release_promotion import lock_verified_identity
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget
from app.services.agent_release_reservation import _execute_owned, _OperationOwner
from app.services.agent_signing_identity import TrustedSigningIdentity
from app.services.release_signing import SigningKeyError, build_release_manifest
from app.services.release_signing_async import (
    InvalidReleaseSignature,
    SigningBusyError,
    sign_manifest_async,
    verify_manifest_async,
)


@dataclass(frozen=True)
class ReleasePublicationResult:
    operation_id: UUID
    release_id: UUID
    decision: str
    newly_published: bool
    release_row_present: bool
    current_is_latest: bool | None
    artifact_verified_this_call: bool
    signature_verified_this_call: bool
    publication_or_storage_authorized: bool = False


async def _publication_state(
    owner: _OperationOwner[ReleasePublicationRequest], db: AsyncSession
) -> tuple[ReleaseOperationRecord, RowMapping | None]:
    row = await owner._load(db)
    if row is None:
        raise HTTPException(404, "Release publication reservation not found")
    release = (
        (
            await db.execute(
                select(AgentRelease.__table__).where(AgentRelease.id == row["release_id"])
            )
        )
        .mappings()
        .one_or_none()
    )
    if release is not None:
        owner.authority.require_scope(release["organization_id"])
        if release["organization_id"] != row["organization_id"]:
            raise HTTPException(409, "Release ownership differs from retained publication")
    if row["phase"] == "decided" and row["decision"] == "published":
        # The latest flag and count may legitimately change after publication.
        # A missing row is historical absence, not permission to recreate it.
        if release is not None and any(
            release[name] != value
            for name, value in owner.request.metadata().items()
            if name != "is_latest"
        ):
            raise HTTPException(409, "Release metadata differs from retained publication")
        return row, release
    if row["phase"] not in ("reserved", "prepared") or row["decision"] is not None:
        raise HTTPException(409, "Release operation is already decided; inspect retained state")
    if release is not None:
        raise HTTPException(409, "Pending publication conflicts with a live release")
    if row["organization_id"] is not None:
        destination = (
            await db.execute(
                select(Organization.id)
                .where(
                    Organization.id == row["organization_id"],
                    Organization.deleted_at.is_(None),
                    Organization.is_active.is_(True),
                )
                .with_for_update(read=True, nowait=True)
            )
        ).one_or_none()
        if destination is None:
            raise HTTPException(404, "Live destination organization not found")
    return row, None


async def _inspect(
    owner: _OperationOwner[ReleasePublicationRequest],
) -> tuple[ReleaseOperationRecord, RowMapping | None]:
    async def observe(db: AsyncSession) -> tuple[ReleaseOperationRecord, RowMapping | None]:
        return await _publication_state(owner, db)

    return await owner.phase(observe)


def _response(
    row: ReleaseOperationRecord,
    release: RowMapping | None,
    *,
    created: bool,
    artifact_checked: bool = False,
    signature_checked: bool = False,
) -> ReleasePublicationResult:
    return ReleasePublicationResult(
        row["operation_id"],
        row["release_id"],
        # Both callers reach this projection only for a confirmed publication.
        cast(str, row["decision"]),
        created,
        release is not None,
        release["is_latest"] if release is not None else None,
        artifact_checked,
        signature_checked,
    )


async def _signature(
    request: ReleasePublicationRequest,
) -> tuple[str | None, TrustedSigningIdentity | None]:
    metadata = request.metadata()
    manifest = build_release_manifest(
        digest_hex=metadata["checksum_sha256"],
        version=metadata["version"],
        platform=metadata["platform"],
        agent_type=metadata["agent_type"],
        channel="prerelease" if metadata["is_prerelease"] else "stable",
    )
    try:
        signature = await sign_manifest_async(manifest)
        identity = await verify_manifest_async(manifest, signature)
        return signature, identity
    except (SigningKeyError, SigningBusyError):
        # Preserve the existing explicit non-latest upload policy. URL metadata
        # publication still requires signing; unexpected errors never downgrade.
        if request.storage_kind == "owned" and metadata["is_latest"] is False:
            return None, None
        raise HTTPException(
            503, "Trusted release signing unavailable; retain the same operation"
        ) from None
    except InvalidReleaseSignature:
        raise HTTPException(
            503, "New release signature did not verify; preserve the same operation"
        ) from None


async def _publish(
    owner: _OperationOwner[ReleasePublicationRequest],
    *,
    signature: str | None,
    identity: TrustedSigningIdentity | None,
    prepared: PreparedArtifact | None,
) -> ReleasePublicationResult:
    async def commit_decision(db: AsyncSession) -> ReleasePublicationResult:
        row, release = await _publication_state(owner, db)
        if row["decision"] == "published":
            return _response(row, release, created=False)
        metadata = owner.request.metadata()
        if row["storage_kind"] == "owned":
            if (
                row["phase"] != "prepared"
                or type(prepared) is not PreparedArtifact
                or prepared.intent != _intent(owner.request)
            ):
                raise HTTPException(409, "Publication needs the retained verified artifact")
        elif prepared is not None:
            raise HTTPException(409, "External metadata cannot claim owned bytes")
        if signature is None:
            if (
                identity is not None
                or row["storage_kind"] != "owned"
                or metadata["is_latest"] is not False
            ):
                raise HTTPException(503, "This release requires a verified signature")
        else:
            if identity is None:
                raise HTTPException(503, "Verified signing identity is required")
            await lock_verified_identity(db, identity)
        if row["phase"] == "reserved":
            # External preparation is metadata/signature only; both journal
            # transitions and the release insert commit together below.
            change = {
                "phase": "prepared",
                "transition_sequence": 1,
                "prepared_at": await db.scalar(select(func.clock_timestamp())),
                "last_transition_by": owner.authority.actor_id,
            }
            await db.execute(
                update(AgentReleaseOperation)
                .where(AgentReleaseOperation.operation_id == row["operation_id"])
                .values(**change)
            )
            row = _record({**row, **change})
        if metadata["is_latest"]:
            await db.execute(
                update(AgentRelease)
                .where(
                    AgentRelease.organization_id.is_not_distinct_from(row["organization_id"]),
                    AgentRelease.platform == metadata["platform"],
                    AgentRelease.agent_type == metadata["agent_type"],
                    AgentRelease.is_latest.is_(True),
                )
                .values(is_latest=False)
            )
        release = (
            (
                await db.execute(
                    insert(AgentRelease)
                    .values(
                        **metadata,
                        id=row["release_id"],
                        organization_id=row["organization_id"],
                        signature=signature,
                        published_at=await db.scalar(select(func.clock_timestamp())),
                        download_count=0,
                    )
                    .returning(*AgentRelease.__table__.columns)
                )
            )
            .mappings()
            .one()
        )
        change = {
            "phase": "decided",
            "decision": "published",
            "transition_sequence": 2,
            "decided_at": await db.scalar(select(func.clock_timestamp())),
            "last_transition_by": owner.authority.actor_id,
        }
        await db.execute(
            update(AgentReleaseOperation)
            .where(AgentReleaseOperation.operation_id == row["operation_id"])
            .values(**change)
        )
        row = _record({**row, **change})
        # owner.phase performs its final live authority check and the sole
        # commit; no intermediate commit can expose a half publication.
        return _response(
            row,
            release,
            created=True,
            artifact_checked=prepared is not None,
            signature_checked=identity is not None,
        )

    return await owner.phase(commit_decision, release_write=True)


async def execute_release_publication(
    *,
    authority: ReleaseMutationAuthority,
    request: ReleasePublicationRequest,
    budget: ReleaseReservationBudget,
    root: str | None = None,
) -> ReleasePublicationResult:
    """Publish owned prepared bytes or signed external metadata with exact retry.

    External metadata is not a network fetch or proof of the URL's served bytes.
    Root and budget are server policy. All artifact ownership is closed before
    returning this historical result; it is not a delivery or cleanup capability.
    """
    if (
        type(request) is not ReleasePublicationRequest
        or type(budget) is not ReleaseReservationBudget
        or (request.storage_kind == "owned" and type(root) is not str)
        or (request.storage_kind == "external" and root is not None)
    ):
        raise HTTPException(422, "Invalid release publication command")

    async def execute(
        owner: _OperationOwner[ReleasePublicationRequest],
    ) -> ReleasePublicationResult:
        if request.storage_kind == "external":
            await owner.reserve(budget)
        row, release = await _inspect(owner)
        if row["decision"] == "published":
            return _response(row, release, created=False)
        storage = _PreparationStorage()
        try:
            with anyio.fail_after(max(0, owner.deadline - anyio.current_time())):
                prepared = None
                if request.storage_kind == "owned":
                    # The entry point checked root's exact string type for owned storage.
                    await storage.acquire(cast(str, root), _intent(request), create=False)
                    await _inspect(owner)
                    prepared = await storage.run("verify_prepared")
                    # Covers bytes that finished durably before an uncertain
                    # earlier prepared-state acknowledgment. Never re-upload.
                    await _record_prepared(owner, prepared)
                signature, identity = await _signature(request)
                return await _publish(
                    owner, signature=signature, identity=identity, prepared=prepared
                )
        except OSError:
            raise HTTPException(
                503, "Retained release storage unavailable; inspect the same operation"
            ) from None
        except SigningKeyError:
            # A trusted identity change detected at the final SQL fence is not
            # an invitation to repeat signing or downgrade to unsigned.
            raise HTTPException(
                503, "Trusted signing identity changed; preserve the same operation"
            ) from None
        finally:
            with anyio.CancelScope(shield=True):
                await storage.close()

    return await _execute_owned(authority=authority, request=request, function=execute)
