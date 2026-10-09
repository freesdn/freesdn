# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Verify before promotion and coordinate supported latest-release writers.

No binary network fetch, filesystem read, signature regeneration or key creation.
All current publisher routes must share the bucket protocol before enablement.
This does not qualify artifact delivery, arbitrary SQL or a mixed-version fleet.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, cast, overload
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_signing import AgentSigningIdentity, AgentSigningIntent
from app.models.agents import AgentRelease
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_signing_identity import (
    TrustedSigningIdentity,
    _identity_statement,
    _trusted,
)
from app.services.release_signing import SigningKeyError, build_release_manifest
from app.services.release_signing_async import (
    InvalidReleaseSignature,
    SigningBusyError,
    verify_manifest_async,
)

_BOUND_FIELDS = (
    "id",
    "organization_id",
    "version",
    "platform",
    "agent_type",
    "checksum_sha256",
    "signature",
    "is_prerelease",
    "download_url",
    "filename",
    "file_size",
    "min_backend_version",
)

# Same order and nullable fields as _BOUND_FIELDS and the AgentRelease model.
# Capture remains a snapshot; manifest verification still validates its values.
type PromotionValues = tuple[
    UUID, UUID | None, str, str, str, str, str | None, bool, str, str | None, int, str
]
type PromotionValue = UUID | str | int | None


@dataclass(frozen=True, repr=False)
class ReleasePromotionSnapshot:
    values: PromotionValues

    @classmethod
    def capture(cls, release: AgentRelease) -> ReleasePromotionSnapshot:
        return cls(cast(PromotionValues, tuple(getattr(release, name) for name in _BOUND_FIELDS)))

    @overload
    def get(self, field: Literal["id"]) -> UUID: ...

    @overload
    def get(self, field: Literal["organization_id"]) -> UUID | None: ...

    @overload
    def get(
        self,
        field: Literal[
            "version",
            "platform",
            "agent_type",
            "checksum_sha256",
            "download_url",
            "min_backend_version",
        ],
    ) -> str: ...

    @overload
    def get(self, field: Literal["signature", "filename"]) -> str | None: ...

    @overload
    def get(self, field: Literal["is_prerelease"]) -> bool: ...

    @overload
    def get(self, field: Literal["file_size"]) -> int: ...

    @overload
    def get(self, field: str) -> PromotionValue: ...

    def get(self, field: str) -> PromotionValue:
        return self.values[_BOUND_FIELDS.index(field)]

    def manifest(self) -> dict[str, object]:
        if (
            self.get("platform") not in {"linux", "windows", "macos"}
            or self.get("agent_type") not in {"daemon", "desktop"}
            or type(self.get("is_prerelease")) is not bool
        ):
            raise InvalidReleaseSignature("Release metadata is not canonical")
        version = self.get("version")
        if type(version) is not str or not 1 <= len(version) <= 50 or not version.strip():
            raise InvalidReleaseSignature("Release version is not canonical")
        checksum = self.get("checksum_sha256")
        if (
            type(checksum) is not str
            or len(checksum) != 64
            or any(c not in "0123456789abcdef" for c in checksum)
        ):
            raise InvalidReleaseSignature("Release checksum is not canonical")
        return build_release_manifest(
            digest_hex=checksum,
            version=self.get("version"),
            platform=self.get("platform"),
            agent_type=self.get("agent_type"),
            channel="prerelease" if self.get("is_prerelease") else "stable",
        )


def release_bucket_key(organization_id: UUID | None, platform: str, agent_type: str) -> int:
    if (
        organization_id is not None
        and not isinstance(organization_id, UUID)
        or platform not in {"linux", "windows", "macos"}
        or agent_type not in {"daemon", "desktop"}
    ):
        raise ValueError("Invalid release bucket")
    encoded = json.dumps(
        [str(organization_id) if organization_id else None, platform, agent_type],
        separators=(",", ":"),
    ).encode()
    return int.from_bytes(
        hashlib.sha256(b"FreeSDN/release-latest/v1\0" + encoded).digest()[:8], "big", signed=True
    )


async def lock_release_bucket(
    session: AsyncSession, organization_id: UUID | None, platform: str, agent_type: str
) -> None:
    """Admit before any release-row lock. A busy operation is never auto-retried."""
    # Starts a transaction when ordinary API-key authentication committed usage.
    await session.execute(text("SET LOCAL lock_timeout = '5s'"))
    await session.execute(text("SET LOCAL statement_timeout = '5s'"))
    acquired = await session.scalar(
        text("SELECT pg_try_advisory_xact_lock(CAST(:key AS bigint))"),
        {"key": release_bucket_key(organization_id, platform, agent_type)},
    )
    if not acquired:
        raise HTTPException(409, "Release publication busy; retry operation")


async def lock_verified_identity(session: AsyncSession, identity: TrustedSigningIdentity) -> None:
    """Retain the verified public identity through this short SQL mutation."""
    await session.execute(
        select(AgentSigningIdentity.singleton_id)
        .where(AgentSigningIdentity.singleton_id == 1)
        .with_for_update(read=True, nowait=True)
    )
    await session.execute(
        select(AgentSigningIntent.operation_id)
        .where(AgentSigningIntent.operation_id == identity.operation_id)
        .with_for_update(read=True, nowait=True)
    )
    if _trusted((await session.execute(_identity_statement())).mappings().all()) != identity:
        raise SigningKeyError("Signing identity changed before release commit")


async def promote_verified_release(
    session: AsyncSession,
    *,
    snapshot: ReleasePromotionSnapshot,
    authority: ReleaseMutationAuthority,
) -> dict[str, object]:
    """Own rollback/commit for the endpoint's session, with no automatic retry."""
    try:
        authority.require_scope(snapshot.get("organization_id"))
        identity = await verify_manifest_async(snapshot.manifest(), snapshot.get("signature"))
        await lock_release_bucket(
            session,
            snapshot.get("organization_id"),
            snapshot.get("platform"),
            snapshot.get("agent_type"),
        )
        # Refresh after the real target-row wait; never authorize the cached ORM.
        release = (
            await session.execute(
                select(AgentRelease)
                .where(AgentRelease.id == snapshot.get("id"))
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if release is None:
            raise HTTPException(404, "Release not found")
        authority.require_scope(release.organization_id)
        if ReleasePromotionSnapshot.capture(release) != snapshot:
            raise HTTPException(
                409, "Release changed during verification; reload it before promotion"
            )
        fence = await authority.lock(session)
        await lock_verified_identity(session, identity)
        bucket = (
            AgentRelease.organization_id.is_(None)
            if release.organization_id is None
            else AgentRelease.organization_id == release.organization_id
        )
        await session.execute(
            update(AgentRelease)
            .where(
                AgentRelease.platform == release.platform,
                AgentRelease.agent_type == release.agent_type,
                AgentRelease.is_latest,
                bucket,
            )
            .values(is_latest=False)
        )
        release.is_latest = True
        await session.flush()
        await fence.recheck()
        response = {
            column.key: getattr(release, column.key) for column in AgentRelease.__table__.columns
        }
        await session.commit()
        return response
    except InvalidReleaseSignature:
        await session.rollback()
        raise HTTPException(
            409, "Release has no valid manifest signature; publish a verified replacement"
        ) from None
    except (SigningKeyError, SigningBusyError):
        await session.rollback()
        raise HTTPException(503, "Trusted release verification is unavailable") from None
    except DBAPIError as error:
        await session.rollback()
        code = getattr(error.orig, "sqlstate", None) or getattr(error.orig, "pgcode", None)
        if code in {"55P03", "57014"}:
            raise HTTPException(
                409, "Release operation is busy; retry with current state"
            ) from None
        raise
    except Exception:
        await session.rollback()
        raise
