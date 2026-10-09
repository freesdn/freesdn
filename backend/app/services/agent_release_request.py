# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Immutable public publication metadata, bound without truncating valid notes.

The journal stores a versioned commitment to the complete validated metadata.
A resume must resubmit that same metadata; the commitment cannot reconstruct it.
This is not authority, a signature, a file path or evidence that bytes exist.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal, TypedDict, cast, overload
from uuid import UUID

from app.schemas.agent_downloads import AgentReleaseCreate

_METADATA_FIELDS = {
    "version",
    "platform",
    "agent_type",
    "download_url",
    "checksum_sha256",
    "file_size",
    "release_notes",
    "min_backend_version",
    "is_prerelease",
    "is_latest",
    "filename",
}


class ReleaseMetadata(TypedDict):
    """Fields validated in full before an immutable publication request exists."""

    version: str
    platform: str
    agent_type: str
    download_url: str
    checksum_sha256: str
    file_size: int
    release_notes: str
    min_backend_version: str
    is_prerelease: bool
    is_latest: bool
    filename: str | None


def _encode(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


@overload
def _uuid(value: object, *, nullable: Literal[False] = False) -> UUID: ...


@overload
def _uuid(value: object, *, nullable: Literal[True]) -> UUID | None: ...


@overload
def _uuid(value: object, *, nullable: bool) -> UUID | None: ...


def _uuid(value: object, *, nullable: bool = False) -> UUID | None:
    if value is None and nullable:
        return None
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("Invalid release request identity")
    # asyncpg returns a UUID subclass. Preserve its exact 128-bit value while
    # keeping downstream immutable requests and filesystem contracts canonical.
    return value if type(value) is UUID else UUID(bytes=value.bytes)


@dataclass(frozen=True, repr=False)
class ReleasePublicationRequest:
    operation_id: UUID
    release_id: UUID
    organization_id: UUID | None
    storage_kind: str
    metadata_bytes: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _uuid(self.operation_id))
        object.__setattr__(self, "release_id", _uuid(self.release_id))
        object.__setattr__(self, "organization_id", _uuid(self.organization_id, nullable=True))
        if self.storage_kind not in ("owned", "external"):
            raise ValueError("New publication requires owned or external storage")
        if type(self.metadata_bytes) is not bytes or not 1 <= len(self.metadata_bytes) <= 262144:
            raise ValueError("Invalid bounded release metadata")
        row = json.loads(self.metadata_bytes)
        if (
            type(row) is not dict
            or set(row) != _METADATA_FIELDS
            or _encode(row) != self.metadata_bytes
        ):
            raise ValueError("Release metadata is not canonical")
        if any(type(value) is str and "\x00" in value for value in row.values()):
            raise ValueError("Release text cannot contain a database-invalid NUL")
        payload = {key: value for key, value in row.items() if key not in ("filename", "is_latest")}
        checked = AgentReleaseCreate.model_validate(payload, strict=True).model_dump()
        if checked != payload or type(row["is_latest"]) is not bool:
            raise ValueError("Release metadata failed validation")
        if (
            row["platform"] not in ("linux", "windows", "macos")
            or row["agent_type"] not in ("daemon", "desktop")
            or row["checksum_sha256"] != row["checksum_sha256"].lower()
        ):
            raise ValueError("Release platform, type or checksum is not normalized")
        if self.storage_kind == "owned":
            name = row["filename"]
            if (
                row["file_size"] > 524288000
                or re.fullmatch(r"[A-Za-z0-9._+-]{1,50}", row["version"]) is None
                or type(name) is not str
                or not 1 <= len(name) <= 128
                or name in (".", "..")
                or any(c in name for c in ("/", "\\", "\x00"))
                or row["download_url"] != f"/api/v1/agents/releases/{self.release_id}/binary"
            ):
                raise ValueError("Owned release metadata does not bind this publication")
        elif row["filename"] is not None:
            raise ValueError("External metadata cannot claim an owned filename")

    @classmethod
    def create(
        cls,
        *,
        operation_id: UUID,
        release_id: UUID,
        organization_id: UUID | None,
        storage_kind: str,
        payload: AgentReleaseCreate,
        is_latest: bool,
        filename: str | None,
    ) -> ReleasePublicationRequest:
        if type(payload) is not AgentReleaseCreate:
            raise ValueError("Validated release metadata is required")
        row = payload.model_dump()
        row.update(
            platform=row["platform"].lower(),
            agent_type=row["agent_type"].lower(),
            checksum_sha256=row["checksum_sha256"].lower(),
            is_latest=is_latest,
            filename=filename,
        )
        return cls(operation_id, release_id, organization_id, storage_kind, _encode(row))

    def metadata(self) -> ReleaseMetadata:
        # __post_init__ validates every field and canonical byte before this
        # frozen value is available. The cast adds no validation or authority.
        return cast(ReleaseMetadata, json.loads(self.metadata_bytes))

    def request_bytes(self) -> bytes:
        # Notes alone can exceed64KiB in canonical JSON while remaining within
        # the existing20,000-character API limit. Preserve all validated bytes;
        # commit to them rather than truncate or shrink the supported request.
        return _encode(
            {
                "format": 1,
                "kind": "publish",
                "operation_id": str(self.operation_id),
                "release_id": str(self.release_id),
                "organization_id": str(self.organization_id)
                if self.organization_id is not None
                else None,
                "storage_kind": self.storage_kind,
                "metadata_sha256": hashlib.sha256(
                    b"FreeSDN/release-public-metadata/v1\0" + self.metadata_bytes
                ).hexdigest(),
            }
        )

    def request_sha256(self) -> str:
        return hashlib.sha256(self.request_bytes()).hexdigest()


@dataclass(frozen=True)
class ReleaseReservationBudget:
    """Trusted deployment policy, not a client-supplied override or disk proof."""

    global_history: int
    organization_history: int
    global_owned_bytes: int
    organization_owned_bytes: int

    def __post_init__(self) -> None:
        for value in (
            self.global_history,
            self.organization_history,
            self.global_owned_bytes,
            self.organization_owned_bytes,
        ):
            if type(value) is not int or not 1 <= value <= 9223372036854775807:
                raise ValueError("Reservation limits require positive bounded integers")
