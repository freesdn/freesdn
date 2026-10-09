# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Immutable reviewed deletion target; never a filename or cleanup capability.

Raw bounded metadata is bound exactly, including signature and publication time.
Download counts are deliberately excluded; latest status remains part of the
reviewed target. Invalid/unrepresentable historical records need a separate
explicit repair flow; this codec never invents a payload hash or truncates them.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from app.services.agent_release_request import ReleaseMetadata, _encode, _uuid

_FIELDS = {
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
    "signature",
    "published_at",
}


class DeletionMetadata(ReleaseMetadata):
    """Canonical target fields checked by ReleaseDeletionRequest.__post_init__."""

    signature: str | None
    published_at: str


class ReleaseRow(Protocol):
    """Named-column access shared by SQLAlchemy rows and plain record mappings."""

    def __getitem__(self, key: str, /) -> object: ...


def _metadata(release: ReleaseRow) -> dict[str, object]:
    result = {name: release[name] for name in _FIELDS}
    stamp = result["published_at"]
    if type(stamp) is not datetime or stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("Release publication time is unavailable")
    result["published_at"] = stamp.astimezone(UTC).isoformat()
    return result


@dataclass(frozen=True, repr=False)
class ReleaseDeletionRequest:
    operation_id: UUID
    release_id: UUID
    organization_id: UUID | None
    metadata_bytes: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _uuid(self.operation_id))
        object.__setattr__(self, "release_id", _uuid(self.release_id))
        object.__setattr__(self, "organization_id", _uuid(self.organization_id, nullable=True))
        if type(self.metadata_bytes) is not bytes or not 1 <= len(self.metadata_bytes) <= 262144:
            raise ValueError("Invalid bounded release deletion metadata")
        row = json.loads(self.metadata_bytes)
        if type(row) is not dict or set(row) != _FIELDS or _encode(row) != self.metadata_bytes:
            raise ValueError("Deletion target is not canonical")
        for name, maximum in [
            ("version", 50),
            ("platform", 50),
            ("agent_type", 50),
            ("download_url", 500),
            ("release_notes", 20000),
            ("min_backend_version", 50),
        ]:
            if type(row[name]) is not str or len(row[name]) > maximum or "\x00" in row[name]:
                raise ValueError("Deletion target text cannot be represented safely")
        if row["platform"].lower() not in ("linux", "windows", "macos") or row[
            "agent_type"
        ].lower() not in ("daemon", "desktop"):
            raise ValueError("Unsupported deletion bucket")
        if (
            type(row["checksum_sha256"]) is not str
            or re.fullmatch(r"[0-9a-fA-F]{64}", row["checksum_sha256"]) is None
            or type(row["file_size"]) is not int
            or not 0 <= row["file_size"] <= 10737418240
            or type(row["is_latest"]) is not bool
            or type(row["is_prerelease"]) is not bool
        ):
            raise ValueError("Invalid deletion payload or status binding")
        for name, maximum in [("filename", 128), ("signature", 4096)]:
            value = row[name]
            if value is not None and (
                type(value) is not str or len(value) > maximum or "\x00" in value
            ):
                raise ValueError("Invalid deletion target field")
        if type(row["published_at"]) is not str or len(row["published_at"]) > 40:
            raise ValueError("Invalid deletion publication time")
        stamp = datetime.fromisoformat(row["published_at"])
        if (
            stamp.tzinfo is None
            or stamp.utcoffset() is None
            or stamp.astimezone(UTC).isoformat() != row["published_at"]
        ):
            raise ValueError("Deletion publication time must be canonical UTC")

    @classmethod
    def capture(cls, *, operation_id: UUID, release: ReleaseRow) -> ReleaseDeletionRequest:
        # The constructor below validates both raw identifiers; these casts
        # describe that boundary without bypassing or moving its checks.
        return cls(
            operation_id,
            cast(UUID, release["id"]),
            cast(UUID | None, release["organization_id"]),
            _encode(_metadata(release)),
        )

    def metadata(self) -> DeletionMetadata:
        # The common owner uses only platform/type for its coordination bucket.
        # Preserve original field case in target bytes and exact row comparison.
        row = cast(DeletionMetadata, json.loads(self.metadata_bytes))
        row["platform"], row["agent_type"] = row["platform"].lower(), row["agent_type"].lower()
        return row

    def matches(self, release: ReleaseRow) -> bool:
        return (
            release["id"] == self.release_id
            and release["organization_id"] == self.organization_id
            and _encode(_metadata(release)) == self.metadata_bytes
        )

    def request_bytes(self) -> bytes:
        return _encode(
            {
                "format": 1,
                "kind": "delete",
                "operation_id": str(self.operation_id),
                "release_id": str(self.release_id),
                "organization_id": str(self.organization_id)
                if self.organization_id is not None
                else None,
                "metadata_sha256": hashlib.sha256(
                    b"FreeSDN/release-deletion-target/v1\0" + self.metadata_bytes
                ).hexdigest(),
            }
        )

    def request_sha256(self) -> str:
        return hashlib.sha256(self.request_bytes()).hexdigest()
