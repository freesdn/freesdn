# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Interpret retained decisions, not exceptions, as a proposed cleanup plan.

This is not the SQL coordinator. Its caller must authenticate, read committed
rows under operation/release coordination, prove absence of every live reference,
and keep ownership across the ensuing filesystem work. Do not populate these
arguments from request JSON, stale ORM instances, a racing SELECT or an ambiguous
commit response. The module contains no SQL or filesystem operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, TypedDict, cast
from uuid import UUID

from sqlalchemy.engine import RowMapping

from app.services.agent_release_artifact_store import (
    ArtifactCleanupDecision,
    ArtifactIntent,
    ArtifactUnavailable,
)

_FIELDS = {
    "operation_id",
    "format_version",
    "kind",
    "release_id",
    "organization_id",
    "requested_by",
    "storage_kind",
    "artifact_id",
    "request_bytes",
    "request_sha256",
    "expected_sha256",
    "expected_size",
    "phase",
    "decision",
    "transition_sequence",
    "created_at",
    "prepared_at",
    "decided_at",
    "cleaned_at",
    "last_transition_by",
}


@dataclass(frozen=True)
class ReleaseCleanupPlan:
    outcome: Literal["preserve-live", "no-owned-file", "retain-unverified", "retire-owned"]
    operation_id: UUID
    decision: ArtifactCleanupDecision | None = None


class ReleaseOperationRecord(TypedDict):
    """Retained fields checked together by the record validator below.

    Optional associations and timestamps remain optional: callers must still
    check the operation kind and phase before relying on their presence.
    """

    operation_id: UUID
    format_version: int
    kind: Literal["publish", "delete"]
    release_id: UUID
    organization_id: UUID | None
    requested_by: UUID
    storage_kind: Literal["owned", "external", "legacy"]
    artifact_id: UUID | None
    request_bytes: bytes
    request_sha256: str
    expected_sha256: str
    expected_size: int
    phase: Literal["reserved", "prepared", "decided", "cleaned"]
    decision: Literal["cancelled", "published", "deleted"] | None
    transition_sequence: int
    created_at: datetime
    prepared_at: datetime | None
    decided_at: datetime | None
    cleaned_at: datetime | None
    last_transition_by: UUID


# SQLAlchemy row mappings also accept expression keys. _record's exact field-set
# check narrows that dynamic database boundary to the named record above.
type ReleaseOperationInput = Mapping[str, Any] | RowMapping


def _record(value: ReleaseOperationInput) -> ReleaseOperationRecord:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise ArtifactUnavailable("Incomplete retained release operation")
    row = dict(value)
    if type(row["format_version"]) is not int or row["format_version"] != 1:
        raise ArtifactUnavailable("Unsupported release operation format")
    for name in ("operation_id", "release_id", "requested_by", "last_transition_by"):
        if not isinstance(row[name], UUID) or row[name].int == 0:
            raise ArtifactUnavailable("Invalid retained operation identity")
        row[name] = UUID(bytes=row[name].bytes)
    for name in ("organization_id", "artifact_id"):
        if row[name] is not None and (not isinstance(row[name], UUID) or row[name].int == 0):
            raise ArtifactUnavailable("Invalid retained operation association")
        if row[name] is not None:
            row[name] = UUID(bytes=row[name].bytes)
    if row["kind"] not in ("publish", "delete") or row["storage_kind"] not in (
        "owned",
        "external",
        "legacy",
    ):
        raise ArtifactUnavailable("Invalid retained operation kind")
    owned = row["storage_kind"] == "owned"
    if (
        owned != (row["artifact_id"] is not None)
        or (row["kind"] == "publish" and row["storage_kind"] == "legacy")
        or (row["kind"] == "publish" and owned and row["artifact_id"] != row["operation_id"])
    ):
        raise ArtifactUnavailable("Invalid retained storage association")
    data = row["request_bytes"]
    if (
        type(data) is not bytes
        or not 1 <= len(data) <= 65536
        or type(row["request_sha256"]) is not str
        or hashlib.sha256(data).hexdigest() != row["request_sha256"]
        or type(row["expected_sha256"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", row["expected_sha256"]) is None
        or type(row["expected_size"]) is not int
        or not 0 <= row["expected_size"] <= (524288000 if owned else 10737418240)
    ):
        raise ArtifactUnavailable("Invalid retained release request or payload binding")
    for name in ("created_at", "prepared_at", "decided_at", "cleaned_at"):
        dt = row[name]
        if dt is not None:
            if type(dt) is not datetime or dt.tzinfo is None or dt.utcoffset() is None:
                raise ArtifactUnavailable("Invalid retained release time")
            row[name] = dt.astimezone(UTC)
    if row["created_at"] is None or type(row["transition_sequence"]) is not int:
        raise ArtifactUnavailable("Invalid retained operation ordering")
    phase, choice, prepared = row["phase"], row["decision"], row["prepared_at"] is not None
    if choice not in (None, "cancelled", "published" if row["kind"] == "publish" else "deleted"):
        raise ArtifactUnavailable("Invalid retained action and decision")
    sequence = row["transition_sequence"]
    valid = (
        (
            phase == "reserved"
            and sequence == 0
            and not prepared
            and choice is None
            and row["decided_at"] is None
            and row["cleaned_at"] is None
        )
        or (
            phase == "prepared"
            and sequence == 1
            and prepared
            and choice is None
            and row["decided_at"] is None
            and row["cleaned_at"] is None
        )
        or (
            phase == "decided"
            and choice is not None
            and row["decided_at"] is not None
            and row["cleaned_at"] is None
            and sequence == (2 if prepared else 1)
            and (prepared or choice == "cancelled")
        )
        or (
            phase == "cleaned"
            and choice in ("deleted", "cancelled")
            and row["decided_at"] is not None
            and row["cleaned_at"] is not None
            and sequence == (3 if prepared else 2)
            and (prepared or choice == "cancelled")
        )
    )
    times = [
        row[name]
        for name in ("created_at", "prepared_at", "decided_at", "cleaned_at")
        if row[name] is not None
    ]
    if not valid or times != sorted(times):
        raise ArtifactUnavailable("Retained release phase is inconsistent")
    # SQL/JSON-derived values are dynamic until every field and cross-field
    # predicate above has passed. This cast is not an alternate validator.
    return cast(ReleaseOperationRecord, row)


def plan_release_cleanup(
    *,
    operation: ReleaseOperationInput,
    publication: ReleaseOperationInput | None,
    live_reference_present: bool,
) -> ReleaseCleanupPlan:
    """Map a coordinated, committed observation to preservation or retirement."""
    row = _record(operation)
    if type(live_reference_present) is not bool:
        raise ArtifactUnavailable("Live reference observation is unavailable")
    if row["phase"] not in ("decided", "cleaned") or row["decision"] not in (
        "cancelled",
        "deleted",
    ):
        raise ArtifactUnavailable("Operation has no confirmed cleanup decision")
    if (row["kind"], row["decision"]) == ("delete", "cancelled"):
        return ReleaseCleanupPlan("preserve-live", row["operation_id"])
    if live_reference_present:
        raise ArtifactUnavailable("A live release still references this artifact")
    if row["storage_kind"] == "external":
        return ReleaseCleanupPlan("no-owned-file", row["operation_id"])
    if row["storage_kind"] == "legacy":
        return ReleaseCleanupPlan("retain-unverified", row["operation_id"])
    original = _record(publication) if publication is not None else row
    if original["kind"] != "publish" or original["storage_kind"] != "owned":
        raise ArtifactUnavailable("Original owned publication is unavailable")
    for name in (
        "release_id",
        "organization_id",
        "artifact_id",
        "expected_sha256",
        "expected_size",
    ):
        if cast(Mapping[str, object], original)[name] != cast(Mapping[str, object], row)[name]:
            raise ArtifactUnavailable("Cleanup targets another publication")
    if row["kind"] == "publish":
        if original != row:
            raise ArtifactUnavailable("Cancellation differs from retained publication")
    elif (
        original["phase"] != "decided"
        or original["decision"] != "published"
        or original["operation_id"] == row["operation_id"]
    ):
        raise ArtifactUnavailable("Deletion has no retained published predecessor")
    intent = ArtifactIntent(
        # The checked original is an owned publication; _record refuses an
        # absent artifact_id for that storage kind.
        cast(UUID, original["artifact_id"]),
        original["operation_id"],
        original["release_id"],
        original["request_sha256"],
        original["expected_sha256"],
        original["expected_size"],
    )
    # Do not include phase/cleaned_at: decided -> cleaned may be observed after a
    # successful cleanup whose SQL bookkeeping acknowledgement was lost.
    binding = {
        "format": 1,
        "operation_id": str(row["operation_id"]),
        "kind": row["kind"],
        "decision": row["decision"],
        # A decided/cleaned record has this timestamp by _record's phase check.
        "decided_at": cast(datetime, row["decided_at"]).isoformat(),
        "decision_sequence": 2 if row["prepared_at"] is not None else 1,
        "request_sha256": row["request_sha256"],
        "organization_id": str(row["organization_id"])
        if row["organization_id"] is not None
        else None,
        "requested_by": str(row["requested_by"]),
        "publication_requested_by": str(original["requested_by"]),
        "intent_sha256": hashlib.sha256(intent.encoded()).hexdigest(),
    }
    digest = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    decision = ArtifactCleanupDecision(
        intent,
        row["operation_id"],
        row["kind"],
        row["decision"],
        digest,
    )
    decision.encoded()
    return ReleaseCleanupPlan("retire-owned", row["operation_id"], decision)
