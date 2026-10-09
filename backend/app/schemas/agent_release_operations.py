# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded explicit operation intent; contains no path, budget or authority proof."""

import json
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import ReleasePublicationRequest, _encode

MAX_COMMAND_BYTES = 300 * 1024


class _Intent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: UUID
    release_id: UUID
    organization_id: UUID | None
    metadata: dict[str, Any]


class PublicationIntent(_Intent):
    kind: Literal["publish"]
    storage_kind: Literal["owned", "external"]

    def command(self) -> ReleasePublicationRequest:
        return ReleasePublicationRequest(
            self.operation_id,
            self.release_id,
            self.organization_id,
            self.storage_kind,
            _encode(self.metadata),
        )


class DeletionIntent(_Intent):
    kind: Literal["delete"]

    def command(self) -> ReleaseDeletionRequest:
        return ReleaseDeletionRequest(
            self.operation_id, self.release_id, self.organization_id, _encode(self.metadata)
        )


_INTENT: TypeAdapter[PublicationIntent | DeletionIntent] = TypeAdapter(
    Annotated[PublicationIntent | DeletionIntent, Field(discriminator="kind")]
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate release command field")
        result[key] = value
    return result


def decode_release_command(raw: bytes) -> ReleasePublicationRequest | ReleaseDeletionRequest:
    """Validate the same full intent on every retry; never reconstruct missing metadata.

    Duplicate fields and non-finite JSON are refused before Pydantic sees input.
    The validated service codec checks exact metadata fields, canonical values,
    supported sizes and publication/deletion binding. No request value can select
    a server storage root or change resource limits.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_COMMAND_BYTES:
        raise ValueError("Invalid bounded release command")
    raw.decode("utf-8", errors="strict")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    _encode(value)  # Reject non-finite numbers and unpaired Unicode surrogates.
    intent = _INTENT.validate_json(raw, strict=True)
    return intent.command()


def encode_release_command(command: ReleasePublicationRequest | ReleaseDeletionRequest) -> bytes:
    """Retain the full validated intent, not just its irreversible commitment.

    Deletion metadata uses its original bytes: metadata() normalizes the bucket
    and would silently change a historical mixed-case target. This document is
    not an authorization token and must not contain operator credentials.
    """
    if type(command) not in (ReleasePublicationRequest, ReleaseDeletionRequest):
        raise ValueError("Validated release intent required")
    value = {
        "kind": "delete" if type(command) is ReleaseDeletionRequest else "publish",
        "operation_id": str(command.operation_id),
        "release_id": str(command.release_id),
        "organization_id": str(command.organization_id)
        if command.organization_id is not None
        else None,
        "metadata": json.loads(command.metadata_bytes),
    }
    if type(command) is ReleasePublicationRequest:
        value["storage_kind"] = command.storage_kind
    raw = _encode(value)
    if decode_release_command(raw) != command:
        raise ValueError("Release intent could not be retained exactly")
    return raw
