# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Typed private wire contract without framework body parsing or authority grants.

Body schemas are documentation only: the existing authenticated bounded readers
and exact service codecs remain the acceptance boundary. Output validation must
not manufacture missing safety flags or discard unexpected result fields.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, is_dataclass
from typing import Annotated, Literal, Self, cast
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    StrictStr,
    TypeAdapter,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue

from app.schemas.agent_release_operations import MAX_COMMAND_BYTES, decode_release_command
from app.services.agent_release_request import _encode, _uuid


def _nonzero(value: UUID) -> UUID:
    _uuid(value)
    return value


def _false(value: object) -> Literal[False]:
    if value is not False:
        raise ValueError("An explicit false safety flag is required")
    return value


def _true(value: object) -> Literal[True]:
    if value is not True:
        raise ValueError("An explicit true observation flag is required")
    return value


Identity = Annotated[UUID, AfterValidator(_nonzero)]
Digest = Annotated[StrictStr, Field(pattern="^[0-9a-f]{64}$", min_length=64, max_length=64)]
FalseFlag = Annotated[Literal[False], BeforeValidator(_false)]
TrueFlag = Annotated[Literal[True], BeforeValidator(_true)]
Phase = Literal["reserved", "prepared", "decided", "cleaned"]
Decision = Literal["cancelled", "published", "deleted"]


class _Wire(BaseModel):
    model_config = ConfigDict(
        extra="forbid", revalidate_instances="always", hide_input_in_errors=True
    )

    @model_validator(mode="before")
    @classmethod
    def complete_fields(cls, value: object) -> object:
        # FastAPI may request from_attributes=True independently of model config.
        # Convert the COMPLETE dataclass, including unexpected future fields,
        # rather than silently projecting whichever attributes the model knows.
        if isinstance(value, cls):
            return value
        if is_dataclass(value) and not isinstance(value, type):
            return asdict(value)
        if type(value) is not dict:
            raise ValueError("Complete release response fields are required")
        return value


class PublicationMetadata(_Wire):
    version: StrictStr = Field(min_length=1, max_length=50)
    platform: Literal["linux", "windows", "macos"]
    agent_type: Literal["daemon", "desktop"]
    download_url: StrictStr = Field(min_length=1, max_length=500)
    checksum_sha256: Digest
    file_size: StrictInt = Field(
        ge=0,
        le=10737418240,
        description="Owned payloads additionally require at most 524288000 bytes.",
    )
    release_notes: StrictStr = Field(max_length=20000)
    min_backend_version: StrictStr = Field(max_length=50)
    is_prerelease: StrictBool
    is_latest: StrictBool
    filename: Annotated[StrictStr, Field(max_length=128)] | None


class DeletionMetadata(_Wire):
    # Historical case/time/signature are part of the original commitment. Do
    # not parse published_at into a datetime or normalize these strings.
    version: StrictStr = Field(max_length=50)
    platform: StrictStr = Field(max_length=50)
    agent_type: StrictStr = Field(max_length=50)
    download_url: StrictStr = Field(max_length=500)
    checksum_sha256: StrictStr = Field(pattern="^[0-9a-fA-F]{64}$", min_length=64, max_length=64)
    file_size: StrictInt = Field(ge=0, le=10737418240)
    release_notes: StrictStr = Field(max_length=20000)
    min_backend_version: StrictStr = Field(max_length=50)
    is_prerelease: StrictBool
    is_latest: StrictBool
    filename: Annotated[StrictStr, Field(max_length=128)] | None
    signature: Annotated[StrictStr, Field(max_length=4096)] | None
    published_at: StrictStr = Field(
        max_length=40,
        description="Original canonical UTC ISO timestamp; retain its exact spelling.",
    )


class _Document(_Wire):
    operation_id: Identity
    release_id: Identity
    organization_id: Identity | None

    @model_validator(mode="after")
    def same_service_contract(self) -> Self:
        # Also enforces linked UUID/URL, storage/filename, canonical timestamp,
        # NUL, UTF-8 byte limits and other semantic rules not expressible as
        # independent JSON Schema field constraints. No database or I/O here.
        decode_release_command(_encode(self.model_dump(mode="json")))
        return self


class PublicationDocument(_Document):
    kind: Literal["publish"]
    storage_kind: Literal["owned", "external"]
    metadata: PublicationMetadata


class DeletionDocument(_Document):
    kind: Literal["delete"]
    metadata: DeletionMetadata


class OwnedPublicationMetadata(PublicationMetadata):
    version: StrictStr = Field(pattern="^[A-Za-z0-9._+-]{1,50}$", min_length=1, max_length=50)
    file_size: StrictInt = Field(ge=0, le=524288000)
    filename: StrictStr = Field(min_length=1, max_length=128)


class OwnedPublicationDocument(PublicationDocument):
    storage_kind: Literal["owned"]
    metadata: OwnedPublicationMetadata


IntentDocument = Annotated[PublicationDocument | DeletionDocument, Field(discriminator="kind")]
_INTENT_DOCUMENT: TypeAdapter[PublicationDocument | DeletionDocument] = TypeAdapter(IntentDocument)
_OWNED_DOCUMENT = TypeAdapter(OwnedPublicationDocument)


class JournalObservation(_Wire):
    operation_id: Identity
    release_id: Identity
    organization_id: Identity | None
    requested_by: Identity
    kind: Literal["publish", "delete"]
    storage_kind: Literal["owned", "external", "legacy"]
    phase: Phase
    decision: Decision | None
    transition_sequence: StrictInt = Field(ge=0, le=3)
    created_at: AwareDatetime
    prepared_at: AwareDatetime | None
    decided_at: AwareDatetime | None
    cleaned_at: AwareDatetime | None
    last_transition_by: Identity


class _UnverifiedObservation(_Wire):
    storage_checked: FalseFlag
    all_artifact_references_checked: FalseFlag
    authorization_granted: FalseFlag
    absence_authorizes_retry_or_cleanup: FalseFlag


class OperationStatusResponse(_UnverifiedObservation):
    operation: JournalObservation
    release_row_present: StrictBool
    observed_at: AwareDatetime


class IntentReviewResponse(_UnverifiedObservation):
    intent: IntentDocument
    intent_sha256: Digest
    operation: JournalObservation | None
    release_row_present: StrictBool
    deletion_target_matches: StrictBool | None
    observed_at: AwareDatetime
    historical_observation: TrueFlag
    reservation_created: FalseFlag
    server_retains_full_intent: FalseFlag
    save_original_intent_before_mutation: TrueFlag
    retry_requires_identical_intent_and_current_authority: TrueFlag

    @model_validator(mode="after")
    def retained_intent_binding(self) -> Self:
        command = decode_release_command(_encode(self.intent.model_dump(mode="json")))
        if command.request_sha256() != self.intent_sha256:
            raise ValueError("Review commitment differs from its retained intent")
        if self.operation is not None and (
            self.operation.operation_id != command.operation_id
            or self.operation.release_id != command.release_id
            or self.operation.organization_id != command.organization_id
            or self.operation.kind != self.intent.kind
        ):
            raise ValueError("Review observation differs from its intent identity")
        return self


class _Result(_Wire):
    operation_id: Identity
    release_id: Identity


class ReservationResult(_Result):
    phase: Phase
    decision: Literal["published", "cancelled"] | None
    created: StrictBool
    requested_by: Identity
    last_transition_by: Identity


class PreparationResult(_Result):
    phase: Literal["prepared"]
    requested_by: Identity
    last_transition_by: Identity
    publication_or_storage_authorized: FalseFlag


class PublicationResult(_Result):
    decision: Literal["published"]
    newly_published: StrictBool
    release_row_present: StrictBool
    current_is_latest: StrictBool | None
    artifact_verified_this_call: StrictBool
    signature_verified_this_call: StrictBool
    publication_or_storage_authorized: FalseFlag


class DeletionResult(_Result):
    phase: Phase
    decision: Literal["deleted", "cancelled"] | None
    newly_changed: StrictBool
    cleanup_disposition: Literal[
        "preserve-live",
        "pending-owned-verification",
        "no-owned-file",
        "retain-unverified",
        "not-authorized",
    ]
    bytes_removed: FalseFlag
    cleanup_authorized: FalseFlag


class CleanupResult(_Result):
    phase: Literal["decided", "cleaned"]
    decision: Literal["deleted", "cancelled"]
    disposition: Literal["preserve-live", "no-owned-file", "retain-unverified", "retire-owned"]
    newly_recorded: StrictBool
    payload_absence_verified_this_call: StrictBool
    complete: StrictBool
    authorization_granted: FalseFlag

    @model_validator(mode="after")
    def cleanup_is_not_an_unverified_completion(self) -> Self:
        if self.complete != (self.phase == "cleaned" and self.disposition != "retain-unverified"):
            raise ValueError("Cleanup completion differs from its retained disposition")
        if self.payload_absence_verified_this_call and self.disposition != "retire-owned":
            raise ValueError("Payload verification differs from the owned cleanup disposition")
        return self


class _Envelope(_Wire):
    result: _Result
    operation_id: Identity
    release_id: Identity
    intent_sha256: Digest
    historical_observation: TrueFlag
    authorization_granted: FalseFlag
    retry_requires_identical_intent_and_current_authority: TrueFlag

    @model_validator(mode="after")
    def result_identity_matches(self) -> Self:
        if (self.result.operation_id, self.result.release_id) != (
            self.operation_id,
            self.release_id,
        ):
            raise ValueError("Result belongs to a different release operation")
        return self


class OperationResponse(_Envelope):
    result: (
        ReservationResult | PreparationResult | PublicationResult | DeletionResult | CleanupResult
    )


class UploadResponse(_Envelope):
    result: PreparationResult


class ValidationDetail(_Wire):
    field: StrictStr
    message: StrictStr
    type: StrictStr


class ErrorDetail(_Wire):
    code: StrictInt
    message: JsonValue
    request_id: StrictStr | None
    details: list[ValidationDetail] | None = None


class ApplicationError(_Wire):
    error: ErrorDetail


class BodyLimitError(_Wire):
    detail: StrictStr


ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    code: {
        "model": ApplicationError | BodyLimitError,
        "description": "Request refused or outcome unconfirmed. This response does not prove rollback; inspect the same operation before any explicit retry.",
    }
    for code in (400, 401, 403, 404, 408, 409, 413, 415, 422, 429, 500, 503)
}


def _intent_schema(*, owned_only: bool = False) -> JsonSchemaValue:
    # Do not add Body/Form parameters: FastAPI would parse before our bounded,
    # authenticated readers. Inline this finite documentation schema so no
    # dangling #/$defs or discriminator mappings enter the OpenAPI document.
    schema = (_OWNED_DOCUMENT if owned_only else _INTENT_DOCUMENT).json_schema()
    definitions = schema.pop("$defs", {})

    def expand(value: object, seen: tuple[str, ...] = ()) -> object:
        if isinstance(value, list):
            return [expand(item, seen) for item in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            ref = value["$ref"]
            if not ref.startswith("#/$defs/") or ref in seen:
                raise ValueError("Unexpected recursive intent documentation")
            target = definitions[ref[len("#/$defs/") :]]
            return expand(
                {**deepcopy(target), **{k: v for k, v in value.items() if k != "$ref"}},
                (*seen, ref),
            )
        return {k: expand(v, seen) for k, v in value.items() if k not in ("$defs", "discriminator")}

    # Pydantic's generated schema root is an object. Expansion preserves that
    # root while resolving only its finite internal documentation references.
    return cast(JsonSchemaValue, expand(schema))


def command_body_contract() -> JsonSchemaValue:
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": _intent_schema()}},
            "description": "Retain the full original intent before mutation. Duplicate JSON keys, non-finite values, semantic identity mismatches and requests above 307200 UTF-8 bytes are refused.",
        },
        "x-max-request-body-bytes": MAX_COMMAND_BYTES,
        "x-automatic-retry-permitted": False,
    }


def upload_body_contract() -> JsonSchemaValue:
    return {
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["intent", "file"],
                        "properties": {
                            "intent": _intent_schema(owned_only=True),
                            "file": {"type": "string", "format": "binary"},
                        },
                    },
                    "encoding": {
                        "intent": {"contentType": "application/json"},
                        "file": {"contentType": "application/octet-stream"},
                    },
                }
            },
            "description": "Exactly two parts in order: full owned-publication intent JSON, then file. Save the intent first. Standard OpenAPI cannot enforce part order or the linked payload checksum/size; the server does. Filename is transport-only. A response is a historical preparation observation, not publication.",
        },
        "x-multipart-part-order": ["intent", "file"],
        "x-max-file-bytes": 524288000,
        "x-max-request-body-bytes": 524660736,
        "x-automatic-retry-permitted": False,
    }


def release_context_contract() -> JsonSchemaValue:
    return {
        "parameters": [
            {
                "name": "X-FreeSDN-Release-Actor",
                "in": "header",
                "required": False,
                "schema": {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36},
                "description": "Browser initiating account, paired with the organization header. Canonical nonzero UUID. Must equal the authenticated caller; grants no authority.",
            },
            {
                "name": "X-FreeSDN-Release-Organization",
                "in": "header",
                "required": False,
                "schema": {
                    "anyOf": [
                        {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36},
                        {"const": "none", "type": "string"},
                    ]
                },
                "description": "Initiating account organization, not target release organization. Use none only for an account without an organization. Both headers must occur exactly once when supplied.",
            },
        ]
    }


def release_download_context_contract() -> JsonSchemaValue:
    """Native browser query pair; nonsecret identity equality, not credentials."""
    contract = release_context_contract()
    contract["parameters"].extend(
        [
            {
                "name": "release_actor",
                "in": "query",
                "required": False,
                "schema": {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36},
                "description": "Native browser initiating account. Canonical nonzero UUID paired with release_organization; must equal the authenticated operator. Not a token or authority grant.",
            },
            {
                "name": "release_organization",
                "in": "query",
                "required": False,
                "schema": {
                    "anyOf": [
                        {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36},
                        {"const": "none", "type": "string"},
                    ]
                },
                "description": "Initiating account organization, never the target release organization. Both query parameters must occur exactly once when supplied. Existing nonbrowser clients may omit both. Any supplied header pair must also match.",
            },
        ]
    )
    contract["parameters"].extend(
        [
            {
                "name": "Range",
                "in": "header",
                "required": False,
                "schema": {"type": "string"},
                "description": "Optional byte ranges. A satisfiable request returns206; multiple ranges use multipart/byteranges.",
            },
            {
                "name": "If-Range",
                "in": "header",
                "required": False,
                "schema": {"type": "string"},
                "description": "ETag or HTTP date condition for Range. A nonmatching condition returns the full representation.",
            },
        ]
    )
    binary_content = {
        "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
    }
    headers = {
        "Content-Length": {"schema": {"type": "integer", "minimum": 0}},
        "Content-Disposition": {
            "schema": {"type": "string"},
            "description": "Attachment filename.",
        },
        "ETag": {
            "schema": {"type": "string"},
            "description": "Quoted SHA-256 content digest; not an authorization grant.",
        },
        "Last-Modified": {
            "schema": {"type": "string"},
            "description": "HTTP date of the verified local file.",
        },
        "Accept-Ranges": {"schema": {"type": "string", "enum": ["bytes"]}},
        "Cache-Control": {
            "schema": {"type": "string"},
            "description": "Private/no-store response policy.",
        },
    }
    contract["responses"] = {
        "200": {
            "description": "Verified binary attachment. HEAD serves the same status/headers without a body or download-count increment.",
            "content": binary_content,
            "headers": headers,
        },
        "206": {
            "description": "Verified partial attachment; multiple ranges use a multipart body.",
            "content": {
                **binary_content,
                "multipart/byteranges": {"schema": {"type": "string", "format": "binary"}},
            },
            "headers": {
                **headers,
                "Content-Range": {
                    "schema": {"type": "string"},
                    "description": "Present for a single range; multipart ranges carry per-part Content-Range.",
                },
            },
        },
        "416": {
            "description": "Requested ranges do not overlap the verified representation. Empty response body.",
            "content": {"text/plain": {"schema": {"type": "string", "maxLength": 0}}},
            "headers": {
                "Content-Range": {
                    "schema": {"type": "string"},
                    "description": "bytes */ followed by the verified total size.",
                }
            },
        },
    }
    return contract
