"""Planned wire fidelity/OpenAPI contracts; unrun, never runtime evidence.

Schemas document the existing acceptance boundary. They must not make FastAPI
consume a body before real authentication or silently change a retained intent.
"""

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from pydantic import TypeAdapter, ValidationError

from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.schemas.agent_release_operation_contract import (
    ApplicationError,
    BodyLimitError,
    CleanupResult,
    IntentDocument,
    IntentReviewResponse,
    OperationResponse,
    OwnedPublicationDocument,
    PreparationResult,
)
from app.schemas.agent_release_operations import decode_release_command, encode_release_command
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_preparation import ReleasePreparationResult
from app.services.agent_release_request import ReleaseReservationBudget, _encode
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_reservation as reservation_probes


def document(kind="publish", notes=""):
    if kind == "delete":
        return ReleaseDeletionRequest.capture(operation_id=uuid4(), release={**deletion_probes.sample(),
            "release_notes": notes, "signature": "opaque+signature/==", "published_at": datetime(2026, 1, 1, 0, 0, 0, 120000, tzinfo=UTC)})
    return reservation_probes.request_for(uuid4(), storage=kind if kind in ("external", "owned") else "owned", notes=notes)


def review_value(command):
    return {"intent": json.loads(encode_release_command(command)), "intent_sha256": command.request_sha256(),
            "operation": None, "release_row_present": False, "deletion_target_matches": None,
            "observed_at": datetime.now(UTC), "historical_observation": True, "authorization_granted": False,
            "storage_checked": False, "all_artifact_references_checked": False,
            "absence_authorizes_retry_or_cleanup": False, "reservation_created": False,
            "server_retains_full_intent": False, "save_original_intent_before_mutation": True,
            "retry_requires_identical_intent_and_current_authority": True}


def envelope():
    command = document()
    result = ReleasePreparationResult(command.operation_id, command.release_id, "prepared", uuid4(), uuid4())
    return {"operation_id": command.operation_id, "release_id": command.release_id,
            "intent_sha256": command.request_sha256(), "result": result, "historical_observation": True,
            "authorization_granted": False, "retry_requires_identical_intent_and_current_authority": True}


@pytest.mark.parametrize("kind", ["owned", "external", "delete"])
@pytest.mark.parametrize("notes", ["🦉" * 20000, "\x01" * 20000, '<script>&untrusted</script>'])
def test_response_roundtrip_retains_full_exact_command_and_historical_spelling(kind, notes):
    command = document(kind, notes)
    response = IntentReviewResponse.model_validate(review_value(command))
    wire = json.loads(response.model_dump_json())
    restored = decode_release_command(_encode(wire["intent"]))
    assert restored == command and restored.metadata_bytes == command.metadata_bytes
    assert restored.request_bytes() == command.request_bytes()
    assert wire["intent_sha256"] == command.request_sha256()
    assert wire["intent"]["metadata"]["release_notes"] == notes
    if kind == "delete":
        assert wire["intent"]["metadata"]["platform"] == "Linux"
        assert wire["intent"]["metadata"]["checksum_sha256"] == "A" * 64
        assert wire["intent"]["metadata"]["published_at"] == "2026-01-01T00:00:00.120000+00:00"
        assert wire["intent"]["metadata"]["signature"] == "opaque+signature/=="


@pytest.mark.parametrize("field", ["authorization_granted", "storage_checked", "all_artifact_references_checked",
                                   "absence_authorizes_retry_or_cleanup", "reservation_created", "server_retains_full_intent"])
@pytest.mark.parametrize("change", ["missing", "true", "zero", "null"])
def test_missing_or_coerced_safety_flags_cannot_be_manufactured(field, change):
    raw = review_value(document())
    if change == "missing":
        del raw[field]
    else:
        raw[field] = {"true": True, "zero": 0, "null": None}[change]
    with pytest.raises(ValidationError):
        IntentReviewResponse.model_validate(raw)


@pytest.mark.parametrize("change", ["digest", "extra-intent", "extra-result", "wrong-result-id", "object-result", "dataclass-extra", "string-size", "boolean-size"])
def test_extra_fields_coercion_or_cross_operation_result_are_refused(change):
    if change in ("digest", "extra-intent", "string-size", "boolean-size"):
        raw = review_value(document())
        if change == "digest":
            raw["intent_sha256"] = "0" * 64
        elif change == "extra-intent":
            raw["intent"]["authority"] = "not-an-authorization"
        else:
            raw["intent"]["metadata"]["file_size"] = "5" if change == "string-size" else True
        with pytest.raises(ValidationError):
            IntentReviewResponse.model_validate(raw)
        return
    raw = envelope()
    result = asdict(raw["result"])
    if change == "extra-result":
        result["credential"] = "synthetic-must-not-disappear"
    elif change == "wrong-result-id":
        result["operation_id"] = uuid4()
    elif change == "object-result":
        result = SimpleNamespace(**result)
    else:
        @dataclass(frozen=True)
        class Unexpected(ReleasePreparationResult):
            credential: str = "synthetic-must-not-disappear"
        result = Unexpected(**result)
    raw["result"] = result
    with pytest.raises(ValidationError):
        TypeAdapter(OperationResponse).validate_python(raw, from_attributes=True)


@pytest.mark.parametrize("shape", ["dataclass", "dict", "wire-json"])
def test_complete_real_dataclass_result_remains_exact(shape):
    raw = envelope()
    expected = asdict(raw["result"])
    if shape == "dict":
        raw["result"] = expected
    parsed = OperationResponse.model_validate(raw)
    if shape == "wire-json":
        parsed = OperationResponse.model_validate_json(parsed.model_dump_json())
    assert isinstance(parsed.result, PreparationResult)
    assert parsed.result.model_dump() == expected
    assert parsed.authorization_granted is False and parsed.result.publication_or_storage_authorized is False


@pytest.mark.parametrize("phase,disposition,verified,complete", [
    ("decided", "retain-unverified", False, True), ("cleaned", "retain-unverified", False, True),
    ("decided", "retire-owned", False, True), ("cleaned", "no-owned-file", True, True),
    ("cleaned", "retire-owned", True, False),
])
def test_cleanup_does_not_turn_incomplete_or_unverified_observation_into_success(phase, disposition, verified, complete):
    with pytest.raises(ValidationError):
        CleanupResult.model_validate({"operation_id": uuid4(), "release_id": uuid4(), "phase": phase,
            "decision": "deleted", "disposition": disposition, "newly_recorded": False,
            "payload_absence_verified_this_call": verified, "complete": complete, "authorization_granted": False})


@pytest.mark.parametrize("kind", ["owned", "external", "delete"])
def test_upload_document_accepts_only_owned_publication(kind):
    raw = json.loads(encode_release_command(document(kind)))
    if kind == "owned":
        assert OwnedPublicationDocument.model_validate(raw).storage_kind == "owned"
    else:
        with pytest.raises(ValidationError):
            OwnedPublicationDocument.model_validate(raw)
    assert TypeAdapter(IntentDocument).validate_python(raw).kind in ("publish", "delete")


def resolve_all_local_references(value, root):
    if isinstance(value, list):
        for item in value:
            resolve_all_local_references(item, root)
    elif isinstance(value, dict):
        if "$ref" in value:
            ref = value["$ref"]
            assert ref.startswith("#/") and not ref.startswith("#/$defs/")
            target = root
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
            assert isinstance(target, dict)
        for item in value.values():
            resolve_all_local_references(item, root)


def test_actual_factory_openapi_is_complete_without_framework_body_fields():
    app = FastAPI()
    router = create_release_operation_router(ReleaseOperationPolicy("/unused-owned-contract-root",
        ReleaseReservationBudget(10, 10, 524288000, 524288000)))
    app.include_router(router, prefix="/api/v1/agents")
    schema = app.openapi()
    resolve_all_local_references(schema, schema)
    assert len(schema["paths"]) == 5
    assert all(route.body_field is None and not route.dependant.body_params for route in router.routes)
    for operation in (v for methods in schema["paths"].values() for k, v in methods.items() if k in ("get", "post")):
        assert set(map(str, (400, 401, 403, 404, 408, 409, 413, 415, 422, 429, 500, 503))) <= operation["responses"].keys()
        assert "schema" in operation["responses"]["200"]["content"]["application/json"]
    upload = schema["paths"]["/api/v1/agents/release-operations/{operation_id}/upload"]["post"]
    body = upload["requestBody"]["content"]["multipart/form-data"]
    assert body["schema"]["required"] == ["intent", "file"]
    intent = body["schema"]["properties"]["intent"]
    assert intent["properties"]["kind"]["const"] == "publish"
    assert intent["properties"]["storage_kind"]["const"] == "owned"
    metadata = intent["properties"]["metadata"]
    assert metadata["properties"]["file_size"]["maximum"] == 524288000
    assert "filename" in metadata["required"]
    assert upload["x-multipart-part-order"] == ["intent", "file"]
    assert upload["x-max-request-body-bytes"] == 524660736
    assert upload["x-automatic-retry-permitted"] is False
    command = schema["paths"]["/api/v1/agents/release-operations/{operation_id}/{action}"]["post"]
    assert command["x-max-request-body-bytes"] == 307200
    assert command["x-automatic-retry-permitted"] is False
    variants = command["requestBody"]["content"]["application/json"]["schema"]["oneOf"]
    assert {v["properties"]["kind"]["const"] for v in variants} == {"publish", "delete"}
    assert all("organization_id" in v["required"] and "metadata" in v["required"] for v in variants)
    assert set(IntentReviewResponse.model_fields) == set(review_value(document()))


@pytest.mark.parametrize("body", [
    {"error": {"code": 503, "message": "Outcome unconfirmed", "request_id": None}},
    {"detail": "Request body exceeds its bound"},
    {"error": {"code": 422, "message": "Validation error", "request_id": None,
               "details": [{"field": "path.operation_id", "message": "Invalid UUID", "type": "uuid_parsing"}]}},
])
def test_documented_error_union_retains_both_actual_application_formats(body):
    parsed = TypeAdapter(ApplicationError | BodyLimitError).validate_python(body)
    assert parsed.model_dump(exclude_unset=True) == body
