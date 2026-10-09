"""Planned real-HTTP/auth/PG contract and post-commit ambiguity qualification.

No acceptance is claimed before these execute. Controlled corruption of an
actual coordinator's returned result must not imply rollback or trigger replay.
"""

from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from uuid import uuid4

import pytest
import pytest_asyncio
from pydantic import TypeAdapter

from app.api.v1.endpoints import agent_release_operations as router_code
from app.schemas.agent_release_operation_contract import (
    ApplicationError,
    BodyLimitError,
    IntentReviewResponse,
    OperationResponse,
    OperationStatusResponse,
    UploadResponse,
)
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_ingress as ingress_probes
from tests.services import test_agent_release_intent_review as review_probes
from tests.services import test_agent_release_operator as operator_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_release_upload_stream as upload_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def contract_http(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(ingress_probes.ingress.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        yield f


def checked(response, model):
    assert response.status_code == 200
    parsed = model.model_validate_json(response.content)
    assert parsed.model_dump(mode="json") == response.json()
    assert response.headers["cache-control"] == "private, no-store"
    return parsed


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("storage", ["owned", "external", "legacy"])
async def test_actual_supported_workflows_emit_lossless_typed_observations(contract_http, kind, storage):
    f = contract_http
    credential = await lifecycle_probes.headers(f, kind)
    if storage == "legacy":
        await deletion_probes.target(f, credential, storage=storage, organization=f.org)
        intent = checked(await review_probes.target(f, credential), IntentReviewResponse)
        assert intent.intent_sha256 == f.deletion.request_sha256()
        command = review_probes.restored(await review_probes.review(f, credential, f.deletion))
    else:
        publication_probes.configure(f, organization=f.org, storage=storage)
        review = checked(await review_probes.review(f, credential, f.publication), IntentReviewResponse)
        assert review.intent_sha256 == f.publication.request_sha256() and review.operation is None
        checked(await operator_probes.call(f, credential, "reserve"), OperationResponse)
        if storage == "owned":
            wire = upload_probes.prefix(f.publication) + f.data + upload_probes.suffix()
            prepared = checked(await ingress_probes.call(f, credential, wire), UploadResponse)
            assert prepared.result.phase == "prepared" and upload_probes.payload(f).read_bytes() == f.data
            checked(await operator_probes.call(f, credential, "resume"), OperationResponse)
        first = checked(await operator_probes.call(f, credential, "publish"), OperationResponse)
        assert first.result.newly_published is True
        replay = checked(await operator_probes.call(f, credential, "publish"), OperationResponse)
        assert replay.result.newly_published is False
        row = next(row for row in await publication_probes.releases(f) if row["id"] == f.publication.release_id)
        command = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
    files_before = preparation_probes.files(f)
    deletion = checked(await operator_probes.call(f, credential, "delete", command), OperationResponse)
    assert deletion.result.decision == "deleted" and preparation_probes.files(f) == files_before
    state = checked(await f.operator_client.get(f"/release-operations/{command.operation_id}", headers=credential), OperationStatusResponse)
    assert state.release_row_present is False and state.operation.decision == "deleted"
    retained = checked(await review_probes.review(f, credential, command), IntentReviewResponse)
    assert retained.intent_sha256 == command.request_sha256()
    cleanup = checked(await operator_probes.call(f, credential, "cleanup", command), OperationResponse)
    assert cleanup.result.complete is (storage != "legacy")
    assert cleanup.result.disposition == {"owned": "retire-owned", "external": "no-owned-file", "legacy": "retain-unverified"}[storage]
    stable = await deletion_probes.state(f)
    checked(await operator_probes.call(f, credential, "cleanup", command), OperationResponse)
    assert await deletion_probes.state(f) == stable
    await reservation_probes.assert_leases_free(f, command)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("action", ["publish", "delete"])
@pytest.mark.parametrize("fault", ["identity", "extra-field", "authority-flag"])
async def test_invalid_response_after_real_commit_is_sanitized_and_never_replayed(contract_http, monkeypatch, caplog, record_property, kind, action, fault):
    f = contract_http
    credential = await lifecycle_probes.headers(f, kind)
    publication_probes.configure(f, organization=f.org, storage="owned")
    marker = "synthetic-private-response-value-not-for-logs"
    f.publication = replace(f.publication, metadata_bytes=_encode({**f.publication.metadata(), "release_notes": marker}))
    await publication_probes.prepare_owned(f, credential)
    command = f.publication
    if action == "delete":
        checked(await operator_probes.call(f, credential, "publish"), OperationResponse)
        row = next(row for row in await publication_probes.releases(f) if row["id"] == f.publication.release_id)
        command = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
    original = router_code._dispatch
    calls = 0

    async def corrupt_after_actual_return(*args, **kwargs):
        nonlocal calls
        result = asdict(await original(*args, **kwargs))
        calls += 1
        if fault == "identity":
            result["operation_id"] = uuid4()
        elif fault == "extra-field":
            result["unexpected_private_field"] = marker
        else:
            result["publication_or_storage_authorized" if action == "publish" else "cleanup_authorized"] = True
        return result

    before_files = preparation_probes.files(f)
    caplog.clear()
    monkeypatch.setattr(router_code, "_dispatch", corrupt_after_actual_return)
    response = await operator_probes.call(f, credential, action, command)
    assert response.status_code == 503 and calls == 1
    assert marker not in response.text and marker not in caplog.text
    assert "inspect the same operation" in response.json()["error"]["message"]
    assert response.headers["cache-control"] == "private, no-store"
    ApplicationError.model_validate_json(response.content)
    rows, history, files = await deletion_probes.state(f)
    decision = next(row for row in history if row["operation_id"] == command.operation_id)
    assert decision["decision"] == ("published" if action == "publish" else "deleted")
    assert any(row["id"] == command.release_id for row in rows) is (action == "publish")
    assert files == before_files and upload_probes.payload(f).read_bytes() == f.data
    record_property("actual_commit_retained_after_invalid_response", True)
    stable = await deletion_probes.state(f)
    # The caller makes the recovery choices explicitly, using its exact original
    # intent. Neither HTTP response validation nor the router retries a mutation.
    monkeypatch.setattr(router_code, "_dispatch", original)
    status = checked(await f.operator_client.get(f"/release-operations/{command.operation_id}", headers=credential), OperationStatusResponse)
    assert status.operation.decision == decision["decision"]
    reviewed = checked(await review_probes.review(f, credential, command), IntentReviewResponse)
    assert reviewed.intent_sha256 == command.request_sha256()
    replay = checked(await operator_probes.call(f, credential, action, command), OperationResponse)
    assert (replay.result.newly_published if action == "publish" else replay.result.newly_changed) is False
    assert await deletion_probes.state(f) == stable and calls == 1
    await reservation_probes.assert_leases_free(f, command)


@pytest.mark.parametrize("route,content_type", [
    ("reserve", "application/json"), ("upload", upload_probes.CONTENT_TYPE),
])
async def test_documented_bodies_are_not_parsed_before_real_authentication(contract_http, route, content_type):
    f = contract_http
    receives = 0

    async def malformed_body():
        nonlocal receives
        receives += 1
        yield b"malformed-and-must-not-be-consumed"

    before = await deletion_probes.state(f)
    response = await f.operator_client.post(f"/release-operations/{f.publication.operation_id}/{route}",
        content=malformed_body(), headers={"Content-Type": content_type})
    assert response.status_code == 401 and receives == 0
    assert await deletion_probes.state(f) == before
    ApplicationError.model_validate_json(response.content)


@pytest.mark.parametrize("error_kind", ["auth", "path", "middleware"])
async def test_real_error_formats_match_documented_union(contract_http, error_kind):
    f = contract_http
    credential = await lifecycle_probes.headers(f)
    before = await deletion_probes.state(f)
    if error_kind == "auth":
        response = await f.operator_client.get(f"/release-operations/{f.publication.operation_id}")
        expected = 401
    elif error_kind == "path":
        response = await f.operator_client.get("/release-operations/not-a-uuid", headers=credential)
        expected = 422
    else:
        response = await f.edge_client.post(f"/api/v1/agents/release-operations/{f.publication.operation_id}/reserve",
            content=b" " * 1048577, headers={**credential, "Content-Type": "application/json"})
        expected = 413
    assert response.status_code == expected and await deletion_probes.state(f) == before
    parsed = TypeAdapter(ApplicationError | BodyLimitError).validate_json(response.content)
    assert parsed.model_dump(mode="json", exclude_unset=True) == response.json()
