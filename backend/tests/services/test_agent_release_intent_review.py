"""Planned real-auth/PG/router review and explicit recovery contracts, unrun.

No review response is a reservation or a credential. These cases exercise the
actual private mutation paths after review and compare committed rows/files.
Controlled response timing is not a deployed network/cancellation guarantee.
"""

import json
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text, update

from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import User
from app.schemas.agent_release_operations import decode_release_command, encode_release_command
from app.services import agent_release_intent_review as review_code
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_operator as operator_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def reviewer(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(operator_probes.operator.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        yield f


async def review(f, credential, command):
    return await f.operator_client.post("/release-operation-intents/review", content=encode_release_command(command),
                                       headers={**credential, "Content-Type": "application/json"})


async def target(f, credential, *, operation_id=None, release_id=None):
    return await f.operator_client.get(
        f"/releases/{release_id or f.deletion.release_id}/deletion-intent/{operation_id or f.deletion.operation_id}",
        headers=credential)


def restored(response):
    body = response.json()
    command = decode_release_command(_encode(body["intent"]))
    assert command.request_sha256() == body["intent_sha256"]
    for flag in ("authorization_granted", "storage_checked", "all_artifact_references_checked",
                 "absence_authorizes_retry_or_cleanup", "reservation_created", "server_retains_full_intent"):
        assert body[flag] is False
    assert body["save_original_intent_before_mutation"] is True
    assert body["retry_requires_identical_intent_and_current_authority"] is True
    assert response.headers["cache-control"] == "private, no-store"
    assert "artifact_id" not in body and "request_bytes" not in body
    return command


@pytest.mark.parametrize("kind", ["publish", "delete"])
@pytest.mark.parametrize("notes", ["🦉" * 20000, "\x01" * 20000, '<script>untrusted & opaque</script>'])
def test_retained_document_preserves_exact_metadata_and_never_normalizes_deletion(kind, notes):
    if kind == "publish":
        command = reservation_probes.request_for(uuid4(), notes=notes)
    else:
        command = ReleaseDeletionRequest.capture(operation_id=uuid4(),
            release={**deletion_probes.sample(), "release_notes": notes})
    document = encode_release_command(command)
    checked = decode_release_command(document)
    assert checked == command and checked.metadata_bytes == command.metadata_bytes
    assert checked.request_bytes() == command.request_bytes()
    assert json.loads(document)["metadata"]["release_notes"] == notes
    if kind == "delete":
        assert json.loads(document)["metadata"]["platform"] == "Linux"
    assert set(json.loads(document)) <= {"kind", "operation_id", "release_id", "organization_id", "metadata", "storage_kind"}


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("storage", ["owned", "external"])
async def test_publication_review_retains_full_intent_without_reservation(reviewer, kind, storage):
    f = reviewer
    credential = await lifecycle_probes.headers(f, kind)
    publication_probes.configure(f, organization=f.org, storage=storage)
    before = await deletion_probes.state(f)
    response = await review(f, credential, f.publication)
    assert response.status_code == 200 and restored(response) == f.publication
    assert response.json()["operation"] is None and response.json()["release_row_present"] is False
    assert await deletion_probes.state(f) == before
    assert (await operator_probes.call(f, credential, "reserve", restored(response))).status_code == 200
    response = await review(f, credential, f.publication)
    assert response.status_code == 200 and response.json()["operation"]["phase"] == "reserved"
    assert restored(response) == f.publication


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("storage", ["owned", "external", "legacy"])
async def test_actual_target_review_then_explicit_deletion_and_original_intent_recovery(reviewer, kind, storage):
    f = reviewer
    credential = await lifecycle_probes.headers(f, kind)
    await deletion_probes.target(f, credential, storage=storage, organization=f.org)
    before = await deletion_probes.state(f)
    response = await target(f, credential)
    assert response.status_code == 200 and restored(response) == f.deletion
    assert response.json()["deletion_target_matches"] is True and response.json()["operation"] is None
    assert await deletion_probes.state(f) == before
    retained = encode_release_command(restored(response))
    assert (await operator_probes.call(f, credential, "delete", decode_release_command(retained))).status_code == 200
    decided = await deletion_probes.state(f)
    missing = await target(f, credential)
    assert missing.status_code == 404 and "intent" not in missing.json()
    result = await review(f, credential, decode_release_command(retained))
    assert result.status_code == 200 and restored(result) == f.deletion
    assert result.json()["operation"]["decision"] == "deleted"
    assert result.json()["release_row_present"] is result.json()["deletion_target_matches"] is False
    assert await deletion_probes.state(f) == decided
    assert (await operator_probes.call(f, credential, "delete", decode_release_command(retained))).status_code == 200
    assert await deletion_probes.state(f) == decided


@pytest.mark.parametrize("field", ["release_notes", "is_latest", "published_at", "checksum_sha256", "file_size"])
async def test_review_does_not_authorize_a_later_changed_target(reviewer, field):
    f = reviewer
    credential = await lifecycle_probes.headers(f)
    row = await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    response = await target(f, credential)
    assert response.status_code == 200
    command = restored(response)
    changed = {"release_notes": "changed after review", "is_latest": not row["is_latest"],
               "published_at": row["published_at"] + timedelta(seconds=1),
               "checksum_sha256": ("0" if row["checksum_sha256"][0] != "0" else "1") + row["checksum_sha256"][1:],
               "file_size": row["file_size"] + 1}[field]
    assert changed != row[field]
    async with f.engine.begin() as db:
        await db.execute(update(AgentRelease).where(AgentRelease.id == command.release_id).values(**{field: changed}))
    before = await deletion_probes.state(f)
    checked = await review(f, credential, command)
    assert checked.status_code == 200 and checked.json()["deletion_target_matches"] is False
    assert restored(checked) == command and await deletion_probes.state(f) == before
    refused = await operator_probes.call(f, credential, "delete", command)
    assert refused.status_code == 409 and await deletion_probes.state(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_bound_operation_cannot_be_replaced_by_new_metadata(reviewer, kind):
    f = reviewer
    credential = await lifecycle_probes.headers(f, kind)
    assert (await operator_probes.call(f, credential, "reserve")).status_code == 200
    before = await deletion_probes.state(f)
    changed = replace(f.publication, metadata_bytes=_encode({**f.publication.metadata(), "release_notes": "replacement"}))
    response = await review(f, credential, changed)
    assert response.status_code == 409 and await deletion_probes.state(f) == before
    row = await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    before = await deletion_probes.state(f)
    response = await target(f, credential, operation_id=f.publication.operation_id, release_id=row["id"])
    assert response.status_code == 409 and await deletion_probes.state(f) == before


@pytest.mark.parametrize("case", ["absent", "viewer", "other-org", "scoped-key"])
async def test_unauthorized_review_never_discloses_full_metadata(reviewer, case):
    f = reviewer
    credential = await lifecycle_probes.headers(f)
    await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    if case == "absent":
        credential = {}
    else:
        async with f.engine.begin() as db:
            values = {"role": "admin", "organization_id": f.org}
            if case == "viewer":
                values["role"] = "viewer"
            elif case == "other-org":
                values["organization_id"] = f.other_org
            else:
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:read"]))
            await db.execute(update(User).where(User.id == f.user).values(**values))
        credential = await lifecycle_probes.headers(f, "key" if case == "scoped-key" else "jwt")
    before = await deletion_probes.state(f)
    response = await target(f, credential)
    assert response.status_code in (401, 403, 404) and "intent" not in response.json()
    assert await deletion_probes.state(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_authority_rechecked_after_database_observation_before_metadata_disclosure(reviewer, monkeypatch, kind):
    f = reviewer
    credential = await lifecycle_probes.headers(f, kind)
    await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    original = review_code._read_review
    seen = False

    async def changed_after_read(*args, **kwargs):
        nonlocal seen
        result = await original(*args, **kwargs)
        async with f.engine.begin() as db:
            if kind == "key":
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            else:
                await db.execute(update(User).where(User.id == f.user).values(token_version=193))
        seen = True
        return result

    monkeypatch.setattr(review_code, "_read_review", changed_after_read)
    before = await deletion_probes.state(f)
    response = await target(f, credential)
    assert seen and response.status_code == 401 and "intent" not in response.json()
    assert await deletion_probes.state(f) == before


@pytest.mark.parametrize("table", ["agent_release_operations", "agent_releases"])
async def test_actual_writer_table_conflict_refuses_then_fresh_review_succeeds(reviewer, table):
    f = reviewer
    credential = await lifecycle_probes.headers(f)
    await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    before = await deletion_probes.state(f)
    async with f.engine.connect() as db:
        async with db.begin():
            statement = {"agent_release_operations": "LOCK TABLE agents.agent_release_operations IN ROW EXCLUSIVE MODE",
                         "agent_releases": "LOCK TABLE agents.agent_releases IN ROW EXCLUSIVE MODE"}[table]
            await db.execute(text(statement))
            response = await target(f, credential)
            assert response.status_code == 409 and "intent" not in response.json()
    assert await deletion_probes.state(f) == before
    response = await target(f, credential)
    assert response.status_code == 200 and restored(response) == f.deletion


@pytest.mark.parametrize("field,value", [("release_notes", "x" * 20001), ("release_notes", "🦉" * 20001),
                                        ("signature", "x" * 4097), ("checksum_sha256", "unknown")])
async def test_legacy_invalid_metadata_is_refused_not_truncated_or_replaced(reviewer, field, value):
    f = reviewer
    credential = await lifecycle_probes.headers(f)
    await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    async with f.engine.begin() as db:
        await db.execute(update(AgentRelease).where(AgentRelease.id == f.deletion.release_id).values(**{field: value}))
    before = await deletion_probes.state(f)
    response = await target(f, credential)
    assert response.status_code == 409 and "intent" not in response.json()
    assert value not in response.text and await deletion_probes.state(f) == before


@pytest.mark.parametrize("identity", ["operation", "release"])
async def test_zero_review_identity_never_reserves_or_returns_a_target(reviewer, identity):
    f = reviewer
    credential = await lifecycle_probes.headers(f)
    await deletion_probes.target(f, credential, storage="legacy", organization=f.org)
    before = await deletion_probes.state(f)
    response = await target(f, credential, **{identity + "_id": UUID(int=0)})
    assert response.status_code == 422 and await deletion_probes.state(f) == before
