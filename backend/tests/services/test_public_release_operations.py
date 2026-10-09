"""Unrun complete-app routing proposals; no public enablement or release claim.

Use actual authentication, middleware, SQL and owned local artifacts. No app
lifespan, hardware, external fetch, browser or final deployment is exercised.
"""

from dataclasses import asdict
from uuid import uuid4

import pytest
from sqlalchemy import update

from app.api.v1.endpoints import agent_release_operations as operations
from app.core.config import settings
from app.models.core import User
from app.schemas.agent_release_operation_contract import (
    IntentReviewResponse,
    OperationResponse,
    OperationStatusResponse,
    UploadResponse,
)
from app.schemas.agent_release_operations import encode_release_command
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion
from tests.services import test_agent_release_publication as publication
from tests.services import test_agent_release_upload_stream as upload
from tests.services import test_agent_signing_lifecycle as lifecycle
from tests.services import test_public_release_binary as binary
from tests.services.test_public_release_binary import public_reader as public_reader

PREFIX = "/api/v1/agents"


def anonymous_csrf_headers():
    # A double-submit CSRF pair is not an authentication credential. Preserve
    # the real front-door guard while reaching the intended auth dependency.
    return {"Cookie": "freesdn_csrf=owned-anonymous-csrf", "X-CSRF-Token": "owned-anonymous-csrf"}


def observed(response, model):
    assert response.status_code == 200
    result = model.model_validate_json(response.content)
    assert result.model_dump(mode="json") == response.json()
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"
    return result


async def command(f, headers, action, intent=None):
    intent = intent or f.publication
    return await f.public_client.post(f"{PREFIX}/release-operations/{intent.operation_id}/{action}",
        content=encode_release_command(intent), headers={**headers, "Content-Type": "application/json"})


async def review(f, headers, intent):
    return observed(await f.public_client.post(f"{PREFIX}/release-operation-intents/review",
        content=encode_release_command(intent), headers={**headers, "Content-Type": "application/json"}),
        IntentReviewResponse)


async def publish(f, headers, storage, organization):
    publication.configure(f, storage=storage, organization=organization, latest=False)
    intent = f.publication
    before = await deletion.state(f)
    check = await review(f, headers, intent)
    assert check.intent_sha256 == intent.request_sha256() and check.operation is None
    assert await deletion.state(f) == before
    observed(await command(f, headers, "reserve"), OperationResponse)
    if storage == "owned":
        raw = upload.prefix(intent) + f.data + upload.suffix()
        value = observed(await f.public_client.post(f"{PREFIX}/release-operations/{intent.operation_id}/upload",
            headers={**headers, "Content-Type": upload.CONTENT_TYPE}, content=raw), UploadResponse)
        assert value.result.phase == "prepared" and upload.payload(f).read_bytes() == f.data
        observed(await command(f, headers, "resume"), OperationResponse)
    result = observed(await command(f, headers, "publish"), OperationResponse)
    assert result.result.newly_published
    current = await deletion.state(f)
    replay = observed(await command(f, headers, "publish"), OperationResponse)
    assert not replay.result.newly_published and await deletion.state(f) == current
    return next(r for r in await publication.releases(f) if r["id"] == intent.release_id)


@pytest.mark.parametrize("kind", ("jwt", "key"))
@pytest.mark.parametrize("storage", ("owned", "external", "legacy"))
@pytest.mark.parametrize("target", ("own", "global"))
async def test_public_routes_complete_publication_delivery_promotion_and_retained_deletion(public_reader, kind, storage, target):
    f = public_reader
    headers = await lifecycle.headers(f, kind)
    organization = f.org if target == "own" else None
    if storage == "legacy":
        await binary.seed(f, "legacy-explicit", organization)
        release = dict(await binary.row(f))
    else:
        release = await publish(f, headers, storage, organization)
    release_id = release["id"]
    listed = await f.public_client.get(f"{PREFIX}/releases", headers=headers)
    assert listed.status_code == 200 and any(v["id"] == str(release_id) for v in listed.json())
    promoted = await f.public_client.patch(f"{PREFIX}/releases/{release_id}/promote", headers=headers)
    assert promoted.status_code == 200 and promoted.json()["is_latest"] is True
    release = next(r for r in await publication.releases(f) if r["id"] == release_id)
    if storage != "external":
        response = await f.public_client.get(f"{PREFIX}/releases/{release_id}/binary", headers=headers)
        assert response.status_code == 200 and response.content == f.data
    operation_id = uuid4()
    deletion_review = observed(await f.public_client.get(
        f"{PREFIX}/releases/{release_id}/deletion-intent/{operation_id}", headers=headers), IntentReviewResponse)
    intent = ReleaseDeletionRequest.capture(operation_id=operation_id, release=release)
    assert deletion_review.intent_sha256 == intent.request_sha256()
    await review(f, headers, intent)
    result = observed(await command(f, headers, "delete", intent), OperationResponse)
    assert result.result.decision == "deleted"
    history = observed(await f.public_client.get(f"{PREFIX}/release-operations/{operation_id}", headers=headers), OperationStatusResponse)
    assert history.release_row_present is False and history.operation.decision == "deleted"
    result = observed(await command(f, headers, "cleanup", intent), OperationResponse)
    assert result.result.complete is (storage != "legacy")
    assert result.result.disposition == {"owned": "retire-owned", "external": "no-owned-file", "legacy": "retain-unverified"}[storage]
    if storage == "legacy":
        assert f.legacy_path.read_bytes() == f.data
    else:
        current = await deletion.state(f)
        observed(await command(f, headers, "cleanup", intent), OperationResponse)
        assert await deletion.state(f) == current
    removed = await f.public_client.get(f"{PREFIX}/releases/{release_id}/binary", headers=headers)
    assert removed.status_code == 404


@pytest.mark.parametrize("route,content_type", (("reserve", "application/json"), ("upload", upload.CONTENT_TYPE)))
async def test_public_operation_auth_precedes_untrusted_body_reads(public_reader, route, content_type):
    f = public_reader
    receives = 0

    async def body():
        nonlocal receives
        receives += 1
        yield b"must-not-be-consumed-before-auth"

    before = await deletion.state(f)
    response = await f.public_client.post(f"{PREFIX}/release-operations/{f.publication.operation_id}/{route}",
        content=body(), headers={**anonymous_csrf_headers(), "Content-Type": content_type})
    assert response.status_code == 401 and receives == 0
    assert await deletion.state(f) == before


@pytest.mark.parametrize("kind", ("jwt", "key"))
@pytest.mark.parametrize("fault", ("actor", "organization", "missing-pair"))
async def test_public_operations_refuse_changed_browser_context_without_side_effects(public_reader, kind, fault):
    f = public_reader
    headers = await lifecycle.headers(f, kind)
    headers.update({"X-FreeSDN-Release-Actor": str(f.user), "X-FreeSDN-Release-Organization": str(f.org)})
    if fault == "actor":
        headers["X-FreeSDN-Release-Actor"] = str(uuid4())
    elif fault == "organization":
        headers["X-FreeSDN-Release-Organization"] = str(f.other_org)
    else:
        del headers["X-FreeSDN-Release-Organization"]
    before = await deletion.state(f)
    response = await command(f, headers, "reserve")
    assert response.status_code == (400 if fault == "missing-pair" else 409)
    assert await deletion.state(f) == before


@pytest.mark.parametrize("kind", ("jwt", "key"))
async def test_public_body_wait_rechecks_real_account_deactivation(public_reader, kind):
    f = public_reader
    headers = await lifecycle.headers(f, kind)
    before = await deletion.state(f)
    delivered = False

    async def body():
        nonlocal delivered
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(is_active=False))
        delivered = True
        yield encode_release_command(f.publication)

    response = await f.public_client.post(f"{PREFIX}/release-operations/{f.publication.operation_id}/reserve",
        content=body(), headers={**headers, "Content-Type": "application/json"})
    assert delivered and response.status_code in (401, 403)
    assert await deletion.state(f) == before


@pytest.mark.parametrize("kind", ("jwt", "key"))
async def test_public_invalid_response_preserves_actual_commit_and_explicit_recovery(public_reader, monkeypatch, kind):
    f = public_reader
    headers = await lifecycle.headers(f, kind)
    publication.configure(f, storage="external", organization=f.org)
    observed(await command(f, headers, "reserve"), OperationResponse)
    original = operations._dispatch
    calls = 0

    async def corrupt(*args, **kwargs):
        nonlocal calls
        value = asdict(await original(*args, **kwargs))
        calls += 1
        value["publication_or_storage_authorized"] = True
        return value

    monkeypatch.setattr(operations, "_dispatch", corrupt)
    response = await command(f, headers, "publish")
    assert response.status_code == 503 and calls == 1
    monkeypatch.setattr(operations, "_dispatch", original)
    snapshot = await deletion.state(f)
    result = observed(await f.public_client.get(f"{PREFIX}/release-operations/{f.publication.operation_id}", headers=headers), OperationStatusResponse)
    assert result.operation.decision == "published" and result.release_row_present
    assert (await review(f, headers, f.publication)).intent_sha256 == f.publication.request_sha256()
    result = observed(await command(f, headers, "publish"), OperationResponse)
    assert not result.result.newly_published and await deletion.state(f) == snapshot


@pytest.mark.parametrize("kind", ("none", "jwt", "key"))
@pytest.mark.parametrize("route", ("upload", "external", "delete"))
async def test_retired_public_mutations_do_not_consume_or_write(public_reader, kind, route):
    f = public_reader
    await binary.seed(f, "legacy-explicit", f.org)
    headers = anonymous_csrf_headers() if kind == "none" else await lifecycle.headers(f, kind)
    receives = 0

    async def body():
        nonlocal receives
        receives += 1
        yield b"untrusted-legacy-request-must-not-be-consumed"

    before = await deletion.state(f), binary.files(f), await lifecycle.snapshot(f)
    url = {"upload": f"{PREFIX}/releases/upload", "external": f"{PREFIX}/downloads/releases",
           "delete": f"{PREFIX}/releases/{f.release_id}"}[route]
    response = await f.public_client.request("DELETE" if route == "delete" else "POST", url,
        headers={**headers, "Content-Type": upload.CONTENT_TYPE if route == "upload" else "application/json"}, content=body())
    assert response.status_code == (401 if kind == "none" else 410)
    assert receives == 0 and (await deletion.state(f), binary.files(f), await lifecycle.snapshot(f)) == before
    if kind != "none":
        assert response.json()["error"]["code"] == 410
        assert "retain the original intent" in response.json()["error"]["message"]


@pytest.mark.parametrize("kind", ("jwt", "key"))
async def test_public_operation_policy_is_captured_before_later_settings_changes(public_reader, monkeypatch, kind):
    f = public_reader
    other_root = f.artifacts.parent / "later-unselected-release-root"
    assert not other_root.exists()
    # The already-created application's policy, not a later mutable global,
    # controls both command budget admission and the selected owned directory.
    monkeypatch.setattr(settings, "FREESDN_AGENT_MANAGED_RELEASE_DIR", str(other_root))
    monkeypatch.setattr(settings, "FREESDN_AGENT_RELEASE_GLOBAL_HISTORY_LIMIT", 0)
    monkeypatch.setattr(settings, "FREESDN_AGENT_RELEASE_ORG_HISTORY_LIMIT", 0)
    await publish(f, await lifecycle.headers(f, kind), "owned", f.org)
    assert not other_root.exists() and upload.payload(f).read_bytes() == f.data


@pytest.mark.parametrize("route", ("reserve", "upload", "retired-upload", "retired-external", "retired-delete"))
async def test_public_missing_csrf_still_refuses_before_auth_or_body(public_reader, route):
    f = public_reader
    await binary.seed(f, "legacy-explicit", f.org)
    receives = 0

    async def body():
        nonlocal receives
        receives += 1
        yield b"must-not-be-consumed-before-csrf"

    before = await deletion.state(f), binary.files(f), await lifecycle.snapshot(f)
    urls = {"reserve": f"{PREFIX}/release-operations/{f.publication.operation_id}/reserve",
            "upload": f"{PREFIX}/release-operations/{f.publication.operation_id}/upload",
            "retired-upload": f"{PREFIX}/releases/upload", "retired-external": f"{PREFIX}/downloads/releases",
            "retired-delete": f"{PREFIX}/releases/{f.release_id}"}
    response = await f.public_client.request("DELETE" if route == "retired-delete" else "POST", urls[route],
        headers={"Content-Type": upload.CONTENT_TYPE if route in ("upload", "retired-upload") else "application/json"}, content=body())
    assert response.status_code == 403 and response.json()["error"]["message"] == "CSRF token missing"
    assert receives == 0
    assert (await deletion.state(f), binary.files(f), await lifecycle.snapshot(f)) == before
