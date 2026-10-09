"""Proposed browser equality contract on the actual catalogue/promotion routes.

These optional headers are equality assertions, not credentials or target-scope
grants. Non-browser clients omitting both retain the existing authenticated
path. Record response and durable state before any contract assertion so a
failure can be interpreted without claiming later assertions executed.
"""

from uuid import uuid4

import pytest
from sqlalchemy import update

from app.models.agents import AgentRelease
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_signing_lifecycle as lifecycle
from tests.services import test_public_release_binary as binary
from tests.services.test_public_release_binary import public_reader as public_reader


@pytest.mark.parametrize("credential", ("jwt", "key"))
@pytest.mark.parametrize("route", ("catalogue", "promote"))
@pytest.mark.parametrize("context", (
    "changed-actor", "changed-organization", "missing-actor", "missing-organization",
    "invalid-actor", "invalid-organization", "matched", "non-browser",
))
async def test_public_release_browser_context_preserves_explicit_initiator(
    public_reader, credential, route, context, record_property,
):
    f = public_reader
    await binary.seed(f, "legacy-explicit", f.org)
    async with f.engine.begin() as db:
        await db.execute(update(AgentRelease).where(AgentRelease.id == f.release_id).values(is_latest=False))
    headers = await lifecycle.headers(f, credential)
    headers.update({"X-FreeSDN-Release-Actor": str(f.user), "X-FreeSDN-Release-Organization": str(f.org)})
    expected = 200
    if context == "changed-actor":
        headers["X-FreeSDN-Release-Actor"] = str(uuid4())
        expected = 409
    elif context == "changed-organization":
        headers["X-FreeSDN-Release-Organization"] = str(f.other_org)
        expected = 409
    elif context in ("missing-actor", "missing-organization"):
        del headers["X-FreeSDN-Release-Actor" if context == "missing-actor" else "X-FreeSDN-Release-Organization"]
        expected = 400
    elif context in ("invalid-actor", "invalid-organization"):
        headers["X-FreeSDN-Release-Actor" if context == "invalid-actor" else "X-FreeSDN-Release-Organization"] = "not-a-uuid"
        expected = 400
    elif context == "non-browser":
        del headers["X-FreeSDN-Release-Actor"]
        del headers["X-FreeSDN-Release-Organization"]
    before = dict(await binary.row(f))
    if route == "catalogue":
        response = await f.public_client.get("/api/v1/agents/releases", headers=headers)
    else:
        response = await f.public_client.patch(f"/api/v1/agents/releases/{f.release_id}/promote", headers=headers)
    after = dict(await binary.row(f))
    record_property("observed_status", response.status_code)
    record_property("expected_status", expected)
    record_property("original_is_latest", before["is_latest"])
    record_property("observed_is_latest", after["is_latest"])
    record_property("entire_release_row_unchanged", before == after)
    record_property("catalogue_disclosed_owned_release", route == "catalogue" and response.status_code == 200
                    and any(item["id"] == str(f.release_id) for item in response.json()))
    assert before["is_latest"] is False
    assert response.status_code == expected
    if expected != 200 or route == "catalogue":
        assert after == before
    else:
        assert after["is_latest"] is True
        assert {name: value for name, value in after.items() if name != "is_latest"} == {
            name: value for name, value in before.items() if name != "is_latest"
        }
    if route == "catalogue" and expected == 200:
        assert any(item["id"] == str(f.release_id) for item in response.json())
