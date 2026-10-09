"""Browser identity assertions cannot grant authentication or administrator scope."""

import pytest
from sqlalchemy import update

from app.main import app
from app.models.api_keys import APIKey
from app.models.core import User
from tests.services.test_backup_artifact_integrity_contract import owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_remote_publication_acknowledgment import fixture
from tests.services.test_remote_write_coordination import configure, history
from tests.services.test_storage_probe_browser_context import ACTOR, ORGANIZATION, headers


@pytest.mark.parametrize("credential,transition", [
    ("jwt", "no-credential"), ("key", "no-credential"),
    ("jwt", "viewer"), ("key", "scoped"),
])
async def test_probe_identity_headers_never_grant_authority(request, monkeypatch, tmp_path, credential, transition):
    remote = fixture(request, monkeypatch, "sftp")
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        await configure(actor, remote, "sftp")
        if transition == "no-credential":
            actor.client.headers.pop("Authorization" if credential == "jwt" else "X-API-Key")
            # Preserve the first observed CSRF refusal, then reach real authentication.
            missing = await actor.client.post(
                f"/api/v1/backups/storage-locations/{actor.storage_id}/test", headers=headers(actor, "exact"),
            )
            assert missing.status_code == 403
            assert missing.json() == {"error": {"code": 403, "message": "CSRF token missing"}}
            assert not await history(actor) and not remote.auths() and not remote.state.events and not remote.files()
            request.node.user_properties.append(("original_missing_csrf_refusal_observed", True))
            actor.client.cookies.set("freesdn_csrf", "owned-probe-control-csrf")
            actor.client.headers["X-CSRF-Token"] = "owned-probe-control-csrf"
        else:
            async with actor.engine.begin() as db:
                if transition == "viewer":
                    changed = await db.execute(update(User).where(User.id == actor.actor_id).values(role="viewer"))
                else:
                    changed = await db.execute(update(APIKey).where(APIKey.user_id == actor.actor_id).values(scopes=["backups:write"]))
                assert changed.rowcount == 1
        response = await actor.client.post(
            f"/api/v1/backups/storage-locations/{actor.storage_id}/test", headers=headers(actor, "exact"),
        )
        rows = await history(actor)
        observations = {"credential": credential, "transition": transition, "HTTP": response.status_code,
                        "remote_authentications": remote.auths(), "remote_events": len(remote.state.events),
                        "history_rows": len(rows), "remote_files": len(remote.files())}
        request.node.user_properties.extend(observations.items())
        assert response.status_code == (401 if transition == "no-credential" else 403)
        assert not rows and not remote.auths() and not remote.state.events and not remote.files()


def test_probe_openapi_documents_optional_paired_equality_headers():
    original = app.openapi_schema
    try:
        app.openapi_schema = None
        schema = app.openapi()
    finally:
        app.openapi_schema = original
    operation = schema["paths"]["/api/v1/backups/storage-locations/{location_id}/test"]["post"]
    parameters = operation["parameters"]
    for name in (ACTOR, ORGANIZATION):
        matching = [p for p in parameters if p.get("name") == name and p.get("in") == "header"]
        assert len(matching) == 1
        item = matching[0]
        assert item["required"] is False
        assert item["schema"] == {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36}
        assert "both" in item["description"]
