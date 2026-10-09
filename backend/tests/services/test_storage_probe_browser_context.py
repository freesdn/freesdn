"""Real authenticated probe requests must honor copied browser identity.

Controlled local SSH/TLS peers and PostgreSQL are used; these cases do not
qualify browser cookie exchange, an external IdP, or customer storage.
"""

from uuid import uuid4

import pytest

from app.main import app
from tests.services.test_backup_artifact_integrity_contract import owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_publication_acknowledgment import fixture
from tests.services.test_remote_write_coordination import configure, history

ACTOR = "X-FreeSDN-Storage-Probe-Actor"
ORGANIZATION = "X-FreeSDN-Storage-Probe-Organization"
CASES = (
    "omitted", "exact", "other-actor", "other-organization", "actor-only",
    "organization-only", "duplicate-actor", "duplicate-organization",
    "empty-actor", "malformed-organization", "nil-organization", "noncanonical-actor",
)


def headers(actor, case):
    pair = [(ACTOR, str(actor.actor_id)), (ORGANIZATION, str(actor.org_id))]
    if case == "omitted":
        return []
    if case == "other-actor":
        pair[0] = (ACTOR, str(uuid4()))
    elif case == "other-organization":
        pair[1] = (ORGANIZATION, str(uuid4()))
    elif case == "actor-only":
        pair = pair[:1]
    elif case == "organization-only":
        pair = pair[1:]
    elif case == "duplicate-actor":
        pair.append(pair[0])
    elif case == "duplicate-organization":
        pair.append(pair[1])
    elif case == "empty-actor":
        pair[0] = (ACTOR, "")
    elif case == "malformed-organization":
        pair[1] = (ORGANIZATION, "invalid")
    elif case == "nil-organization":
        pair[1] = (ORGANIZATION, "00000000-0000-0000-0000-000000000000")
    elif case == "noncanonical-actor":
        pair[0] = (ACTOR, actor.actor_id.hex)
    return pair


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("case", CASES)
async def test_probe_browser_identity_before_remote_mutation(
    request, monkeypatch, tmp_path, protocol, credential, case,
):
    remote = fixture(request, monkeypatch, protocol)
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        await configure(actor, remote, protocol)
        answer = await actor.client.post(
            f"/api/v1/backups/storage-locations/{actor.storage_id}/test",
            headers=headers(actor, case),
        )
        rows = await history(actor)
        # Observe all remote and durable effects before the status assertion.
        observed = {
            "case": case, "credential": credential, "protocol": protocol,
            "HTTP": answer.status_code, "success": answer.json().get("success"),
            "authentications": remote.auths(), "remote_events": len(remote.state.events),
            "renames": sum(e[0] == "rename" for e in remote.state.events),
            "deletes": sum(e[0] == "delete" for e in remote.state.events),
            "remaining_files": len(remote.files()), "history_rows": len(rows),
            "history_phases": ",".join(row.phase for row in rows),
        }
        request.node.user_properties.extend(observed.items())
        if case in {"omitted", "exact"}:
            assert answer.status_code == 200 and observed["success"] is True
            assert observed["authentications"] == 4
            assert observed["renames"] == observed["deletes"] == 1
            assert observed["remaining_files"] == 0
            assert len(rows) == 1 and rows[0].phase == "acknowledged"
        else:
            expected = 409 if case in {"other-actor", "other-organization"} else 400
            assert answer.status_code == expected, "Browser identity must not be silently ignored"
            assert observed["authentications"] == observed["remote_events"] == 0
            assert observed["remaining_files"] == observed["history_rows"] == 0


@pytest.mark.parametrize("case", ["probe-headers", "existing-headers", "foreign-origin", "foreign-header"])
async def test_probe_context_cors_uses_existing_origin_policy(request, monkeypatch, tmp_path, case):
    middleware = next(m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware")
    origins = middleware.kwargs["allow_origins"]
    assert origins and "*" not in origins, "Existing concrete CORS origin prerequisite"
    origin = origins[0]
    requested = ",".join(["Content-Type", "X-CSRF-Token", ACTOR, ORGANIZATION])
    if case == "existing-headers":
        requested = "Content-Type,X-CSRF-Token"
    elif case == "foreign-origin":
        origin = "https://untrusted-probe.invalid"
        assert origin not in origins
    elif case == "foreign-header":
        requested = "X-Unapproved-Probe-Header"
    async with owned_actor(monkeypatch, tmp_path) as actor:
        answer = await actor.client.options(
            f"/api/v1/backups/storage-locations/{actor.storage_id}/test",
            headers={"Origin": origin, "Access-Control-Request-Method": "POST",
                     "Access-Control-Request-Headers": requested},
        )
        rows = await history(actor)
        observed = {"case": case, "HTTP": answer.status_code, "history_rows": len(rows),
                    "allow_origin": answer.headers.get("access-control-allow-origin", ""),
                    "allow_credentials": answer.headers.get("access-control-allow-credentials", "")}
        request.node.user_properties.extend(observed.items())
        assert not rows
        if case in {"probe-headers", "existing-headers"}:
            assert answer.status_code == 200
            assert observed["allow_origin"] == origin and observed["allow_credentials"] == "true"
        else:
            assert answer.status_code == 400
            if case == "foreign-origin":
                assert not observed["allow_origin"]
