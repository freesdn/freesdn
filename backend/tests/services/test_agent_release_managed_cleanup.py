"""Actual operator cleanup of retained owned, external and legacy decisions."""

import pytest

from app.services import agent_release_cleanup_coordinator as cleanup_code
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_cleanup_coordinator as cleanup_probes
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_operator as operator_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes
from tests.services.test_agent_release_operator import operator as operator


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("scenario", ["owned-delete", "owned-cancel", "external-delete", "external-cancel", "delete-cancel", "legacy-delete"])
async def test_actual_http_cleanup_selects_root_from_retained_decision(
    operator, monkeypatch, record_property, kind, scenario,
):
    f = operator
    credential = await lifecycle_probes.headers(f, kind)
    await cleanup_probes.prepare(f, credential, scenario)
    unrelated = f.artifacts / "unrelated-http-cleanup-evidence"
    unrelated.write_bytes(b"preserve unrelated fixture bytes")
    before_files = preparation_probes.files(f)
    original = cleanup_code._CleanupStorage._acquire
    acquired = []

    def observe_acquire(storage, root, intent):
        acquired.append(root)
        return original(storage, root, intent)

    monkeypatch.setattr(cleanup_code._CleanupStorage, "_acquire", observe_acquire)
    response = await operator_probes.call(f, credential, "cleanup", f.cleanup_request)
    row = await cleanup_probes.operation(f)
    after_files = preparation_probes.files(f)
    record_property("observed_http_status", response.status_code)
    record_property("observed_retained_phase", row["phase"])
    record_property("observed_storage_acquisitions", len(acquired))
    record_property("unrelated_bytes_preserved", unrelated.read_bytes() == b"preserve unrelated fixture bytes")
    owned = scenario in ("owned-delete", "owned-cancel")
    complete = scenario != "legacy-delete"
    assert response.status_code == 200
    body = response.json()
    assert body["authorization_granted"] is False and body["historical_observation"] is True
    assert body["result"]["complete"] is complete
    assert body["result"]["payload_absence_verified_this_call"] is owned
    assert response.headers["cache-control"] == "private, no-store"
    assert row["phase"] == ("cleaned" if complete else "decided")
    assert unrelated.read_bytes() == b"preserve unrelated fixture bytes"
    if owned:
        assert acquired == [str(f.artifacts)]
        assert not cleanup_probes.payload(f).exists()
        for name in ("intent.json", "retired.json", "cleaned.json"):
            assert (cleanup_probes.payload(f).parent / name).is_file()
    else:
        assert acquired == [] and after_files == before_files
    stable = await deletion_probes.state(f)
    replay = await operator_probes.call(f, credential, "cleanup", f.cleanup_request)
    assert replay.status_code == 200 and replay.json()["result"]["newly_recorded"] is False
    assert await deletion_probes.state(f) == stable
    assert replay.json()["result"]["complete"] is complete
    if not owned:
        assert acquired == [] and preparation_probes.files(f) == before_files
    record_property("exact_explicit_replay_preserves_committed_state", True)
