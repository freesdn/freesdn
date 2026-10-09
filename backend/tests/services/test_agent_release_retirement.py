# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Planned decision and native filesystem contracts, not committed SQL evidence."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services import agent_release_artifact_store as storage
from app.services.agent_release_cleanup import plan_release_cleanup

_PAYLOAD = b"release bytes"
_REQUEST = b'{"version":"owned fixture"}'


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "owned"
    path.mkdir(mode=0o700)
    return path


def _intent():
    identity = uuid4()
    return storage.ArtifactIntent(identity, identity, uuid4(), hashlib.sha256(_REQUEST).hexdigest(),
                                  hashlib.sha256(_PAYLOAD).hexdigest(), len(_PAYLOAD))


def _publication(intent, *, cancelled=False, prepared=True):
    created = datetime(2026, 9, 29, tzinfo=UTC)
    actor = uuid4()
    return {"operation_id": intent.publish_operation_id, "format_version": 1, "kind": "publish",
            "release_id": intent.release_id, "organization_id": uuid4(), "requested_by": actor,
            "storage_kind": "owned", "artifact_id": intent.artifact_id, "request_bytes": _REQUEST,
            "request_sha256": intent.request_sha256, "expected_sha256": intent.payload_sha256,
            "expected_size": intent.size, "phase": "decided", "decision": "cancelled" if cancelled else "published",
            "transition_sequence": 2 if prepared else 1, "created_at": created,
            "prepared_at": created + timedelta(seconds=1) if prepared else None,
            "decided_at": created + timedelta(seconds=2), "cleaned_at": None, "last_transition_by": actor}


def _deletion(publication, *, cancelled=False):
    request = b'{"action":"delete owned fixture"}'
    return {**publication, "operation_id": uuid4(), "kind": "delete", "request_bytes": request,
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "decision": "cancelled" if cancelled else "deleted"}


def _grant(intent, *, cancellation=False, prepared=True):
    publication = _publication(intent, cancelled=cancellation, prepared=prepared)
    operation = publication if cancellation else _deletion(publication)
    plan = plan_release_cleanup(operation=operation, publication=publication, live_reference_present=False)
    assert plan.outcome == "retire-owned" and plan.decision is not None
    return plan.decision


def _prepare(root, intent):
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as lease:
        lease.begin()
        lease.append(_PAYLOAD)
        lease.finish()


def _snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes()
            for p in root.rglob("*") if p.is_file() and not p.is_symlink()}


@pytest.mark.parametrize("storage_kind", ["owned", "external", "legacy"])
@pytest.mark.parametrize("reference", [False, True])
def test_cancelled_deletion_always_preserves_live_bytes(storage_kind, reference):
    intent = _intent()
    original = _publication(intent)
    operation = _deletion(original, cancelled=True)
    operation["storage_kind"] = storage_kind
    operation["artifact_id"] = intent.artifact_id if storage_kind == "owned" else None
    plan = plan_release_cleanup(operation=operation, publication=original, live_reference_present=reference)
    assert plan.outcome == "preserve-live" and plan.decision is None


@pytest.mark.parametrize("storage_kind,expected", [("external", "no-owned-file"), ("legacy", "retain-unverified")])
def test_other_storage_is_not_adopted_as_an_owned_payload(storage_kind, expected):
    operation = _deletion(_publication(_intent()))
    operation.update(storage_kind=storage_kind, artifact_id=None)
    plan = plan_release_cleanup(operation=operation, publication=None, live_reference_present=False)
    assert plan.outcome == expected and plan.decision is None


@pytest.mark.parametrize("state", ["reserved", "prepared", "published", "missing", "exception", "unknown-reference"])
def test_uncertain_or_unpublished_decisions_never_create_cleanup_authority(state):
    intent = _intent()
    original = _publication(intent)
    operation = _deletion(original)
    present = False
    if state == "reserved":
        operation.update(phase="reserved", decision=None, transition_sequence=0, prepared_at=None, decided_at=None)
    elif state == "prepared":
        operation.update(phase="prepared", decision=None, transition_sequence=1, decided_at=None)
    elif state == "published":
        operation = original
    elif state == "missing":
        operation = None
    elif state == "exception":
        operation = RuntimeError("commit acknowledgement unavailable")
    else:
        present = None
    with pytest.raises(storage.ArtifactUnavailable):
        plan_release_cleanup(operation=operation, publication=original, live_reference_present=present)


@pytest.mark.parametrize("change", [
    "operation-id", "artifact-id", "release-id", "organization-id", "payload-hash", "size",
    "request-bytes", "request-hash", "format", "sequence", "date-naive", "date-order",
    "prepared-missing", "foreign-field", "missing-field", "bool-size", "bool-sequence",
    "publication-cancelled", "publication-absent", "live-reference",
])
def test_malformed_or_mismatched_committed_observations_are_refused(change):
    intent = _intent()
    original = _publication(intent)
    operation = _deletion(original)
    present = False
    if change == "operation-id":
        operation["operation_id"] = original["operation_id"]
    elif change in ("artifact-id", "release-id", "organization-id"):
        operation[change.replace("-", "_")] = uuid4()
    elif change == "payload-hash":
        operation["expected_sha256"] = "b" * 64
    elif change == "size":
        operation["expected_size"] += 1
    elif change == "request-bytes":
        operation["request_bytes"] = b"changed"
    elif change == "request-hash":
        operation["request_sha256"] = "b" * 64
    elif change == "format":
        operation["format_version"] = 2
    elif change == "sequence":
        operation["transition_sequence"] = 3
    elif change == "date-naive":
        operation["decided_at"] = datetime(2026, 9, 29)
    elif change == "date-order":
        operation["decided_at"] = operation["created_at"] - timedelta(seconds=1)
    elif change == "prepared-missing":
        operation["prepared_at"] = None
    elif change == "foreign-field":
        operation["unknown"] = "not a retained field"
    elif change == "missing-field":
        operation.pop("artifact_id")
    elif change == "bool-size":
        operation["expected_size"] = True
    elif change == "bool-sequence":
        operation["transition_sequence"] = True
    elif change == "publication-cancelled":
        original["decision"] = "cancelled"
    elif change == "publication-absent":
        original = None
    else:
        present = True
    with pytest.raises(storage.ArtifactUnavailable):
        plan_release_cleanup(operation=operation, publication=original, live_reference_present=present)


@pytest.mark.parametrize("prepared", [False, True])
def test_cancelled_publication_binding_survives_cleaned_bookkeeping_without_rebinding(prepared):
    intent = _intent()
    row = _publication(intent, cancelled=True, prepared=prepared)
    first = plan_release_cleanup(operation=row, publication=row, live_reference_present=False)
    after = {**row, "phase": "cleaned", "transition_sequence": row["transition_sequence"] + 1,
             "cleaned_at": row["decided_at"] + timedelta(seconds=1), "last_transition_by": uuid4()}
    retry = plan_release_cleanup(operation=after, publication=after, live_reference_present=False)
    assert first.decision == retry.decision
    assert first.decision.intent == intent


def test_deleted_binding_survives_cleaned_bookkeeping_with_original_publication():
    intent = _intent()
    original = _publication(intent)
    row = _deletion(original)
    first = plan_release_cleanup(operation=row, publication=original, live_reference_present=False)
    row.update(phase="cleaned", transition_sequence=3, cleaned_at=row["decided_at"] + timedelta(seconds=1),
               last_transition_by=uuid4())
    retry = plan_release_cleanup(operation=row, publication=original, live_reference_present=False)
    assert first.decision == retry.decision


@pytest.mark.parametrize("cancellation", [False, True])
def test_retire_then_cleanup_fences_delivery_and_keeps_all_history(root, cancellation):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent, cancellation=cancellation)
    directory = root / str(intent.artifact_id)
    before = _snapshot(root)
    directory_inode = directory.stat().st_ino
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        retirement = lease.retire(decision)
        assert (directory / "payload").read_bytes() == _PAYLOAD
        assert json.loads((directory / "retired.json").read_bytes())["file_state"][6] == len(_PAYLOAD)
        with pytest.raises(storage.ArtifactUnavailable):
            lease.verify_prepared()
        with pytest.raises(storage.ArtifactUnavailable):
            lease.read(0, 1)
        result = lease.cleanup_retired(decision)
        assert result.retirement_sha256 == retirement
        assert result.artifact_id == intent.artifact_id
        assert not (directory / "payload").exists()
        assert lease.cleanup_retired(decision) == result
    assert directory.stat().st_ino == directory_inode
    for name, content in before.items():
        if not name.endswith("/payload"):
            assert (root / name).read_bytes() == content
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as retry:
        with pytest.raises(storage.ArtifactUnavailable):
            retry.begin()
        assert retry.retire(decision) == retirement
        assert retry.cleanup_retired(decision) == result


@pytest.mark.parametrize("partial", [False, True])
def test_cancelled_reservation_handles_intent_only_or_verified_owned_partial(root, partial):
    intent = _intent()
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as writer:
        if partial:
            writer.begin()
            writer.append(b"part")
    decision = _grant(intent, cancellation=True, prepared=False)
    directory = root / str(intent.artifact_id)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        lease.retire(decision)
        lease.cleanup_retired(decision)
    assert not (directory / "payload").exists()
    assert (directory / "intent.json").exists()
    assert (directory / "retired.json").exists() and (directory / "cleaned.json").exists()


@pytest.mark.parametrize("state", ["unrecorded-payload", "missing-payload", "missing-intent", "missing-allocation"])
def test_unknown_partial_ownership_is_not_turned_into_cleanup(root, state):
    intent = _intent()
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as writer:
        if state != "unrecorded-payload":
            writer.begin()
            writer.append(b"part")
    directory = root / str(intent.artifact_id)
    if state == "unrecorded-payload":
        (directory / "payload").write_bytes(b"unknown")
        (directory / "payload").chmod(0o600)
    else:
        target = {"missing-payload": "payload", "missing-intent": "intent.json", "missing-allocation": "allocation.json"}[state]
        (directory / target).unlink()
    before = _snapshot(root)
    with pytest.raises((storage.ArtifactUnavailable, OSError)):
        with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
            lease.retire(_grant(intent, cancellation=True, prepared=False))
    assert _snapshot(root) == before


@pytest.mark.parametrize("choice", ["cancelled-delete", "published", "unknown", "other-operation", "other-intent"])
def test_storage_rejects_invalid_cleanup_decision_before_any_marker_or_unlink(root, choice):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent, cancellation=True)
    if choice == "cancelled-delete":
        decision = replace(decision, kind="delete")
    elif choice == "published":
        decision = replace(decision, decision="published")
    elif choice == "unknown":
        decision = None
    elif choice == "other-operation":
        decision = replace(decision, operation_id=uuid4())
    else:
        decision = replace(decision, intent=_intent())
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        with pytest.raises(storage.ArtifactUnavailable):
            lease.retire(decision)
        with pytest.raises(storage.ArtifactUnavailable):
            lease.cleanup_retired(decision)
    assert _snapshot(root) == before


@pytest.mark.parametrize("phase", ["retired", "cleaned"])
@pytest.mark.parametrize("replacement", ["regular", "symlink", "hardlink", "fifo"])
def test_retry_never_removes_a_replacement_payload(root, phase, replacement):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent)
    directory = root / str(intent.artifact_id)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        lease.retire(decision)
        if phase == "cleaned":
            lease.cleanup_retired(decision)
        else:
            (directory / "payload").unlink()
        path = directory / "payload"
        outside = root / "foreign"
        outside.write_bytes(_PAYLOAD)
        outside.chmod(0o600)
        if replacement == "regular":
            path.write_bytes(_PAYLOAD)
            path.chmod(0o600)
        elif replacement == "symlink":
            path.symlink_to(outside)
        elif replacement == "hardlink":
            os.link(outside, path)
        else:
            os.mkfifo(path, mode=0o600)
        inode = path.lstat().st_ino
        with pytest.raises((storage.ArtifactUnavailable, OSError)):
            lease.cleanup_retired(decision)
        assert path.lstat().st_ino == inode and outside.read_bytes() == _PAYLOAD


@pytest.mark.parametrize("phase", ["retirement-sync", "before-unlink", "after-unlink", "directory-sync", "cleaned-sync"])
def test_cleanup_failure_retains_tombstone_and_retry_does_not_recreate_or_retarget(root, monkeypatch, phase):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent)
    directory = root / str(intent.artifact_id)
    unlinked = []
    original_unlink, original_sync = storage.os.unlink, storage.os.fsync
    def fail_unlink(name, *, dir_fd):
        if phase == "before-unlink":
            raise OSError(errno.EIO, "owned injected before unlink")
        result = original_unlink(name, dir_fd=dir_fd)
        unlinked.append(name)
        if phase == "after-unlink":
            raise OSError(errno.EIO, "owned injected after unlink acknowledgement")
        return result
    def fail_sync(fd):
        path = os.readlink(f"/proc/self/fd/{fd}")
        target = (phase == "retirement-sync" and path == str(directory / "retired.json")) or (
            phase == "directory-sync" and unlinked and path == str(directory)) or (
            phase == "cleaned-sync" and path == str(directory / "cleaned.json"))
        if target:
            raise OSError(errno.EIO, "owned injected synchronization error")
        return original_sync(fd)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        if phase != "retirement-sync":
            lease.retire(decision)
        with monkeypatch.context() as patch:
            patch.setattr(storage.os, "unlink", fail_unlink)
            patch.setattr(storage.os, "fsync", fail_sync)
            with pytest.raises(OSError):
                if phase == "retirement-sync":
                    lease.retire(decision)
                else:
                    lease.cleanup_retired(decision)
        assert (directory / "retired.json").exists()
        expected_present = phase in ("retirement-sync", "before-unlink")
        assert (directory / "payload").exists() is expected_present
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as retry:
        retry.retire(decision)
        result = retry.cleanup_retired(decision)
        assert retry.cleanup_retired(decision) == result
    assert not (directory / "payload").exists()
    assert (directory / "retired.json").exists() and (directory / "cleaned.json").exists()


@pytest.mark.parametrize("marker", ["retired.json", "cleaned.json"])
def test_partial_recovery_record_is_preserved_and_never_overwritten(root, marker):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent)
    directory = root / str(intent.artifact_id)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        lease.retire(decision)
        if marker == "cleaned.json":
            lease.cleanup_retired(decision)
        (directory / marker).write_bytes(b'{"format":')
        before = _snapshot(root)
        with pytest.raises(storage.ArtifactUnavailable):
            lease.cleanup_retired(decision)
        assert _snapshot(root) == before


@pytest.mark.parametrize("change", ["operation", "decision-binding"])
def test_retirement_cannot_be_rebound_on_retry(root, change):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent)
    other = replace(decision, **({"operation_id": uuid4()} if change == "operation"
                                 else {"retained_decision_sha256": "b" * 64}))
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        lease.retire(decision)
        before = _snapshot(root)
        with pytest.raises(storage.ArtifactUnavailable):
            lease.retire(other)
        with pytest.raises(storage.ArtifactUnavailable):
            lease.cleanup_retired(other)
        assert _snapshot(root) == before


def test_shared_delivery_lifetime_excludes_retirement_until_reader_closes(root):
    intent = _intent()
    _prepare(root, intent)
    decision = _grant(intent)
    with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as reader:
        reader.verify_prepared()
        with pytest.raises(storage.ArtifactUnavailable):
            reader.retire(decision)
        with pytest.raises(storage.ArtifactBusy):
            storage.ArtifactLease.acquire(str(root), intent, mode="exclusive")
        assert reader.read(0, 1024) == _PAYLOAD
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        lease.retire(decision)
        lease.cleanup_retired(decision)
    with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as reader:
        with pytest.raises(storage.ArtifactUnavailable):
            reader.verify_prepared()


def test_absence_without_durable_retirement_does_not_authorize_cleanup(root):
    intent = _intent()
    _prepare(root, intent)
    directory = root / str(intent.artifact_id)
    (directory / "payload").unlink()
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as lease:
        with pytest.raises(FileNotFoundError):
            lease.cleanup_retired(_grant(intent))
    assert _snapshot(root) == before
