# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Planned native local storage contracts; not SQL, container or NFS acceptance."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import subprocess
import sys
import threading
from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from app.services import agent_release_artifact_store as storage


@pytest.fixture
def root(tmp_path):
    directory = tmp_path / "owned"
    directory.mkdir(mode=0o700)
    return directory


def _intent(data=b"release bytes"):
    return storage.ArtifactIntent(uuid4(), uuid4(), uuid4(), "a" * 64,
                                  hashlib.sha256(data).hexdigest(), len(data))


def _prepared(root, intent, data=b"release bytes"):
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as lease:
        lease.begin()
        if data:
            lease.append(data)
        receipt = lease.finish()
        assert lease.read(0, max(1024, len(data))) == data
        return receipt


def _snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*") if path.is_file() and not path.is_symlink()}


@pytest.mark.parametrize("data", [b"", b"release bytes", b"a" * 1048576])
def test_owned_prepare_reopen_and_shared_delivery_preserve_bytes_and_identity(root, data):
    intent = _intent(data)
    receipt = _prepared(root, intent, data)
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as one:
        with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as two:
            assert one.verify_prepared() == two.verify_prepared() == receipt
            assert one.read(0, 1048576) == two.read(0, 1048576) == data
            with pytest.raises(storage.ArtifactBusy):
                storage.ArtifactLease.acquire(str(root), intent, mode="exclusive")
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as after:
        assert after.verify_prepared() == receipt
    assert _snapshot(root) == before


@pytest.mark.parametrize("field,value", [
    ("artifact_id", "../escape"), ("artifact_id", UUID(int=0)),
    ("release_id", "a" * 36), ("publish_operation_id", None),
    ("request_sha256", "A" * 64), ("payload_sha256", "0" * 63),
    ("size", -1), ("size", 524288001), ("size", True),
])
def test_invalid_intent_refuses_before_any_storage(root, field, value):
    intent = replace(_intent(), **{field: value})
    with pytest.raises(storage.ArtifactUnavailable):
        storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("shape", ["relative", "parent", "dot", "double", "root", "trailing"])
def test_ambiguous_root_path_refuses_without_creating_objects(root, shape):
    paths = {"relative": "owned", "parent": str(root / ".." / "owned"),
             "dot": str(root) + "/./child", "double": str(root) + "//child",
             "root": "/", "trailing": str(root) + "/"}
    with pytest.raises(storage.ArtifactUnavailable):
        storage.ArtifactLease.acquire(paths[shape], _intent(), mode="exclusive", create=True)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("shape", ["root-link", "root-mode", "ancestor-mode", "object-link", "object-mode"])
def test_unsafe_directory_path_refuses_without_repair(root, shape):
    intent = _intent()
    candidate = root
    if shape == "root-link":
        candidate = root.parent / "alias"
        candidate.symlink_to(root, target_is_directory=True)
    elif shape == "root-mode":
        root.chmod(0o750)
    elif shape == "ancestor-mode":
        root.parent.chmod(0o777)
    elif shape == "object-link":
        (root / str(intent.artifact_id)).symlink_to(root.parent, target_is_directory=True)
    else:
        (root / str(intent.artifact_id)).mkdir(mode=0o755)
    before = {str(p): p.lstat() for p in (root, root.parent, *root.iterdir())}
    with pytest.raises((storage.ArtifactUnavailable, OSError)):
        storage.ArtifactLease.acquire(str(candidate), intent, mode="exclusive", create=True)
    for name, old in before.items():
        now = os.lstat(name)
        assert (now.st_ino, now.st_mode, now.st_uid) == (old.st_ino, old.st_mode, old.st_uid)
    if shape == "ancestor-mode":
        root.parent.chmod(0o700)


@pytest.mark.parametrize("field", ["release_id", "publish_operation_id", "request_sha256", "payload_sha256", "size"])
def test_existing_object_cannot_be_rebound_to_another_intent(root, field):
    intent = _intent()
    _prepared(root, intent)
    before = _snapshot(root)
    replacement = uuid4() if field.endswith("_id") else (999 if field == "size" else "b" * 64)
    with pytest.raises(storage.ArtifactUnavailable):
        storage.ArtifactLease.acquire(str(root), replace(intent, **{field: replacement}),
                                      mode="exclusive", create=True)
    assert _snapshot(root) == before


@pytest.mark.parametrize("fault", ["short", "long", "hash", "chunk", "mutable", "zero-write"])
def test_failed_preparation_retains_partial_bytes_and_never_overwrites_on_retry(root, monkeypatch, fault):
    intent = _intent()
    lease = storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True)
    lease.begin()
    with pytest.raises(storage.ArtifactUnavailable):
        if fault == "long":
            lease.append(b"release bytes plus extra")
        elif fault == "chunk":
            lease.append(b"z" * (1048576 + 1))
        elif fault == "mutable":
            lease.append(bytearray(b"release bytes"))
        elif fault == "zero-write":
            with monkeypatch.context() as patch:
                patch.setattr(storage.os, "write", lambda *_args: 0)
                lease.append(b"release bytes")
        else:
            lease.append(b"wrong content" if fault == "hash" else b"short")
            lease.finish()
    lease.close()
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as retry:
        with pytest.raises((storage.ArtifactUnavailable, OSError)):
            retry.begin()
    assert _snapshot(root) == before
    assert (root / str(intent.artifact_id) / "payload").exists()
    assert not (root / str(intent.artifact_id) / "prepared.json").exists()


@pytest.mark.parametrize("target", ["payload", "prepared.json", "object-directory"])
def test_sync_error_is_not_success_and_preserves_first_owned_files(root, monkeypatch, target):
    intent = _intent()
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True) as lease:
        lease.begin()
        lease.append(b"release bytes")
        original = storage.os.fsync
        object_path = root / str(intent.artifact_id)
        def fail_selected(fd):
            path = os.readlink(f"/proc/self/fd/{fd}")
            expected = str(object_path if target == "object-directory" else object_path / target)
            if path == expected:
                raise OSError(errno.EIO, "owned injected synchronization boundary")
            return original(fd)
        with monkeypatch.context() as patch:
            patch.setattr(storage.os, "fsync", fail_selected)
            with pytest.raises(OSError):
                lease.finish()
        assert (object_path / "payload").read_bytes() == b"release bytes"
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as retry:
        with pytest.raises((storage.ArtifactUnavailable, OSError)):
            retry.begin()
        # begin failure poisons this lease; recovery is a distinct inspection.
    assert _snapshot(root) == before
    if target != "payload":
        with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as inspected:
            assert inspected.verify_prepared().intent == intent
    assert _snapshot(root) == before


@pytest.mark.parametrize("name", ["payload", "intent.json", "allocation.json", "prepared.json"])
@pytest.mark.parametrize("shape", ["symlink", "hardlink", "fifo", "mode", "replacement"])
def test_delivery_rejects_unsafe_or_replaced_owned_files_without_deleting_them(root, name, shape):
    intent = _intent()
    _prepared(root, intent)
    path = root / str(intent.artifact_id) / name
    original = path.read_bytes()
    if shape == "mode":
        path.chmod(0o644)
    elif shape == "hardlink":
        os.link(path, root / "retained-link")
    else:
        path.unlink()
        if shape == "symlink":
            target = root / "outside"
            target.write_bytes(original)
            target.chmod(0o600)
            path.symlink_to(target)
        elif shape == "fifo":
            os.mkfifo(path, mode=0o600)
        else:
            path.write_bytes(b"changed")
            path.chmod(0o600)
    held_inode = path.lstat().st_ino
    with pytest.raises((storage.ArtifactUnavailable, OSError)):
        with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as lease:
            lease.verify_prepared()
    assert path.lstat().st_ino == held_inode


@pytest.mark.parametrize("which", ["root", "object"])
def test_replaced_directory_after_acquisition_cannot_redirect_writes(root, which):
    intent = _intent()
    lease = storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True)
    path = root if which == "root" else root / str(intent.artifact_id)
    moved = path.with_name(path.name + "-retained")
    path.rename(moved)
    path.mkdir(mode=0o700)
    try:
        with pytest.raises(storage.ArtifactUnavailable):
            lease.begin()
        assert list(path.iterdir()) == []
        assert not (moved / "payload").exists()
    finally:
        lease.close()


def test_expired_lease_preserves_prepared_bytes_and_releases_capacity(root, monkeypatch):
    intent = _intent()
    _prepared(root, intent)
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as lease:
        lease.verify_prepared()
        with monkeypatch.context() as patch:
            patch.setattr(storage.time, "monotonic", lambda: lease._deadline)
            with pytest.raises(storage.ArtifactUnavailable):
                lease.read(0, 1)
    assert _snapshot(root) == before
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive") as retry:
        assert retry.verify_prepared().intent == intent


def test_admission_is_bounded_and_failed_open_does_not_leak_a_slot(root):
    leases = []
    try:
        for _ in range(8):
            leases.append(storage.ArtifactLease.acquire(str(root), _intent(), mode="exclusive", create=True))
        before = _snapshot(root)
        with pytest.raises(storage.ArtifactBusy):
            storage.ArtifactLease.acquire(str(root), _intent(), mode="exclusive", create=True)
        assert _snapshot(root) == before
    finally:
        for lease in leases:
            lease.close()
    for _ in range(9):
        with pytest.raises(FileNotFoundError):
            storage.ArtifactLease.acquire(str(root), _intent(), mode="shared")
    with storage.ArtifactLease.acquire(str(root), _intent(), mode="exclusive", create=True):
        pass


def test_failed_reverification_invalidates_prior_delivery_receipt(root):
    intent = _intent()
    _prepared(root, intent)
    with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as lease:
        lease.verify_prepared()
        (root / str(intent.artifact_id) / "prepared.json").write_bytes(b"bad")
        with pytest.raises(storage.ArtifactUnavailable):
            lease.verify_prepared()
        with pytest.raises(storage.ArtifactUnavailable):
            lease.read(0, 1)


def test_close_drains_the_owned_writer_before_releasing_lifetime(root, monkeypatch):
    intent = _intent()
    lease = storage.ArtifactLease.acquire(str(root), intent, mode="exclusive", create=True)
    lease.begin()
    entered, release, closing, closed = (threading.Event() for _ in range(4))
    errors = []
    original = storage.os.write
    def delayed_write(fd, data):
        entered.set()
        if not release.wait(5):
            raise RuntimeError("owned fixture failed to release writer")
        return original(fd, data)
    def writer():
        try:
            lease.append(b"release bytes")
        except BaseException as exc:
            errors.append(exc)
    def closer():
        closing.set()
        lease.close()
        closed.set()
    with monkeypatch.context() as patch:
        patch.setattr(storage.os, "write", delayed_write)
        task, cleanup = threading.Thread(target=writer), threading.Thread(target=closer)
        task.start()
        try:
            assert entered.wait(5)
            cleanup.start()
            assert closing.wait(5)
            assert not closed.wait(0.05)
            with pytest.raises(storage.ArtifactBusy):
                storage.ArtifactLease.acquire(str(root), intent, mode="exclusive")
        finally:
            release.set()
            task.join(5)
            if cleanup.ident is not None:
                cleanup.join(5)
            lease.close()
    assert not task.is_alive() and not cleanup.is_alive() and closed.is_set() and errors == []
    assert (root / str(intent.artifact_id) / "payload").read_bytes() == b"release bytes"
    with storage.ArtifactLease.acquire(str(root), intent, mode="exclusive"):
        pass


@pytest.mark.parametrize("held_mode,next_mode,blocked", [
    ("exclusive", "shared", True), ("exclusive", "exclusive", True),
    ("shared", "exclusive", True), ("shared", "shared", False),
])
def test_independent_process_observes_real_directory_lifetime_lock(root, held_mode, next_mode, blocked):
    intent = _intent()
    _prepared(root, intent)
    script = """
import json, sys
from uuid import UUID
from app.services.agent_release_artifact_store import ArtifactIntent, ArtifactLease, ArtifactBusy
value=json.loads(sys.argv[2])
for name in ('artifact_id','publish_operation_id','release_id'):
    value[name]=UUID(value[name])
value.pop('format')
try:
    with ArtifactLease.acquire(sys.argv[1],ArtifactIntent(**value),mode=sys.argv[3]) as lease:
        lease.verify_prepared()
        print('verified')
except ArtifactBusy:
    print('busy')
"""
    command = [sys.executable, "-B", "-c", script, str(root), intent.encoded().decode(), next_mode]
    before = _snapshot(root)
    with storage.ArtifactLease.acquire(str(root), intent, mode=held_mode):
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == ("busy" if blocked else "verified")
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "verified"
    assert _snapshot(root) == before


def test_receipt_parser_rejects_duplicate_keys_even_with_equivalent_decoded_object(root):
    intent = _intent()
    _prepared(root, intent)
    path = root / str(intent.artifact_id) / "prepared.json"
    data = path.read_bytes()
    assert json.loads(data)["format"] == 1
    path.write_bytes(b'{"format":1,' + data[1:])
    with storage.ArtifactLease.acquire(str(root), intent, mode="shared") as lease:
        with pytest.raises(storage.ArtifactUnavailable):
            lease.verify_prepared()
    assert path.read_bytes() == b'{"format":1,' + data[1:]
