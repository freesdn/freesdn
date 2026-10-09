"""Additional proposed contracts; not collected or executed."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from test_agent_signing_identity import (
    OPERATIONS,
    PRIVATE_NAME,
    PUBLIC_NAME,
    _invoke,
    _new_pair,
    _snapshot,
    _verify,
    _write,
)
from test_agent_signing_identity import signer as signer

IDENTITY_NAME = ".signing-identity.sha256"


def _mark(root, public):
    p = root / IDENTITY_NAME
    p.write_bytes(hashlib.sha256(public).hexdigest().encode() + b"\n")
    p.chmod(0o600)


def _complete_snapshot(root):
    result = _snapshot(root)
    marker = root / IDENTITY_NAME
    result[IDENTITY_NAME] = (
        (stat.S_IMODE(marker.stat().st_mode), hashlib.sha256(marker.read_bytes()).hexdigest())
        if marker.exists() else None
    )
    return result


@pytest.mark.parametrize("line_ending", (b"\n", b"\r\n"))
def test_valid_imported_public_bytes_keep_the_enrollment_fingerprint(signer, line_ending):
    module, root = signer
    private, public = _new_pair()
    public = public.replace(b"\n", line_ending)
    _write(root, private, public)
    before = _complete_snapshot(root)
    value, error = _invoke(module, "public")
    after = _complete_snapshot(root)
    assert error is None and value == public
    assert after[PRIVATE_NAME] == before[PRIVATE_NAME]
    assert after[PUBLIC_NAME] == before[PUBLIC_NAME]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("state", ("short", "nonhex", "no_newline", "wrong_identity"))
def test_untrusted_identity_marker_is_refused_without_repair(signer, operation, state):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    content = {
        "short": b"0\n",
        "nonhex": b"z" * 64 + b"\n",
        "no_newline": hashlib.sha256(public).hexdigest().encode(),
        "wrong_identity": b"0" * 64 + b"\n",
    }[state]
    marker = root / IDENTITY_NAME
    marker.write_bytes(content)
    marker.chmod(0o600)
    before = _complete_snapshot(root)
    value, error = _invoke(module, operation)
    after = _complete_snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
def test_recorded_identity_prevents_generation_when_both_keys_are_missing(signer, operation):
    module, root = signer
    _, public = _new_pair()
    _mark(root, public)
    before = _complete_snapshot(root)
    value, error = _invoke(module, operation)
    after = _complete_snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("change", ("replacement_pair", "exposed_private", "malformed_public"))
def test_warm_process_rechecks_current_storage_policy(signer, operation, change):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    _mark(root, public)
    initial, error = _invoke(module, "public")
    assert error is None and initial == public
    if change == "replacement_pair":
        replacement_private, replacement_public = _new_pair()
        _write(root, replacement_private, replacement_public)
    elif change == "exposed_private":
        (root / PRIVATE_NAME).chmod(0o644)
    else:
        (root / PUBLIC_NAME).write_bytes(b"invalid synthetic public data\n")
    before = _complete_snapshot(root)
    value, error = _invoke(module, operation)
    after = _complete_snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("name", (PRIVATE_NAME, PUBLIC_NAME))
def test_key_file_size_is_bounded_before_acceptance(signer, operation, name):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    target = root / name
    # The old parser may accept trailing whitespace after a valid PEM. This is
    # a bounded-storage contract, not a claim that whitespace changes the key.
    content = target.read_bytes()
    target.write_bytes(content + b"\n" * (4097 - len(content)))
    before = _complete_snapshot(root)
    value, error = _invoke(module, operation)
    after = _complete_snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("mode", (0o4600, 0o2600))
def test_special_permission_bits_are_refused(signer, operation, mode):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    (root / PRIVATE_NAME).chmod(mode)
    before = _complete_snapshot(root)
    value, error = _invoke(module, operation)
    after = _complete_snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("target", (PRIVATE_NAME, PUBLIC_NAME, IDENTITY_NAME, "directory"))
def test_sync_failure_refuses_and_retry_preserves_any_created_identity(signer, monkeypatch, target):
    module, root = signer
    real_fsync = os.fsync
    events = []

    def fault(fd):
        st = os.fstat(fd)
        name = "directory" if stat.S_ISDIR(st.st_mode) else Path(os.readlink(f"/proc/self/fd/{fd}")).name
        if name == target and (target != "directory" or Path(os.readlink(f"/proc/self/fd/{fd}")) == root):
            events.append(name)
            raise OSError("owned sync fault")
        return real_fsync(fd)

    with monkeypatch.context() as scope:
        scope.setattr(os, "fsync", fault)
        value, error = _invoke(module, "manifest")
        first_state = _complete_snapshot(root)
    # Capture storage and outcome before the contract assertions. An untouched
    # original implementation never calls fsync and may instead report success.
    assert error is not None and value is None
    assert events
    private_before = first_state[PRIVATE_NAME]
    assert private_before is not None
    # Re-enter with an independently loaded process-like module cache state.
    # A real fresh-process/crash comparison remains separately required.
    module._PRIVATE_KEY = None
    module._PUBLIC_KEY_PEM = None
    signature, second_error = _invoke(module, "manifest")
    second_state = _complete_snapshot(root)
    assert second_error is None
    assert second_state[PRIVATE_NAME] == private_before
    _verify((root / PUBLIC_NAME).read_bytes(), signature)


def test_private_permissions_are_safe_before_the_first_write_returns(signer, monkeypatch):
    module, root = signer
    observations = []
    original_path_write = Path.write_bytes
    original_os_write = os.write

    def observe_path(path, data):
        result = original_path_write(path, data)
        if path == root / PRIVATE_NAME:
            observations.append(stat.S_IMODE(path.stat().st_mode))
        return result

    def observe_fd(fd, data):
        target = root / PRIVATE_NAME
        if target.exists():
            opened, named = os.fstat(fd), target.stat()
            if (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino):
                observations.append(stat.S_IMODE(opened.st_mode))
        return original_os_write(fd, data)

    monkeypatch.setattr(Path, "write_bytes", observe_path)
    monkeypatch.setattr(os, "write", observe_fd)
    original_umask = os.umask(0)
    try:
        signature, error = _invoke(module, "manifest")
        state = _complete_snapshot(root)
    finally:
        os.umask(original_umask)
    assert error is None
    assert observations and set(observations) == {0o600}
    assert state[PRIVATE_NAME]["mode"] == 0o600
    _verify((root / PUBLIC_NAME).read_bytes(), signature)
