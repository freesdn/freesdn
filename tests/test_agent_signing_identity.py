"""Private proposed signing-key contracts; no deployed signing material is used.

This module has not been collected or executed. The qualification runner must
provide the exact frozen source module and independent resource/headroom guards.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

SOURCE_ENV = "FREESDN_SIGNING_PROBE_SOURCE"
SOURCE_SHA_ENV = "FREESDN_SIGNING_PROBE_SHA256"
PRIVATE_NAME = ".signing-key.pem"
PUBLIC_NAME = ".public-key.pem"
OPERATIONS = ("public", "manifest")
MANIFEST = {
    "agent_type": "daemon",
    "channel": "stable",
    "digest": hashlib.sha256(b"owned synthetic agent binary").hexdigest(),
    "platform": "linux-amd64",
    "v": 1,
    "version": "99.0.1",
}


def _new_pair(curve=None):
    key = ec.generate_private_key(curve or ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _write(root: Path, private: bytes, public: bytes):
    root.mkdir(mode=0o700, exist_ok=True)
    (root / PRIVATE_NAME).write_bytes(private)
    (root / PRIVATE_NAME).chmod(0o600)
    (root / PUBLIC_NAME).write_bytes(public)
    (root / PUBLIC_NAME).chmod(0o644)


def _snapshot(root: Path):
    """Observe owned files before assertions, without recording PEM contents."""
    result = {}
    for name in (PRIVATE_NAME, PUBLIC_NAME):
        path = root / name
        try:
            st = path.lstat()
        except FileNotFoundError:
            result[name] = None
            continue
        result[name] = {
            "mode": stat.S_IMODE(st.st_mode),
            "inode": st.st_ino,
            "links": st.st_nlink,
            "symlink": path.is_symlink(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return result


@pytest.fixture
def signer(tmp_path, monkeypatch):
    # Fail before importing application code if the future runner omitted its
    # immutable source binding. This must never default to a deployment path.
    source = Path(os.environ[SOURCE_ENV])
    assert source.is_absolute() and source.is_file()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == os.environ[SOURCE_SHA_ENV]
    root = tmp_path / "owned-signing"
    root.mkdir(mode=0o700)
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(root))
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(root))
    spec = importlib.util.spec_from_file_location("owned_signing_probe", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module, root
    # No synthetic key is intentionally retained in the application's cache.
    module._PRIVATE_KEY = None
    module._PUBLIC_KEY_PEM = None


def _invoke(module, operation):
    try:
        value = module.public_key_pem() if operation == "public" else module.sign_manifest(MANIFEST)
        return value, None
    except Exception as exc:
        return None, type(exc).__name__


def _verify(public, signature):
    key = serialization.load_pem_public_key(public)
    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert isinstance(key.curve, ec.SECP256R1)
    # Independently encode the six known fields; do not reuse the signer's
    # serializer or verifier to decide whether the signature is valid.
    import json

    payload = json.dumps(MANIFEST, sort_keys=True, separators=(",", ":")).encode()
    key.verify(base64.b64decode(signature, validate=True), payload, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("operation", OPERATIONS)
def test_valid_owned_pair_is_preserved_and_usable(signer, operation):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    before = _snapshot(root)
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    assert error is None
    assert after == before
    if operation == "public":
        assert value == public
    else:
        _verify(public, value)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_private_only_state_never_replaces_surviving_identity(signer, operation):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    (root / PUBLIC_NAME).unlink()
    before = _snapshot(root)
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    assert after[PRIVATE_NAME] == before[PRIVATE_NAME]
    # Either refuse without further mutation, or recover the *same* public
    # identity from the existing private key. Neither policy permits rotation.
    if error is not None:
        assert after == before
    else:
        assert after[PUBLIC_NAME]["sha256"] == hashlib.sha256(public).hexdigest()
        if operation == "public":
            assert value == public
        else:
            _verify(public, value)


def test_public_only_signing_refuses_without_replacing_trusted_identity(signer):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    (root / PRIVATE_NAME).unlink()
    before = _snapshot(root)
    value, error = _invoke(module, "manifest")
    after = _snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("state", ("mismatch", "p384", "rsa", "invalid_private", "invalid_public"))
def test_invalid_pair_is_refused_without_mutation(signer, operation, state):
    module, root = signer
    private, public = _new_pair()
    if state == "mismatch":
        _, public = _new_pair()
    elif state == "p384":
        private, public = _new_pair(ec.SECP384R1())
    elif state == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    elif state == "invalid_private":
        private = b"synthetic non-key data\n"
    else:
        public = b"synthetic non-key data\n"
    _write(root, private, public)
    before = _snapshot(root)
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("mode", (0o644, 0o660, 0o666))
def test_existing_exposed_private_key_is_not_silently_accepted(signer, operation, mode):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    (root / PRIVATE_NAME).chmod(mode)
    before = _snapshot(root)
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    # Explicit recovery is needed; silently chmod-ing an already exposed key
    # does not revoke any copies or establish that its identity is trustworthy.
    assert after == before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("name", (PRIVATE_NAME, PUBLIC_NAME))
def test_symlinked_pair_member_is_refused(signer, tmp_path, operation, name):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    # The target is also test-owned. No path points to a real key or outside
    # this per-test temporary directory.
    target = tmp_path / "owned-link-target"
    (root / name).replace(target)
    (root / name).symlink_to(target)
    before = _snapshot(root)
    target_before = hashlib.sha256(target.read_bytes()).hexdigest()
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    target_after = hashlib.sha256(target.read_bytes()).hexdigest()
    assert after == before and target_after == target_before
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
def test_private_key_with_another_hardlink_is_refused(signer, tmp_path, operation):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    link = tmp_path / "owned-other-link"
    link.hardlink_to(root / PRIVATE_NAME)
    before = _snapshot(root)
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    assert after == before and link.read_bytes() == private
    assert error is not None and value is None


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("mode", (0o770, 0o777))
def test_untrusted_writable_key_directory_is_refused(signer, operation, mode):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    root.chmod(mode)
    before = _snapshot(root)
    value, error = _invoke(module, operation)
    after = _snapshot(root)
    assert after == before and stat.S_IMODE(root.stat().st_mode) == mode
    assert error is not None and value is None


@pytest.mark.parametrize("umask", (0o022, 0o077))
def test_empty_owned_directory_provisions_usable_private_pair(signer, umask):
    module, root = signer
    original_umask = os.umask(umask)
    try:
        signature, error = _invoke(module, "manifest")
    finally:
        os.umask(original_umask)
    state = _snapshot(root)
    assert error is None
    assert state[PRIVATE_NAME]["mode"] == 0o600
    assert not state[PRIVATE_NAME]["symlink"] and state[PRIVATE_NAME]["links"] == 1
    assert not state[PUBLIC_NAME]["symlink"]
    _verify((root / PUBLIC_NAME).read_bytes(), signature)
