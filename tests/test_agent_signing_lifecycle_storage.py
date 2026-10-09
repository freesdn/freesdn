"""AFTER-only explicit storage modes; owned synthetic files, not live keys."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from test_agent_signing_identity import PRIVATE_NAME, PUBLIC_NAME, _new_pair, _write
from test_agent_signing_identity import signer as signer

MARKER = ".signing-identity.sha256"


def all_files(root):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}


@pytest.mark.parametrize("state", ["empty", "private", "public", "pair", "marker"])
def test_explicit_initialization_never_adopts_surviving_files(signer, state):
    module, root = signer
    private, public = _new_pair()
    if state in {"private", "pair"}:
        p = root / PRIVATE_NAME
        p.write_bytes(private)
        p.chmod(0o600)
    if state in {"public", "pair"}:
        (root / PUBLIC_NAME).write_bytes(public)
    if state == "marker":
        p = root / MARKER
        p.write_text(hashlib.sha256(public).hexdigest()+"\n")
        p.chmod(0o600)
    before = all_files(root)
    if state == "empty":
        actual = module.prepare_signing_identity(mode="initialize")
        assert actual == (root / PUBLIC_NAME).read_bytes()
        assert set(all_files(root)) == {PRIVATE_NAME, PUBLIC_NAME, MARKER}
    else:
        with pytest.raises(module.SigningKeyError):
            module.prepare_signing_identity(mode="initialize")
        assert all_files(root) == before


@pytest.mark.parametrize("state", ["empty", "private", "pair", "marker_only", "public_only"])
def test_resumption_never_generates_absent_private_material(signer, monkeypatch, state):
    module, root = signer
    private, public = _new_pair()
    if state in {"private", "pair"}:
        p = root / PRIVATE_NAME
        p.write_bytes(private)
        p.chmod(0o600)
    if state in {"pair", "public_only"}:
        (root / PUBLIC_NAME).write_bytes(public)
    if state == "marker_only":
        p = root / MARKER
        p.write_text(hashlib.sha256(public).hexdigest()+"\n")
        p.chmod(0o600)
    before = all_files(root)

    def forbidden_generation(*args, **kwargs):
        raise AssertionError("Resume must never generate a new private identity")

    monkeypatch.setattr(ec, "generate_private_key", forbidden_generation)
    if state in {"private", "pair"}:
        result = module.prepare_signing_identity(mode="resume")
        assert result == public
        assert all_files(root)[PRIVATE_NAME] == before[PRIVATE_NAME]
    else:
        with pytest.raises(module.SigningKeyError):
            module.prepare_signing_identity(mode="resume")
        assert all_files(root) == before


@pytest.mark.parametrize("crlf", [False, True])
@pytest.mark.parametrize("state", ["matching", "wrong", "missing_public", "missing_private"])
def test_adoption_checks_expected_raw_pin_before_any_repair(signer, monkeypatch, crlf, state):
    module, root = signer
    private, public = _new_pair()
    if crlf:
        public = public.replace(b"\n", b"\r\n")
    _write(root, private, public)
    if state == "missing_public":
        (root / PUBLIC_NAME).unlink()
    if state == "missing_private":
        (root / PRIVATE_NAME).unlink()
    expected = "0"*64 if state == "wrong" else hashlib.sha256(public).hexdigest()
    before = all_files(root)

    def forbidden_generation(*args, **kwargs):
        raise AssertionError("Adoption must not generate a private key")

    monkeypatch.setattr(ec, "generate_private_key", forbidden_generation)
    if state == "matching":
        assert module.prepare_signing_identity(mode="adopt", expected_sha256=expected) == public
        assert all(all_files(root)[name] == value for name,value in before.items())
    else:
        with pytest.raises(module.SigningKeyError):
            module.prepare_signing_identity(mode="adopt", expected_sha256=expected)
        assert all_files(root) == before


@pytest.mark.parametrize("mode,expected", [
    ("unknown", None), (None, None), (b"initialize", None),
    ("initialize", "0"*64), ("resume", "0"*64), ("adopt", None),
])
def test_invalid_storage_intent_refuses_before_descriptor_access(signer, monkeypatch, mode, expected):
    module, root = signer
    before = all_files(root)

    def forbidden_store(*args, **kwargs):
        raise AssertionError("Invalid mode must refuse before accessing the store")

    monkeypatch.setattr(module, "_load_or_generate", forbidden_store)
    with pytest.raises(module.SigningKeyError):
        module.prepare_signing_identity(mode=mode, expected_sha256=expected)
    assert all_files(root) == before
