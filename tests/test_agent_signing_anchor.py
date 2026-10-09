"""Unrun AFTER-only anchor primitives; no database/authentication acceptance."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from test_agent_signing_boundaries import IDENTITY_NAME, _complete_snapshot, _mark
from test_agent_signing_identity import (
    MANIFEST,
    PRIVATE_NAME,
    PUBLIC_NAME,
    _new_pair,
    _verify,
    _write,
)
from test_agent_signing_identity import signer as signer

ANCHOR_OPERATIONS = ("check", "manifest")
ALL_OPERATIONS = ("public", "check", "manifest")


def _arguments(public):
    return {"anchor_public_pem": public, "anchor_sha256": hashlib.sha256(public).hexdigest()}


def _call(module, operation, arguments, manifest=None):
    if operation == "public":
        return module.public_key_for_anchor(**arguments)
    if operation == "check":
        return module.check_signing_anchor(**arguments)
    return module.sign_manifest_for_anchor(dict(MANIFEST) if manifest is None else manifest, **arguments)


def _observe(module, operation, arguments):
    try:
        return _call(module, operation, arguments), None
    except Exception as exc:
        return None, type(exc).__name__


@pytest.mark.parametrize("operation", ANCHOR_OPERATIONS)
@pytest.mark.parametrize("state", ("empty", "public_only", "marker_only", "public_and_marker", "missing_directory"))
def test_trusted_anchor_never_replaces_missing_private_material(
    signer, monkeypatch, record_property, operation, state,
):
    module, root = signer
    _, trusted_public = _new_pair()
    if state == "missing_directory":
        root = root / "missing/keys"
        monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(root))
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(root))
    if state in {"public_only", "public_and_marker"}:
        (root / PUBLIC_NAME).write_bytes(trusted_public)
        (root / PUBLIC_NAME).chmod(0o644)
    if state in {"marker_only", "public_and_marker"}:
        _mark(root, trusted_public)
    before = _complete_snapshot(root)
    generation_calls = []

    def forbidden_generation(*args, **kwargs):
        generation_calls.append(True)
        raise AssertionError("anchored recovery may not create a replacement private key")

    monkeypatch.setattr(ec, "generate_private_key", forbidden_generation)
    value, error = _observe(module, operation, _arguments(trusted_public))
    after = _complete_snapshot(root)
    record_property("replacement_generation_calls", len(generation_calls))
    record_property("key_material_unchanged", before == after)
    record_property("anchored_operation_refused", error is not None)
    assert error == "SigningKeyError" and value is None
    assert not generation_calls and before == after
    if state == "missing_directory":
        assert not root.parent.exists()


@pytest.mark.parametrize("operation", ANCHOR_OPERATIONS)
@pytest.mark.parametrize("line_ending", (b"\n", b"\r\n"))
@pytest.mark.parametrize("public_present", (False, True))
@pytest.mark.parametrize("marker_present", (False, True))
def test_matching_anchor_preserves_private_key_and_exact_provisioned_public_bytes(
    signer, record_property, operation, line_ending, public_present, marker_present,
):
    module, root = signer
    private, trusted_public = _new_pair()
    trusted_public = trusted_public.replace(b"\n", line_ending)
    _write(root, private, trusted_public)
    if not public_present:
        (root / PUBLIC_NAME).unlink()
    if marker_present:
        _mark(root, trusted_public)
    before = _complete_snapshot(root)
    value, error = _observe(module, operation, _arguments(trusted_public))
    after = _complete_snapshot(root)
    observed_public = (root / PUBLIC_NAME).read_bytes()
    observed_marker = (root / IDENTITY_NAME).read_bytes()
    record_property("private_identity_preserved", before[PRIVATE_NAME] == after[PRIVATE_NAME])
    record_property("provisioned_public_bytes_preserved", observed_public == trusted_public)
    assert error is None
    assert before[PRIVATE_NAME] == after[PRIVATE_NAME]
    assert observed_public == trusted_public
    assert observed_marker == hashlib.sha256(trusted_public).hexdigest().encode() + b"\n"
    if marker_present:
        assert before[IDENTITY_NAME] == after[IDENTITY_NAME]
    if operation == "check":
        assert value == trusted_public
    else:
        _verify(trusted_public, value)


@pytest.mark.parametrize("operation", ANCHOR_OPERATIONS)
@pytest.mark.parametrize("state", ("different_pair", "different_raw_public_bytes", "wrong_marker", "missing_public_wrong_private"))
def test_independent_anchor_conflict_refuses_without_repair(signer, operation, state):
    module, root = signer
    private, local_public = _new_pair()
    _, other_public = _new_pair()
    _write(root, private, local_public)
    trusted_public = local_public
    if state in {"different_pair", "missing_public_wrong_private"}:
        trusted_public = other_public
    elif state == "different_raw_public_bytes":
        trusted_public = local_public.replace(b"\n", b"\r\n")
    else:
        _mark(root, other_public)
    if state == "missing_public_wrong_private":
        (root / PUBLIC_NAME).unlink()
    before = _complete_snapshot(root)
    value, error = _observe(module, operation, _arguments(trusted_public))
    after = _complete_snapshot(root)
    assert error == "SigningKeyError" and value is None
    assert before == after


@pytest.mark.parametrize("state", ("empty", "different_pair", "malformed_private", "missing_directory"))
def test_public_verification_anchor_remains_available_without_private_storage(
    signer, monkeypatch, state,
):
    module, root = signer
    _, trusted_public = _new_pair()
    if state == "different_pair":
        other_private, other_public = _new_pair()
        _write(root, other_private, other_public)
    elif state == "malformed_private":
        (root / PRIVATE_NAME).write_bytes(b"owned invalid fixture material")
        (root / PRIVATE_NAME).chmod(0o600)
    elif state == "missing_directory":
        root = root / "missing/keys"
        monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(root))
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(root))
    before = _complete_snapshot(root)
    touched = []

    def forbidden_store(*args, **kwargs):
        touched.append(True)
        raise AssertionError("public verification does not require private storage")

    monkeypatch.setattr(module, "_load_or_generate", forbidden_store)
    value, error = _observe(module, "public", _arguments(trusted_public))
    after = _complete_snapshot(root)
    assert error is None and value == trusted_public
    assert not touched and before == after
    if state == "missing_directory":
        assert not root.parent.exists()


@pytest.mark.parametrize("operation", ALL_OPERATIONS)
@pytest.mark.parametrize("state", ("none", "string", "mutable_bytes", "oversized", "wrong_curve", "private_object", "wrong_digest", "uppercase_digest"))
def test_malformed_anchor_refuses_before_private_storage(signer, monkeypatch, operation, state):
    module, root = signer
    private, public = _new_pair()
    arguments = _arguments(public)
    if state == "none":
        arguments["anchor_public_pem"] = None
    elif state == "string":
        arguments["anchor_public_pem"] = public.decode()
    elif state == "mutable_bytes":
        arguments["anchor_public_pem"] = bytearray(public)
    elif state == "oversized":
        arguments = _arguments(public + b"\n" * (4097 - len(public)))
    elif state == "wrong_curve":
        _, wrong = _new_pair(ec.SECP384R1())
        arguments = _arguments(wrong)
    elif state == "private_object":
        arguments = _arguments(private)
    elif state == "wrong_digest":
        arguments["anchor_sha256"] = "0" * 64
    else:
        arguments["anchor_sha256"] = "A" + "0" * 63
    touched = []

    def forbidden_store(*args, **kwargs):
        touched.append(True)
        raise AssertionError("invalid anchor may not enter storage")

    monkeypatch.setattr(module, "_load_or_generate", forbidden_store)
    value, error = _observe(module, operation, arguments)
    assert error == "SigningKeyError" and value is None
    assert not touched and not list(root.iterdir())


@pytest.mark.parametrize("state", ("not_dictionary", "boolean_version", "missing", "oversized_field", "nested", "byte_budget"))
def test_anchored_manifest_bounds_are_checked_before_storage(signer, monkeypatch, state):
    module, root = signer
    _, public = _new_pair()
    manifest = dict(MANIFEST)
    if state == "not_dictionary":
        manifest = []
    elif state == "boolean_version":
        manifest["v"] = True
    elif state == "missing":
        del manifest["digest"]
    elif state == "oversized_field":
        manifest["version"] = "x" * 1025
    elif state == "nested":
        manifest["version"] = {"unexpected": "mapping"}
    else:
        manifest.update({field: "x" * 1024 for field in MANIFEST if field != "v"})
    touched = []

    def forbidden_store(*args, **kwargs):
        touched.append(True)
        raise AssertionError("invalid manifest may not enter storage")

    monkeypatch.setattr(module, "_load_or_generate", forbidden_store)
    with pytest.raises(ValueError):
        _call(module, "manifest", _arguments(public), manifest)
    assert not touched and not list(root.iterdir())
