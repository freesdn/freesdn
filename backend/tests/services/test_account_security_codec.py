"""Bounded account-security format checks through the application package."""

import base64
import json

import pytest
from argon2 import PasswordHasher

from app.services.backup_contributors import account_security_codec as codec


@pytest.fixture(scope="module")
def actual_hash():
    # Only this known bounded work factor is executed. Malicious PHC variants
    # below must never be sent to an Argon2 verifier or hash implementation.
    return PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4).hash(
        "Owned codec qualification password",
    )


def test_actual_supported_hash_preserved_byte_for_byte(actual_hash):
    assert codec.require_argon2_hash(actual_hash) == actual_hash
    assert codec.require_password_hash(actual_hash, active=True,
                                       external_binding_validated=False) == actual_hash


@pytest.mark.parametrize("old,new", [
    ("m=65536", "m=1073741824"), ("t=3", "t=1000000"), ("p=4", "p=1024"),
    ("m=65536", "m=8"), ("t=3", "t=0"), ("p=4", "p=0"),
    ("v=19", "v=16"), ("argon2id", "argon2i"), ("argon2id", "argon2d"),
])
def test_unreviewed_or_unbounded_profiles_refused_without_verification(actual_hash, monkeypatch, old, new):
    def forbidden(*args, **kwargs):
        pytest.fail("An imported hash must not be executed to validate its format")
    monkeypatch.setattr(PasswordHasher, "verify", forbidden)
    monkeypatch.setattr(PasswordHasher, "hash", forbidden)
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_argon2_hash(actual_hash.replace(old, new))


@pytest.mark.parametrize("value", [None, True, 12, [], {}, "", "plaintext", "x" * 4096])
def test_non_hash_inputs_refused(value):
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_argon2_hash(value)


@pytest.mark.parametrize("part", [4, 5])
def test_noncanonical_base64_tail_refused(actual_hash, part):
    pieces = actual_hash.split("$")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    final = alphabet.index(pieces[part][-1])
    pieces[part] = pieces[part][:-1] + alphabet[final + 1]
    # Both strings decode to identical bytes; the malformed tail is refused.
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_argon2_hash("$".join(pieces))


@pytest.mark.parametrize("value,active,external,accepted", [
    ("!", False, False, True), ("!", True, False, False),
    ("!", False, True, False), ("!", True, True, False),
    ("!SSO_MANAGED", True, True, True), ("!SSO_MANAGED", False, True, True),
    ("!SSO_MANAGED", True, False, False), ("!SSO_MANAGED", False, False, False),
    ("!SSO_MANAGED", True, "oidc", False), ("!", 0, False, False),
])
def test_unusable_markers_require_exact_account_mode(value, active, external, accepted):
    if accepted:
        assert codec.require_password_hash(value, active=active,
                                            external_binding_validated=external) == value
    else:
        with pytest.raises(codec.AccountSecurityFormatError):
            codec.require_password_hash(value, active=active, external_binding_validated=external)


def test_canonical_seed_and_absence_are_preserved():
    seed = base64.b32encode(bytes(range(20))).decode()
    assert codec.require_portable_seed(seed) == seed
    assert codec.require_portable_seed(None) is None


@pytest.mark.parametrize("value", [True, 32, [], "", "A" * 31, "A" * 33,
                                   "a" * 32, "0" * 32, "fernet:owned-source-ciphertext"])
def test_nonportable_seeds_are_refused(value):
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_portable_seed(value)


def test_remaining_code_list_preserves_hashes_and_distinguishes_empty(actual_hash):
    assert codec.require_backup_code_hashes(json.dumps([actual_hash])) == [actual_hash]
    assert codec.require_backup_code_hashes("[]") == []
    assert codec.require_backup_code_hashes(None) is None


@pytest.mark.parametrize("value", [True, 12, [], {}, "{}", "null", "[invalid",
                                   '["AB12CD34EF"]', "x" * 4097, '"\\ud800"'])
def test_invalid_code_container_is_refused(value):
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_backup_code_hashes(value)


def test_duplicate_hashes_refused(actual_hash):
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_backup_code_hashes(json.dumps([actual_hash, actual_hash]))


def test_eleven_distinct_hashes_refused(actual_hash):
    parts = actual_hash.split("$")
    values = ["$".join([*parts[:4], c + parts[4][1:], parts[5]]) for c in "ABCDEFGHIJK"]
    assert len(set(values)) == 11
    with pytest.raises(codec.AccountSecurityFormatError):
        codec.require_backup_code_hashes(json.dumps(values))


def test_maximum_supported_remaining_list_accepted(actual_hash):
    parts = actual_hash.split("$")
    values = ["$".join([*parts[:4], c + parts[4][1:], parts[5]]) for c in "ABCDEFGHIJ"]
    assert codec.require_backup_code_hashes(json.dumps(values)) == values


def test_encoded_work_factor_in_code_list_not_executed(actual_hash, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("An imported hash must not be executed")
    monkeypatch.setattr(PasswordHasher, "verify", forbidden)
    malicious = actual_hash.replace("m=65536", "m=1073741824")
    with pytest.raises(codec.AccountSecurityFormatError) as error:
        codec.require_backup_code_hashes(json.dumps([malicious]))
    assert malicious not in str(error.value) and actual_hash not in str(error.value)
