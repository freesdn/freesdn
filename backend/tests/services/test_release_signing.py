# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the ECDSA-P256 release signing helper.

Validates the full sign + verify round-trip, key persistence, and
public-key export. We point the helper at a tmp dir per test so the
global cached keypair doesn't bleed between tests.
"""

from __future__ import annotations

import hashlib
import importlib

import pytest


def _reload_signing(tmp_path, monkeypatch):
    """Force the signing module to re-initialize against a fresh dir.

    The module caches the keypair in module-level globals so we reset
    those + point the dir env var at tmp_path before re-importing.
    """
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(tmp_path))
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
    import app.services.release_signing as signing

    importlib.reload(signing)
    return signing


class TestKeyGeneration:
    def test_lazy_generates_keypair_on_first_call(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        pem = signing.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        # On-disk persistence
        priv_path = tmp_path / ".signing-key.pem"
        pub_path = tmp_path / ".public-key.pem"
        assert priv_path.exists()
        assert pub_path.exists()

    def test_reuses_existing_keypair_across_reloads(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        pem_first = signing.public_key_pem()

        # Re-import: should NOT regenerate the key (key file persists)
        signing2 = _reload_signing(tmp_path, monkeypatch)
        pem_second = signing2.public_key_pem()
        assert pem_first == pem_second


class TestSignVerify:
    def test_round_trip_valid_digest(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        digest = hashlib.sha256(b"fake-binary-bytes").hexdigest()
        sig = signing.sign_digest(digest)
        assert signing.verify_digest(digest, sig) is True

    def test_verify_rejects_tampered_digest(self, tmp_path, monkeypatch):
        """If the binary changed after signing, the digest changes and
        verification must fail."""
        signing = _reload_signing(tmp_path, monkeypatch)
        digest_orig = hashlib.sha256(b"original").hexdigest()
        digest_tampered = hashlib.sha256(b"tampered").hexdigest()
        sig = signing.sign_digest(digest_orig)
        assert signing.verify_digest(digest_tampered, sig) is False

    def test_verify_rejects_garbage_signature(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        digest = hashlib.sha256(b"x").hexdigest()
        assert signing.verify_digest(digest, "AAAAAAAA") is False
        assert signing.verify_digest(digest, "not-base64-at-all!!!") is False

    def test_sign_rejects_non_hex_digest(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        with pytest.raises(ValueError):
            signing.sign_digest("not-hex")

    def test_sign_rejects_wrong_length_digest(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        # Hex but not 32 bytes
        short = "ab" * 16  # 16 bytes
        with pytest.raises(ValueError):
            signing.sign_digest(short)


# ---------------------------------------------------------------------------
# Release manifest signing (F-02)
# ---------------------------------------------------------------------------
#
# Signing the bare digest bound nothing else. A backend that does NOT hold the
# private key could re-serve a genuine OLDER release -- its binary, its checksum
# and its stored signature -- as an update, because the signed object never said
# which version/platform/agent-type/channel that digest belonged to. The
# signature now covers a canonical manifest carrying all of them.


@pytest.fixture
def isolated_manifest_keys(tmp_path, monkeypatch):
    """Use owned real key storage without reloading or replacing signer behavior."""
    directory = str(tmp_path / "owned-manifest-keys")
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", directory)
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", directory)


@pytest.mark.usefixtures("isolated_manifest_keys")
class TestReleaseManifestSigning:
    @staticmethod
    def _manifest(**overrides):
        from app.services.release_signing import build_release_manifest

        base = {
            "digest_hex": "a" * 64,
            "version": "1.0.4",
            "platform": "linux-amd64",
            "agent_type": "daemon",
            "channel": "stable",
        }
        base.update(overrides)
        return build_release_manifest(**base)

    def test_roundtrip_verifies(self) -> None:
        from app.services.release_signing import sign_manifest, verify_manifest

        m = self._manifest()
        assert verify_manifest(m, sign_manifest(m)) is True

    @pytest.mark.parametrize(
        "field,value",
        [
            ("version", "9.9.9"),
            ("platform", "win64"),
            ("agent_type", "gui"),
            ("channel", "prerelease"),
            ("digest", "b" * 64),
        ],
    )
    def test_tampering_with_any_bound_field_invalidates(self, field, value) -> None:
        """The whole point: the metadata is bound, so relabelling breaks the sig."""
        from app.services.release_signing import sign_manifest, verify_manifest

        m = self._manifest()
        sig = sign_manifest(m)
        tampered = dict(m)
        tampered[field] = value
        assert verify_manifest(tampered, sig) is False

    def test_canonical_form_is_stable_and_sorted(self) -> None:
        """Both sides must derive identical bytes; signing one serialisation and
        verifying another is how a signature scheme quietly stops meaning
        anything."""
        from app.services.release_signing import canonical_manifest_bytes

        m = self._manifest()
        raw = canonical_manifest_bytes(m)
        assert raw == canonical_manifest_bytes(dict(reversed(list(m.items()))))
        assert raw.startswith(b'{"agent_type"'), "keys must be sorted"
        assert b" " not in raw, "no insignificant whitespace"

    def test_incomplete_manifest_is_refused(self) -> None:
        from app.services.release_signing import canonical_manifest_bytes

        m = self._manifest()
        del m["platform"]
        with pytest.raises(ValueError, match="missing required field"):
            canonical_manifest_bytes(m)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"digest_hex": "short"},
            {"version": ""},
            {"platform": "  "},
            {"agent_type": ""},
            {"channel": ""},
        ],
    )
    def test_a_manifest_that_cannot_describe_a_release_is_refused(self, kwargs) -> None:
        """Fail at build time rather than signing something meaningless."""
        with pytest.raises(ValueError):
            self._manifest(**kwargs)


@pytest.mark.usefixtures("isolated_manifest_keys")
class TestManifestSurvivesThePersistenceLifecycle:
    """Sign -> persist -> rebuild -> verify must hold for accepted input.

    The endpoints accept mixed-case ``platform``/``agent_type`` (validation
    lower-cases before comparing) but used to SIGN the raw values and PERSIST the
    lower-cased ones. The update-check endpoint rebuilds the manifest from the
    stored row, so the bytes it produced could never match the signature and the
    agent refused a perfectly legitimate update.

    Neither the endpoint tests nor the signing tests covered the round trip --
    each end was fine in isolation. This pins the seam between them.
    """

    def test_normalised_metadata_still_verifies_after_a_rebuild(self) -> None:
        from app.services.release_signing import (
            build_release_manifest,
            sign_manifest,
            verify_manifest,
        )

        raw_platform, raw_agent_type = "Linux-AMD64", "Daemon"
        # What the endpoints now do: normalise BEFORE signing.
        platform, agent_type = raw_platform.lower(), raw_agent_type.lower()

        signed = build_release_manifest(
            digest_hex="c" * 64,
            version="1.0.4",
            platform=platform,
            agent_type=agent_type,
            channel="stable",
        )
        signature = sign_manifest(signed)

        # What the update-check endpoint does: rebuild from the persisted row,
        # which stores the lower-cased values.
        rebuilt = build_release_manifest(
            digest_hex="c" * 64,
            version="1.0.4",
            platform=platform,   # as stored
            agent_type=agent_type,
            channel="stable",
        )
        assert verify_manifest(rebuilt, signature) is True

    def test_signing_raw_case_then_rebuilding_lowercase_would_fail(self) -> None:
        """Pins WHY the normalisation matters, so removing it is caught here."""
        from app.services.release_signing import (
            build_release_manifest,
            sign_manifest,
            verify_manifest,
        )

        signed_raw = build_release_manifest(
            digest_hex="c" * 64,
            version="1.0.4",
            platform="Linux-AMD64",
            agent_type="Daemon",
            channel="stable",
        )
        signature = sign_manifest(signed_raw)

        rebuilt_lower = build_release_manifest(
            digest_hex="c" * 64,
            version="1.0.4",
            platform="linux-amd64",
            agent_type="daemon",
            channel="stable",
        )
        assert verify_manifest(rebuilt_lower, signature) is False, (
            "if this ever passes, the manifest stopped binding platform/agent_type"
        )
