# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""ECDSA-P256 release signing for the agent auto-update path.

Functionally equivalent to cosign key-based signing (cosign also uses
ECDSA) but pure-Python — no external `cosign` binary required. The
agent verifies signatures using the same ``cryptography`` library
already in tree.

Flow:

  1. Backend lazily generates an ECDSA P-256 keypair on first sign.
     Private key persisted to ``$FREESDN_AGENT_RELEASE_DIR/.signing-key.pem``
     (chmod 0600 on Unix); public key in the sibling ``.public-key.pem``.
  2. Upload endpoint signs the binary's SHA-256 digest after computing
     the checksum.  Signature stored on the AgentRelease row.
  3. ``GET /agents/releases/public-key`` exposes the PEM-encoded public
     key (unauthenticated — the public key is public).
  4. Agent fetches the public key on first run + verifies each downloaded
     binary's signature against the row's claimed signature before
     staging.  Mismatch aborts the update with no rollback marker.

What this DOESN'T do (deferred to v2 cosign chapter):

- Transparency log (Rekor) submission.
- Keyless signing via OIDC.
- Key rotation / multiple trusted public keys.

For a single-tenant or low-trust-multi-tenant deployment, the static
P-256 key on the backend is acceptable — it's checked in addition to
the existing HTTPS-only download URL + SHA-256 mandatory check.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)


_SIGNING_LOCK = threading.Lock()
_PRIVATE_KEY: ec.EllipticCurvePrivateKey | None = None
_PUBLIC_KEY_PEM: bytes | None = None


def _key_dir() -> Path:
    """Where signing keys live on disk.

    Defaults to ``$FREESDN_AGENT_RELEASE_DIR`` so signing material sits
    next to the binaries it protects (and gets backed up together).
    Override via ``$FREESDN_SIGNING_KEY_DIR`` if you want keys on a
    different volume.
    """
    base = os.environ.get(
        "FREESDN_SIGNING_KEY_DIR",
        os.environ.get("FREESDN_AGENT_RELEASE_DIR", "/var/lib/freesdn/agent-releases"),
    )
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _load_or_generate() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Lazy: load the keypair from disk; generate + persist if missing.

    Thread-safe via the module-level lock — first concurrent caller
    wins and the rest read the populated globals.
    """
    global _PRIVATE_KEY, _PUBLIC_KEY_PEM
    if _PRIVATE_KEY is not None and _PUBLIC_KEY_PEM is not None:
        return _PRIVATE_KEY, _PUBLIC_KEY_PEM
    with _SIGNING_LOCK:
        if _PRIVATE_KEY is not None and _PUBLIC_KEY_PEM is not None:
            return _PRIVATE_KEY, _PUBLIC_KEY_PEM

        priv_path = _key_dir() / ".signing-key.pem"
        pub_path = _key_dir() / ".public-key.pem"

        if priv_path.exists() and pub_path.exists():
            priv_bytes = priv_path.read_bytes()
            pub_bytes = pub_path.read_bytes()
            priv = serialization.load_pem_private_key(priv_bytes, password=None)
            if not isinstance(priv, ec.EllipticCurvePrivateKey):
                raise RuntimeError("On-disk signing key is not ECDSA — refusing to use it")
            _PRIVATE_KEY = priv
            _PUBLIC_KEY_PEM = pub_bytes
            logger.info("Loaded existing release-signing keypair from %s", priv_path)
            return _PRIVATE_KEY, _PUBLIC_KEY_PEM

        # First-run generation
        logger.info("Generating new ECDSA-P256 release-signing keypair at %s", priv_path)
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_path.write_bytes(priv_bytes)
        pub_path.write_bytes(pub_bytes)
        try:
            # 0600 on Unix; no-op on Windows (NTFS ACL would be set by
            # an installer in real deployments).
            os.chmod(priv_path, 0o600)
        except Exception:
            pass

        _PRIVATE_KEY = priv
        _PUBLIC_KEY_PEM = pub_bytes
        return _PRIVATE_KEY, _PUBLIC_KEY_PEM


def sign_digest(digest_hex: str) -> str:
    """Sign a hex-encoded SHA-256 digest.

    Returns a base64-encoded ASN.1 DER signature. We sign the digest
    bytes directly (not the binary itself) so callers can produce the
    signature from the SHA-256 they already compute during upload,
    without re-hashing.
    """
    priv, _ = _load_or_generate()
    try:
        digest_bytes = bytes.fromhex(digest_hex)
    except ValueError as exc:
        raise ValueError(f"digest must be hex-encoded SHA-256: {exc}") from exc
    if len(digest_bytes) != 32:
        raise ValueError("digest must be 32 bytes (SHA-256)")
    # ECDSA.sign expects to hash the input itself, but we already have
    # the hash. Use Prehashed to skip the inner hashing.
    sig_der = priv.sign(digest_bytes, ec.ECDSA(hashes.SHA256(), deterministic_signing=False))
    return base64.b64encode(sig_der).decode("ascii")


def verify_digest(digest_hex: str, signature_b64: str) -> bool:
    """Verify a signature produced by ``sign_digest``.

    Mirrors what the agent's UpdaterService will do once the verify
    step is wired in. Returns True on a valid signature, False
    otherwise — never raises for a bad sig.
    """
    _, pub_bytes = _load_or_generate()
    pub = serialization.load_pem_public_key(pub_bytes)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    try:
        digest_bytes = bytes.fromhex(digest_hex)
        sig_der = base64.b64decode(signature_b64)
        pub.verify(sig_der, digest_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


#: Manifest format version. Bump when a field is added or its meaning changes,
#: so an agent can refuse a manifest it does not fully understand rather than
#: silently ignoring a field that carries security meaning.
RELEASE_MANIFEST_VERSION = 1

#: Fields bound by the signature, in canonical order.
_MANIFEST_FIELDS = ("agent_type", "channel", "digest", "platform", "v", "version")


def parse_agent_version(raw: str) -> tuple[int, ...]:
    """Parse a dotted agent version into a comparable tuple.

    This MUST stay byte-for-byte equivalent to the agent's
    ``UpdaterService._parse_version``. The two sides independently decide
    "is this newer", and when they disagree the update either loops
    (backend offers, agent refuses, agent re-downloads next poll) or is
    silently suppressed (backend refuses, agent would have accepted).

    Grammar, deliberately forgiving in the same way the agent is:
      * an optional leading ``v``/``V`` is ignored;
      * each dot-separated chunk contributes its leading digits, and parsing
        stops at the first chunk with no leading digit (so ``2.0.0-beta``
        reads as ``(2,)`` after trailing-zero normalisation, not an error);
      * INSIGNIFICANT TRAILING ZEROS are stripped, so ``1.0.0.0`` == ``1.0``;
      * at least one component is kept, so ``1.0.0`` does not normalise to ().

    An unparseable value yields ``()``, which compares lower than any real
    version -- it can never look newer.
    """
    parts: list[int] = []
    for chunk in str(raw or "").strip().lstrip("vV").split("."):
        piece = ""
        for ch in chunk:
            if ch.isdigit():
                piece += ch
            else:
                break
        if piece == "":
            break
        parts.append(int(piece))
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def build_release_manifest(
    *,
    digest_hex: str,
    version: str,
    platform: str,
    agent_type: str,
    channel: str,
) -> dict[str, Any]:
    """Assemble the release manifest that the signature will cover.

    Signing the bare digest was not enough. A backend that does NOT hold the
    private key could take a genuine older release -- its binary, its checksum
    and its stored signature -- and offer it as an update, optionally relabelled
    with an invented higher version, because nothing in the signed object said
    which version, platform, agent type or channel that digest belonged to.
    Verification passed and the agent installed a known-vulnerable build.

    Binding the metadata to the digest makes that impossible: the agent compares
    the SIGNED version against what it is running, not an unsigned envelope
    field.
    """
    if not digest_hex or len(digest_hex) != 64:
        raise ValueError("digest must be a hex-encoded SHA-256 (64 chars)")
    for name, value in (
        ("version", version),
        ("platform", platform),
        ("agent_type", agent_type),
        ("channel", channel),
    ):
        if not value or not str(value).strip():
            raise ValueError(f"{name} is required and must be non-empty")
    return {
        "v": RELEASE_MANIFEST_VERSION,
        "digest": digest_hex.lower(),
        "version": str(version),
        "platform": str(platform),
        "agent_type": str(agent_type),
        "channel": str(channel),
    }


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Serialise a manifest to the exact bytes that are signed and verified.

    Canonical form: sorted keys, no insignificant whitespace, UTF-8. Both sides
    MUST derive the bytes this way -- signing one serialisation and verifying
    another is the classic way a signature scheme silently stops meaning
    anything.
    """
    missing = [f for f in _MANIFEST_FIELDS if f not in manifest]
    if missing:
        raise ValueError(f"manifest is missing required field(s): {', '.join(missing)}")
    subset = {k: manifest[k] for k in _MANIFEST_FIELDS}
    return json.dumps(subset, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: dict[str, Any]) -> str:
    """Sign a release manifest. Returns base64 ASN.1 DER."""
    priv, _ = _load_or_generate()
    payload = canonical_manifest_bytes(manifest)
    sig = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode("ascii")


def verify_manifest(manifest: dict[str, Any], signature_b64: str) -> bool:
    """Verify a manifest signature. Never raises for a bad signature."""
    _, pub_bytes = _load_or_generate()
    try:
        pub = serialization.load_pem_public_key(pub_bytes)
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        payload = canonical_manifest_bytes(manifest)
        pub.verify(base64.b64decode(signature_b64), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def public_key_pem() -> bytes:
    """Return the PEM-encoded public key for distribution to agents."""
    _, pub_bytes = _load_or_generate()
    return pub_bytes
