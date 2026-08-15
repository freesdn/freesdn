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
import logging
import os
import threading
from pathlib import Path

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


def public_key_pem() -> bytes:
    """Return the PEM-encoded public key for distribution to agents."""
    _, pub_bytes = _load_or_generate()
    return pub_bytes
