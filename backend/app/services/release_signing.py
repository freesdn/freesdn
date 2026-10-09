# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""ECDSA-P256 agent-update signing with a persistent installation identity.

This local POSIX filesystem implementation preserves the legacy key filenames.
New files are exclusively created with private permissions; existing keys are
never overwritten or silently repaired. A valid surviving private key can recover
its public counterpart only when that matches any previously recorded identity.
Missing private material, unsafe permissions or a mismatched pair require explicit
operator recovery. The identity marker is not a substitute for backup or an HSM.

All cooperating backend processes lock the same directory inode. Key reads use
bounded regular-file descriptors without following links. Cryptographic identity
and filesystem policy are rechecked on each call rather than trusting stale cache.
This does not isolate malicious code running as the same OS user, qualify network
filesystems, or implement Windows ACL policy. It is not core-release provenance,
keyless signing, a transparency log, or an automatic key-rotation workflow.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_SIGNING_LOCK = threading.Lock()
# Retained for existing callers/tests that clear the old globals. These values
# never short-circuit current filesystem or identity validation.
_PRIVATE_KEY: ec.EllipticCurvePrivateKey | None = None
_PUBLIC_KEY_PEM: bytes | None = None
_PRIVATE_NAME = ".signing-key.pem"
_PUBLIC_NAME = ".public-key.pem"
_IDENTITY_NAME = ".signing-identity.sha256"
_KEY_BYTES_LIMIT = 4096
_LOCK_WAIT_SECONDS = 5.0


class SigningKeyError(RuntimeError):
    """Signing is unavailable; retain stored material for operator recovery."""


def _key_dir() -> Path:
    """Return the configured path without following links or creating it yet."""
    value = os.environ.get(
        "FREESDN_SIGNING_KEY_DIR",
        os.environ.get("FREESDN_AGENT_RELEASE_DIR", "/var/lib/freesdn/agent-releases"),
    )
    p = Path(value)
    if not p.is_absolute() or ".." in p.parts or len(p.parts) > 64 or len(value) > 4096:
        raise SigningKeyError("Signing directory must be a bounded absolute path")
    if len(p.parts) < 2:
        raise SigningKeyError("The filesystem root cannot be a signing directory")
    return p


def _open_directory(path: Path, *, create: bool, synchronize_parents: bool = False) -> int:
    """Walk by descriptor; synchronize parent entries on every creating walk.

    An existing child may survive a previous failed parent fsync in the running
    kernel. Its presence alone is not proof that its directory entry is durable.
    Retries must synchronize those parents too, before accepting any key identity.
    Unsupported directory synchronization refuses; it is not silently ignored.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    # A competing initializer may have created the component.
                    # The same no-follow open below still validates its type.
                    pass
                child = os.open(component, flags, dir_fd=fd)
            try:
                if create or synchronize_parents:
                    os.fsync(fd)
            except BaseException:
                # child was acquired before synchronization. It has not yet
                # become the walk's owner, so release it before propagating.
                os.close(child)
                raise
            previous, fd = fd, child
            os.close(previous)
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:
            raise SigningKeyError("Signing directory must be owned and not writable by others")
        if stat.S_IMODE(st.st_mode) & 0o700 != 0o700:
            raise SigningKeyError("Signing directory requires owner read, write and search")
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _check_file(st: os.stat_result, *, private: bool) -> None:
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid():
        raise SigningKeyError("Signing material must be an owned, singly linked regular file")
    mode = stat.S_IMODE(st.st_mode)
    forbidden = 0o177 if private else 0o133
    if not mode & 0o400 or mode & forbidden or mode & 0o7000:
        raise SigningKeyError("Signing material has unsafe permissions")


def _file_state(st: os.stat_result) -> tuple[int, ...]:
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_nlink,
        st.st_uid,
        st.st_gid,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )


def _read_file(
    directory: int, name: str, *, private: bool, maximum: int, synchronize: bool = False
) -> bytes | None:
    # O_NONBLOCK avoids blocking on a FIFO before fstat can refuse its type.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        _check_file(before, private=private)
        if not 0 < before.st_size <= maximum:
            raise SigningKeyError("Signing material has invalid size")
        parts = bytearray()
        while len(parts) <= maximum:
            block = os.read(fd, maximum + 1 - len(parts))
            if not block:
                break
            parts.extend(block)
        if synchronize:
            os.fsync(fd)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if len(parts) != before.st_size or len(parts) > maximum:
            raise SigningKeyError("Signing material changed or exceeded its size limit")
        if _file_state(before) != _file_state(after) or _file_state(after) != _file_state(current):
            raise SigningKeyError("Signing material changed while being read")
        return bytes(parts)
    finally:
        os.close(fd)


def _create_file(directory: int, name: str, data: bytes) -> None:
    """Publish without clobbering anything, retaining partial failures for recovery.

    Cooperating processes hold the directory lock while this file is incomplete.
    A crash/failed write can leave an invalid file; later calls refuse it. They never
    mistake an incomplete existing identity for permission to replace it. Successful
    return requires the contents and directory entry to be synchronized.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        initial = os.fstat(fd)
        _check_file(initial, private=True)
        pending = memoryview(data)
        while pending:
            written = os.write(fd, pending)
            if written <= 0:
                raise SigningKeyError("Signing material could not be written completely")
            pending = pending[written:]
        os.fsync(fd)
        completed = os.fstat(fd)
        _check_file(completed, private=True)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if completed.st_size != len(data) or _file_state(completed) != _file_state(current):
            raise SigningKeyError("Signing material changed during publication")
    finally:
        os.close(fd)
    os.fsync(directory)


def _single_pem(data: bytes, labels: tuple[bytes, ...]) -> None:
    stripped = data.strip()
    if data.count(b"-----BEGIN ") != 1 or data.count(b"-----END ") != 1:
        raise SigningKeyError("Signing material must contain exactly one PEM object")
    if not any(
        stripped.startswith(b"-----BEGIN " + label + b"-----")
        and stripped.endswith(b"-----END " + label + b"-----")
        for label in labels
    ):
        raise SigningKeyError("Signing material uses an unsupported PEM object")


def _private_from_bytes(data: bytes) -> ec.EllipticCurvePrivateKey:
    _single_pem(data, (b"PRIVATE KEY", b"EC PRIVATE KEY"))
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SigningKeyError("Agent signing requires an ECDSA P-256 private key")
    return key


def _validate_public(data: bytes, private: ec.EllipticCurvePrivateKey) -> None:
    _single_pem(data, (b"PUBLIC KEY",))
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SigningKeyError("Agent signing requires an ECDSA P-256 public key")
    if key.public_numbers() != private.public_key().public_numbers():
        raise SigningKeyError("Stored signing keys have different identities")


def _pair_under_lock(
    directory: int,
    *,
    expected_public_pem: bytes | None = None,
    intent_mode: str | None = None,
    expected_sha256: str | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    private_bytes = _read_file(directory, _PRIVATE_NAME, private=True, maximum=_KEY_BYTES_LIMIT)
    public_bytes = _read_file(directory, _PUBLIC_NAME, private=False, maximum=_KEY_BYTES_LIMIT)
    identity = _read_file(directory, _IDENTITY_NAME, private=True, maximum=65)
    if identity is not None:
        if (
            len(identity) != 65
            or identity[-1:] != b"\n"
            or any(c not in b"0123456789abcdef" for c in identity[:64])
        ):
            raise SigningKeyError("Stored signing identity marker is malformed")
    if intent_mode == "initialize":
        if any(value is not None for value in (private_bytes, public_bytes, identity)):
            raise SigningKeyError(
                "Initialization requires an empty key store; review existing identity"
            )
    elif intent_mode == "adopt":
        if private_bytes is None or public_bytes is None:
            raise SigningKeyError(
                "Adoption requires the existing private and exact public key files"
            )
        expected_public_pem = _validated_anchor(public_bytes, expected_sha256)
    elif intent_mode == "resume" and private_bytes is None:
        raise SigningKeyError(
            "Pending initialization has no private material; explicit cancellation/recovery required"
        )
    if private_bytes is None:
        if expected_public_pem is not None or public_bytes is not None or identity is not None:
            raise SigningKeyError("Signing private key is missing; restore the existing identity")
        private = ec.generate_private_key(ec.SECP256R1())
        private_bytes = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _create_file(directory, _PRIVATE_NAME, private_bytes)
    else:
        private = _private_from_bytes(private_bytes)
    recovered_public = public_bytes is None
    if public_bytes is None:
        public_bytes = (
            expected_public_pem
            if expected_public_pem is not None
            else private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    _validate_public(public_bytes, private)
    if expected_public_pem is not None and public_bytes != expected_public_pem:
        raise SigningKeyError("Stored signing keys do not match the trusted installation identity")
    fingerprint = hashlib.sha256(public_bytes).hexdigest().encode("ascii") + b"\n"
    if identity is not None and identity != fingerprint:
        raise SigningKeyError("Stored signing identity does not match the keypair")
    if identity is None:
        _create_file(directory, _IDENTITY_NAME, fingerprint)
    if recovered_public:
        _create_file(directory, _PUBLIC_NAME, public_bytes)
    # Existing raw public bytes are preserved: enrollment fingerprints those
    # bytes, so normalizing an imported PEM would itself alter the trusted pin.
    final_private = _read_file(
        directory, _PRIVATE_NAME, private=True, maximum=_KEY_BYTES_LIMIT, synchronize=True
    )
    final_public = _read_file(
        directory, _PUBLIC_NAME, private=False, maximum=_KEY_BYTES_LIMIT, synchronize=True
    )
    final_identity = _read_file(
        directory, _IDENTITY_NAME, private=True, maximum=65, synchronize=True
    )
    if (final_private, final_public, final_identity) != (private_bytes, public_bytes, fingerprint):
        raise SigningKeyError("Signing material changed during validation")
    # Also synchronize an existing pair on recovery, including any entry left
    # behind by a previous caller whose own fsync failed before acceptance.
    os.fsync(directory)
    return private, public_bytes


def _load_or_generate(
    *,
    expected_public_pem: bytes | None = None,
    intent_mode: str | None = None,
    expected_sha256: str | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Validate a current pair under local and interprocess locks, or refuse."""
    global _PRIVATE_KEY, _PUBLIC_KEY_PEM
    if os.name != "posix":
        raise SigningKeyError("This signer requires qualified POSIX filesystem key storage")
    import fcntl

    path = _key_dir()
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    if not _SIGNING_LOCK.acquire(timeout=_LOCK_WAIT_SECONDS):
        raise SigningKeyError("Signing key is busy; retry without replacing any material")
    directory = -1
    locked = False
    try:
        directory = _open_directory(
            path,
            create=(
                intent_mode == "initialize"
                if intent_mode is not None
                else expected_public_pem is None
            ),
            synchronize_parents=expected_public_pem is not None or intent_mode is not None,
        )
        while True:
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SigningKeyError(
                        "Signing key is busy; retry without replacing any material"
                    ) from None
                time.sleep(min(0.025, remaining))
        if time.monotonic() >= deadline:
            raise SigningKeyError("Signing key lock deadline elapsed")
        result = _pair_under_lock(
            directory,
            expected_public_pem=expected_public_pem,
            intent_mode=intent_mode,
            expected_sha256=expected_sha256,
        )
        check = _open_directory(path, create=False)
        try:
            original, current = os.fstat(directory), os.fstat(check)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                raise SigningKeyError("Signing directory changed during validation")
        finally:
            os.close(check)
        _PRIVATE_KEY, _PUBLIC_KEY_PEM = result
        return result
    except (OSError, ValueError, TypeError):
        raise SigningKeyError(
            "Signing material is unavailable or invalid; explicit recovery is required"
        ) from None
    finally:
        try:
            try:
                if locked:
                    fcntl.flock(directory, fcntl.LOCK_UN)
            finally:
                if directory >= 0:
                    os.close(directory)
        finally:
            _SIGNING_LOCK.release()


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


def _validated_anchor(anchor_public_pem: bytes, anchor_sha256: str | None) -> bytes:
    """Validate format and byte binding, not the authority of the supplied anchor.

    The coordinator must obtain both values from a separately authenticated,
    installation-wide trust record. Accepting caller-selected or local-file-derived
    values here would not establish an independent trust anchor.
    """
    if type(anchor_public_pem) is not bytes or not 0 < len(anchor_public_pem) <= _KEY_BYTES_LIMIT:
        raise SigningKeyError("Installation signing public key has invalid format or size")
    if (
        type(anchor_sha256) is not str
        or len(anchor_sha256) != 64
        or any(c not in "0123456789abcdef" for c in anchor_sha256)
    ):
        raise SigningKeyError("Installation signing fingerprint has invalid format")
    if not hmac.compare_digest(hashlib.sha256(anchor_public_pem).hexdigest(), anchor_sha256):
        raise SigningKeyError("Installation signing public key and fingerprint disagree")
    try:
        anchor_public_pem.decode("ascii")
        _single_pem(anchor_public_pem, (b"PUBLIC KEY",))
        key = serialization.load_pem_public_key(anchor_public_pem)
    except (TypeError, ValueError):
        raise SigningKeyError("Installation signing public key is invalid") from None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SigningKeyError("Installation signing requires an ECDSA P-256 public key")
    return anchor_public_pem


def public_key_for_anchor(*, anchor_public_pem: bytes, anchor_sha256: str) -> bytes:
    """Serve a validated independent anchor without touching private-key storage.

    Existing release verification can remain available during private-key loss.
    This function neither creates a key nor proves that signing is available.
    """
    return _validated_anchor(anchor_public_pem, anchor_sha256)


def check_signing_anchor(*, anchor_public_pem: bytes, anchor_sha256: str) -> bytes:
    """Validate current storage against the required raw trusted public bytes.

    Missing private material always refuses, even when the entire key store is
    empty. A surviving matching private key may recover a missing public file using
    the exact trusted bytes, preserving enrollment fingerprints including CRLF.
    """
    expected = _validated_anchor(anchor_public_pem, anchor_sha256)
    _, public = _load_or_generate(expected_public_pem=expected)
    return public


def sign_manifest_for_anchor(
    manifest: dict[str, Any],
    *,
    anchor_public_pem: bytes,
    anchor_sha256: str,
) -> str:
    """Sign only with the private key matching an independently trusted anchor.

    Ordinary asynchronous callers must supply the dedicated database anchor. The
    retained legacy helpers still permit explicit empty-store provisioning; they
    must not be used as fallbacks during rollout or recovery.
    """
    expected = _validated_anchor(anchor_public_pem, anchor_sha256)
    if type(manifest) is not dict:
        raise ValueError("Signing manifest must be a dictionary")
    try:
        frozen = {field: manifest[field] for field in _MANIFEST_FIELDS}
    except KeyError:
        raise ValueError("Signing manifest is incomplete") from None
    if type(frozen["v"]) is not int or frozen["v"] != RELEASE_MANIFEST_VERSION:
        raise ValueError("Signing manifest version is unsupported")
    if any(
        type(frozen[f]) is not str or not 1 <= len(frozen[f]) <= 1024
        for f in _MANIFEST_FIELDS
        if f != "v"
    ):
        raise ValueError("Signing manifest fields must be bounded strings")
    payload = canonical_manifest_bytes(frozen)
    if len(payload) > 4096:
        raise ValueError("Signing manifest exceeds its byte limit")
    private, _ = _load_or_generate(expected_public_pem=expected)
    signature = private.sign(payload, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def prepare_signing_identity(*, mode: str, expected_sha256: str | None = None) -> bytes:
    """Private coordinator-only storage modes; none establishes caller authority.

    The coordinator owns a durable pending intent and global operation lock before
    calling this. Only a newly inserted initialize intent receives initialize mode.
    A retry/resume never generates absent private material. Adoption requires exact
    existing public bytes matching the separately confirmed expected fingerprint.
    """
    if type(mode) is not str or mode not in {"initialize", "adopt", "resume"}:
        raise SigningKeyError("Signing lifecycle storage mode is invalid")
    if mode == "adopt":
        if (
            type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)
        ):
            raise SigningKeyError("Adoption requires a trusted expected fingerprint")
    elif expected_sha256 is not None:
        raise SigningKeyError("Unexpected fingerprint for initialization storage mode")
    _, public = _load_or_generate(intent_mode=mode, expected_sha256=expected_sha256)
    return public


def verify_manifest_for_anchor(
    manifest: dict[str, Any],
    signature_b64: str,
    *,
    anchor_public_pem: bytes,
    anchor_sha256: str,
) -> bool:
    """Bounded P-256 verification against trusted public bytes; no key-file I/O.

    Bad manifest/signature returns False. A malformed trust anchor raises
    SigningKeyError so missing installation trust is not relabeled a bad artifact.
    No signature is regenerated and no missing key or identity is initialized.
    """
    expected = _validated_anchor(anchor_public_pem, anchor_sha256)
    if type(manifest) is not dict or set(manifest) != set(_MANIFEST_FIELDS):
        return False
    if type(manifest["v"]) is not int or manifest["v"] != RELEASE_MANIFEST_VERSION:
        return False
    if any(
        type(manifest[f]) is not str or not 1 <= len(manifest[f]) <= 1024
        for f in _MANIFEST_FIELDS
        if f != "v"
    ):
        return False
    digest = manifest["digest"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return False
    if type(signature_b64) is not str or not 8 <= len(signature_b64) <= 128:
        return False
    payload = canonical_manifest_bytes(manifest)
    if len(payload) > 4096:
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        if (
            not 8 <= len(signature) <= 80
            or base64.b64encode(signature).decode("ascii") != signature_b64
        ):
            return False
        public = cast(ec.EllipticCurvePublicKey, serialization.load_pem_public_key(expected))
        public.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
