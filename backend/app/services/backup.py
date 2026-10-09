# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Backup Service
==============================

Enterprise-grade backup system with 7 storage backends, encryption,
scheduled backups, export/import, and restore functionality.

File format (.fsdn):
    [4 bytes: header length, big-endian]
    [N bytes: JSON header with backup_id, checksum, encrypted, compressed, created_at]
    [remaining: gzip-compressed, optionally Fernet-encrypted JSON payload]
"""

from __future__ import annotations

import base64
import contextlib
import ftplib
import gzip
import hashlib
import io
import json
import logging
import os
import posixpath
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import anyio.to_thread
from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_artifacts import (
    BackupArtifactError,
    make_identity,
    recorded_identity,
    verify_identity,
)
from app.core.backup_download_response import LocalDownloadSource
from app.core.backup_downloads import DownloadSnapshot
from app.core.backup_files import BackupFiles, BackupPublicationError
from app.core.owned_async import complete_before_cancellation
from app.core.remote_write_plan import RemotePublicationError, RemoteSavePlan
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES, escape_like, resolve_and_pin_host
from app.core.site_access import site_ids_for_request
from app.modules.backup.models import (
    Backup,
    BackupSchedule,
    BackupStatus,
    RestoreJob,
    StorageLocation,
)
from app.services.backup_transport import (
    StorageConfigurationError,
    StorageConfigurationView,
    ftps_connection,
    remote_path,
    sftp_connection,
    validate_policy,
)

logger = logging.getLogger(__name__)


class BackupInputError(ValueError):
    """An explicitly authored input diagnostic that is safe for the operator."""


class BackupRecoveryError(RuntimeError):
    """An explicitly authored recovery refusal, without provider details."""


def backup_failure_detail(error: Exception, fallback: str) -> str:
    """Never publish arbitrary provider, parser, database or plugin exceptions.

    A general ValueError is not proof that its text is safe: SDKs and parsers
    can include connection strings or decrypted input. Only our explicit
    diagnostic types carry reviewed operator messages.
    """
    if isinstance(error, (BackupInputError, BackupRecoveryError)):
        return str(error)
    return fallback


def _must_force_encryption(is_encrypted: bool, environment: str, allow_plaintext: bool) -> bool:
    """Fail-closed gate: True iff a plaintext backup request must be upgraded to
    encrypted. A backup carries decrypted secrets, so plaintext-at-rest is a leak;
    in production/staging we never honor a plaintext request unless the operator
    explicitly opted into the risk via BACKUP_ALLOW_PLAINTEXT."""
    return (not is_encrypted) and environment in ("production", "staging") and not allow_plaintext


def _bounded_gunzip(payload: bytes, limit: int = MAX_BACKUP_IMPORT_BYTES) -> bytes:
    """Decompress a gzip stream with a hard output-size ceiling.

    Plain gzip.decompress() inflates fully into RAM, so a high-ratio
    decompression bomb (a ~50 MB compressed stream can inflate to tens of GB)
    OOM-kills the worker. Decompress in chunks and abort once the output
    exceeds ``limit`` (backup import/restore). Mirrors the
    bounded pattern already used by the plugin loader.
    """
    import zlib

    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)  # 16 → gzip header
    out = bytearray()
    chunk = 1 << 20
    for i in range(0, len(payload), chunk):
        out += dec.decompress(payload[i : i + chunk], limit - len(out) + 1)
        if len(out) > limit:
            raise BackupInputError(
                f"Decompressed backup exceeds {limit // (1024 * 1024)} MB limit "
                "— refusing to inflate (possible decompression bomb)"
            )
    out += dec.flush()
    if len(out) > limit:
        raise BackupInputError("Decompressed backup exceeds size limit")
    return bytes(out)


# =============================================================================
# Encryption
# =============================================================================


# Controller secret config keys encrypted INDIVIDUALLY via encrypt_credential
# (see Controller.password / .client_secret). The vault export decrypts these into
# the passphrase-sealed payload; the vault restore re-encrypts them under the target
# instance's SECRET_KEY so the secret is portable + bound to the new instance.
CONTROLLER_SECRET_CONFIG_KEYS = ("password", "client_secret")

# Secret-bearing COLUMNS on core.credentials. Stored encrypted under the instance
# SECRET_KEY; decrypted into a `.fsdnvault` (which is sealed by the operator
# passphrase) and re-encrypted under the destination instance's key on restore.
CREDENTIAL_SECRET_FIELDS = (
    "encrypted_password",
    "api_key",
    "token",
    "ssh_private_key",
    "certificate",
    "snmp_community",
)


class BackupEncryption:
    """Fernet encryption with PBKDF2-derived keys and random per-backup salt.

    KEY DERIVATION (readiness): historical backups used
    PBKDF2-SHA256 at 100,000 iterations. OWASP 2025 raised the
    recommended minimum for PBKDF2-SHA256 to 600,000 — the prior
    iteration count made offline brute-force of stolen ``.fsdn``
    archives 6× easier than current guidance permits.

    Backwards-compatible upgrade via a versioned ``key_id`` string:

      - **v1 (legacy)**: ``key_id`` is the raw base64-encoded salt. The
        iteration count is implicit (100k) — what the historical code
        wrote. Decrypt-only.
      - **v2 (current)**: ``key_id`` is ``"v2:<iterations>:<base64-salt>"``.
        Iteration count is explicit so a future bump (e.g. 800k) can
        ship without breaking already-written archives. New encrypts
        always use v2 at the current default.

    Old backups in DB still decrypt because ``decrypt()`` parses the
    key_id format and picks the right iteration count. New backups
    use v2 at 600k and are not decryptable by callers stuck on the
    pre-bump implementation (one-way upgrade — acceptable: a backup
    is read forward in time, not backward).
    """

    # OWASP Cheat Sheet 2025: PBKDF2-SHA256 ≥ 600,000 iterations.
    PBKDF2_ITERATIONS = 600_000
    # Historical value used by archives written before the v2 format.
    _PBKDF2_ITERATIONS_LEGACY_V1 = 100_000
    # Ceiling on the iteration count a v2 key_id is allowed to DECLARE.
    #
    # The count is read out of the archive's own header, and on
    # ``POST /setup/restore`` that header is an UNAUTHENTICATED upload (the
    # endpoint is gated only by "no super_admin exists yet", is CSRF-exempt,
    # and the passphrase is a form field the uploader also supplies). Without
    # a ceiling, a ~100-byte file declaring ``v2:999999999:AAAA`` made PBKDF2
    # grind for minutes of straight CPU inside the async handler — past
    # GUNICORN_TIMEOUT, so the arbiter SIGKILLed the worker and took every
    # other in-flight request with it. int() has no upper bound, so the cost
    # was whatever integer the uploader typed.
    #
    # 2,000,000 keeps headroom for a future bump past 600k (and keeps the
    # already-written 1.2M archives in tests/services/test_backup_encryption.py
    # readable) while capping one derive at a fraction of a second.
    _PBKDF2_ITERATIONS_MAX = 2_000_000

    def __init__(self, master_key: str | None = None):
        from app.core.config import settings

        self.master_key = master_key or settings.SECRET_KEY

    def _derive_key(self, salt: bytes, iterations: int) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))

    @staticmethod
    def _parse_key_id(key_id: str) -> tuple[int, str]:
        """Return ``(iterations, base64_salt)`` for a v1 or v2 ``key_id``.

        v2 format:  ``v2:<iterations>:<base64-urlsafe-salt>``
        v1 (legacy): the raw base64-urlsafe salt (no prefix). The historical
        iteration count was a hard-coded 100,000.
        """
        if key_id.startswith("v2:"):
            parts = key_id.split(":", 2)
            if len(parts) != 3:
                raise BackupInputError("malformed v2 key_id (expected 'v2:<iter>:<salt>')")
            try:
                iterations = int(parts[1])
            except ValueError:
                raise BackupInputError("v2 key_id has non-numeric iteration count") from None
            # Reject before the KDF runs — see _PBKDF2_ITERATIONS_MAX. The
            # declared count is attacker-controlled on the unauthenticated
            # first-install restore, and every check that runs before this one
            # (checksum, "secrets", "encrypted", the passphrase) is supplied by
            # the same uploader, so this parser is the only chokepoint.
            lo = BackupEncryption._PBKDF2_ITERATIONS_LEGACY_V1
            hi = BackupEncryption._PBKDF2_ITERATIONS_MAX
            if not lo <= iterations <= hi:
                raise BackupInputError(
                    f"v2 key_id declares an unsupported iteration count "
                    f"({iterations}); accepted range is {lo:,}-{hi:,}"
                )
            return iterations, parts[2]
        # Legacy: bare base64-salt.
        return BackupEncryption._PBKDF2_ITERATIONS_LEGACY_V1, key_id

    def encrypt(self, data: bytes) -> tuple[bytes, str]:
        """Encrypt data → ``(ciphertext, key_id)`` in v2 format.

        ``key_id`` is ``"v2:<iterations>:<base64-salt>"`` so future
        iteration bumps don't break already-written archives.
        """
        from cryptography.fernet import Fernet

        salt = os.urandom(16)
        key = self._derive_key(salt, self.PBKDF2_ITERATIONS)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        salt_b64 = base64.urlsafe_b64encode(salt).decode()
        key_id = f"v2:{self.PBKDF2_ITERATIONS}:{salt_b64}"
        return encrypted, key_id

    def decrypt(self, encrypted_data: bytes, key_id: str) -> bytes:
        """Decrypt data using ``key_id``. Supports v1 (legacy bare salt
        at 100k iterations) and v2 (explicit iteration count)."""
        from cryptography.fernet import Fernet

        iterations, salt_b64 = self._parse_key_id(key_id)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        key = self._derive_key(salt, iterations)
        fernet = Fernet(key)
        return bytes(fernet.decrypt(encrypted_data))


# =============================================================================
# Sandboxed key directory (NOTE H6)
# =============================================================================
# SFTP private-key paths supplied through StorageLocation config are
# attacker-controlled (operator-supplied JSON) and Paramiko will happily
# read /etc/shadow if we let it. We constrain reads to a single sandboxed
# directory. If FREESDN_BACKUP_KEYS_DIR is not set we default to a path
# that won't exist by default (so the feature is opt-in by the deployer).
_BACKUP_KEYS_DIR = os.environ.get("FREESDN_BACKUP_KEYS_DIR", "/etc/freesdn/backup-keys")


def _validate_private_key_path(path: str) -> str:
    """NOTE H6: reject any path that escapes the sandboxed keys dir."""
    if not path:
        return path
    real = os.path.realpath(path)
    base = os.path.realpath(_BACKUP_KEYS_DIR)
    try:
        common = os.path.commonpath([real, base])
    except ValueError:
        # Different drives on Windows
        raise ValueError(f"private_key_path must reside under {_BACKUP_KEYS_DIR}")
    if common != base:
        raise ValueError(f"private_key_path must reside under {_BACKUP_KEYS_DIR}")
    return real


def _validate_endpoint_url(url: str | None) -> str | None:
    """NOTE H6 / block SSRF via endpoint_url pointing at internal hosts.

    Delegates to ``resolve_and_pin_host`` (DNS-resolving, rebinding-safe) so
    that a hostname that currently resolves to a public IP but can be rebinded
    to 127.0.0.1 / 169.254.169.254 is rejected consistently at every call site.
    Returns the ORIGINAL url (the resolved IP is only used for validation here;
    callers that need an IP-pinned URL rebuild it themselves — see
    S3StorageBackend and WebDAVStorageBackend).
    """
    if not url:
        return url
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"endpoint_url scheme must be http(s): {url}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"endpoint_url missing host: {url}")
    # resolve_and_pin_host blocks loopback / link-local / metadata / private
    # (allow_private=False) via DNS resolution — no TOCTOU.
    resolve_and_pin_host(host, allow_private=False)
    return url


def _ssrf_validate_storage_cfg(storage_type: str, cfg: dict[str, Any]) -> None:
    """validate the destination field(s) used by each
    storage backend type at create/update time (DNS-resolving, rebinding-safe).

    - webdav  → ``url``
    - s3      → ``endpoint_url`` (optional; only validated when present)
    - ftp / sftp → ``host``
    """
    st = (storage_type or "").lower()
    if st == "webdav":
        url_field = cfg.get("url")
        if url_field:
            _validate_endpoint_url(url_field)
    elif st == "s3":
        ep = cfg.get("endpoint_url")
        if ep:
            _validate_endpoint_url(ep)
    elif st in ("ftp", "sftp"):
        host = cfg.get("host")
        if host:
            resolve_and_pin_host(host, allow_private=False)
    elif st == "truenas":
        # Nothing to validate, and that is the point: this type accepts no
        # address at all. It names a controller that was vetted when it was
        # registered, so there is no operator-supplied hostname for an SSRF
        # check to bite on. Spelled out because an empty branch here would
        # otherwise read as an oversight -- and because the ftp/sftp rule above
        # (allow_private=False) would refuse every real NAS, which live on
        # private LANs.
        return


# =============================================================================
# Storage Backends
# =============================================================================


class StorageDeleteUnsupported(Exception):
    """A destination that cannot remove a stored file.

    Not every backend can. TrueNAS via its middleware writes, reads, sizes and
    stats a file but has no delete method on any version (verified live on
    26.0.0-BETA.3) -- so a backup written there stays until it is pruned on the
    appliance. A DISTINCT type lets the retention path tell "this destination
    never prunes" apart from "this delete failed", and refuse to orphan.
    """


class BackupStorageBackend(ABC):
    """Abstract base for all backup storage backends."""

    #: Whether this backend can acknowledge removal of a stored backup.
    #: Retention preserves the catalog when a provider cannot prune it.
    SUPPORTS_DELETE: bool = True

    @abstractmethod
    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        """Save data. Returns the storage path/URI."""

    @abstractmethod
    async def load(self, path: str) -> bytes:
        """Load data from path."""

    @abstractmethod
    async def delete(self, path: str) -> bool:
        """Acknowledge deletion (or confirmed absence); false is an unconfirmed failure."""

    @abstractmethod
    async def exists(self, path: str) -> bool:
        """Check if path exists."""

    @abstractmethod
    async def get_size(self, path: str) -> int:
        """Get file size in bytes."""

    def _date_prefix(self) -> str:
        now = datetime.now(UTC)
        return f"{now.year}/{now.month:02d}/{now.day:02d}"


class LocalStorageBackend(BackupStorageBackend):
    """Store backups on local filesystem."""

    def __init__(self, config: dict[str, Any]):
        self.base_path = Path(config.get("path", "/data/backups"))

    def _files(self) -> BackupFiles:
        return BackupFiles(self.base_path, MAX_BACKUP_IMPORT_BYTES)

    @complete_before_cancellation
    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        rel = f"{self._date_prefix()}/{backup_id}_{filename}"
        # Keep the owning coroutine alive through worker completion, including
        # direct task cancellation as well as framework cancellation scopes.
        return await anyio.to_thread.run_sync(self._files().save, rel, data)

    @complete_before_cancellation
    async def load(self, path: str) -> bytes:
        return await anyio.to_thread.run_sync(self._files().load, path)

    @complete_before_cancellation
    async def delete(self, path: str) -> bool:
        return await anyio.to_thread.run_sync(self._files().delete, path)

    @complete_before_cancellation
    async def exists(self, path: str) -> bool:
        return await anyio.to_thread.run_sync(self._files().exists, path)

    @complete_before_cancellation
    async def get_size(self, path: str) -> int:
        return await anyio.to_thread.run_sync(self._files().get_size, path)


class S3StorageBackend(BackupStorageBackend):
    """Store backups in S3 / S3-compatible storage."""

    def __init__(self, config: dict[str, Any]):
        from urllib.parse import urlparse, urlunparse

        import boto3
        from botocore.config import Config

        self.bucket = config["bucket"]
        self.prefix = config.get("path_prefix", "backups")
        kwargs: dict[str, Any] = {
            "region_name": config.get("region", "us-east-1"),
            # force path-style so boto3 does not rewrite netloc back
            # to a hostname-based form (virtual-hosted style would re-introduce
            # a second DNS lookup that bypasses our pin).
            "config": Config(s3={"addressing_style": "path"}),
        }
        # resolve_and_pin_host once at __init__ time and rebuild
        # endpoint_url from the returned IP literal so boto3 never performs
        # its own DNS lookup against the original hostname.
        # store the original hostname so botocore's
        # urllib3 HTTP session verifies TLS against the HOSTNAME cert (SNI),
        # not against the pinned IP literal in endpoint_url.
        raw_endpoint = config.get("endpoint_url")
        self._sni_hostname: str | None = None
        if raw_endpoint:
            _validate_endpoint_url(raw_endpoint)  # scheme + reachability check
            parsed_ep = urlparse(raw_endpoint)
            ep_host = parsed_ep.hostname or ""
            pinned_ip = resolve_and_pin_host(ep_host, allow_private=False)
            # Rebuild netloc with the IP literal (preserving port if present).
            port = parsed_ep.port
            if ":" in pinned_ip:
                # IPv6 literal must be bracketed in URLs.
                netloc_ip = f"[{pinned_ip}]:{port}" if port else f"[{pinned_ip}]"
            else:
                netloc_ip = f"{pinned_ip}:{port}" if port else pinned_ip
            pinned_endpoint = urlunparse(
                (
                    parsed_ep.scheme,
                    netloc_ip,
                    parsed_ep.path,
                    parsed_ep.params,
                    parsed_ep.query,
                    parsed_ep.fragment,
                )
            )
            kwargs["endpoint_url"] = pinned_endpoint
            # record the original hostname for SNI correction.
            # Only applies to HTTPS (HTTP needs no TLS SNI) and only when the
            # hostname was not already an IP literal (ep_host == pinned_ip means
            # the operator passed a raw IP → no SNI mismatch to fix).
            if parsed_ep.scheme == "https" and ep_host and ep_host != pinned_ip:
                self._sni_hostname = ep_host
        # Populate credentials before any client construction path.
        if config.get("access_key"):
            kwargs["aws_access_key_id"] = config["access_key"]
            kwargs["aws_secret_access_key"] = config.get("secret_key", "")
        # when scheme is HTTPS the endpoint_url hostname is
        # now an IP literal, which breaks TLS certificate verification against
        # hostname-signed certs.  Teach botocore's URLLib3Session to assert the
        # ORIGINAL hostname during TLS so SNI and cert verification both use
        # the right name.
        if (
            raw_endpoint and self._sni_hostname  # set above only when https + host ≠ ip
        ):
            try:
                from botocore.httpsession import URLLib3Session

                _sni_host = self._sni_hostname  # capture for closure

                class _SNIFixedSession(URLLib3Session):
                    """URLLib3Session that corrects TLS SNI for pinned-IP endpoints.

                    When endpoint_url is an IP literal (SSRF mitigation), urllib3
                    verifies the TLS cert against the IP rather than the original
                    hostname.  Inject ``assert_hostname`` on every HTTPS pool so
                    the cert is verified against the operator-configured hostname.
                    """

                    def send(self, request: Any) -> Any:  # type: ignore[override]
                        from urllib.parse import urlparse as _up

                        parsed_req = _up(request.url)
                        if parsed_req.scheme == "https":
                            try:
                                pool = self._pool_manager.connection_from_url(request.url)
                                pool.assert_hostname = _sni_host
                            except Exception:
                                pass
                        return super().send(request)

                import botocore.session as _bcs

                bc_session = _bcs.Session()
                bc_session.register_component("http_session", _SNIFixedSession())
                boto3_session = boto3.Session(botocore_session=bc_session)
                self.client = boto3_session.client("s3", **kwargs)
                return
            except Exception:
                logger.warning(
                    "S3StorageBackend: failed to install SNI-fix session "
                    "(botocore internals changed?); falling back to default session. "
                    "TLS cert verification may fail for hostname-signed certs."
                )
        self.client = boto3.client("s3", **kwargs)

    def _key(self, backup_id: str, filename: str) -> str:
        return f"{self.prefix}/{self._date_prefix()}/{backup_id}_{filename}"

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        key = self._key(backup_id, filename)
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)
        return f"s3://{self.bucket}/{key}"

    async def load(self, path: str) -> bytes:
        # path may be "s3://bucket/key" or just "key"
        if path.startswith("s3://"):
            _, _, key = path.partition(f"s3://{self.bucket}/")
        else:
            key = path
        resp = self.client.get_object(Bucket=self.bucket, Key=key)
        return bytes(resp["Body"].read())

    async def delete(self, path: str) -> bool:
        key = path.replace(f"s3://{self.bucket}/", "") if path.startswith("s3://") else path
        self.client.delete_object(Bucket=self.bucket, Key=key)
        return True

    async def exists(self, path: str) -> bool:
        key = path.replace(f"s3://{self.bucket}/", "") if path.startswith("s3://") else path
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    async def get_size(self, path: str) -> int:
        key = path.replace(f"s3://{self.bucket}/", "") if path.startswith("s3://") else path
        resp = self.client.head_object(Bucket=self.bucket, Key=key)
        return int(resp["ContentLength"])


class _RemoteFileStorageBackend(BackupStorageBackend):
    """One isolated connection per operation; blocking protocol I/O runs off-loop."""

    scheme: str
    default_port: int

    # A filesystem configuration worker remains owned through cancellation.
    _PREPARATION_ADMISSION = anyio.CapacityLimiter(2)
    _CONFIG_THREADS = anyio.CapacityLimiter(2)
    # Shared by direct SSH/FTPS operations across all backend instances in this
    # process. Callers retain ownership until protocol cleanup has finished.
    _OPERATION_ADMISSION = anyio.CapacityLimiter(2)
    _OPERATION_THREADS = anyio.CapacityLimiter(2)

    def __init__(self, config: dict[str, Any]):
        self.hostname = config["host"]
        pinned_ip = resolve_and_pin_host(self.hostname, allow_private=False)
        self._configure_endpoint(config, pinned_ip)

    @classmethod
    async def create_bounded(cls, config: dict[str, Any]):
        from copy import deepcopy
        from time import monotonic

        from app.services.vault_native_resolution import resolve_storage_host

        await anyio.lowlevel.checkpoint()
        try:
            cls._PREPARATION_ADMISSION.acquire_nowait()
        except anyio.WouldBlock:
            raise StorageConfigurationError(
                "Remote storage preparation is busy; retry later"
            ) from None
        started = monotonic()
        try:
            prepared = deepcopy(config)
            pinned_ip = await resolve_storage_host(prepared["host"], allow_private=False)
            await anyio.lowlevel.checkpoint()
            result = cls.__new__(cls)
            result.hostname = prepared["host"]
            await result._configure_owned(prepared, pinned_ip)
            await anyio.lowlevel.checkpoint()
            if monotonic() - started > 5.0:
                raise StorageConfigurationError(
                    "Remote storage preparation exceeded its acceptance deadline"
                )
            return result
        finally:
            cls._PREPARATION_ADMISSION.release()

    @complete_before_cancellation
    async def _configure_owned(self, config, pinned_ip):
        # SFTP path canonicalization can touch the filesystem. Drain this
        # worker before releasing admission, even when the caller is cancelled.
        # The acceptance deadline does not promise to kill blocked kernel I/O.
        await anyio.to_thread.run_sync(
            self._configure_endpoint, config, pinned_ip, limiter=self._CONFIG_THREADS
        )

    def _configure_endpoint(self, config: dict[str, Any], pinned_ip: str):
        self.host = pinned_ip
        self.port = int(config.get("port", self.default_port))
        if not 1 <= self.port <= 65535:
            raise StorageConfigurationError("Storage port must be between 1 and 65535.")
        self.username = config.get("username", "anonymous")
        self.password = config.get("password")
        self.remote_path = config.get("remote_path", "/backups").rstrip("/") or "/"
        # Validate the root using a synthetic child, without making a connection.
        self._path(self.remote_path.rstrip("/") + "/.validation")
        self.config = config

    def _path(self, path: str) -> str:
        return remote_path(path, self.remote_path, self.hostname, self.host, self.port)

    def _new_path(self, backup_id: str, filename: str) -> str:
        for component in (backup_id, filename):
            if not component or "/" in component or "\\" in component or component in {".", ".."}:
                raise StorageConfigurationError(
                    "Backup ID and filename must be single path segments."
                )
        return self._path(
            f"{self.remote_path.rstrip('/')}/{self._date_prefix()}/{backup_id}_{filename}"
        )

    def _url(self, path: str) -> str:
        authority = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{authority}:{self.port}{path}"

    async def _run_bounded(
        self, operation: str, path: str, data: bytes | None, *, temporary: str | None = None
    ) -> Any:
        # Each public caller is complete_before_cancellation-owned. Admission
        # must remain charged while its thread drains, including late failures.
        try:
            self._OPERATION_ADMISSION.acquire_nowait()
        except anyio.WouldBlock:
            raise StorageConfigurationError(
                "Remote backup operation capacity is busy; retry later"
            ) from None
        try:
            target = self._run if temporary is None else partial(self._run, temporary=temporary)
            authorize = getattr(self, "_probe_authorize", None)
            native_check = getattr(self, "_probe_native_check", None)

            def checked_target(operation, path, data):
                # The worker has acquired its real thread limiter before this
                # check. Never trust an earlier check across that handoff.
                if authorize is not None:
                    anyio.from_thread.run(authorize)
                if native_check is not None:
                    native_check()
                return target(operation, path, data)

            return await anyio.to_thread.run_sync(
                checked_target, operation, path, data, limiter=self._OPERATION_THREADS
            )
        finally:
            self._OPERATION_ADMISSION.release()

    def prepare_save(self, backup_id: str, data: bytes, filename: str) -> RemoteSavePlan:
        path = self._new_path(backup_id, filename)
        if type(data) is not bytes or not 0 < len(data) <= MAX_BACKUP_IMPORT_BYTES:
            raise StorageConfigurationError("Backup exceeds the remote transfer size limit.")
        operation = uuid4()
        temporary = path + ".partial-" + operation.hex
        return RemoteSavePlan(
            operation,
            path,
            temporary,
            self._url(path),
            self._url(temporary),
            hashlib.sha256(data).hexdigest(),
            len(data),
        )

    @complete_before_cancellation
    async def save_prepared(self, plan: RemoteSavePlan, data: bytes) -> str:
        if (
            type(plan) is not RemoteSavePlan
            or type(data) is not bytes
            or not 0 < len(data) <= MAX_BACKUP_IMPORT_BYTES
            or self._path(plan.path) != plan.path
            or plan.location != self._url(plan.path)
            or plan.temporary != plan.path + ".partial-" + plan.operation_id.hex
            or plan.temporary_location != self._url(plan.temporary)
            or plan.payload_size != len(data)
            or plan.payload_sha256 != hashlib.sha256(data).hexdigest()
        ):
            raise StorageConfigurationError("Remote write no longer matches its retained plan")
        await self._run_bounded("save", plan.path, data, temporary=plan.temporary)
        return plan.location

    @complete_before_cancellation
    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        # Standalone storage probes have no catalogue transaction. Application
        # backup creation reserves this exact plan before calling save_prepared.
        return await self.save_prepared(self.prepare_save(backup_id, data, filename), data)

    @complete_before_cancellation
    async def load(self, path: str) -> bytes:
        return await self._run_bounded("load", self._path(path), None)

    @complete_before_cancellation
    async def delete(self, path: str) -> bool:
        return await self._run_bounded("delete", self._path(path), None)

    @complete_before_cancellation
    async def exists(self, path: str) -> bool:
        return await self._run_bounded("exists", self._path(path), None)

    @complete_before_cancellation
    async def get_size(self, path: str) -> int:
        return await self._run_bounded("size", self._path(path), None)

    async def copy_download_into(
        self, path: str, expected: dict | None, snapshot: DownloadSnapshot
    ) -> None:
        from app.services.vault_remote_stream import copy_remote_into

        await copy_remote_into(self, path, expected, snapshot)

    @abstractmethod
    def _run(self, operation: str, path: str, data: bytes | None) -> Any:
        raise NotImplementedError


class SFTPStorageBackend(_RemoteFileStorageBackend):
    """SFTP with an operator-enrolled server fingerprint, checked before authentication."""

    scheme = "sftp"
    default_port = 22

    def _configure_endpoint(self, config: dict[str, Any], pinned_ip: str):
        super()._configure_endpoint(config, pinned_ip)
        raw_key = config.get("private_key_path")
        self.private_key_path = _validate_private_key_path(raw_key) if raw_key else None

    def _run(
        self, operation: str, path: str, data: bytes | None, *, temporary: str | None = None
    ) -> Any:
        mutation_attempted = False
        try:
            with sftp_connection(
                self.host,
                self.port,
                self.username,
                self.password,
                self.private_key_path,
                self.config.get("host_key_sha256"),
            ) as client:
                if operation == "save":
                    current = ""
                    for part in posixpath.dirname(path).strip("/").split("/"):
                        if not part:
                            continue
                        current += "/" + part
                        try:
                            client.stat(current)
                        except FileNotFoundError:
                            client.mkdir(current)
                    temporary = temporary or path + ".partial-" + uuid4().hex
                    mutation_attempted = True
                    try:
                        with client.open(temporary, "wb") as output:
                            output.write(data)
                        client.rename(temporary, path)
                    except BaseException:
                        # The complete or partial object may remain. Preserve
                        # recovery names; never reconnect or replay cleanup here.
                        raise
                    return None
                if operation == "load":
                    with client.open(path, "rb") as source:
                        payload = source.read(MAX_BACKUP_IMPORT_BYTES + 1)
                        if len(payload) > MAX_BACKUP_IMPORT_BYTES:
                            raise StorageConfigurationError("Remote backup exceeds the size limit.")
                        return payload
                try:
                    if operation == "delete":
                        client.remove(path)
                        return True
                    size = client.stat(path).st_size
                    return True if operation == "exists" else size
                except FileNotFoundError:
                    if operation == "delete":
                        return True  # the server specifically confirmed absence
                    if operation == "exists":
                        return False
                    raise
        except Exception as error:
            if operation == "save" and mutation_attempted:
                raise RemotePublicationError(self._url(path), self._url(temporary)) from error
            raise


class FTPStorageBackend(_RemoteFileStorageBackend):
    """Explicit FTPS only, with system CA trust and protected data connections."""

    scheme = "ftps"
    default_port = 21

    def _run(
        self, operation: str, path: str, data: bytes | None, *, temporary: str | None = None
    ) -> Any:
        mutation_attempted = False
        try:
            with ftps_connection(
                self.hostname,
                self.host,
                self.port,
                self.username,
                self.password or "",
                self.config.get("use_tls"),
            ) as client:
                if operation == "save":
                    current = ""
                    for part in posixpath.dirname(path).strip("/").split("/"):
                        if not part:
                            continue
                        current += "/" + part
                        try:
                            client.cwd(current)
                        except ftplib.error_perm:
                            client.mkd(current)
                    temporary = temporary or path + ".partial-" + uuid4().hex
                    mutation_attempted = True
                    try:
                        client.storbinary(f"STOR {temporary}", io.BytesIO(data))
                        client.rename(temporary, path)
                    except BaseException:
                        # The complete or partial object may remain. Preserve
                        # recovery names; never reconnect or replay cleanup here.
                        raise
                    return None
                if operation == "load":
                    buf = io.BytesIO()

                    def receive(chunk: bytes) -> None:
                        if buf.tell() + len(chunk) > MAX_BACKUP_IMPORT_BYTES:
                            raise StorageConfigurationError("Remote backup exceeds the size limit.")
                        buf.write(chunk)

                    client.retrbinary(f"RETR {path}", receive)
                    return buf.getvalue()
                if operation == "delete":
                    client.delete(path)
                    return True
                client.voidcmd("TYPE I")
                # FTP 550 conflates missing files with permission errors. Never turn
                # it into a false 'missing' or a successful connectivity result.
                size = client.size(path)
                if size is None:
                    raise StorageConfigurationError("FTPS server did not return a file size.")
                return True if operation == "exists" else size
        except Exception as error:
            if operation == "save" and mutation_attempted:
                raise RemotePublicationError(self._url(path), self._url(temporary)) from error
            raise


class GoogleDriveStorageBackend(BackupStorageBackend):
    """Store backups in Google Drive."""

    def __init__(self, config: dict[str, Any]):
        self.folder_id = config.get("folder_id")
        self.credentials_json = config.get("credentials_json")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.access_token = config.get("access_token")
        self.refresh_token = config.get("refresh_token")
        self._service = None

    def _get_service(self) -> Any:
        if self._service:
            return self._service
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        if self.credentials_json:
            creds_data = (
                json.loads(self.credentials_json)
                if isinstance(self.credentials_json, str)
                else self.credentials_json
            )
            creds = service_account.Credentials.from_service_account_info(
                creds_data,
                scopes=["https://www.googleapis.com/auth/drive.file"],
            )
        else:
            from google.oauth2.credentials import Credentials

            creds = Credentials(
                token=self.access_token,
                refresh_token=self.refresh_token,
                client_id=self.client_id,
                client_secret=self.client_secret,
                token_uri="https://oauth2.googleapis.com/token",
            )
        self._service = build("drive", "v3", credentials=creds)
        return self._service

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        from googleapiclient.http import MediaInMemoryUpload

        service = self._get_service()
        fname = f"{backup_id}_{filename}"
        metadata: dict[str, Any] = {"name": fname, "mimeType": "application/octet-stream"}
        if self.folder_id:
            metadata["parents"] = [self.folder_id]
        media = MediaInMemoryUpload(data, mimetype="application/octet-stream")
        f = service.files().create(body=metadata, media_body=media, fields="id").execute()  # noqa: E501
        return f"gdrive://{f['id']}"

    async def load(self, path: str) -> bytes:
        service = self._get_service()
        file_id = path.replace("gdrive://", "")
        request = service.files().get_media(fileId=file_id)
        buf = io.BytesIO()
        from googleapiclient.http import MediaIoBaseDownload

        downloader = MediaIoBaseDownload(buf, request)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        return buf.getvalue()

    async def delete(self, path: str) -> bool:
        service = self._get_service()
        file_id = path.replace("gdrive://", "")
        service.files().delete(fileId=file_id).execute()
        return True

    async def exists(self, path: str) -> bool:
        try:
            service = self._get_service()
            file_id = path.replace("gdrive://", "")
            service.files().get(fileId=file_id, fields="id").execute()
            return True
        except Exception:
            return False

    async def get_size(self, path: str) -> int:
        service = self._get_service()
        file_id = path.replace("gdrive://", "")
        f = service.files().get(fileId=file_id, fields="size").execute()
        return int(f.get("size", 0))


class DropboxStorageBackend(BackupStorageBackend):
    """Store backups in Dropbox."""

    def __init__(self, config: dict[str, Any]):
        import dropbox as dbx

        self.folder_path = config.get("folder_path", "/freesdn-backups")
        access_token = config.get("access_token")
        refresh_token = config.get("refresh_token")
        app_key = config.get("app_key")
        app_secret = config.get("app_secret")

        if refresh_token and app_key:
            self.dbx = dbx.Dropbox(
                oauth2_refresh_token=refresh_token,
                app_key=app_key,
                app_secret=app_secret or "",
            )
        else:
            self.dbx = dbx.Dropbox(access_token)

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        import dropbox as dbx

        path = f"{self.folder_path}/{self._date_prefix()}/{backup_id}_{filename}"
        self.dbx.files_upload(data, path, mode=dbx.files.WriteMode.overwrite)
        return f"dropbox://{path}"

    async def load(self, path: str) -> bytes:
        remote = path.replace("dropbox://", "")
        _, resp = self.dbx.files_download(remote)
        return bytes(resp.content)

    async def delete(self, path: str) -> bool:
        remote = path.replace("dropbox://", "")
        self.dbx.files_delete_v2(remote)
        return True

    async def exists(self, path: str) -> bool:
        try:
            remote = path.replace("dropbox://", "")
            self.dbx.files_get_metadata(remote)
            return True
        except Exception:
            return False

    async def get_size(self, path: str) -> int:
        remote = path.replace("dropbox://", "")
        meta = self.dbx.files_get_metadata(remote)
        return getattr(meta, "size", 0)


class WebDAVStorageBackend(BackupStorageBackend):
    """Store backups via WebDAV with an independently owned client per operation."""

    _METADATA_LIMIT = 256 * 1024
    _CHUNK_BYTES = 64 * 1024
    _OPERATION_SECONDS = 60.0

    def __init__(self, config: dict[str, Any]):
        # Preserve the existing synchronous factory while callers migrate to
        # create_bounded(). Its two historical resolution calls remain explicit.
        raw_url, parsed_raw = self._parse_endpoint(config)
        _validate_endpoint_url(raw_url)
        pinned_ip = resolve_and_pin_host(parsed_raw.hostname or "", allow_private=False)
        self._configure_endpoint(config, parsed_raw, pinned_ip)

    @classmethod
    def _parse_endpoint(cls, config: dict[str, Any]):
        from urllib.parse import urlsplit

        raw_url = (config["url"] or "").rstrip("/")
        cls._check_url_text(raw_url)
        parsed_raw = urlsplit(raw_url)
        if parsed_raw.username is not None or parsed_raw.password is not None:
            raise ValueError("WebDAV endpoint credentials must use the credential fields")
        return raw_url, parsed_raw

    @classmethod
    async def create_bounded(cls, config: dict[str, Any]):
        from copy import deepcopy

        from app.services.vault_native_resolution import resolve_storage_host

        # Pin the exact copied configuration; a wait cannot adopt caller changes.
        prepared = deepcopy(config)
        _, parsed_raw = cls._parse_endpoint(prepared)
        if parsed_raw.scheme not in ("http", "https") or not parsed_raw.hostname:
            raise ValueError("WebDAV endpoint must have an http(s) scheme and hostname")
        pinned_ip = await resolve_storage_host(parsed_raw.hostname or "", allow_private=False)
        await anyio.lowlevel.checkpoint()
        result = cls.__new__(cls)
        result._configure_endpoint(prepared, parsed_raw, pinned_ip)
        return result

    def _configure_endpoint(self, config, parsed_raw, pinned_ip):
        from urllib.parse import quote, urlunsplit

        import httpx

        raw_host = parsed_raw.hostname or ""
        # Store original hostname for Host header injection.
        self._orig_hostname = raw_host
        port = parsed_raw.port
        if port == 0:
            raise ValueError("Invalid WebDAV endpoint port")
        self._port = port or (443 if parsed_raw.scheme == "https" else 80)
        self._pinned_ip = pinned_ip
        self._base_path = self._checked_path(parsed_raw.path)
        self.path_prefix = self._checked_path(config.get("path", "/backups"))
        self._storage_root = self._base_path + self.path_prefix
        if ":" in pinned_ip:
            netloc_ip = f"[{pinned_ip}]:{port}" if port else f"[{pinned_ip}]"
        else:
            netloc_ip = f"{pinned_ip}:{port}" if port else pinned_ip
        self._origin = urlunsplit((parsed_raw.scheme, netloc_ip, "", "", ""))
        self.base_url = urlunsplit(
            (
                parsed_raw.scheme,
                netloc_ip,
                quote(self._base_path, safe="/"),
                "",
                "",
            )
        ).rstrip("/")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        auth = httpx.BasicAuth(self.username, self.password) if self.username else None
        # Inject Host header so HTTP vhost routing works against the original
        # hostname while the TCP connection goes to the pinned IP.
        default_port = 443 if parsed_raw.scheme == "https" else 80
        routing_host = f"[{raw_host}]" if ":" in raw_host else raw_host
        host_header = routing_host if port in (None, default_port) else f"{routing_host}:{port}"
        # Constructing a backend must not allocate an unowned network client.
        # Operations reuse their own client for related requests and close it
        # before returning; independent concurrent operations share no pool.
        self._client_options = {
            "auth": auth,
            "timeout": 60.0,
            "headers": {"Host": host_header, "Accept-Encoding": "identity"},
            "follow_redirects": False,
        }
        self._closed = False
        # preserve the original hostname for TLS SNI so
        # httpcore verifies the certificate against the hostname (not the
        # pinned IP).  ``sni_hostname`` is passed per-request via extensions
        # (httpx/httpcore API) only when the scheme is HTTPS.
        self._sni_extensions: dict[str, Any] = (
            {"sni_hostname": raw_host} if parsed_raw.scheme == "https" and raw_host else {}
        )

    @staticmethod
    def _check_url_text(value: str) -> None:
        # urllib strips some controls before parsing; refuse them first.
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Invalid WebDAV locator")
        if any(c in value for c in ("\\", "?", "#")) or value != value.strip():
            raise ValueError("Ambiguous WebDAV locator")

    @classmethod
    def _checked_path(cls, value: str) -> str:
        """Decode once, reject ambiguous segments, then encode for transport."""
        import re
        from urllib.parse import unquote

        cls._check_url_text(value)
        if value and not value.startswith("/"):
            raise ValueError("WebDAV paths must begin with a slash")
        if re.search(r"%(?![0-9a-fA-F]{2})|%2[fF]|%5[cC]", value):
            raise ValueError("Ambiguous WebDAV path encoding")
        try:
            decoded = unquote(value, errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError("Invalid WebDAV path encoding") from error
        cls._check_url_text(decoded)
        if "//" in decoded or ";" in decoded or re.search(r"%[0-9a-fA-F]{2}", decoded):
            raise ValueError("Ambiguous WebDAV path")
        if any(part in (".", "..") for part in decoded.split("/")):
            raise ValueError("WebDAV path traversal is not allowed")
        return decoded.rstrip("/")

    def _url(self, path: str) -> str:
        from urllib.parse import quote

        return self._origin + quote(self._base_path + self._checked_path(path), safe="/")

    def _object_url(self, locator: str) -> str:
        """A stored locator identifies an object, never a new destination."""
        from ipaddress import ip_address
        from urllib.parse import quote, urlsplit

        self._check_url_text(locator)
        parsed = urlsplit(locator)
        if parsed.path.endswith("/"):
            raise ValueError("WebDAV backup locators must identify a file")
        if parsed.scheme:
            if parsed.scheme != "webdav" or not parsed.netloc:
                raise ValueError("Unsupported WebDAV locator")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("WebDAV locators cannot contain credentials")

            def normalized_host(host: str) -> str:
                try:
                    return str(ip_address(host))
                except ValueError:
                    return host.encode("idna").decode("ascii").lower()

            allowed = {normalized_host(self._orig_hostname), normalized_host(self._pinned_ip)}
            if normalized_host(parsed.hostname or "") not in allowed:
                raise ValueError("WebDAV locator does not match the configured destination")
            default_port = 443 if self._origin.startswith("https:") else 80
            locator_port = parsed.port if parsed.port is not None else default_port
            if locator_port != self._port:
                raise ValueError("WebDAV locator does not match the configured port")
            path = self._checked_path(parsed.path)
        else:
            if parsed.netloc:
                raise ValueError("WebDAV locators cannot replace the configured authority")
            path = self._base_path + self._checked_path(parsed.path)
        if not path.startswith(self._storage_root + "/"):
            raise ValueError("WebDAV locator is outside the configured backup root")
        # Legacy webdav:// records contain no scheme. Preserve the configured
        # scheme and current pin, with the configured Host header and TLS SNI.
        return self._origin + quote(path, safe="/")

    @staticmethod
    async def _close_client(client: Any) -> None:
        import asyncio

        # Cleanup admission cannot have a cancellable checkpoint: the client
        # already exists. Keep the close task owned under repeated cancellation.
        cancelled = None
        with anyio.CancelScope(shield=True):

            async def capture() -> Exception | None:
                try:
                    await client.aclose()
                except Exception as error:
                    return error
                return None

            cleanup = asyncio.create_task(capture())
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError as error:
                    if cleanup.cancelled():
                        raise
                    cancelled = error
            error = cleanup.result()
            if error is not None:
                logger.error("WebDAV client cleanup ended with %s", type(error).__name__)
        if cancelled is not None:
            raise cancelled from None
        # An outer AnyIO cancellation was shielded during close. Recheck only
        # after the physical resources are closed, before delivering any result.
        await anyio.lowlevel.checkpoint_if_cancelled()
        if error is not None:
            raise BackupRecoveryError("WebDAV client cleanup failed") from None

    @contextlib.asynccontextmanager
    async def _session(self):
        import httpx

        if self._closed:
            raise ValueError("WebDAV backend is closed")
        deadline = time.monotonic() + self._OPERATION_SECONDS
        client = httpx.AsyncClient(**self._client_options)
        try:
            # A slow peer must not extend the operation indefinitely by sending
            # a byte before each per-read timeout. Mandatory close is outside
            # this scope and remains owned when that deadline cancels I/O.
            with anyio.fail_after(max(0.0, deadline - time.monotonic())):
                yield client
        finally:
            await self._close_client(client)
        if time.monotonic() >= deadline:
            raise TimeoutError("WebDAV operation deadline exceeded")

    @classmethod
    async def _iter_bounded(cls, response: Any, limit: int) -> AsyncIterator[bytes]:
        """Bound transport and decoded output before each bounded handoff."""
        import zlib

        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in {"", "identity", "gzip"}:
            raise ValueError("Unsupported WebDAV content encoding")
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
        encoded_limit = limit + max(cls._CHUNK_BYTES, limit // 100 + 64)
        encoded_bytes = 0
        decoded_bytes = 0

        def account(data: bytes) -> bytes:
            nonlocal decoded_bytes
            if len(data) > limit - decoded_bytes:
                raise ValueError("WebDAV response exceeds the size limit")
            decoded_bytes += len(data)
            return data

        try:
            async for chunk in response.aiter_raw(chunk_size=cls._CHUNK_BYTES):
                encoded_bytes += len(chunk)
                if encoded_bytes > encoded_limit:
                    raise ValueError("WebDAV encoded response exceeds the size limit")
                if decoder is None:
                    yield account(chunk)
                    continue
                pending = chunk
                while pending:
                    decoded = account(
                        decoder.decompress(
                            pending, min(cls._CHUNK_BYTES, limit - decoded_bytes + 1)
                        )
                    )
                    pending = decoder.unconsumed_tail
                    if decoder.unused_data:
                        raise ValueError("WebDAV gzip response has trailing data")
                    if decoded:
                        yield decoded
            if decoder is not None and not decoder.eof:
                raise ValueError("WebDAV gzip response is incomplete")
        except zlib.error as error:
            raise ValueError("Invalid WebDAV gzip response") from error

    @classmethod
    async def _read_bounded(cls, response: Any, limit: int) -> bytes:
        """Materialize only callers that still explicitly require bounded bytes."""
        result = bytearray()
        async for chunk in cls._iter_bounded(response, limit):
            result.extend(chunk)
        return bytes(result)

    @staticmethod
    @complete_before_cancellation
    async def _append_download_owned(snapshot: DownloadSnapshot, chunk: bytes) -> None:
        await anyio.to_thread.run_sync(snapshot.append, chunk)

    @staticmethod
    @complete_before_cancellation
    async def _seal_download_owned(
        snapshot: DownloadSnapshot, expected: dict[str, Any] | None
    ) -> None:
        await anyio.to_thread.run_sync(snapshot.seal, expected)

    async def copy_download_into(
        self, path: str, expected: dict[str, Any] | None, snapshot: DownloadSnapshot
    ) -> None:
        """Fill an already-owned disk snapshot without materializing the archive."""
        url = self._object_url(path)
        async with self._session() as client:
            async with client.stream("GET", url, extensions=self._sni_extensions) as response:
                self._require_status(response, {200})
                async for chunk in self._iter_bounded(
                    response, min(MAX_BACKUP_IMPORT_BYTES, snapshot.limit)
                ):
                    await self._append_download_owned(snapshot, chunk)
        # The real network client is closed before disk readback verification.
        # The response owner retains the snapshot through every failure path.
        await self._seal_download_owned(snapshot, expected)

    @staticmethod
    def _require_status(response: Any, accepted: set[int]) -> None:
        response.raise_for_status()
        if response.status_code not in accepted:
            raise ValueError("Unexpected WebDAV response status")

    async def _ensure_dirs(self, client: Any, path: str) -> None:
        parts = path.strip("/").split("/")
        current = ""
        for part in parts:
            current += f"/{part}"
            async with client.stream(
                "MKCOL", self._url(current), extensions=self._sni_extensions
            ) as response:
                # WebDAV uses 405 for a collection which already exists. The
                # following PUT still has to independently acknowledge success.
                if response.status_code != 405:
                    self._require_status(response, {201})

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        from urllib.parse import quote

        for component in (backup_id, filename):
            if not component or "/" in component or "/" in self._checked_path("/" + component)[1:]:
                raise ValueError("WebDAV backup names must be single path components")
        if len(data) > MAX_BACKUP_IMPORT_BYTES:
            raise ValueError("WebDAV backup exceeds the size limit")
        rel = f"{quote(self.path_prefix, safe='/')}/{self._date_prefix()}/{backup_id}_{filename}"
        url = self._object_url(rel)  # Validate before MKCOL or PUT can occur.
        async with self._session() as client:
            await self._ensure_dirs(client, str(Path(rel).parent))
            async with client.stream(
                "PUT", url, content=data, extensions=self._sni_extensions
            ) as response:
                self._require_status(response, {200, 201, 204})
        return f"webdav://{url.split('://', 1)[-1]}"

    async def load(self, path: str) -> bytes:
        url = self._object_url(path)
        async with self._session() as client:
            async with client.stream("GET", url, extensions=self._sni_extensions) as response:
                self._require_status(response, {200})
                return await self._read_bounded(response, MAX_BACKUP_IMPORT_BYTES)

    async def delete(self, path: str) -> bool:
        url = self._object_url(path)
        async with self._session() as client:
            async with client.stream("DELETE", url, extensions=self._sni_extensions) as response:
                if response.status_code == 404:
                    return True  # Backend contract: already absent is complete.
                self._require_status(response, {200, 204})
                return True

    @staticmethod
    def _metadata_status(element: Any) -> int:
        import re

        if element is None or len(element):
            raise ValueError("WebDAV metadata status must be a scalar value")
        text = element.text if element is not None else None
        match = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?", (text or "").strip())
        if match is None:
            raise ValueError("Invalid WebDAV metadata status")
        return int(match.group(1))

    def _metadata_href(self, href: str, expected_url: str) -> None:
        from urllib.parse import quote, urlsplit

        self._check_url_text(href)
        parsed = urlsplit(href)
        if parsed.path.endswith("/"):
            raise ValueError("WebDAV metadata must describe the requested file")
        if parsed.scheme:
            if parsed.scheme != urlsplit(self._origin).scheme:
                raise ValueError("WebDAV metadata has a different origin")
            resolved = self._object_url("webdav" + href[len(parsed.scheme) :])
        else:
            if parsed.netloc or not parsed.path.startswith("/"):
                raise ValueError("Invalid WebDAV metadata reference")
            resolved = self._origin + quote(self._checked_path(parsed.path), safe="/")
        if resolved != expected_url:
            raise ValueError("WebDAV metadata does not match the requested file")

    async def _file_size(self, path: str) -> int | None:
        from app.core.xml_utils import parse_untrusted_xml

        url = self._object_url(path)
        body = (
            b'<d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/>'
            b"<d:resourcetype/></d:prop></d:propfind>"
        )
        async with self._session() as client:
            async with client.stream(
                "PROPFIND",
                url,
                content=body,
                headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
                extensions=self._sni_extensions,
            ) as response:
                if response.status_code == 404:
                    return None
                self._require_status(response, {207})
                payload = await self._read_bounded(response, self._METADATA_LIMIT)
        root = parse_untrusted_xml(payload, max_bytes=self._METADATA_LIMIT)
        namespace = "{DAV:}"
        entries = root.findall(namespace + "response")
        if root.tag != namespace + "multistatus" or len(entries) != 1:
            raise ValueError("Ambiguous WebDAV metadata response")
        entry = entries[0]
        hrefs = entry.findall(namespace + "href")
        if len(hrefs) != 1 or len(hrefs[0]) or not hrefs[0].text:
            raise ValueError("Invalid WebDAV metadata reference")
        self._metadata_href(hrefs[0].text, url)
        statuses = entry.findall(namespace + "status")
        propstats = entry.findall(namespace + "propstat")
        if statuses:
            if len(statuses) != 1 or propstats or self._metadata_status(statuses[0]) != 404:
                raise ValueError("WebDAV metadata did not confirm the file")
            return None
        sizes = []
        for propstat in propstats:
            statuses = propstat.findall(namespace + "status")
            properties = propstat.findall(namespace + "prop")
            if len(statuses) != 1 or len(properties) != 1:
                raise ValueError("Malformed WebDAV file properties")
            code = self._metadata_status(statuses[0])
            prop = properties[0]
            lengths = prop.findall(namespace + "getcontentlength")
            if prop.find(namespace + "resourcetype/" + namespace + "collection") is not None:
                raise ValueError("WebDAV metadata describes a collection")
            if lengths:
                if code != 200 or len(lengths) != 1 or len(lengths[0]):
                    raise ValueError("WebDAV file size is unavailable or ambiguous")
                text = lengths[0].text or ""
                if not text.isascii() or not text.isdecimal() or len(text) > 19:
                    raise ValueError("Invalid WebDAV file size")
                size = int(text)
                if size > 2**63 - 1:
                    raise ValueError("WebDAV file size exceeds the supported range")
                sizes.append(size)
        if len(sizes) != 1:
            raise ValueError("WebDAV metadata lacks an unambiguous file size")
        return sizes[0]

    async def exists(self, path: str) -> bool:
        return await self._file_size(path) is not None

    async def get_size(self, path: str) -> int:
        size = await self._file_size(path)
        if size is None:
            raise FileNotFoundError("WebDAV backup does not exist")
        return size

    async def close(self) -> None:
        """Disallow new work; in-flight operations retain their own cleanup."""
        self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


# =============================================================================
# Storage Factory
# =============================================================================


class TrueNASStorageBackend(BackupStorageBackend):
    """Store backups on a TrueNAS appliance FreeSDN already manages.

    The gap this closes: FreeSDN could show an operator their NAS in detail --
    pool health, disk SMART, scrub state, snapshot coverage -- and then offer
    them Dropbox and Google Drive as backup destinations. Not the appliance in
    the same rack that it already holds working credentials for.

    **Configured by controller, not by host.** Every other remote backend takes
    a hostname and its own credentials. This one takes a ``controller_id``: the
    appliance is already registered, already authenticated, and already
    org-scoped, so asking the operator to retype its address and API key would
    duplicate a secret for no benefit and create a second thing to rotate.

    It also sidesteps a real conflict. ``_ssrf_validate_storage_cfg`` pins
    ftp/sftp hosts with ``allow_private=False``, because an operator-supplied
    hostname is an SSRF vector. A NAS lives on a private LAN, so that rule
    would refuse every legitimate TrueNAS. Referencing a controller means the
    destination was vetted when it was added, and no new address is accepted
    here at all.

    WS-only, by refusal rather than by silence: a legacy appliance answering on
    REST can still be monitored, but cannot be a backup destination, and the
    operator learns that when they configure it instead of when they restore.
    """

    def __init__(self, config: dict[str, Any]):
        raw_id = config.get("controller_id")
        if not raw_id:
            raise ValueError("TrueNAS backup storage requires a controller_id")
        try:
            self.controller_id = UUID(str(raw_id))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"controller_id is not a UUID: {raw_id!r}") from exc

        self.dataset_path = str(config.get("dataset_path") or "").strip()
        if not self.dataset_path:
            raise ValueError("TrueNAS backup storage requires a dataset_path")

        # Threaded through by _resolve_storage, which has already checked that
        # the StorageLocation belongs to the caller's org. Without it the
        # controller lookup below would accept ANY controller id an operator
        # could put in a config blob -- org A backing up into org B's
        # appliance, using org B's stored credentials. That is the same defect
        # V3 found on storage_location_id itself.
        self._organization_id = config.get("_organization_id")

    async def _adapter(self) -> Any:
        from sqlalchemy import select

        from app.db.session import AsyncSessionLocal
        from app.models.core import Controller, Site
        from app.services.adapter_truenas_storage import build_truenas_adapter

        # Controller ownership is on Site, never Controller.organization_id.
        # Require the caller's org before a database lookup or network access.
        try:
            organization_id = UUID(str(self._organization_id))
        except (TypeError, ValueError, AttributeError):
            raise ValueError(f"TrueNAS controller {self.controller_id} not found") from None

        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    select(Controller, Site.organization_id)
                    .join(Site, Site.id == Controller.site_id)
                    .where(
                        Controller.id == self.controller_id,
                        Controller.deleted_at.is_(None),
                        Controller.is_active.is_(True),
                        Controller.controller_type == "truenas",
                        Site.deleted_at.is_(None),
                        Site.organization_id == organization_id,
                    )
                )
            ).one_or_none()
            if row is None:
                raise ValueError(f"TrueNAS controller {self.controller_id} not found")
            ctrl, site_organization_id = row
            if site_organization_id != organization_id:
                # Keep every refusal indistinguishable from an absent target.
                raise ValueError(f"TrueNAS controller {self.controller_id} not found")
        # The controller's connection fields are loaded by the scoped query.
        # Do not keep a database session open across appliance network I/O.
        return await build_truenas_adapter(ctrl)

    #: Delete works again -- via ``pool.dataset.delete``, not a file unlink.
    #: The middleware has no file-delete on any version (verified live on
    #: 26.0.0-BETA.3), so each backup is its own child dataset and pruning a
    #: backup destroys its dataset. Validated end-to-end against a real box.
    SUPPORTS_DELETE = True

    def _child_mount(self, backup_id: str) -> str:
        """``/mnt/<base>/<safe-id>`` -- the auto-mount of this backup's dataset."""
        base = self.dataset_path
        if not base.startswith("/mnt/"):
            base = "/mnt/" + base.strip("/")
        token = "".join(c for c in str(backup_id) if c.isalnum() or c in "-_")
        if not token:
            raise ValueError(f"backup id yields no safe dataset segment: {backup_id!r}")
        return f"{base.rstrip('/')}/{token}"

    def _split_key(self, key: str) -> tuple[str, str]:
        """A storage key is ``<safe-id>/<filename>``. Returns (id, filename)."""
        segment, _, filename = key.partition("/")
        if not segment or not filename:
            raise ValueError(f"malformed TrueNAS storage key: {key!r}")
        return segment, filename

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        # One dataset per backup, so it can be pruned by destroying the dataset.
        token = "".join(c for c in str(backup_id) if c.isalnum() or c in "-_")
        key = f"{token}/{filename}"
        adapter = await self._adapter()
        try:
            await adapter.ensure_backup_dataset(
                base_dataset_path=self.dataset_path, backup_id=backup_id
            )
            await adapter.put_data_file(
                dataset_path=self._child_mount(backup_id), filename=filename, blob=data
            )
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()
        return key

    async def load(self, path: str) -> bytes:
        backup_id, filename = self._split_key(path)
        adapter = await self._adapter()
        try:
            return await adapter.get_data_file(
                dataset_path=self._child_mount(backup_id), filename=filename
            )
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

    async def delete(self, path: str) -> bool:
        # Destroys the backup's dataset -- the only recursive delete in the
        # storage code. The adapter rebuilds the target name from the validated
        # base plus a single sanitised id token, so it can never escape the
        # operator-nominated backup dataset.
        backup_id, _ = self._split_key(path)
        adapter = await self._adapter()
        try:
            return await adapter.remove_backup_dataset(
                base_dataset_path=self.dataset_path, backup_id=backup_id
            )
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

    async def exists(self, path: str) -> bool:
        backup_id, filename = self._split_key(path)
        adapter = await self._adapter()
        try:
            return (
                await adapter.stat_data_file(
                    dataset_path=self._child_mount(backup_id), filename=filename
                )
            ) is not None
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()

    async def get_size(self, path: str) -> int:
        backup_id, filename = self._split_key(path)
        adapter = await self._adapter()
        try:
            row = await adapter.stat_data_file(
                dataset_path=self._child_mount(backup_id), filename=filename
            )
        finally:
            with contextlib.suppress(Exception):
                await adapter.disconnect()
        if not row:
            return 0
        return int(row.get("size") or 0)


def get_storage_backend(storage_type: str, config: dict[str, Any]) -> BackupStorageBackend:
    """Factory to create a storage backend instance."""
    backends = {
        "local": LocalStorageBackend,
        "nfs": LocalStorageBackend,  # NFS mounts appear as local paths
        "s3": S3StorageBackend,
        "sftp": SFTPStorageBackend,
        "ftp": FTPStorageBackend,
        "google_drive": GoogleDriveStorageBackend,
        "dropbox": DropboxStorageBackend,
        "webdav": WebDAVStorageBackend,
        "truenas": TrueNASStorageBackend,
    }
    cls = backends.get(storage_type)
    if not cls:
        raise ValueError(f"Unsupported storage type: {storage_type}")
    return cls(config)  # type: ignore[abstract]


# =============================================================================
# Supported Storage Types Definition
# =============================================================================

SUPPORTED_STORAGE_TYPES = [
    {
        "id": "local",
        "name": "Local Storage",
        "description": "Store backups on the server's local filesystem",
        "icon": "HardDrive",
        "fields": [
            {
                "name": "path",
                "type": "text",
                "label": "Storage Path",
                "required": False,
                "default": "/data/backups",
                "placeholder": "/data/backups",
            },
        ],
    },
    {
        "id": "s3",
        "name": "Amazon S3 / S3-Compatible",
        "description": "Store backups in S3 or S3-compatible storage (MinIO, etc.)",
        "icon": "Cloud",
        "fields": [
            {
                "name": "bucket",
                "type": "text",
                "label": "Bucket Name",
                "required": True,
                "placeholder": "my-backups",
            },
            {
                "name": "region",
                "type": "text",
                "label": "Region",
                "required": False,
                "default": "us-east-1",
                "placeholder": "us-east-1",
            },
            {
                "name": "endpoint_url",
                "type": "text",
                "label": "Endpoint URL (for S3-compatible)",
                "required": False,
                "placeholder": "https://s3.example.com",
            },
            {
                "name": "access_key",
                "type": "text",
                "label": "Access Key",
                "required": True,
                "placeholder": "AKIA...",
            },
            {
                "name": "secret_key",
                "type": "password",
                "label": "Secret Key",
                "required": True,
                "placeholder": "",
            },
            {
                "name": "path_prefix",
                "type": "text",
                "label": "Path Prefix",
                "required": False,
                "default": "backups",
                "placeholder": "backups",
            },
        ],
    },
    {
        "id": "sftp",
        "name": "SFTP",
        "description": "Store backups on a remote server via SFTP",
        "icon": "Server",
        "fields": [
            {
                "name": "host_key_sha256",
                "type": "text",
                "label": "Trusted server fingerprint (obtain from server administrator)",
                "required": True,
                "placeholder": "SHA256:...",
            },
            {
                "name": "host",
                "type": "text",
                "label": "Host",
                "required": True,
                "placeholder": "sftp.example.com",
            },
            {
                "name": "port",
                "type": "number",
                "label": "Port",
                "required": False,
                "default": "22",
                "placeholder": "22",
            },
            {
                "name": "username",
                "type": "text",
                "label": "Username",
                "required": True,
                "placeholder": "backup-user",
            },
            {
                "name": "password",
                "type": "password",
                "label": "Password",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "private_key_path",
                "type": "text",
                "label": "Private Key Path",
                "required": False,
                "placeholder": "/path/to/key",
            },
            {
                "name": "remote_path",
                "type": "text",
                "label": "Remote Path",
                "required": False,
                "default": "/backups",
                "placeholder": "/backups",
            },
        ],
    },
    {
        "id": "ftp",
        "name": "FTPS (TLS required)",
        "description": "Authenticated TLS for control and data; plaintext FTP is disabled",
        "icon": "FolderSync",
        "fields": [
            {
                "name": "host",
                "type": "text",
                "label": "Host",
                "required": True,
                "placeholder": "ftp.example.com",
            },
            {
                "name": "port",
                "type": "number",
                "label": "Port",
                "required": False,
                "default": "21",
                "placeholder": "21",
            },
            {
                "name": "username",
                "type": "text",
                "label": "Username",
                "required": True,
                "placeholder": "backup-user",
            },
            {
                "name": "password",
                "type": "password",
                "label": "Password",
                "required": True,
                "placeholder": "",
            },
            {
                "name": "remote_path",
                "type": "text",
                "label": "Remote Path",
                "required": False,
                "default": "/backups",
                "placeholder": "/backups",
            },
            {
                "name": "use_tls",
                "type": "boolean",
                "label": "TLS required (trusted server certificate)",
                "required": True,
                "default": "true",
            },
        ],
    },
    {
        "id": "google_drive",
        "name": "Google Drive",
        "description": "Store backups in Google Drive",
        "icon": "CloudCog",
        "fields": [
            {
                "name": "credentials_json",
                "type": "textarea",
                "label": "Service Account JSON",
                "required": False,
                "placeholder": "Paste the downloaded service account key JSON here",
            },
            {
                "name": "folder_id",
                "type": "text",
                "label": "Folder ID",
                "required": False,
                "placeholder": "1abc...xyz",
            },
            {
                "name": "client_id",
                "type": "text",
                "label": "OAuth Client ID",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "client_secret",
                "type": "password",
                "label": "OAuth Client Secret",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "refresh_token",
                "type": "password",
                "label": "OAuth Refresh Token",
                "required": False,
                "placeholder": "",
            },
        ],
    },
    {
        "id": "dropbox",
        "name": "Dropbox",
        "description": "Store backups in Dropbox",
        "icon": "Box",
        "fields": [
            {
                "name": "access_token",
                "type": "password",
                "label": "Access Token",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "refresh_token",
                "type": "password",
                "label": "Refresh Token",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "app_key",
                "type": "text",
                "label": "App Key",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "app_secret",
                "type": "password",
                "label": "App Secret",
                "required": False,
                "placeholder": "",
            },
            {
                "name": "folder_path",
                "type": "text",
                "label": "Folder Path",
                "required": False,
                "default": "/freesdn-backups",
                "placeholder": "/freesdn-backups",
            },
        ],
    },
    {
        "id": "truenas",
        "name": "TrueNAS (managed appliance)",
        "description": (
            "Store backups on a TrueNAS appliance FreeSDN already manages. Uses the "
            "controller's existing credentials -- nothing to retype, nothing extra to "
            "rotate. Requires SCALE 25.04+ (the WS JSON-RPC API). Each backup is "
            "stored as its own child dataset under the path you choose, so "
            "retention prunes it by destroying that dataset -- clean, and you get "
            "per-backup ZFS visibility as a side effect."
        ),
        "supports_delete": True,
        "icon": "Server",
        "fields": [
            {
                "name": "controller_id",
                "type": "controller",
                "controller_type": "truenas",
                "label": "TrueNAS Appliance",
                "required": True,
                "placeholder": "Select a managed TrueNAS",
            },
            {
                "name": "dataset_path",
                "type": "text",
                "label": "Dataset Path",
                "required": True,
                "default": "/mnt/tank/freesdn-backups",
                "placeholder": "/mnt/tank/freesdn-backups",
            },
        ],
    },
    {
        "id": "webdav",
        "name": "WebDAV",
        "description": "Store backups via WebDAV (Nextcloud, ownCloud, etc.)",
        "icon": "Globe",
        "fields": [
            {
                "name": "url",
                "type": "text",
                "label": "WebDAV URL",
                "required": True,
                "placeholder": "https://nextcloud.example.com/remote.php/dav/files/user/",
            },
            {
                "name": "username",
                "type": "text",
                "label": "Username",
                "required": True,
                "placeholder": "admin",
            },
            {
                "name": "password",
                "type": "password",
                "label": "Password",
                "required": True,
                "placeholder": "",
            },
            {
                "name": "path",
                "type": "text",
                "label": "Path",
                "required": False,
                "default": "/backups",
                "placeholder": "/backups",
            },
        ],
    },
]


# =============================================================================
# Backup Service
# =============================================================================


class BackupService:
    """Main backup service — data collection, backup/restore, storage, stats."""

    # Enterprise chapter (Phase 2b): once the first BackupService is
    # instantiated, ensure the global contributor registry knows about
    # the CoreBackupContributor + has walked the module registry for
    # any module-provided contributors. ``_contributors_initialized`` is
    # a class-level guard so the initialization is idempotent (every
    # subsequent BackupService instance reuses the populated registry).
    _contributors_initialized: bool = False

    def __init__(self, db: AsyncSession):
        self.db = db
        self.encryption = BackupEncryption()
        # NOTE H2/H3/H4: org_id is set by callers that need to scope data
        # collection / restoration. Without it, collect_backup_data refuses
        # to run (fail-closed) because it would otherwise leak every org.
        self.org_id: UUID | None = None
        # Contributors dropped by the last _assemble_backup_archive because
        # their collect() raised — surfaced on Backup.error_message so an
        # incomplete archive is not presented to the operator as a clean one.
        self._collect_omissions: list[str] = []
        # Ensure the contributor registry is populated. Idempotent —
        # subsequent instances re-enter ``_ensure_contributors_registered``
        # but it short-circuits on the class-level guard. This pattern
        # avoids forcing every test fixture + lifespan hook to remember
        # to bootstrap the registry separately.
        type(self)._ensure_contributors_registered()

    @classmethod
    def _ensure_contributors_registered(cls) -> None:
        """Register the CoreBackupContributor + run module-driven
        discovery if not already done. Idempotent.

        The CORE contributor is registered explicitly (not via the
        module discovery hook) because the "core" data set crosses
        module boundaries — sites + users + organizations are owned
        by ``core``, controllers + devices are owned by ``network``,
        automation rules are owned by the automation module. No
        single module owns it, so it cannot be exposed via
        ``BaseModule.get_backup_contributor()``.
        """
        if cls._contributors_initialized:
            return
        from app.services.backup_contributors import (
            CoreBackupContributor,
            get_registry,
        )

        registry = get_registry()
        if "core" not in registry:
            registry.register(CoreBackupContributor())
        # Module-provided contributors (VoIP, Cameras, Firewall — landing
        # in Phases 3-5) get picked up automatically once their modules
        # are loaded. discover_from_modules is idempotent so calling it
        # here every first-instance is safe.
        registry.discover_from_modules()
        cls._contributors_initialized = True

    async def _assemble_backup_archive(
        self,
        *,
        backup_id: UUID,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> Any:
        """Run every registered contributor's ``collect()`` in dependency
        order and assemble the result into a v2.0 ``BackupArchive``.

        Per-contributor independence: if any contributor's ``collect()``
        raises, the contributor is omitted from the manifest with a
        warning logged, and the rest continue. The alternative —
        aborting the entire backup on one module's failure — would
        force operators to disable broken modules just to take a
        backup of the others, which we deliberately avoid.

        Args:
          backup_id: The new Backup.id (already assigned via flush).
          organization_id: Tenant scope.
          options: Operator-supplied flags from the new-backup dialog
            (site_id, device_ids, include_* booleans). Passed through
            to each contributor's ``collect()`` — contributors that
            don't understand a key ignore it.
        """
        from app.core.config import settings
        from app.services.backup_contributors import (
            BackupArchive,
            BackupManifest,
            ContributorEntry,
            get_registry,
        )

        registry = get_registry()
        manifest_entries: list[ContributorEntry] = []
        contributor_data: dict[str, dict[str, Any]] = {}
        # Contributors whose collect() blew up. Read by create_backup, which
        # stamps them onto Backup.error_message: omitting a module from the
        # archive while marking the row COMPLETED and logging the reason to a
        # file nobody reads is how a broken module produces a backup that
        # reports success and quietly has no VoIP/camera/firewall data in it.
        self._collect_omissions = []

        for contrib in registry.topological_order():
            try:
                payload = await contrib.collect(
                    self.db,
                    organization_id,
                    options,
                )
            except Exception as exc:
                logger.warning(
                    "Contributor %s collection failed (%s)",
                    contrib.contributor_id,
                    type(exc).__name__,
                )
                self._collect_omissions.append(f"{contrib.contributor_id} ({type(exc).__name__})")
                if options.get("include_secrets"):
                    # A disaster-recovery vault must not seal a silently partial
                    # account/module set. Refuse before writing any archive, with
                    # a fixed diagnostic rather than a contributor exception.
                    raise BackupRecoveryError(
                        "Full vault collection failed; no archive was stored. "
                        "Repair the failing collector and retry the backup."
                    ) from None
                continue

            contributor_data[contrib.contributor_id] = payload.data
            manifest_entries.append(
                ContributorEntry(
                    id=contrib.contributor_id,
                    schema_version=payload.schema_version,
                    counts=payload.counts,
                    metadata=payload.metadata,
                ),
            )

        if options.get("include_secrets") and "core" not in contributor_data:
            raise BackupRecoveryError(
                "Full vault collection requires the core collector; no archive was stored. "
                "Restore the core collector and retry the backup."
            )

        manifest = BackupManifest(
            backup_id=str(backup_id),
            created_at=datetime.now(UTC),
            organization_id=str(organization_id),
            source_version=getattr(settings, "APP_VERSION", None),
            # ``source_instance_id`` is forensic provenance — useful
            # for distinguishing "did this backup come from prod or
            # staging?" Not enforced here; emitted as None until a
            # future commit wires a stable instance id (uuid stored
            # in the platform's settings table on first boot).
            source_instance_id=None,
            contributors=manifest_entries,
        )

        return BackupArchive(
            manifest=manifest,
            contributors=contributor_data,
        )

    async def _dispatch_restore_via_contributors(
        self,
        archive: Any,
        *,
        organization_id: UUID,
        dry_run: bool,
        restore_options: dict[str, Any],
        selected_contributors: list[str] | None = None,
    ) -> dict[str, Any]:
        """Walk the registry in topological order and dispatch each
        contributor's payload to its ``restore()``.

        Per-module independence: each contributor's restore runs in its
        OWN SAVEPOINT (``begin_nested``). If one contributor fails, its
        savepoint rolls back, the failure is recorded in the per-module
        report, and the next contributor proceeds — the operator's
        choice during scope review (matches UniFi / Cisco DNA's
        behavior).

        Schema compatibility: each manifest entry's schema_version is
        checked against the live contributor's via ``is_compatible``.
        Cross-major mismatches skip that contributor with
        ``status="schema_mismatch"`` unless the contributor implements
        ``MigratingContributor.migrate_from`` (which can convert the
        old payload to the current schema).

        Returns:
          ``{"contributors": [<per-contributor RestoreResult-as-dict>, ...],
             "summary": {"total_created": N, "total_updated": N,
                         "total_skipped": N, "total_errors": N}}``

          Designed to populate RestoreJob.dry_run_report (dry runs) or
          RestoreJob.restore_log (real runs) — the existing operator-
          visible report shape is preserved.
        """
        from app.services.backup_contributors import (
            ContributorPayload,
            MigratingContributor,
            RestoreResult,
            describe_mismatch,
            get_registry,
            is_compatible,
        )

        registry = get_registry()
        results: list[RestoreResult] = []

        # Selective restore (enterprise backup v2): None = restore every
        # contributor in the archive; a list = restore only those ids.
        # Normalized to a set for O(1) membership; None short-circuits.
        selected = set(selected_contributors) if selected_contributors else None

        # Build a quick lookup of manifest entries by contributor id.
        manifest_by_id = {entry.id: entry for entry in archive.manifest.contributors}

        for contrib in registry.topological_order():
            cid = contrib.contributor_id

            # Operator deselected this contributor — record + skip. Still
            # appears in the report so the UI shows it was intentionally
            # left out (distinct from "missing" = not in the archive).
            if selected is not None and cid not in selected:
                results.append(RestoreResult(contributor_id=cid, status="skipped"))
                continue

            entry = manifest_by_id.get(cid)

            if entry is None:
                # The backup does NOT include data for this contributor.
                # That's expected for backups taken before a module was
                # installed, or for backups where the operator
                # explicitly excluded the contributor at collect time.
                # Not an error — just a per-contributor "missing".
                results.append(RestoreResult(contributor_id=cid, status="missing"))
                continue

            # Schema compatibility check. If incompatible major and the
            # contributor supports migration, try it; otherwise refuse.
            payload_data = archive.contributors.get(cid, {})
            payload = ContributorPayload(
                schema_version=entry.schema_version,
                counts=entry.counts,
                data=payload_data,
                metadata=entry.metadata,
            )
            if not is_compatible(entry.schema_version, contrib.schema_version):
                migrated: ContributorPayload | None = None
                if isinstance(contrib, MigratingContributor):
                    try:
                        migrated = contrib.migrate_from(
                            entry.schema_version,
                            payload,
                        )
                    except Exception as exc:
                        logger.warning(
                            "Contributor %s migration failed (%s)",
                            cid,
                            type(exc).__name__,
                        )
                if migrated is None:
                    results.append(
                        RestoreResult(
                            contributor_id=cid,
                            status="schema_mismatch",
                            errors=[
                                describe_mismatch(
                                    entry.schema_version,
                                    contrib.schema_version,
                                )
                            ],
                        )
                    )
                    continue
                payload = migrated

            # Per-module savepoint. If the contributor raises mid-restore
            # or returns status=error, its writes roll back independently
            # of the others. The caller's outer transaction continues to
            # hold the RestoreJob row updates.
            try:
                if dry_run:
                    result = await contrib.restore(
                        self.db,
                        organization_id,
                        payload,
                        dry_run=True,
                        options=restore_options,
                    )
                else:
                    async with self.db.begin_nested() as transaction:
                        result = await contrib.restore(
                            self.db,
                            organization_id,
                            payload,
                            dry_run=False,
                            options=restore_options,
                        )
                        if result.status == "error":
                            # Contributors may report a caught Python failure
                            # without raising through this context manager.
                            # Explicitly undo their pending/flushed writes.
                            await transaction.rollback()
                            skipped = dict(result.skipped)
                            for counts in (result.created, result.updated):
                                for resource, count in counts.items():
                                    skipped[resource] = skipped.get(resource, 0) + count
                            result.created = {}
                            result.updated = {}
                            result.skipped = skipped
            except Exception as exc:
                logger.warning(
                    "Contributor %s restore failed (%s); rolling back savepoint",
                    cid,
                    type(exc).__name__,
                )
                result = RestoreResult(
                    contributor_id=cid,
                    status="error",
                    errors=["Contributor restore failed; review module availability and retry."],
                )

            results.append(result)

        # Archive sections this instance has NO contributor for.
        #
        # The loop above walks the LIVE registry and looks each id up in the
        # manifest, so it can only ever see the "registry has it, archive
        # doesn't" direction (status="missing"). The reverse was invisible: an
        # archive section whose module isn't loaded here was never visited,
        # never counted and never named. That is reachable in normal
        # operation — ModuleLoader.load_all_modules deliberately logs-and-
        # continues on a module load failure, so a module that fails on_load()
        # leaves the app "degraded but running" and its contributor silently
        # gone. The operator rebuilt from a .fsdnvault, lost their VoIP
        # extensions / cameras / firewall rules, and got total_errors: 0,
        # contributors_failed: 0 and a green "completed" job.
        #
        # preview_backup_manifest already computes exactly this check
        # (restorable=False, "is the module installed?"); the restore path
        # never got it, and restore_fresh_instance_from_vault — the documented
        # bare-metal recovery — runs no preview at all.
        #
        # Reported as status="error" rather than a new status string so the
        # counts below, the RestoreJob's items_failed, and the UI's existing
        # per-contributor renderer all treat it as the failure it is. The
        # per-resource counts ride in ``skipped`` so ``total_skipped`` (→
        # RestoreJob.items_failed) reflects the records left on the floor.
        live_ids = {c.contributor_id for c in registry.topological_order()}
        for entry in archive.manifest.contributors:
            if entry.id in live_ids:
                continue
            if selected is not None and entry.id not in selected:
                results.append(RestoreResult(contributor_id=entry.id, status="skipped"))
                continue
            results.append(
                RestoreResult(
                    contributor_id=entry.id,
                    status="error",
                    skipped=dict(entry.counts),
                    errors=[
                        f"no '{entry.id}' contributor registered in this instance "
                        f"(is the module installed?) — its "
                        f"{sum(entry.counts.values())} record(s) were NOT restored"
                    ],
                )
            )

        # Aggregate the per-module results into the existing operator-
        # visible report shape so callers (validate_restore, the UI's
        # restore-job detail page) don't need to change their consumers.
        per_contributor_dicts = [
            {
                "contributor_id": r.contributor_id,
                "status": r.status,
                "created": r.created,
                "updated": r.updated,
                "skipped": r.skipped,
                "errors": r.errors,
                "warnings": r.warnings,
                "duration_sec": r.duration_sec,
            }
            for r in results
        ]
        summary = {
            "total_created": sum(sum(r.created.values()) for r in results),
            "total_updated": sum(sum(r.updated.values()) for r in results),
            "total_skipped": sum(sum(r.skipped.values()) for r in results),
            "total_errors": sum(len(r.errors) for r in results),
            "contributors_ok": sum(1 for r in results if r.status in ("ok", "dry_run_ok")),
            "contributors_failed": sum(
                1 for r in results if r.status in ("error", "schema_mismatch")
            ),
        }
        return {"contributors": per_contributor_dicts, "summary": summary}

    def _scoped_backup_select(self, organization_id: UUID) -> Any:
        # NOTE C4: backups now carry a direct organization_id. The previous
        # implementation tried to infer org membership from joins on
        # site → user → schedule, which was both fragile and bypass-prone
        # (e.g. a backup with no site/schedule/created_by leaked everywhere).
        return select(Backup).where(Backup.organization_id == organization_id)

    async def get_backup_for_organization(
        self,
        backup_id: UUID,
        organization_id: UUID,
    ) -> Backup | None:
        result = await self.db.execute(
            select(Backup).where(
                Backup.id == backup_id,
                Backup.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_restore_job_for_organization(
        self,
        job_id: UUID,
        organization_id: UUID,
    ) -> RestoreJob | None:
        # NOTE C4: restore jobs inherit their org-scope from the parent
        # Backup row.
        result = await self.db.execute(
            select(RestoreJob)
            .join(Backup, RestoreJob.backup_id == Backup.id)
            .where(
                RestoreJob.id == job_id,
                Backup.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    def _scoped_schedule_select(self, organization_id: UUID) -> Any:
        # NOTE C4: schedules already carry organization_id directly.
        # The legacy site-join lookup is redundant.
        return select(BackupSchedule).where(BackupSchedule.organization_id == organization_id)

    async def get_schedule_for_organization(
        self,
        schedule_id: UUID,
        organization_id: UUID,
    ) -> BackupSchedule | None:
        result = await self.db.execute(
            self._scoped_schedule_select(organization_id).where(BackupSchedule.id == schedule_id)
        )
        return result.scalar_one_or_none()

    # -------------------------------------------------------------------------
    # Storage resolution
    # -------------------------------------------------------------------------

    async def _resolve_storage(
        self,
        storage_type: str = "local",
        storage_location_id: UUID | None = None,
    ) -> tuple[BackupStorageBackend, UUID | None]:
        """Resolve a storage backend from a location ID or type + defaults.

        NOTE C1: encrypted_credentials is a Fernet token produced by
        app.core.crypto.encrypt_credential — NOT the per-backup PBKDF2/Fernet
        scheme used for backup payloads. The previous implementation tried to
        decrypt with a hardcoded null salt and always silently failed.
        """
        if storage_location_id:
            loc = await self.db.get(StorageLocation, storage_location_id)
            # SECURITY: the StorageLocation FK is caller-supplied
            # (BackupCreate/BackupScheduleCreate) and the create/schedule paths
            # only validate site_id, not storage_location_id. Without this org
            # check, org A could write its backup into org B's storage backend
            # and exercise org B's decrypted storage credentials — re-fired by
            # the Celery scheduler on every run. Scope the lookup to the
            # caller's org. (self.org_id is set on create_backup/create_schedule
            # and forwarded by the scheduled-backup Celery task.)
            if not loc or (self.org_id is not None and loc.organization_id != self.org_id):
                raise ValueError(f"Storage location {storage_location_id} not found")
            if loc.is_active is False:
                raise StorageConfigurationError("Storage location is disabled.")
            config = self._storage_config(loc)
            return get_storage_backend(loc.storage_type, config), loc.id

        # Default local
        config = {"path": "/data/backups"}
        return get_storage_backend(storage_type, config), None

    @staticmethod
    def _storage_config(loc: StorageConfigurationView) -> dict[str, Any]:
        config = dict(loc.config or {})
        if loc.encrypted_credentials:
            from app.core.crypto import decrypt_credential

            try:
                credentials = json.loads(decrypt_credential(loc.encrypted_credentials))
                if not isinstance(credentials, dict) or any(
                    key not in BackupService._SENSITIVE_STORAGE_FIELDS for key in credentials
                ):
                    raise ValueError("Invalid credential fields")
            except Exception:
                raise StorageConfigurationError(
                    "Stored credentials could not be decrypted or validated; restore the encryption key or recreate this destination with valid credentials."
                ) from None
            config.update(credentials)
        if loc.storage_type == "truenas":
            config["_organization_id"] = str(loc.organization_id)
        return config

    # Sensitive fields that must live in encrypted_credentials, never in
    # the plaintext JSONB ``config`` column. (NOTE C1)
    _SENSITIVE_STORAGE_FIELDS = frozenset(
        {
            "access_key",
            "secret_key",
            "password",
            "private_key",
            "token",
            "client_secret",
            "refresh_token",
            "api_key",
            "access_token",
            "app_secret",
            "credentials_json",
        }
    )

    def _extract_sensitive(self, config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Split a storage config into (public_config, sensitive_creds).

        NOTE C1: sensitive_creds is encrypted via app.core.crypto and stored
        in StorageLocation.encrypted_credentials; public_config goes to
        StorageLocation.config.
        """
        public: dict[str, Any] = {}
        sensitive: dict[str, Any] = {}
        for k, v in (config or {}).items():
            if k in self._SENSITIVE_STORAGE_FIELDS and v not in (None, ""):
                sensitive[k] = v
            else:
                public[k] = v
        return public, sensitive

    # -------------------------------------------------------------------------
    # Data collection (like pfSense/FreePBX config export)
    # -------------------------------------------------------------------------

    async def collect_backup_data(
        self,
        *,
        site_id: UUID | None = None,
        device_ids: list[UUID] | None = None,
        include_devices: bool = True,
        include_vlans: bool = True,
        include_ssids: bool = True,
        include_users: bool = True,
        include_automation: bool = True,
        include_settings: bool = True,
        include_secrets: bool = False,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Collect all configuration data into a JSON-serializable dict.
        Follows pfSense/FreePBX pattern: export everything as structured JSON.

        ``include_secrets`` (vault/.fsdnvault only): emit DECRYPTED controller
        credentials (the ``config`` blob) + user ``hashed_password`` so a full
        restore reconnects controllers and old logins keep working. NEVER set for
        a config snapshot — these are sealed under the operator passphrase upstream.

        NOTE H2/H3: every collection query is filtered to the supplied
        organization_id. Previously these queries had no WHERE clause and
        therefore dumped every org's data into a single backup blob.
        We dropped the Organization dump entirely — a backup only needs the
        creator's own org, never the global org table.
        """
        from app.models import (
            Controller,
            Credential,
            Device,
            Site,
            User,
            UserSiteAccess,
        )

        org_id = organization_id or self.org_id
        if org_id is None:
            raise ValueError(
                "organization_id is required to collect backup data — refusing "
                "to dump cross-tenant data."
            )

        data: dict[str, Any] = {}

        # --- Sites ---
        query = select(Site).where(Site.organization_id == org_id)
        if site_id:
            query = query.where(Site.id == site_id)
        result = await self.db.execute(query)
        sites = result.scalars().all()
        data["sites"] = [
            {
                "id": str(s.id),
                "name": s.name,
                # slug is NOT NULL — without it a site restore fails the flush and rolls
                # back the whole core section (latent: prior restore tests had no sites).
                "slug": getattr(s, "slug", None),
                "description": getattr(s, "description", None),
                "address": getattr(s, "address", None),
                "city": getattr(s, "city", None),
                "state": getattr(s, "state", None),
                "country": getattr(s, "country", None),
                "zip_code": getattr(s, "zip_code", None),
                "latitude": getattr(s, "latitude", None),
                "longitude": getattr(s, "longitude", None),
                "timezone": getattr(s, "timezone", None),
                "site_type": getattr(s, "site_type", None),
                "is_active": getattr(s, "is_active", True),
                "organization_id": str(s.organization_id)
                if getattr(s, "organization_id", None)
                else None,
            }
            for s in sites
        ]

        # --- Controllers ---  (org-scoped via Site join)
        query = (
            select(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(Site.organization_id == org_id)
        )
        if site_id:
            query = query.where(Controller.site_id == site_id)
        result = await self.db.execute(query)
        controllers = result.scalars().all()
        # Controllers encrypt secret config fields INDIVIDUALLY (config.password /
        # config.client_secret via encrypt_credential — see Controller.password /
        # .client_secret). For a vault we decrypt those specific fields so they travel
        # as plaintext INSIDE the passphrase-sealed payload; restore re-encrypts them
        # under the target instance's key. Non-secret keys pass through unchanged.
        from app.core.crypto import decrypt_credential, is_encrypted

        def _ctrl_config_for_vault(cfg: dict | None) -> dict:
            out = dict(cfg or {})
            for k in CONTROLLER_SECRET_CONFIG_KEYS:
                v = out.get(k)
                if isinstance(v, str) and is_encrypted(v):
                    out[k] = decrypt_credential(v)
            return out

        data["controllers"] = [
            {
                "id": str(c.id),
                "name": c.name,
                "description": getattr(c, "description", None),
                "controller_type": str(getattr(c, "controller_type", "")),
                "host": getattr(c, "host", None),
                "port": getattr(c, "port", None),
                "use_ssl": getattr(c, "use_ssl", True),
                "verify_ssl": getattr(c, "verify_ssl", False),
                "sync_enabled": getattr(c, "sync_enabled", True),
                "sync_interval_seconds": getattr(c, "sync_interval_seconds", 300),
                "is_active": getattr(c, "is_active", True),
                "credential_id": str(c.credential_id)
                if getattr(c, "credential_id", None)
                else None,
                "status": str(getattr(c, "status", "")),
                "site_id": str(c.site_id) if getattr(c, "site_id", None) else None,
                # Config snapshot: credentials excluded. Vault: decrypted config so a
                # full restore reconnects (sealed under the passphrase upstream).
                **(
                    {"config": _ctrl_config_for_vault(getattr(c, "config", None))}
                    if include_secrets
                    else {}
                ),
            }
            for c in controllers
        ]

        # --- Credentials (the credential vault) ---
        #
        # These were missing entirely. A `.fsdnvault` is documented as carrying
        # "every credential in the deployment" and the restore dialog says the
        # operator will not need to re-enter anything -- but core.credentials was
        # never collected, so after a bare-metal recovery Settings -> Credentials
        # was empty and every Device.credential_id pointed at a row that no
        # longer existed. The restore still reported success.
        #
        # Controller secrets and user logins WERE included, which is why the gap
        # went unnoticed: the vault was partly true.
        #
        # Secret columns are stored encrypted under the instance SECRET_KEY. In
        # vault mode they are decrypted here, inside the passphrase-sealed
        # payload, and re-encrypted under the TARGET instance's key on restore --
        # exactly the treatment controller config secrets already get above. In
        # NON-vault (.fsdn) mode they are omitted entirely rather than carried as
        # ciphertext, because a config snapshot must not contain secrets at all
        # and ciphertext from a different SECRET_KEY would be undecryptable
        # anyway.
        cred_query = select(Credential).where(
            Credential.organization_id == org_id,
            Credential.deleted_at.is_(None),
        )
        cred_result = await self.db.execute(cred_query)
        credentials = list(cred_result.scalars().all())

        def _cred_secret(value: str | None) -> str | None:
            if not include_secrets:
                return None
            if isinstance(value, str) and value and is_encrypted(value):
                return decrypt_credential(value)
            return value

        data["credentials"] = [
            {
                "id": str(c.id),
                "organization_id": str(c.organization_id),
                "site_id": str(c.site_id) if c.site_id else None,
                "name": c.name,
                "description": c.description,
                "credential_type": str(c.credential_type),
                "scope": str(c.scope),
                "vendor": c.vendor,
                "username": c.username,
                "encrypted_password": _cred_secret(c.encrypted_password),
                "api_key": _cred_secret(c.api_key),
                "token": _cred_secret(c.token),
                "ssh_private_key": _cred_secret(c.ssh_private_key),
                "certificate": _cred_secret(c.certificate),
                "snmp_community": _cred_secret(c.snmp_community),
                "options": c.options or {},
                "is_default": c.is_default,
                "is_active": c.is_active,
            }
            for c in credentials
        ]

        # --- Devices ---
        if include_devices:
            # Device has NO direct organization_id column — it's tenant-
            # scoped through ``site_id → Site.organization_id`` (the same
            # join _devices_for_org and every other Device query uses).
            # The previous ``Device.organization_id == org_id`` raised
            # AttributeError, which (post per-contributor try/except)
            # silently dropped ALL core data from every backup. Surfaced
            # by the live A-to-Z verification.
            query = (
                select(Device)
                .join(Site, Device.site_id == Site.id)
                .where(Site.organization_id == org_id, Device.deleted_at.is_(None))
            )
            if device_ids:
                query = query.where(Device.id.in_(device_ids))
            # Explicit device IDs narrow the selected site, never override it.
            if site_id:
                query = query.where(Device.site_id == site_id)
            result = await self.db.execute(query)
            devices = result.scalars().all()
            data["devices"] = [
                {
                    "id": str(d.id),
                    "name": d.name,
                    "device_type": str(getattr(d, "device_type", "")),
                    "vendor": getattr(d, "vendor", None),
                    "model": getattr(d, "model", None),
                    "ip_address": str(d.ip_address) if getattr(d, "ip_address", None) else None,
                    "external_id": getattr(d, "external_id", None),
                    "credential_id": str(d.credential_id)
                    if getattr(d, "credential_id", None)
                    else None,
                    "mac_address": getattr(d, "mac_address", None),
                    "hostname": getattr(d, "hostname", None),
                    "firmware_version": getattr(d, "firmware_version", None),
                    "serial_number": getattr(d, "serial_number", None),
                    "status": str(getattr(d, "status", "")),
                    "site_id": str(d.site_id) if getattr(d, "site_id", None) else None,
                    "controller_id": str(d.controller_id)
                    if getattr(d, "controller_id", None)
                    else None,
                }
                for d in devices
            ]

        # --- Configuration-only user profiles ---
        if include_users and not include_secrets:
            user_q = select(User).where(User.organization_id == org_id, User.deleted_at.is_(None))
            if site_id:
                # Only users with an explicit grant to this active site can
                # travel with its partial grant set. Otherwise an unrelated
                # restricted account restores with zero grants and becomes
                # unrestricted. Organization-wide accounts belong in an
                # organization-wide backup.
                user_q = user_q.where(
                    User.id.in_(
                        select(UserSiteAccess.user_id)
                        .join(Site, UserSiteAccess.site_id == Site.id)
                        .where(
                            Site.id == site_id,
                            Site.organization_id == org_id,
                            Site.deleted_at.is_(None),
                        )
                    )
                )
            result = await self.db.execute(user_q)
            users = result.scalars().all()
            data["users"] = [
                {
                    "id": str(u.id),
                    "username": getattr(u, "username", None),
                    "email": u.email,
                    "full_name": getattr(u, "full_name", None),
                    "first_name": getattr(u, "first_name", None),
                    "last_name": getattr(u, "last_name", None),
                    "display_name": getattr(u, "display_name", None),
                    "role": str(getattr(u, "role", "")),
                    "is_active": getattr(u, "is_active", True),
                    "organization_id": str(u.organization_id)
                    if getattr(u, "organization_id", None)
                    else None,
                    # Config snapshot: password hashes excluded. Vault backup: include
                    # the hash (one-way, instance-independent) + role/is_superuser so old
                    # logins survive a full restore. Sealed under the passphrase upstream.
                    **(
                        {
                            "hashed_password": getattr(u, "hashed_password", None),
                            "role": str(getattr(u, "role", "")),
                            "is_superuser": bool(getattr(u, "is_superuser", False)),
                        }
                        if include_secrets
                        else {}
                    ),
                }
                for u in users
            ]

            # --- Per-user site grants ---
            #
            # These were never collected, and the fail-open in
            # CurrentUser.is_site_limited turned that omission into a privilege
            # ESCALATION on restore: the property is `bool(self._accessible_site_ids)`,
            # so a user restored with ZERO grants is not "site-limited" at all,
            # can_access_site() returns True for every site in the org, and the
            # per-grant access_level cap ('read') is gone with it. A technician
            # who was a site_admin with read-only access to one site came back
            # from the documented bare-metal recovery as an unrestricted
            # site_admin over every site — with the job reporting "completed".
            # (Fail-open is correct for an UPGRADE, where nobody has grants yet;
            # it is wrong for a restore, which is supposed to reproduce state.)
            #
            # Scoped through site_id -> Site.organization_id (the row has no
            # organization_id of its own), and joined to User as well so a grant
            # can only ride along when BOTH ends live in this org.
            grant_q = (
                select(UserSiteAccess)
                .join(Site, UserSiteAccess.site_id == Site.id)
                .join(User, UserSiteAccess.user_id == User.id)
                .where(
                    Site.organization_id == org_id,
                    Site.deleted_at.is_(None),
                    User.organization_id == org_id,
                    User.deleted_at.is_(None),
                )
            )
            if site_id:
                grant_q = grant_q.where(UserSiteAccess.site_id == site_id)
            grant_result = await self.db.execute(grant_q)
            data["user_site_access"] = [
                {
                    "id": str(g.id),
                    "user_id": str(g.user_id),
                    "site_id": str(g.site_id),
                    "access_level": g.access_level,
                }
                for g in grant_result.scalars().all()
            ]
            if site_id:
                # The two queries can observe a grant/lifecycle change between
                # reads. Export only matching pairs; never emit a selected user
                # without a grant or a new grant without its selected user.
                selected_user_ids = {row["id"] for row in data["users"]}
                data["user_site_access"] = [
                    row for row in data["user_site_access"] if row["user_id"] in selected_user_ids
                ]
                granted_user_ids = {row["user_id"] for row in data["user_site_access"]}
                data["users"] = [row for row in data["users"] if row["id"] in granted_user_ids]

        if include_secrets:
            from app.services.backup_contributors.account_security import FORMAT, collect_snapshot

            if include_users:
                data.update(await collect_snapshot(self.db, org_id, site_id=site_id))
            else:
                data.update(
                    account_security_format=FORMAT, users=[], sso_providers=[], user_site_access=[]
                )

        # --- Automation rules ---
        if include_automation:
            try:
                # The model is AutomationRuleRecord. This imported
                # ``AutomationRule``, which does not exist and never has, so the
                # ImportError was raised on EVERY call and swallowed by the
                # bare except below -- every backup ever taken recorded
                # `automation_rules: []` while the create dialog's Automation
                # toggle, the detail view's Automation badge and the pre-restore
                # manifest all reported on data that was not in the file.
                from app.models.automation import AutomationRuleRecord

                ar_q = select(AutomationRuleRecord).where(
                    AutomationRuleRecord.organization_id == org_id
                )
                result = await self.db.execute(ar_q)
                rules = result.scalars().all()
                # Real column names. The old block also read `is_enabled`, which
                # the model does not have either -- getattr's default quietly
                # returned True for every rule regardless of its actual status.
                data["automation_rules"] = [
                    {
                        "id": str(r.id),
                        "organization_id": str(r.organization_id),
                        "name": r.name,
                        "description": r.description,
                        "trigger_type": r.trigger_type,
                        "trigger_config": r.trigger_config,
                        "conditions": r.conditions,
                        "actions": r.actions,
                        "status": r.status,
                        "priority": r.priority,
                        "cooldown_seconds": r.cooldown_seconds,
                        "max_triggers_per_hour": r.max_triggers_per_hour,
                    }
                    for r in rules
                ]
            except Exception:
                # Still tolerant, but no longer SILENT: swallowing without a
                # trace is what let a permanently-broken import look like "this
                # org has no automation rules" for the life of the feature.
                logger.warning("Automation rules omitted from backup", exc_info=True)
                data["automation_rules"] = []

        # NOTE H3: the previous implementation dumped the full Organization
        # table here. That leaked tenant names + settings into every backup.
        # A backup does NOT need the global org list — drop it entirely.

        from app.core.config import settings as _settings

        return {
            "version": "2.0",
            "schema_version": 2,
            "created_at": datetime.now(UTC).isoformat(),
            "freesdn_version": _settings.APP_VERSION,
            "organization_id": str(org_id),
            "data": data,
        }

    # -------------------------------------------------------------------------
    # Backup creation
    # -------------------------------------------------------------------------

    @complete_before_cancellation
    async def create_backup(
        self,
        *,
        name: str,
        description: str | None = None,
        backup_type: str = "full",
        site_id: UUID | None = None,
        device_ids: list[UUID] | None = None,
        include_devices: bool = True,
        include_vlans: bool = True,
        include_ssids: bool = True,
        include_users: bool = True,
        include_automation: bool = True,
        storage_type: str = "local",
        storage_location_id: UUID | None = None,
        is_encrypted: bool = True,
        include_secrets: bool = False,
        passphrase: str | None = None,
        retention_days: int = 30,
        created_by_id: UUID | None = None,
        schedule_id: UUID | None = None,
        organization_id: UUID | None = None,
        creation_guard: Any | None = None,
    ) -> Backup:
        """Create a backup: collect → compress → encrypt → store → record.

        Two flavours, selected by ``include_secrets``:
          * ``False`` (default) — a CONFIG snapshot (``.fsdn``): no secrets, encrypted
            under the instance ``SECRET_KEY``. Safe to share as a config template.
          * ``True`` — a FULL/secure backup (``.fsdnvault``): carries decrypted
            credentials + user logins, sealed under the operator ``passphrase`` (NOT
            the instance key) so it is portable and re-keys onto the target instance
            at restore. Requires a passphrase; always encrypted.

        NOTE C4: organization_id is now required for tenant isolation. The
        endpoint always supplies the caller's org. Tasks pass it explicitly.
        """
        if organization_id is None:
            raise ValueError("organization_id is required — backups must be tenant-scoped")
        self.org_id = organization_id

        async def checkpoint() -> None:
            # This capability comes only from a server-side fresh-export
            # consumer. Existing internal snapshots keep their separate policy.
            if creation_guard is not None:
                await creation_guard.check()

        if creation_guard is not None and not include_secrets:
            raise BackupInputError("Vault authorization cannot create a configuration snapshot")
        await checkpoint()

        # A secure (vault) backup carries decrypted secrets, so it MUST be encrypted
        # under a strong operator passphrase — reject rather than silently write a
        # leaky/instance-bound file. The passphrase (not SECRET_KEY) is what makes the
        # archive portable across instances (proven by the re-key drill).
        if include_secrets:
            if not passphrase or len(passphrase) < 12:
                raise BackupInputError(
                    "a secure (full) backup requires a passphrase of at least 12 characters"
                )
            is_encrypted = True  # never write a plaintext secrets archive

        # Fail-closed to encrypted: a backup carries decrypted secrets, so a
        # plaintext archive at rest is a leak. In production/staging, a caller or
        # policy that asks for plaintext is UPGRADED to encrypted (never silently
        # written plaintext) unless an operator has explicitly opted into the risk
        # via BACKUP_ALLOW_PLAINTEXT (e.g. for restore on a host without this
        # SECRET_KEY). Dev keeps plaintext available for testing.
        if not is_encrypted:
            from app.core.config import settings as _settings

            if _must_force_encryption(
                is_encrypted, _settings.ENVIRONMENT, _settings.BACKUP_ALLOW_PLAINTEXT
            ):
                logger.warning(
                    "Plaintext backup requested in %s but coerced to encrypted "
                    "(backups contain secrets); set BACKUP_ALLOW_PLAINTEXT=true to override.",
                    _settings.ENVIRONMENT,
                )
                is_encrypted = True

        backup = Backup(
            name=name,
            description=description,
            backup_type=backup_type,
            status=BackupStatus.PENDING,
            progress=0,
            organization_id=organization_id,
            site_id=site_id,
            device_ids=[str(d) for d in device_ids] if device_ids else [],
            include_devices=include_devices,
            include_vlans=include_vlans,
            include_ssids=include_ssids,
            include_users=include_users,
            include_automation=include_automation,
            include_secrets=include_secrets,
            storage_type=storage_type,
            storage_location_id=storage_location_id,
            is_encrypted=is_encrypted,
            retention_days=retention_days,
            created_by_id=created_by_id,
            schedule_id=schedule_id,
            expires_at=datetime.now(UTC) + timedelta(days=retention_days),
        )
        self.db.add(backup)
        await self.db.flush()

        remote_write = None
        try:
            backup.status = BackupStatus.IN_PROGRESS
            backup.started_at = datetime.now(UTC)
            backup.progress = 5
            await self.db.flush()

            # 1. Collect data via the contributor registry (enterprise
            # chapter Phase 2b). Walks contributors in topological order
            # and assembles a v2.0 BackupArchive with per-contributor
            # sections + a manifest header. CoreBackupContributor is
            # always present (the platform's foundational contributor);
            # module-provided contributors (VoIP / Cameras / Firewall —
            # Phases 3-5) join automatically via module discovery.
            #
            # The OUTER file header below stays at version "2.0" — the
            # change here is purely the SHAPE of the encrypted payload.
            # Old monolithic v1 payloads stay readable on restore via
            # ``wrap_legacy_v1_as_archive`` so existing .fsdn files on
            # disk continue to restore without any operator action.
            collect_options = {
                "site_id": site_id,
                "device_ids": device_ids,
                "include_devices": include_devices,
                # include_vlans / include_ssids are NOT recorded here.
                #
                # A backup contains sites, controllers, credentials, automation
                # rules, devices and users -- the whole of ``restore_map``. It
                # has never contained VLANs or SSIDs, and nothing in this file
                # reads either flag: there is no ``if include_vlans:`` anywhere.
                #
                # Writing them into the archive's own metadata made the file
                # describe contents it does not have, using an answer the
                # operator was asked for and which changed nothing. On a
                # disaster restore that is the worst possible place to be
                # reassured. The UI toggles are gone; these parameters remain
                # only so existing API callers and stored schedule rows do not
                # 422, and they are deliberately inert.
                "include_users": include_users,
                "include_automation": include_automation,
                # When True, contributors emit DECRYPTED secret material (creds, VPN
                # keys, password hashes) into the payload — which is then sealed under
                # the passphrase below. Contributors ignore this key for a config snapshot.
                "include_secrets": include_secrets,
            }
            await checkpoint()
            archive = await self._assemble_backup_archive(
                backup_id=backup.id,
                organization_id=organization_id,
                options=collect_options,
            )
            await checkpoint()
            backup.progress = 30

            # 2. Serialize + compress. Pydantic's model_dump_json handles
            # UUIDs + datetimes natively (the old ``default=str`` fallback
            # is no longer needed).
            json_data = archive.model_dump_json(indent=2)
            compressed = gzip.compress(json_data.encode("utf-8"))
            backup.progress = 50

            # 3. Encrypt. A vault backup is sealed under the operator PASSPHRASE (so the
            # archive is portable + re-keys onto the target at restore); a config
            # snapshot uses the instance SECRET_KEY (self.encryption).
            key_id = None
            if is_encrypted:
                encryptor = (
                    BackupEncryption(master_key=passphrase) if include_secrets else self.encryption
                )
                compressed, key_id = encryptor.encrypt(compressed)
                backup.encryption_key_id = key_id
            backup.progress = 60

            # 4. Checksum + file header
            checksum = hashlib.sha256(compressed).hexdigest()
            header = {
                "backup_id": str(backup.id),
                "checksum": checksum,
                "encrypted": is_encrypted,
                "compressed": True,
                # secrets=True marks a .fsdnvault: payload carries decrypted secrets and
                # is passphrase-sealed, so restore must prompt for the passphrase and
                # re-key. Read back in _parse_fsdn_file / restore.
                "secrets": include_secrets,
                # key_id = the PBKDF2 "v2:<iter>:<salt>" descriptor. The salt is NOT
                # secret (standard PBKDF2), and embedding it makes the FILE self-
                # decryptable on ANOTHER instance (with the passphrase) — without it a
                # transferred .fsdnvault could only be decrypted via its origin DB row,
                # defeating portability. Restore prefers this, falling back to the DB row
                # for legacy files written before this field existed.
                "key_id": key_id,
                "created_at": datetime.now(UTC).isoformat(),
                "version": "2.0",
            }
            header_bytes = json.dumps(header).encode("utf-8")
            header_len = len(header_bytes)
            final_data = header_len.to_bytes(4, "big") + header_bytes + compressed
            identity = make_identity(final_data)
            backup.progress = 70

            # 5. Store
            await checkpoint()
            if creation_guard is None:
                backend, loc_id = await self._resolve_storage(storage_type, storage_location_id)
            else:
                backend, loc_id = await creation_guard.backend()
            await checkpoint()
            ext = "fsdnvault" if include_secrets else "fsdn"
            filename = f"backup_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{ext}"
            try:
                if isinstance(backend, _RemoteFileStorageBackend):
                    from app.services.remote_write_coordination import RemoteBackupWrite

                    plan = backend.prepare_save(str(backup.id), final_data, filename)
                    remote_write = await RemoteBackupWrite.reserve(
                        self.db,
                        backend,
                        plan,
                        backup_id=backup.id,
                        organization_id=organization_id,
                        storage_location_id=loc_id,
                        created_by_id=created_by_id,
                        schedule_id=schedule_id,
                        include_secrets=include_secrets,
                    )
                    backup.storage_path = plan.location  # possible, not verified
                    backup.file_size = plan.payload_size
                    backup.storage_location_id = loc_id
                    backup.metadata_json = {
                        **(backup.metadata_json or {}),
                        "remote_write": {
                            "operation_id": str(plan.operation_id),
                            "recovery_required": True,
                        },
                    }
                    await checkpoint()
                    await remote_write.dispatch()
                    await checkpoint()
                    storage_path = await backend.save_prepared(plan, final_data)
                    await remote_write.acknowledge()
                else:
                    storage_path = await backend.save(str(backup.id), final_data, filename)
            except BackupPublicationError as error:
                # The final file exists, but fsync/close acknowledgement failed.
                # Retain its locator in the FAILED catalog row for inspection;
                # never promote an unverified identity or imply rollback.
                backup.storage_path = error.storage_path
                backup.file_size = len(final_data)
                if loc_id:
                    backup.storage_location_id = loc_id
                raise BackupRecoveryError(
                    "Backup publication could not be confirmed; its file locator "
                    "is retained for inspection. The backup is not verified."
                ) from error
            # Keep the acknowledged locator even if verification fails, so the
            # failed catalog entry can still identify its stored file for cleanup.
            backup.storage_path = storage_path
            backup.file_size = len(final_data)
            if loc_id:
                backup.storage_location_id = loc_id
            # Keep the acknowledged locator before a late permission refusal.
            # A failed response must not imply that an acknowledged write vanished.
            await checkpoint()
            if remote_write is not None:
                await remote_write.check_destination()
            verify_identity(await backend.load(storage_path), identity)
            await checkpoint()
            if remote_write is not None:
                await remote_write.check_destination()
            backup.metadata_json = {**(backup.metadata_json or {}), "artifact_identity": identity}
            if remote_write is not None:
                backup.metadata_json = {
                    **backup.metadata_json,
                    "remote_write": {
                        "operation_id": str(remote_write.intent.operation_id),
                        "recovery_required": False,
                    },
                }
            backup.progress = 90

            await checkpoint()
            # 6. Update record only after the stored complete file matches.
            backup.status = BackupStatus.COMPLETED
            backup.completed_at = datetime.now(UTC)
            backup.progress = 100
            if loc_id:
                backup.storage_location_id = loc_id
            # A contributor whose collect() raised is omitted from the archive
            # (deliberately — one broken module must not block a backup of the
            # others), but the row was still marked COMPLETED with the reason
            # only in the log. Put it where the operator looks: the catalog and
            # the detail drawer both render Backup.error_message in destructive
            # styling regardless of status, so an incomplete archive now says so.
            if self._collect_omissions:
                backup.error_message = (
                    "Incomplete backup — these modules failed to collect and are "
                    "NOT in this archive: " + "; ".join(self._collect_omissions)
                )[:2000]

            await self.db.commit()
            await self.db.refresh(backup)
            await checkpoint()
            logger.info(
                "Backup %s completed: %s (%d bytes)", backup.id, storage_path, len(final_data)
            )
            return backup

        except Exception as e:
            backup.status = BackupStatus.FAILED
            if remote_write is not None:
                backup.metadata_json = {
                    **(backup.metadata_json or {}),
                    "remote_write": {
                        "operation_id": str(remote_write.intent.operation_id),
                        "recovery_required": True,
                    },
                }
                # Late authority/commit/readback failure does not undo remote
                # publication. Do not advertise retry as rollback or cleanup.
                backup.error_message = (
                    "Remote backup publication needs inspection. Recovery history "
                    "and possible file locations are retained; do not retry automatically."
                )
            else:
                backup.error_message = backup_failure_detail(
                    BackupInputError(str(e)) if isinstance(e, BackupArtifactError) else e,
                    "Backup creation failed; review storage access and retry.",
                )
            backup.completed_at = datetime.now(UTC)
            await self.db.commit()
            logger.error("Backup %s failed (%s)", backup.id, type(e).__name__)
            if isinstance(e, BackupArtifactError):
                raise BackupInputError(str(e)) from None
            raise

    # -------------------------------------------------------------------------
    # Export (instant JSON download, no DB record)
    # -------------------------------------------------------------------------

    async def export_config(
        self,
        *,
        include_devices: bool = True,
        include_vlans: bool = True,
        include_ssids: bool = True,
        include_users: bool = True,
        include_automation: bool = True,
        include_settings: bool = True,
        compress: bool = False,
        organization_id: UUID | None = None,
    ) -> bytes:
        """
        Export configuration as JSON (like pfSense config.xml export).
        Returns raw JSON bytes or gzip-compressed JSON.

        NOTE H2: organization_id is required — export honours tenant scope.
        """
        data = await self.collect_backup_data(
            include_devices=include_devices,
            include_vlans=include_vlans,
            include_ssids=include_ssids,
            include_users=include_users,
            include_automation=include_automation,
            include_settings=include_settings,
            organization_id=organization_id,
        )
        raw = json.dumps(data, indent=2, default=str).encode("utf-8")
        if compress:
            return gzip.compress(raw)
        return raw

    # -------------------------------------------------------------------------
    # Import (config file → DB)
    # -------------------------------------------------------------------------

    async def import_config(
        self,
        file_data: bytes,
        *,
        dry_run: bool = True,
        overwrite_existing: bool = False,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Import a configuration file. Returns summary of imported items.

        NOTE C5: ONLY the .fsdn format is accepted. The old raw-JSON and
        gzip-JSON paths bypassed the SHA-256 checksum check entirely and
        let an attacker hand us arbitrary JSON to ingest. The .fsdn format
        carries an integrity-verified header + checksum.

        NOTE H4: organization_id is required and forced onto every inserted
        record. Any record with a foreign organization_id is rejected.
        """
        if organization_id is None:
            raise ValueError(
                "organization_id is required for import — refusing to ingest unscoped tenant data."
            )
        self.org_id = organization_id

        # NOTE C5: only .fsdn files are accepted now. The first 4 bytes are
        # the big-endian header length; reject anything that doesn't start
        # with a plausible .fsdn binary header.
        if not file_data or len(file_data) < 8:
            return {
                "success": False,
                "dry_run": dry_run,
                "message": (
                    "Import file is too small to be a valid .fsdn archive. "
                    "Only .fsdn format (with SHA-256 integrity verification) "
                    "is accepted; raw JSON imports have been removed."
                ),
            }
        try:
            config = self._parse_fsdn_file(file_data)
        except Exception as e:
            logger.warning("Config import archive rejected (%s)", type(e).__name__)
            return {
                "success": False,
                "dry_run": dry_run,
                "message": backup_failure_detail(
                    e,
                    "Invalid .fsdn file. Only the .fsdn format with a verified "
                    "SHA-256 checksum is accepted.",
                ),
            }

        # v2 archives ({manifest, contributors:{core:{sites,...}}}) are what
        # create_backup has written since the contributor chapter landed, but
        # this reader was still coded against the pre-v2 {data:{sites,...}}
        # envelope. On a v2 archive ``config.get("data", config)`` returns the
        # ENVELOPE, every ``data.get(<resource>)`` is [], and the endpoint
        # answered `success: true` with an empty summary and all-null metadata
        # — the UI never checks `success`, so the operator got a preview reading
        # "Sites 0 / Devices 0" and then a green "Import complete" toast having
        # imported nothing at all.
        from app.services.backup_contributors import BackupArchive, is_legacy_v1_payload

        meta: dict[str, Any]
        if is_legacy_v1_payload(config):
            data = config.get("data", config)
            meta = {
                "version": config.get("version"),
                "schema_version": config.get("schema_version"),
                "created_at": config.get("created_at"),
                # ``freesdn_version`` is the key written by collect_backup_data()
                # at export time (see _settings.APP_VERSION). Surface it as
                # ``product_version`` so the import-preview UI can show which
                # FreeSDN build produced the archive.
                "product_version": config.get("freesdn_version"),
            }
        else:
            try:
                archive = BackupArchive.model_validate(config)
            except Exception as e:
                logger.warning("Config import layout rejected (%s)", type(e).__name__)
                return {
                    "success": False,
                    "dry_run": dry_run,
                    "message": "Unrecognized .fsdn archive layout; check the archive format.",
                }
            # Each contributor section IS its flat resource dict; only ``core``
            # holds the sites/controllers/devices/users this importer handles.
            # Module sections (voip, cameras, firewall, vpn) are NOT imported
            # here — import is a config-merge tool, not a restore.
            core = archive.contributors.get("core") or {}
            data = core.get("data", core) if isinstance(core, dict) else {}
            created_at = archive.manifest.created_at
            meta = {
                "version": archive.manifest.format_version,
                "schema_version": archive.manifest.manifest_version,
                "created_at": created_at.isoformat() if created_at else None,
                "product_version": archive.manifest.source_version,
            }
        from app.services.backup_import import ConfigImportError, plan_config_import

        try:
            # Planning must not flush any pending resource before all ownership
            # and reference checks have accepted the complete configuration.
            with self.db.no_autoflush:
                plan = await plan_config_import(
                    self.db,
                    data,
                    organization_id,
                    overwrite_existing=overwrite_existing,
                    dry_run=dry_run,
                    controller_secret_fields=CONTROLLER_SECRET_CONFIG_KEYS,
                )
        except ConfigImportError as exc:
            await self.db.rollback()
            return {"success": False, "dry_run": dry_run, "message": str(exc)}

        if not dry_run:
            try:
                plan.apply(self.db)
                await self.db.commit()
            except Exception as exc:
                await self.db.rollback()
                logger.error(
                    "Config import transaction failed for organization %s (%s)",
                    organization_id,
                    type(exc).__name__,
                )
                return {
                    "success": False,
                    "dry_run": False,
                    "message": "Import failed; no changes were applied. Check the configuration and retry.",
                }

        message = (
            "Dry run complete — no changes applied" if dry_run else "Import completed successfully"
        )
        if plan.new_disabled_users:
            message += (
                ". New user profiles are disabled and have no usable password; "
                "complete account setup and access grants before activation."
            )
        return {
            "success": True,
            "dry_run": dry_run,
            "would_import" if dry_run else "imported": plan.summary,
            "message": message,
            "metadata": meta,
        }

    def _parse_fsdn_file(self, raw: bytes) -> dict[str, Any]:
        """Parse our binary .fsdn backup format."""
        header_len = int.from_bytes(raw[:4], "big")
        header = json.loads(raw[4 : 4 + header_len].decode("utf-8"))
        payload = raw[4 + header_len :]

        # Verify checksum
        if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
            raise BackupInputError("Checksum verification failed — file may be corrupted")

        # Decrypt if needed
        if header.get("encrypted"):
            raise BackupInputError(
                "Encrypted backup detected — use the restore endpoint with the backup ID instead of import"
            )

        # Decompress
        if header.get("compressed"):
            payload = _bounded_gunzip(payload)

        result: dict[str, Any] = json.loads(payload.decode("utf-8"))
        return result

    # -------------------------------------------------------------------------
    # Restore
    # -------------------------------------------------------------------------

    async def _load_catalogue_artifact(
        self, backup: Backup, *, backend: BackupStorageBackend | None = None
    ) -> tuple[bytes, str]:
        """Validate metadata before storage, then verify the exact returned bytes."""
        try:
            expected = recorded_identity(backup.metadata_json)
            if backend is None:
                backend, _ = await self._resolve_storage(
                    backup.storage_type, backup.storage_location_id
                )
            raw = await backend.load(backup.storage_path)
            integrity = verify_identity(raw, expected)
        except BackupArtifactError as exc:
            raise BackupInputError(str(exc)) from None
        return raw, integrity

    async def preview_backup_manifest(
        self,
        backup_id: UUID,
        organization_id: UUID,
    ) -> dict[str, Any]:
        """Decode a backup just far enough to read its manifest, WITHOUT
        running a restore. Powers the operator's pre-restore preview +
        per-contributor selection UI.

        Returns a dict shaped for ``BackupManifestPreview``:
          {backup_id, format_version, created_at, source_version,
           organization_id, contributors: [{id, schema_version, counts,
           restorable, incompatibility_reason}]}

        ``restorable`` per contributor reflects the strict-semver check
        against the live code, so the UI can grey-out incompatible
        sections before the operator commits to a restore.

        Cost: the same decrypt + decompress as a restore (the manifest
        lives inside the encrypted payload), but NO DB writes and no
        contributor dispatch.
        """
        from app.services.backup_contributors import (
            BackupArchive,
            describe_mismatch,
            get_registry,
            is_compatible,
            is_legacy_v1_payload,
            wrap_legacy_v1_as_archive,
        )

        backup = await self.get_backup_for_organization(backup_id, organization_id)
        if not backup:
            raise ValueError(f"Backup {backup_id} not found")
        if backup.status != BackupStatus.COMPLETED:
            raise ValueError(f"Backup {backup_id} is not completed (status: {backup.status})")

        # A Full (.fsdnvault) backup is sealed with the OPERATOR PASSPHRASE, not
        # the instance key, so the decrypt further down cannot open it. This
        # method has no passphrase parameter, and the Restore dialog fires the
        # preview unconditionally the moment it opens -- so every vault produced
        # a decrypt failure, a 500, a stack trace in the logs, and the "Modules
        # to restore" panel replaced by "Could not read the backup manifest".
        # On the artifact documented for bare-metal recovery.
        #
        # Answer clearly instead of attempting a decrypt that cannot succeed:
        # the caller gets a well-formed response it can render as "passphrase
        # required" rather than an error it cannot explain.
        if getattr(backup, "include_secrets", False):
            try:
                recorded_identity(backup.metadata_json)
            except BackupArtifactError as exc:
                raise BackupInputError(str(exc)) from None
            return {
                "backup_id": str(backup.id),
                "artifact_integrity": backup.artifact_integrity,
                "format_version": None,
                "created_at": backup.created_at.isoformat() if backup.created_at else None,
                "source_version": None,
                "organization_id": str(organization_id),
                "contributors": [],
                "requires_passphrase": True,
                "reason": (
                    "This is a Full (.fsdnvault) backup, sealed with your "
                    "passphrase. Its contents cannot be previewed without it."
                ),
            }

        raw, integrity = await self._load_catalogue_artifact(backup)

        header_len = int.from_bytes(raw[:4], "big")
        header = json.loads(raw[4 : 4 + header_len].decode("utf-8"))
        payload = raw[4 + header_len :]

        if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
            raise BackupInputError("Checksum verification failed")
        if header.get("encrypted") and backup.encryption_key_id:
            payload = self.encryption.decrypt(payload, backup.encryption_key_id)
        if header.get("compressed"):
            payload = _bounded_gunzip(payload)

        config = json.loads(payload.decode("utf-8"))
        if is_legacy_v1_payload(config):
            archive = wrap_legacy_v1_as_archive(
                config,
                backup_id=str(backup.id),
                created_at=backup.created_at or datetime.now(UTC),
                organization_id=str(organization_id),
            )
        else:
            archive = BackupArchive.model_validate(config)

        # Annotate each contributor with restorability against live code.
        registry = get_registry()
        contributors_out: list[dict[str, Any]] = []
        for entry in archive.manifest.contributors:
            live = registry.get(entry.id)
            restorable = True
            reason: str | None = None
            if live is None:
                # The module that owns this contributor isn't loaded in
                # this deployment — can't restore it here.
                restorable = False
                reason = (
                    f"no '{entry.id}' contributor registered in this "
                    f"instance (is the module installed?)"
                )
            elif not is_compatible(entry.schema_version, live.schema_version):
                restorable = False
                reason = describe_mismatch(
                    entry.schema_version,
                    live.schema_version,
                )
            contributors_out.append(
                {
                    "id": entry.id,
                    "schema_version": entry.schema_version,
                    "counts": entry.counts,
                    "restorable": restorable,
                    "incompatibility_reason": reason,
                }
            )

        return {
            "backup_id": backup.id,
            "format_version": archive.manifest.format_version,
            "artifact_integrity": integrity,
            "created_at": archive.manifest.created_at,
            "source_version": archive.manifest.source_version,
            "organization_id": archive.manifest.organization_id,
            "contributors": contributors_out,
        }

    async def restore_from_backup(
        self,
        backup_id: UUID,
        *,
        restore_devices: bool = True,
        restore_vlans: bool = True,
        restore_ssids: bool = True,
        restore_users: bool = False,
        restore_automation: bool = True,
        overwrite_existing: bool = False,
        dry_run: bool = True,
        target_site_id: UUID | None = None,
        organization_id: UUID | None = None,
        initiated_by_id: UUID | None = None,
        contributors: list[str] | None = None,
        passphrase: str | None = None,
    ) -> RestoreJob:
        """Restore from a recorded backup → creates a RestoreJob.

        ``contributors`` (enterprise backup v2): the subset of manifest
        contributor ids to restore. None restores every contributor in
        the archive; a list restores only those (the rest report
        ``status="skipped"`` in the job report).

        NOTE C4: organization_id is required — restore is always tenant-scoped.
        NOTE H8: the inner restore loop runs atomically. If anything throws
        mid-restore, the partially-applied changes roll back cleanly.
        """
        if organization_id is None:
            raise ValueError("organization_id is required for restore")
        self.org_id = organization_id

        backup = await self.get_backup_for_organization(backup_id, organization_id)
        if not backup:
            raise ValueError(f"Backup {backup_id} not found")
        if backup.status != BackupStatus.COMPLETED:
            raise ValueError(f"Backup {backup_id} is not completed (status: {backup.status})")

        # A vault (full) backup is a complete-instance recovery — always restore users
        # so the operator's logins come back; otherwise the restore is half-useless.
        if backup.include_secrets:
            restore_users = True

        if target_site_id:
            from app.models.core import Site

            target_site = await self.db.get(Site, target_site_id)
            if (
                not target_site
                or target_site.organization_id != organization_id
                or target_site.deleted_at is not None
            ):
                raise ValueError(f"Target site {target_site_id} not found")

        # Create RestoreJob
        job = RestoreJob(
            backup_id=backup.id,
            status="pending",
            restore_devices=restore_devices,
            restore_vlans=restore_vlans,
            restore_ssids=restore_ssids,
            restore_users=restore_users,
            restore_automation=restore_automation,
            overwrite_existing=overwrite_existing,
            dry_run=dry_run,
            target_site_id=target_site_id,
            initiated_by_id=initiated_by_id,
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)

        try:
            job.status = "in_progress"
            job.started_at = datetime.now(UTC)
            job.progress = 5
            await self.db.commit()

            # Load backup data (outside the atomic restore txn — read-only).
            raw, _ = await self._load_catalogue_artifact(backup)

            # Parse .fsdn
            header_len = int.from_bytes(raw[:4], "big")
            header = json.loads(raw[4 : 4 + header_len].decode("utf-8"))
            payload = raw[4 + header_len :]

            # Verify checksum
            if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
                raise BackupInputError("Checksum verification failed")

            # Decrypt. A vault (.fsdnvault) is sealed under the operator PASSPHRASE
            # (portable across instances); a config snapshot uses the instance
            # SECRET_KEY. The passphrase is required for a vault restore. Prefer the
            # key_id embedded in the file header (self-describing / portable), falling
            # back to the DB row for legacy archives written before key_id was embedded.
            key_id = header.get("key_id") or backup.encryption_key_id
            if header.get("encrypted") and key_id:
                if backup.include_secrets:
                    if not passphrase:
                        raise BackupInputError(
                            "this is a secure (full) backup — a passphrase is required to restore it"
                        )
                    # A wrong passphrase surfaces as ``cryptography.fernet
                    # .InvalidToken``, whose ``str()`` is the EMPTY STRING. Left
                    # unwrapped it escaped the endpoint's ``except ValueError``
                    # as an unhandled 500 and wrote a blank RestoreJob
                    # .error_message, so a one-character typo during a recovery
                    # read as "the file is corrupt / the server is broken".
                    # restore_fresh_instance_from_vault already wraps the
                    # identical call; the live-instance path never got it.
                    try:
                        payload = BackupEncryption(master_key=passphrase).decrypt(payload, key_id)
                    except ValueError:
                        # _parse_key_id's own diagnostics (malformed key_id,
                        # out-of-range iteration count) name a real defect in the
                        # FILE — do not mask them as a passphrase mistake.
                        raise
                    except Exception as exc:
                        raise BackupInputError(
                            "could not decrypt this backup — wrong passphrase?"
                        ) from exc
                else:
                    payload = self.encryption.decrypt(payload, key_id)

            # Decompress
            if header.get("compressed"):
                payload = _bounded_gunzip(payload)

            config = json.loads(payload.decode("utf-8"))
            job.progress = 30

            # Enterprise chapter Phase 2b: detect v1 vs v2 payload and
            # dispatch through the registered contributors.
            #
            # v1 (legacy monolithic dict, top-level sites/controllers/etc.,
            # no manifest) → wrap as a synthetic v2 archive with a single
            # ``core`` contributor section, preserving backwards
            # compatibility for every .fsdn file on disk taken before
            # this commit landed.
            #
            # v2 (BackupArchive with ``manifest`` key) → parse via
            # Pydantic, which fails fast on shape drift.
            from app.services.backup_contributors import (
                BackupArchive,
                is_legacy_v1_payload,
                wrap_legacy_v1_as_archive,
            )

            if is_legacy_v1_payload(config):
                archive = wrap_legacy_v1_as_archive(
                    config,
                    backup_id=str(backup.id),
                    created_at=backup.created_at or datetime.now(UTC),
                    organization_id=str(organization_id),
                )
            else:
                archive = BackupArchive.model_validate(config)

            # Capture the pre-restore rollback slot (Cisco-DNA-style undo)
            # BEFORE applying any writes. Operators can later restore the
            # slot via the catalog UI to undo a botched restore. Dry runs
            # don't write, so they skip the slot.
            #
            # SECURITY/SAFETY (backup restore): a real
            # restore mutates live config across every contributor. If the
            # rollback slot can't be captured, there is NO undo for a
            # botched restore. Per ``capture_rollback_slot``'s documented
            # contract (v1 is strict), we REFUSE to proceed rather than
            # silently performing a destructive, irreversible restore.
            # This raises BEFORE any contributor savepoint commits (the
            # dispatch loop below has not run yet), so the outer handler
            # rolls back cleanly and marks the job failed with a clear
            # no-undo reason — leaving live state untouched.
            if not dry_run:
                try:
                    from app.services.backup_contributors import (
                        capture_rollback_slot,
                    )

                    await capture_rollback_slot(
                        self.db,
                        organization_id=organization_id,
                        restore_job=job,
                        created_by_id=initiated_by_id,
                    )
                except Exception as exc:
                    logger.error(
                        "Pre-restore rollback capture failed for RestoreJob %s (%s); "
                        "refusing to proceed without undo support",
                        job.id,
                        type(exc).__name__,
                    )
                    raise BackupRecoveryError(
                        "Pre-restore rollback snapshot could not be captured; "
                        "refusing to perform a destructive restore without an "
                        "undo point. Resolve the snapshot failure and retry."
                    ) from None
            job.progress = 40

            restore_options = {
                "overwrite_existing": overwrite_existing,
                "restore_devices": restore_devices,
                "restore_users": restore_users,
                # Vault restore: contributors restore secret fields (logins, creds) and
                # RE-ENCRYPT them under THIS instance's SECRET_KEY (the payload arrived
                # decrypted-then-passphrase-sealed). Ignored by config-snapshot restores.
                "include_secrets": backup.include_secrets,
            }

            # NOTE H8 (per-module independence per audit-locked scope):
            # the contributor dispatch creates per-contributor savepoints
            # internally (begin_nested per contributor). A single
            # contributor's failure rolls back ONLY its own writes; the
            # next contributor proceeds. The outer session-level
            # transaction (containing the RestoreJob row updates) still
            # survives any contributor-level failure.
            result = await self._dispatch_restore_via_contributors(
                archive,
                organization_id=organization_id,
                dry_run=dry_run,
                restore_options=restore_options,
                selected_contributors=contributors,
            )
            job.progress = 90

            # Finalize. The result shape is now {contributors:[...], summary:{...}}
            # rather than the old per-model dict, but the UI's restore-
            # detail page already renders structured JSON so the change
            # is forward-compatible.
            if dry_run:
                job.dry_run_report = result
            else:
                job.restore_log = result
            summary = result.get("summary", {})
            job.items_restored = summary.get("total_created", 0) + summary.get("total_updated", 0)
            # Deliberately preserved records are skips, not failed writes.
            # Some module failures have no reliable record count; their status
            # and errors still fail the job even when items_failed is zero.
            job.items_failed = sum(
                sum(section.get("skipped", {}).values())
                for section in result.get("contributors", [])
                if section.get("status") in {"error", "schema_mismatch"}
            )
            failed = bool(summary.get("contributors_failed", 0) or summary.get("total_errors", 0))
            job.status = "failed" if failed else "completed"
            job.error_message = (
                (
                    "Restore preview found errors; no configuration was applied. Review the contributor report."
                    if dry_run
                    else "Restore finished with errors. Other sections may have been applied; "
                    "review the contributor report before retrying."
                )
                if failed
                else None
            )
            job.completed_at = datetime.now(UTC)
            job.progress = 100
            await self.db.commit()
            await self.db.refresh(job)
            return job

        except Exception as e:
            # NOTE H8: rollback any pending writes (including the failed
            # SAVEPOINT) before we update the job to "failed".
            await self.db.rollback()
            job.status = "failed"
            job.error_message = backup_failure_detail(
                e, "Backup restore failed; review archive and destination access before retrying."
            )
            job.completed_at = datetime.now(UTC)
            self.db.add(job)
            await self.db.commit()
            raise

    async def restore_fresh_instance_from_vault(
        self,
        file_bytes: bytes,
        *,
        passphrase: str,
        org_name: str | None = None,
    ) -> dict[str, Any]:
        """First-install restore: rebuild a fresh instance from an uploaded ``.fsdnvault``.

        Drives the setup wizard's "Restore from Backup" branch (no org / no admin exists
        yet). Decrypts the file with the operator passphrase — the salt rides in the
        header, so NO origin DB row is needed — recreates the Organization with its
        ORIGINAL id (orgs are never inside a backup; matching the id means the archive's
        org-scoped records are accepted instead of rejected as cross-tenant), then
        restores every contributor INCLUDING secrets, re-keyed onto THIS instance. The
        restored super_admin makes setup complete and the operator's old login works.
        """
        from app.models.core import Organization, User, UserRole
        from app.services.backup_contributors import (
            BackupArchive,
            is_legacy_v1_payload,
            wrap_legacy_v1_as_archive,
        )

        # 1. Parse + decrypt (key_id from the self-describing header — portable).
        if len(file_bytes) < 4:
            raise BackupInputError("not a FreeSDN backup file")
        header_len = int.from_bytes(file_bytes[:4], "big")
        try:
            header = json.loads(file_bytes[4 : 4 + header_len].decode("utf-8"))
        except Exception as exc:
            raise BackupInputError("unrecognized backup file") from exc
        payload = file_bytes[4 + header_len :]
        if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
            raise BackupInputError("checksum verification failed — the file is corrupt")
        if not header.get("secrets"):
            raise BackupInputError(
                "this is a config snapshot (.fsdn), not a full backup — first-install "
                "restore needs a secure .fsdnvault that carries your accounts + credentials"
            )
        if header.get("encrypted"):
            key_id = header.get("key_id")
            if not key_id:
                raise BackupInputError(
                    "encrypted file is missing its key descriptor — cannot restore"
                )
            if not passphrase:
                raise BackupInputError("a passphrase is required to restore a secure backup")
            # PBKDF2 is a synchronous CPU burn and this handler is
            # unauthenticated (only "no super_admin exists yet" gates it), so a
            # derive run inline stalls the whole event loop — /health, the setup
            # wizard and the frontend all stop being served for its duration.
            # _PBKDF2_ITERATIONS_MAX caps how long that can be; running it on a
            # worker thread keeps even a legitimate 600k derive off the loop.
            try:
                payload = await anyio.to_thread.run_sync(
                    BackupEncryption(master_key=passphrase).decrypt, payload, key_id
                )
            except ValueError:
                # Malformed / out-of-range key_id: _parse_key_id's message names
                # the actual problem with the file. Reporting it as a passphrase
                # mistake would send the operator chasing the wrong thing.
                raise
            except Exception as exc:
                raise BackupInputError("could not decrypt — wrong passphrase?") from exc
        if header.get("compressed"):
            payload = _bounded_gunzip(payload)
        config = json.loads(payload.decode("utf-8"))

        archive = (
            wrap_legacy_v1_as_archive(
                config,
                backup_id=str(header.get("backup_id") or ""),
                created_at=datetime.now(UTC),
                organization_id="",
            )
            if is_legacy_v1_payload(config)
            else BackupArchive.model_validate(config)
        )

        # 2. Find the original org id (every org-scoped record carries it). In the
        # assembled archive each contributor section IS its flat data dict
        # ({users, sites, controllers, ...}); tolerate a ContributorPayload too.
        core = archive.contributors.get("core")
        if hasattr(core, "data"):
            core_data = core.data or {}
        elif isinstance(core, dict):
            core_data = core
        else:
            core_data = {}
        org_id: UUID | None = None
        for key in ("users", "sites", "controllers"):
            for rec in core_data.get(key, []):
                oid = rec.get("organization_id")
                if oid:
                    try:
                        org_id = UUID(str(oid))
                    except (ValueError, TypeError):
                        continue
                    break
            if org_id is not None:
                break
        if org_id is None:
            raise BackupInputError("backup contains no organization-scoped data to restore")

        # A partial first-install restore can create an administrator and
        # close the setup gate before the remaining modules are recovered.
        # Keep every database change, including the organization, in one
        # savepoint so a failed contributor leaves this setup retryable.
        async with self.db.begin_nested():
            # 3. Recreate the Organization with its ORIGINAL id (so records match). The org
            # row itself is never inside a backup, so name/slug are synthesized — a unique
            # slug is derived from the preserved id (the operator can rename it later).
            existing_org = (
                await self.db.execute(
                    select(Organization).where(
                        Organization.id == org_id, Organization.deleted_at.is_(None)
                    )
                )
            ).scalar_one_or_none()
            if existing_org is None:
                self.db.add(
                    Organization(
                        id=org_id,
                        name=(org_name or "Restored Organization"),
                        slug=f"restored-{str(org_id).replace('-', '')[:16]}",
                    )
                )
                await self.db.flush()
            self.org_id = org_id

            # 4. Restore everything, re-keyed onto this instance.
            result = await self._dispatch_restore_via_contributors(
                archive,
                organization_id=org_id,
                dry_run=False,
                restore_options={
                    "include_secrets": True,
                    "restore_users": True,
                    "restore_devices": True,
                    "overwrite_existing": True,
                },
                selected_contributors=None,
            )
            summary = result.get("summary", {})
            if summary.get("contributors_failed", 0) or summary.get("total_errors", 0):
                raise BackupRecoveryError(
                    "Vault restore did not complete; no setup changes were committed. "
                    "Check required modules and archive compatibility before retrying."
                )
            await self.db.flush()
            administrator = await self.db.scalar(
                select(User.id)
                .where(
                    User.organization_id == org_id,
                    User.role == UserRole.SUPER_ADMIN,
                    User.is_active.is_(True),
                    User.deleted_at.is_(None),
                )
                .limit(1)
            )
            if administrator is None:
                raise BackupRecoveryError(
                    "Vault restore did not include an active administrator; no setup "
                    "changes were committed. Choose a full backup containing an active "
                    "super administrator before retrying."
                )
        return {"organization_id": str(org_id), "result": result}

    async def _restore_data(
        self,
        data: dict[str, Any],
        *,
        dry_run: bool,
        overwrite_existing: bool,
        restore_devices: bool,
        restore_users: bool,
        include_secrets: bool = False,
    ) -> dict[str, Any]:
        """Restore sites, credentials and their consumers in dependency order.

        NOTE H4: organization_id is forced to ``self.org_id`` on every insert.
        Records whose stored organization_id doesn't match are REJECTED
        (not silently rewritten — the rewriter policy is risky because it
        masks restore-into-wrong-tenant mistakes).
        NOTE H8: caller wraps this in ``self.db.begin()`` so a half-applied
        restore rolls back cleanly.
        """
        # NOTE C4/H3: Organization is intentionally excluded from the restore
        # map. A restore must NEVER create or modify Organization rows.
        from app.models import Controller, Credential, Device, Site, User, UserRole, UserSiteAccess
        from app.models.automation import AutomationRuleRecord
        from app.models.sso import SSOProvider
        from app.services.backup_contributors.account_security import (
            administrator_bits,
            destination_fields,
            merge_existing_user,
            require_administrator_survivors,
            require_same_provider_security,
            validate_snapshot,
        )
        from app.services.backup_contributors.account_security_codec import (
            AccountSecurityFormatError,
        )

        if self.org_id is None:
            raise ValueError("BackupService.org_id must be set before _restore_data")

        security_restore = include_secrets and restore_users
        if security_restore:
            data = {**data, **validate_snapshot(data, self.org_id)}
        if restore_users and not dry_run:
            # Configuration profile restore also locks User rows after Sites;
            # join lifecycle coordination before either class of resource lock.
            from app.core.user_lifecycle import try_lock_user_lifecycle

            if not await try_lock_user_lifecycle(self.db):
                raise AccountSecurityFormatError(
                    "Account lifecycle changes are in progress. No core restore changes were applied; retry the vault restore."
                )
        preserved_destination_users: set[UUID] = set()
        administrator_transitions: list[tuple[bool, bool, bool, bool]] = []

        # NOTE H4/H5: identical blocked-field set on BOTH update and insert.
        # A config-snapshot restore blocks identity/secret fields (they're never in the
        # payload anyway). A VAULT restore (include_secrets) intentionally restores them
        # so old logins survive — controller ``config`` secrets are RE-ENCRYPTED under
        # THIS instance's key in the loop below before they touch the DB.
        #: Columns a NON-SECRET (.fsdn config-only) restore must never write.
        #:
        #: A config-only export deliberately emits credential rows with every
        #: secret column set to literal None, so device foreign keys still
        #: resolve -- see _cred_secret() and the test at
        #: tests/services/test_backup_credential_vault.py:174-182, which states
        #: the intent as "only the secrets are withheld".
        #:
        #: The overwrite branch below does setattr(existing, k, v) for every key
        #: not blocked here. So restoring yesterday's config snapshot with
        #: "Overwrite existing" wrote those Nones straight over the live
        #: ciphertext: SSH private keys, API keys, tokens, certificates and SNMP
        #: communities for every credential in the org, with the job reporting
        #: credentials: {updated: N} and completing green. The operator's next
        #: device poll fails everywhere and the secrets are unrecoverable.
        #:
        #: Every MODULE contributor already guards exactly this -- firewall
        #: passes {"credentials"}, voip {"voicemail_pin"}, cameras and network
        #: their own sets -- but the core restore, which owns the credentials
        #: table itself, did not. Blocking by column NAME across every table is
        #: the correct conservative rule here: in a no-secrets restore, a secret
        #: column carries None by construction, so it must never be written.
        #: Reuses the module-level CREDENTIAL_SECRET_FIELDS rather than a second
        #: copy, so a secret column added to the model is blocked here the moment
        #: it is added there. test_every_secret_column_is_covered already pins
        #: that list against the model.
        _BLOCKED_FIELDS = (
            {"id", "organization_id"}
            if include_secrets
            else {
                "id",
                "hashed_password",
                "password_hash",
                "role",
                "is_superuser",
                "mfa_secret",
                "organization_id",
                *CREDENTIAL_SECRET_FIELDS,
            }
        )

        _BLOCKED_FIELDS |= {"created_at", "updated_at", "created_by", "updated_by", "deleted_at"}

        user_profile_fields = {"full_name", "language", "preferences"}
        user_create_fields = user_profile_fields | {"email", "username"}

        result: dict[str, Any] = {}
        restore_map = [
            ("sites", Site),
            # Restore dependencies before consumers in both preview and apply.
            ("credentials", Credential),
            ("controllers", Controller),
            # Collected since the feature shipped, but nothing ever restored
            # them -- the rules rode along in the file and were dropped on the
            # way back in. They reference only the organization, so ordering
            # against the rest does not matter.
            ("automation_rules", AutomationRuleRecord),
        ]
        if restore_devices:
            restore_map.append(("devices", Device))
        if restore_users:
            if security_restore:
                restore_map.append(("sso_providers", SSOProvider))
            restore_map.append(("users", User))
            # AFTER users: a grant's user_id references the row restored above.
            # Gated on restore_users for the same reason — restoring grants for
            # users that were not restored would either dangle or, worse, apply
            # one org's access model to another instance's accounts.
            restore_map.append(("user_site_access", UserSiteAccess))

        from types import SimpleNamespace

        from sqlalchemy import Uuid

        from app.models.enterprise import SiteGroup

        # Loaded rows are refreshed, and application holds both resource and
        # parent rows through the surrounding contributor transaction. Preview
        # is advisory and revalidates without locks when actually applied.
        loaded: dict[tuple[Any, UUID], Any] = {}
        accepted: dict[tuple[Any, UUID], Any] = {}
        moved_parents: set[tuple[Any, UUID]] = set()

        async def load(model: Any, identifier: Any) -> Any:
            if identifier is None:
                return None
            identity = identifier if isinstance(identifier, UUID) else UUID(str(identifier))
            key = (model, identity)
            if key not in loaded:
                query = (
                    select(model)
                    .where(model.id == identity)
                    .execution_options(populate_existing=True)
                )
                if not dry_run:
                    query = query.with_for_update()
                loaded[key] = (await self.db.execute(query)).scalars().first()
            return loaded[key]

        async def owned(model: Any, row: Any) -> bool:
            if row is None or getattr(row, "deleted_at", None) is not None:
                return False
            if model in (Controller, Device):
                return await owned(Site, await load(Site, row.site_id))
            if model is UserSiteAccess:
                return await owned(Site, await load(Site, row.site_id)) and await owned(
                    User, await load(User, row.user_id)
                )
            return getattr(row, "organization_id", None) == self.org_id

        async def reference(model: Any, identifier: Any) -> Any:
            if identifier is None:
                return None
            identity = identifier if isinstance(identifier, UUID) else UUID(str(identifier))
            key = (model, identity)
            if key in accepted:
                return accepted[key]
            row = await load(model, identity)
            return row if await owned(model, row) else None

        for key, model_cls in restore_map:
            columns = {prop.key: prop.columns[0] for prop in model_cls.__mapper__.column_attrs}
            uuid_columns = {
                field
                for field, column in columns.items()
                if isinstance(column.type, Uuid) and column.type.as_uuid
            }
            records = data.get(key, [])
            seen: set[UUID] = set()
            created = 0
            updated = 0
            skipped = 0
            rejected_org = 0

            for record in records:
                # Only explicit vault recovery can reinstate account access.
                # Config snapshots may carry old grants, but must not undo
                # current permission decisions or activate imported profiles.
                if model_cls is UserSiteAccess and not include_secrets:
                    skipped += 1
                    continue
                # JSON carries UUIDs as strings, whereas mapped UUID columns
                # expect UUID objects. Bulk INSERT RETURNING correlates these
                # identities in Python; implicit driver coercion is insufficient.
                # Convert only mapped columns, leaving JSON payloads untouched.
                portable_security_record = dict(record)
                record = dict(record)
                try:
                    for field in uuid_columns:
                        value = record.get(field)
                        if value is None or isinstance(value, UUID):
                            continue
                        if not isinstance(value, str):
                            raise ValueError("Invalid archived UUID")
                        record[field] = UUID(value)
                except ValueError:
                    skipped += 1
                    continue

                # Vault restore: the controller ``config`` arrived with its secret fields
                # DECRYPTED inside the passphrase-sealed payload. Re-encrypt those fields
                # INDIVIDUALLY under THIS instance's SECRET_KEY (matching how the live app
                # stores them) so plaintext creds never land in the DB and the controller
                # decrypts on this instance.
                if (
                    include_secrets
                    and model_cls is Controller
                    and isinstance(record.get("config"), dict)
                ):
                    from app.core.crypto import encrypt_credential, is_encrypted

                    cfg = dict(record["config"])
                    for k in CONTROLLER_SECRET_CONFIG_KEYS:
                        v = cfg.get(k)
                        if isinstance(v, str) and v and not is_encrypted(v):
                            cfg[k] = encrypt_credential(v)
                    record = {**record, "config": cfg}

                # Same treatment for the credential vault, whose secrets are
                # top-level COLUMNS rather than a config dict. They arrived
                # decrypted inside the passphrase-sealed payload; re-encrypt each
                # under THIS instance's SECRET_KEY so plaintext never reaches the
                # database.
                if include_secrets and model_cls is Credential:
                    from app.core.crypto import encrypt_credential, is_encrypted

                    fixed = dict(record)
                    for field in CREDENTIAL_SECRET_FIELDS:
                        v = fixed.get(field)
                        if isinstance(v, str) and v and not is_encrypted(v):
                            fixed[field] = encrypt_credential(v)
                    record = fixed

                # NOTE H4: reject any record claiming a foreign org.
                rec_org = record.get("organization_id")
                if rec_org and str(rec_org) != str(self.org_id):
                    rejected_org += 1
                    skipped += 1
                    continue

                pk = record.get("id")
                if not pk:
                    skipped += 1
                    continue

                if pk in seen:
                    raise ValueError("Core restore contains duplicate resource identifiers.")
                seen.add(pk)
                existing = await load(model_cls, pk)
                if existing is not None and not await owned(model_cls, existing):
                    if security_restore and model_cls in (User, UserSiteAccess, SSOProvider):
                        raise AccountSecurityFormatError(
                            "Account-security destination ownership conflicts with the archive."
                        )
                    rejected_org += 1
                    skipped += 1
                    continue

                # Validate effective references, including values retained when
                # overwrite is disabled. A payload claim alone never authorizes
                # a rejected parent or another tenant's existing resource.
                def value(
                    field: str, row: Any = existing, archived: dict[str, Any] = record
                ) -> Any:
                    if (row is None or overwrite_existing) and field in archived:
                        return archived[field]
                    return getattr(row, field, None) if row is not None else None

                refs_valid = True
                if model_cls in (Controller, Device, Credential):
                    site_id = value("site_id")
                    site = await reference(Site, site_id)
                    refs_valid = site is not None or (model_cls is Credential and site_id is None)
                    if model_cls in (Controller, Device) and refs_valid:
                        credential_id = value("credential_id")
                        if credential_id is not None:
                            credential = await reference(Credential, credential_id)
                            refs_valid = credential is not None and (
                                getattr(credential, "site_id", None) is None
                                or credential.site_id == site_id
                            )
                        if model_cls is Device and value("controller_id") is not None:
                            controller = await reference(Controller, value("controller_id"))
                            refs_valid = (
                                refs_valid
                                and controller is not None
                                and controller.site_id == site_id
                            )
                elif model_cls is UserSiteAccess:
                    refs_valid = (
                        await reference(Site, value("site_id")) is not None
                        and await reference(User, value("user_id")) is not None
                    )
                elif model_cls is Site and value("site_group_id") is not None:
                    refs_valid = await reference(SiteGroup, value("site_group_id")) is not None
                elif model_cls is User and include_secrets and value("sso_provider_id") is not None:
                    refs_valid = await reference(SSOProvider, value("sso_provider_id")) is not None
                if not refs_valid:
                    if security_restore and model_cls in (User, UserSiteAccess, SSOProvider):
                        raise AccountSecurityFormatError(
                            "Account-security restore requires every referenced parent."
                        )
                    rejected_org += 1
                    skipped += 1
                    continue
                if (
                    security_restore
                    and model_cls is UserSiteAccess
                    and record.get("user_id") in preserved_destination_users
                ):
                    skipped += 1
                    continue
                if existing is None and model_cls is UserSiteAccess:
                    # ix_user_site_access_user_site is UNIQUE on (user_id,
                    # site_id). A grant re-created by hand after the backup has
                    # the same pair under a DIFFERENT id, so inserting the
                    # archived row raises at flush — and that takes the whole
                    # core section down with it, not just this record. Match on
                    # the unique key as well as the pk.
                    query = (
                        select(UserSiteAccess)
                        .where(
                            UserSiteAccess.user_id == record.get("user_id"),
                            UserSiteAccess.site_id == record.get("site_id"),
                        )
                        .execution_options(populate_existing=True)
                    )
                    if not dry_run:
                        query = query.with_for_update()
                    existing = (await self.db.execute(query)).scalars().first()
                    if existing is not None and not await owned(model_cls, existing):
                        rejected_org += 1
                        skipped += 1
                        continue
                if security_restore and model_cls in (User, SSOProvider):
                    portable = portable_security_record
                    if model_cls is SSOProvider and existing is not None:
                        require_same_provider_security(portable, existing)
                    elif model_cls is User:
                        if (existing is None or overwrite_existing) and portable[
                            "sso_provider_id"
                        ] is not None:
                            # The incoming archive can be internally unique yet
                            # collide with a different destination account. Check
                            # preview and apply without transferring that identity.
                            # Apply already owns lifecycle coordination; the DB
                            # unique index also covers independent legacy writers.
                            collision = await self.db.scalar(
                                select(User.id)
                                .where(
                                    User.sso_provider_id == UUID(portable["sso_provider_id"]),
                                    User.external_id == portable["external_id"],
                                    User.deleted_at.is_(None),
                                    User.id != pk,
                                )
                                .limit(1)
                            )
                            if collision is not None:
                                raise AccountSecurityFormatError(
                                    "External identity already belongs to another destination account; "
                                    "an explicit authenticated account migration is required."
                                )
                        if existing is None:
                            portable = {**portable, "token_version": portable["token_version"] + 1}
                        elif overwrite_existing:
                            current_grants = {
                                (str(site), level)
                                for site, level in (
                                    await self.db.execute(
                                        select(
                                            UserSiteAccess.site_id, UserSiteAccess.access_level
                                        ).where(UserSiteAccess.user_id == existing.id)
                                    )
                                ).all()
                            }
                            archived_grants = {
                                (row["site_id"], row["access_level"])
                                for row in data["user_site_access"]
                                if row["user_id"] == str(existing.id)
                            }
                            portable = merge_existing_user(
                                portable, existing, current_grants, archived_grants
                            )
                        else:
                            preserved_destination_users.add(existing.id)
                    record = destination_fields(portable, provider=model_cls is SSOProvider)
                    if model_cls is User and (existing is None or overwrite_existing):
                        before_bits = (
                            administrator_bits(existing.is_active, existing.role)
                            if existing
                            else (False, False)
                        )
                        after_bits = administrator_bits(record["is_active"], record["role"])
                        administrator_transitions.append((*before_bits, *after_bits))
                    for field in uuid_columns:
                        if record.get(field) is not None:
                            record[field] = UUID(str(record[field]))
                if existing:
                    if (
                        model_cls in (Controller, Credential)
                        and overwrite_existing
                        and value("site_id") != existing.site_id
                    ):
                        moved_parents.add((model_cls, pk))
                    # H4: never touch a row owned by a different org.
                    existing_org = getattr(existing, "organization_id", None)
                    if existing_org and existing_org != self.org_id:
                        rejected_org += 1
                        skipped += 1
                        continue
                    if model_cls is User and include_secrets and overwrite_existing:
                        # Restoring login or authority is a security change. Never
                        # reuse an archived counter or leave destination sessions
                        # valid after replacing the account. The row was refreshed
                        # and locked above; validate during preview as well.
                        current_version = existing.token_version
                        archived_version = record.get("token_version", current_version)
                        versions = (current_version, archived_version)
                        if any(
                            type(version) is not int or not 0 <= version < 2**31 - 1
                            for version in versions
                        ):
                            raise ValueError(
                                "Account restore requires valid non-exhausted token versions."
                            )
                        record = {**record, "token_version": max(versions) + 1}
                        # A snapshot predates later security decisions. Keep a
                        # destination account disabled; reactivation belongs to
                        # the explicit administrator account-management path.
                        if existing.is_active is False and record.get("is_active") is True:
                            record = {**record, "is_active": False}
                    if overwrite_existing and not dry_run:
                        for k, v in record.items():
                            if (
                                model_cls is User
                                and not include_secrets
                                and k not in user_profile_fields
                            ):
                                continue
                            if k != "id" and k in columns and k not in _BLOCKED_FIELDS:
                                setattr(existing, k, v)
                        if model_cls is User and include_secrets:
                            from sqlalchemy import update

                            from app.models import UserSession
                            from app.models.api_keys import revoke_user_api_keys

                            await revoke_user_api_keys(self.db, existing.id)
                            await self.db.execute(
                                update(UserSession)
                                .where(UserSession.user_id == existing.id)
                                .values(
                                    is_revoked=True,
                                    revoked_at=func.coalesce(
                                        UserSession.revoked_at, datetime.now(UTC)
                                    ),
                                )
                            )
                        updated += 1
                    else:
                        skipped += 1
                else:
                    if not dry_run:
                        # NOTE H5: apply _BLOCKED_FIELDS on insert too.
                        clean = {
                            k: v
                            for k, v in record.items()
                            if k in columns and k not in _BLOCKED_FIELDS
                        }
                        if model_cls is User and not include_secrets:
                            clean = {k: v for k, v in clean.items() if k in user_create_fields}
                            # This is a profile, not a recovered login. Require
                            # normal account setup and separately assigned access.
                            clean.update(
                                hashed_password="!",
                                role=UserRole.VIEWER,
                                is_active=False,
                                is_verified=False,
                            )
                        # PRESERVE the original primary key on insert so intra-core FKs
                        # resolve (e.g. a restored Controller's site_id points at the
                        # restored Site) and the restore is faithful — matching the
                        # contributor restore_records helper. ``id`` stays in
                        # _BLOCKED_FIELDS so an UPDATE never rewrites it; only the
                        # not-yet-existing INSERT path sets it here.
                        clean["id"] = pk
                        # NOTE H4: force the caller's org on every insert.
                        if hasattr(model_cls, "organization_id"):
                            clean["organization_id"] = self.org_id
                        self.db.add(model_cls(**clean))
                    created += 1

                if not dry_run:
                    # A database rejection fails the complete contributor. Do
                    # not retain success counts or accept its parent identity.
                    await self.db.flush()
                if existing is not None:
                    if dry_run and overwrite_existing:
                        fields = {field: getattr(existing, field) for field in columns}
                        fields.update(
                            {
                                k: v
                                for k, v in record.items()
                                if k in columns and k not in _BLOCKED_FIELDS
                            }
                        )
                        accepted[(model_cls, pk)] = SimpleNamespace(**fields)
                    else:
                        accepted[(model_cls, pk)] = existing
                else:
                    fields = {
                        k: v for k, v in record.items() if k in columns and k not in _BLOCKED_FIELDS
                    }
                    if "organization_id" in columns:
                        fields["organization_id"] = self.org_id
                    accepted[(model_cls, pk)] = SimpleNamespace(id=pk, **fields)

            result[key] = {
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "rejected_cross_org": rejected_org,
            }

        # A parent may move only if every retained dependent remains coherent.
        # Check the final accepted graph, including rows omitted from the archive
        # and rows whose incoming edits were rejected. Preview uses virtual rows;
        # application uses flushed rows and locks every retained dependent. A
        # failure is a contributor error: its dispatcher savepoint rolls back ALL
        # core writes, including earlier accepted records.
        for model, identity in moved_parents:
            parent = accepted[(model, identity)]
            if model is Credential and parent.site_id is None:
                continue  # Organization-wide credentials may serve any owned site.
            dependents = (
                ((Device, "controller_id"),)
                if model is Controller
                else (
                    (Controller, "credential_id"),
                    (Device, "credential_id"),
                )
            )
            for child_model, field in dependents:
                query = (
                    select(child_model)
                    .where(
                        getattr(child_model, field) == identity,
                    )
                    .execution_options(populate_existing=True)
                )
                if not dry_run:
                    query = query.with_for_update()
                for stored in (await self.db.execute(query)).scalars().all():
                    child = accepted.get((child_model, stored.id), stored)
                    if getattr(child, field, None) == identity and child.site_id != parent.site_id:
                        raise ValueError(
                            "Core restore would leave dependent resources in another site."
                        )

        if not dry_run:
            await self.db.flush()
        if security_restore:
            await require_administrator_survivors(
                self.db,
                self.org_id,
                administrator_transitions,
                dry_run=dry_run,
            )
        return result

    # -------------------------------------------------------------------------
    # List / Get / Delete
    # -------------------------------------------------------------------------

    async def list_backups(
        self,
        *,
        site_id: UUID | None = None,
        backup_type: str | None = None,
        status: str | None = None,
        storage_type: str | None = None,
        search: str | None = None,
        page: int = 1,
        per_page: int = 20,
        organization_id: UUID | None = None,
        accessible_site_ids: set[UUID] | list[UUID] | None = None,
    ) -> dict[str, Any]:
        """Paginated backup listing with filters.

        ``accessible_site_ids`` restricts the result to a site-limited caller's
        grants IN SQL. The endpoint used to filter the returned PAGE in Python
        instead, which meant the database happily returned 20 rows the caller
        could not see, the filter removed all of them, and the operator was told
        "No backups (0)" while their granted site had plenty on page 2. An empty
        collection is fail-closed: no grants means no rows, not all rows.
        """
        if organization_id:
            base_query = self._scoped_backup_select(organization_id)
            query = base_query.order_by(Backup.created_at.desc())
            count_source = base_query.subquery()
            count_query = select(func.count()).select_from(count_source)
        else:
            query = select(Backup).order_by(Backup.created_at.desc())
            count_query = select(func.count(Backup.id))

        # Filters
        if site_id:
            query = query.where(Backup.site_id == site_id)
            if organization_id:
                count_query = count_query.where(count_source.c.site_id == site_id)
            else:
                count_query = count_query.where(Backup.site_id == site_id)
        if accessible_site_ids is not None:
            allowed = list(accessible_site_ids)
            query = query.where(Backup.site_id.in_(allowed))
            if organization_id:
                count_query = count_query.where(count_source.c.site_id.in_(allowed))
            else:
                count_query = count_query.where(Backup.site_id.in_(allowed))
        if backup_type:
            query = query.where(Backup.backup_type == backup_type)
            if organization_id:
                count_query = count_query.where(count_source.c.backup_type == backup_type)
            else:
                count_query = count_query.where(Backup.backup_type == backup_type)
        if status:
            query = query.where(Backup.status == status)
            if organization_id:
                count_query = count_query.where(count_source.c.status == status)
            else:
                count_query = count_query.where(Backup.status == status)
        if storage_type:
            query = query.where(Backup.storage_type == storage_type)
            if organization_id:
                count_query = count_query.where(count_source.c.storage_type == storage_type)
            else:
                count_query = count_query.where(Backup.storage_type == storage_type)
        if search:
            escaped_search = escape_like(search)
            query = query.where(Backup.name.ilike(f"%{escaped_search}%", escape="\\"))
            if organization_id:
                count_query = count_query.where(
                    count_source.c.name.ilike(f"%{escaped_search}%", escape="\\")
                )
            else:
                count_query = count_query.where(
                    Backup.name.ilike(f"%{escaped_search}%", escape="\\")
                )

        # Pagination
        total = (await self.db.execute(count_query)).scalar() or 0
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        result = await self.db.execute(query)
        items = result.scalars().all()

        pages = (total + per_page - 1) // per_page if per_page > 0 else 0

        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    async def get_backup(self, backup_id: UUID) -> Backup | None:
        return await self.db.get(Backup, backup_id)

    @complete_before_cancellation
    async def delete_backup(self, backup_id: UUID) -> bool:
        """Delete backup record and storage file."""
        backup = await self.db.get(Backup, backup_id)
        if not backup:
            return False

        if backup.remote_write_recovery_required:
            raise HTTPException(
                409, "Remote write outcome requires explicit recovery; the record is retained"
            )

        # Delete from storage
        if backup.storage_path:
            try:
                backend, _ = await self._resolve_storage(
                    backup.storage_type, backup.storage_location_id
                )
                if not getattr(backend, "SUPPORTS_DELETE", True):
                    # A destination that cannot prune. Removing the record while the file
                    # stays on the appliance is an orphan, and doing it in a
                    # debug log is how a NAS silently fills. Surface it loudly
                    # and keep the record so the file is still accounted for.
                    logger.warning(
                        "Backup %s is on a %s destination that cannot auto-delete; "
                        "the file at %s remains on the appliance. Prune it there, "
                        "or set a ZFS retention policy on the dataset.",
                        backup_id,
                        backup.storage_type,
                        backup.storage_path,
                    )
                    raise StorageDeleteUnsupported(backup.storage_type)
                if await backend.delete(backup.storage_path) is not True:
                    raise RuntimeError("Storage did not acknowledge deletion")
            except StorageDeleteUnsupported:
                # Deliberately NOT deleting the record: the file is still there,
                # and a record pointing at it is better than a silent orphan.
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail=(
                        f"This backup is stored on a {backup.storage_type} appliance, "
                        "which FreeSDN cannot prune through its API. Remove the file "
                        "on the appliance (or set a ZFS retention policy); the backup "
                        "record is kept so the file is not orphaned."
                    ),
                )
            except Exception as exc:
                # Keep the catalog row so an unconfirmed file is still visible
                # and retryable. Provider exceptions may contain credentials or
                # signed URLs, so neither logs nor the API echo their text.
                logger.warning(
                    "Backup storage deletion was not confirmed for %s (%s)",
                    backup_id,
                    type(exc).__name__,
                )
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Backup storage deletion could not be confirmed. "
                        "The backup record is retained; check the destination and retry."
                    ),
                ) from None

        await self.db.delete(backup)
        await self.db.commit()
        return True

    async def local_download_source(
        self, backup: Backup, *, backend: BackupStorageBackend | None = None
    ) -> LocalDownloadSource | None:
        """Copy a local download plan without opening a file or retaining ORM state.

        The route has already applied its organization/site/secret-vault gates.
        Remote transports retain their existing behavior pending bounded SDK work.
        """
        if not backup.storage_path:
            return None
        if backup.status != BackupStatus.COMPLETED:
            raise BackupInputError("Backup is not completed.")
        try:
            recorded_identity(backup.metadata_json)
            if backend is None:
                backend, _ = await self._resolve_storage(
                    backup.storage_type, backup.storage_location_id
                )
            if not isinstance(backend, LocalStorageBackend):
                return None
            return LocalDownloadSource(
                backend.base_path,
                backup.storage_path,
                backup.metadata_json,
                MAX_BACKUP_IMPORT_BYTES,
            )
        except BackupArtifactError as error:
            raise BackupInputError(str(error)) from None

    def webdav_download_source(
        self, backup: Backup, *, backend: BackupStorageBackend
    ) -> Callable[[DownloadSnapshot], Awaitable[None]] | None:
        """Copy remote intent without retaining a session or mutable ORM row."""
        if not isinstance(backend, WebDAVStorageBackend) or not backup.storage_path:
            return None
        if backup.status != BackupStatus.COMPLETED:
            raise BackupInputError("Backup is not completed.")
        try:
            expected = recorded_identity(backup.metadata_json)
        except BackupArtifactError as error:
            raise BackupInputError(str(error)) from None
        return partial(backend.copy_download_into, backup.storage_path, expected)

    async def download_backup(
        self, backup_id: UUID, *, backend: BackupStorageBackend | None = None
    ) -> tuple[bytes, str] | None:
        """Download a backup file. Returns (data, filename) or None."""
        backup = await self.db.get(Backup, backup_id)
        if not backup or not backup.storage_path:
            return None

        if backup.status != BackupStatus.COMPLETED:
            raise BackupInputError("Backup is not completed.")
        data, _ = await self._load_catalogue_artifact(backup, backend=backend)
        filename = (
            backup.storage_path.rsplit("/", 1)[-1]
            if "/" in backup.storage_path
            else backup.storage_path
        )
        return data, filename

    # -------------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------------

    async def get_stats(
        self, site_id: UUID | None = None, organization_id: UUID | None = None
    ) -> dict[str, Any]:
        """Get backup statistics."""
        # when the request caller is site-limited, constrain every
        # aggregate (status / size / recent / schedule counts) to their granted
        # sites; org-level (site_id IS NULL) backups stay visible. None =
        # unrestricted / admin / background context (no-op).
        _granted = site_ids_for_request()
        if organization_id:
            base_source = self._scoped_backup_select(organization_id).subquery()
            base = self._scoped_backup_select(organization_id)
            if site_id:
                base = base.where(Backup.site_id == site_id)
            if _granted is not None:
                base = base.where(or_(Backup.site_id.is_(None), Backup.site_id.in_(_granted)))

            _src_grant = (
                or_(base_source.c.site_id.is_(None), base_source.c.site_id.in_(_granted))
                if _granted is not None
                else None
            )
            status_query = select(
                base_source.c.status,
                func.count(base_source.c.id),
            ).group_by(base_source.c.status)
            if site_id:
                status_query = status_query.where(base_source.c.site_id == site_id)
            if _granted is not None:
                status_query = status_query.where(_src_grant)

            size_query = select(func.coalesce(func.sum(base_source.c.file_size), 0))
            if site_id:
                size_query = size_query.where(base_source.c.site_id == site_id)
            if _granted is not None:
                size_query = size_query.where(_src_grant)

            # NOTE C3: ``BackupSchedule.is_enabled`` (NOT ``BackupSchedule.organization_id``)
            # join through Site was needed before BackupSchedule had a direct
            # organization_id. We now scope schedules directly by org and
            # use ``.is_(False)`` because Python's unary ``not`` operates at
            # evaluation time (returning a plain bool) instead of producing
            # a SQL expression.
            enabled_q = select(func.count(BackupSchedule.id)).where(
                BackupSchedule.is_enabled.is_(True),
                BackupSchedule.organization_id == organization_id,
            )
            disabled_q = select(func.count(BackupSchedule.id)).where(
                BackupSchedule.is_enabled.is_(False),
                BackupSchedule.organization_id == organization_id,
            )
            if _granted is not None:
                _sched_grant = or_(
                    BackupSchedule.site_id.is_(None), BackupSchedule.site_id.in_(_granted)
                )
                enabled_q = enabled_q.where(_sched_grant)
                disabled_q = disabled_q.where(_sched_grant)
        else:
            base = select(Backup)
            if site_id:
                base = base.where(Backup.site_id == site_id)
            _bk_grant = (
                or_(Backup.site_id.is_(None), Backup.site_id.in_(_granted))
                if _granted is not None
                else None
            )
            if _granted is not None:
                base = base.where(_bk_grant)

            status_query = select(
                Backup.status,
                func.count(Backup.id),
            ).group_by(Backup.status)
            if site_id:
                status_query = status_query.where(Backup.site_id == site_id)
            if _granted is not None:
                status_query = status_query.where(_bk_grant)

            size_query = select(func.coalesce(func.sum(Backup.file_size), 0))
            if site_id:
                size_query = size_query.where(Backup.site_id == site_id)
            if _granted is not None:
                size_query = size_query.where(_bk_grant)

            # NOTE C3: ``.is_(False)`` is the SQL-expression form; the
            # previous ``not BackupSchedule.is_enabled`` was evaluated by
            # Python at query-build time and produced a constant False
            # WHERE clause that always counted zero rows.
            enabled_q = select(func.count(BackupSchedule.id)).where(
                BackupSchedule.is_enabled.is_(True)
            )
            disabled_q = select(func.count(BackupSchedule.id)).where(
                BackupSchedule.is_enabled.is_(False)
            )
            if _granted is not None:
                _sched_grant = or_(
                    BackupSchedule.site_id.is_(None), BackupSchedule.site_id.in_(_granted)
                )
                enabled_q = enabled_q.where(_sched_grant)
                disabled_q = disabled_q.where(_sched_grant)

        result = await self.db.execute(status_query)
        status_counts = {row[0]: row[1] for row in result.all()}

        total_size = (await self.db.execute(size_query)).scalar() or 0

        enabled = (await self.db.execute(enabled_q)).scalar() or 0
        disabled = (await self.db.execute(disabled_q)).scalar() or 0

        # Recent backups
        recent_q = base.order_by(Backup.created_at.desc()).limit(5)
        recent = (await self.db.execute(recent_q)).scalars().all()

        total = sum(status_counts.values())

        return {
            "total_backups": total,
            "completed_backups": status_counts.get("completed", 0),
            "failed_backups": status_counts.get("failed", 0),
            "in_progress": status_counts.get("in_progress", 0) + status_counts.get("pending", 0),
            "total_size_bytes": total_size,
            "total_size_gb": round(total_size / (1024**3), 2) if total_size else 0.0,
            "recent_backups": recent,
            "schedules_enabled": enabled,
            "schedules_disabled": disabled,
        }

    # -------------------------------------------------------------------------
    # Schedules CRUD
    # -------------------------------------------------------------------------

    async def list_schedules(
        self,
        *,
        site_id: UUID | None = None,
        is_enabled: bool | None = None,
        organization_id: UUID | None = None,
    ) -> list[BackupSchedule]:
        if organization_id:
            query = self._scoped_schedule_select(organization_id).order_by(
                BackupSchedule.created_at.desc()
            )
        else:
            query = select(BackupSchedule).order_by(BackupSchedule.created_at.desc())
        if site_id:
            query = query.where(BackupSchedule.site_id == site_id)
        if is_enabled is not None:
            query = query.where(BackupSchedule.is_enabled == is_enabled)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_schedule(self, schedule_id: UUID) -> BackupSchedule | None:
        return await self.db.get(BackupSchedule, schedule_id)

    async def create_schedule(self, **kwargs: Any) -> BackupSchedule:
        # Calculate next_run_at from cron expression
        next_run = self._calculate_next_run(
            kwargs.get("cron_expression", "0 2 * * *"),
            kwargs.get("timezone", "UTC"),
        )
        schedule = BackupSchedule(next_run_at=next_run, **kwargs)
        self.db.add(schedule)
        await self.db.commit()
        await self.db.refresh(schedule)
        return schedule

    async def update_schedule(self, schedule_id: UUID, **kwargs: Any) -> BackupSchedule | None:
        schedule = await self.db.get(BackupSchedule, schedule_id)
        if not schedule:
            return None
        _ALLOWED = {
            "name",
            "description",
            "cron_expression",
            "timezone",
            "backup_type",
            "site_id",
            "device_ids",
            "is_enabled",
            "organization_id",
            "include_devices",
            "include_vlans",
            "include_ssids",
            "include_users",
            "include_automation",
            "storage_type",
            "storage_location_id",
            "is_encrypted",
            "retention_days",
            "max_backups",
        }
        # Validate before mutating the ORM row. Enabling through PUT follows
        # the same missed-run policy as the dedicated toggle endpoint.
        next_run = None
        if (
            kwargs.get("cron_expression") is not None
            or kwargs.get("timezone") is not None
            or kwargs.get("is_enabled") is True
        ):
            cron = kwargs.get("cron_expression")
            tz = kwargs.get("timezone")
            cron = schedule.cron_expression if cron is None else cron
            tz = schedule.timezone if tz is None else tz
            next_run = self._calculate_next_run(
                "0 2 * * *" if cron is None else cron,
                "UTC" if tz is None else tz,
            )
        for k, v in kwargs.items():
            if v is not None and k in _ALLOWED and hasattr(schedule, k):
                setattr(schedule, k, v)
        if next_run is not None:
            schedule.next_run_at = next_run
        await self.db.commit()
        await self.db.refresh(schedule)
        return schedule

    async def delete_schedule(self, schedule_id: UUID) -> bool:
        schedule = await self.db.get(BackupSchedule, schedule_id)
        if not schedule:
            return False
        await self.db.delete(schedule)
        await self.db.commit()
        return True

    async def toggle_schedule(self, schedule_id: UUID, is_enabled: bool) -> BackupSchedule | None:
        schedule = await self.db.get(BackupSchedule, schedule_id)
        if not schedule:
            return None
        if is_enabled:
            schedule.next_run_at = self._calculate_next_run(
                "0 2 * * *" if schedule.cron_expression is None else schedule.cron_expression,
                "UTC" if schedule.timezone is None else schedule.timezone,
            )
        schedule.is_enabled = is_enabled
        await self.db.commit()
        await self.db.refresh(schedule)
        return schedule

    def _calculate_next_run(self, cron_expr: str, tz: str = "UTC") -> datetime:
        """Honor the local calendar and persist its next occurrence in UTC."""
        from app.core.backup_schedule import next_backup_run

        return next_backup_run(cron_expr, tz, after=datetime.now(UTC))

    # -------------------------------------------------------------------------
    # Storage Locations CRUD
    # -------------------------------------------------------------------------

    async def list_storage_locations(
        self,
        *,
        storage_type: str | None = None,
        is_active: bool | None = None,
        organization_id: UUID | None = None,
    ) -> list[StorageLocation]:
        query = select(StorageLocation).order_by(StorageLocation.created_at.desc())
        if organization_id:
            query = query.where(StorageLocation.organization_id == organization_id)
        if storage_type:
            query = query.where(StorageLocation.storage_type == storage_type)
        if is_active is not None:
            query = query.where(StorageLocation.is_active == is_active)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_storage_location(self, loc_id: UUID) -> StorageLocation | None:
        return await self.db.get(StorageLocation, loc_id)

    async def create_storage_location(self, **kwargs: Any) -> StorageLocation:
        # NOTE C1+C2: extract sensitive fields from config and encrypt them
        # via app.core.crypto. Public config keeps only non-secret connection
        # data (host, region, bucket, etc.).
        # also handle the explicit ``credentials`` kwarg
        # (from StorageLocationCreate.credentials) so the operator can pass
        # credential-class keys through a dedicated field that bypasses the
        # credential-key validator on ``config``.
        from app.core.crypto import encrypt_credential

        cfg = dict(kwargs.get("config") or {})
        # SSRF guard at create time: backends re-check at client-construction
        # but rejecting at create-time gives the operator immediate feedback
        # and prevents persisting a stash of internal-IP locations that fail
        # mysteriously later.  Validate the ACTUAL field each backend uses:
        # - webdav uses ``url``
        # - s3 uses ``endpoint_url`` (optional S3-compatible override)
        # - ftp / sftp use ``host``
        storage_type = (kwargs.get("storage_type") or "").lower()
        _ssrf_validate_storage_cfg(storage_type, cfg)
        validate_policy(storage_type, cfg, creating=True)

        public, sensitive = self._extract_sensitive(cfg)
        kwargs["config"] = public

        # Merge the explicit credentials dict on top of
        # anything split from config.  Explicit credentials win on key conflicts.
        explicit_creds: dict[str, Any] = kwargs.pop("credentials", None) or {}
        if any(key not in self._SENSITIVE_STORAGE_FIELDS for key in explicit_creds):
            raise StorageConfigurationError("Credentials contain unsupported fields.")
        sensitive.update(explicit_creds)

        if sensitive:
            kwargs["encrypted_credentials"] = encrypt_credential(
                json.dumps(sensitive, separators=(",", ":"))
            )
        loc = StorageLocation(**kwargs)
        self.db.add(loc)
        await self.db.commit()
        await self.db.refresh(loc)
        return loc

    async def update_storage_location(self, loc_id: UUID, **kwargs: Any) -> StorageLocation | None:
        loc = await self.db.get(StorageLocation, loc_id)
        if not loc:
            return None
        # NOTE C2: encrypted_credentials added to _ALLOWED. The 'config'
        # field is split into public + sensitive halves before save.
        _ALLOWED = {
            "name",
            "description",
            "storage_type",
            "config",
            "is_active",
            "is_default",
            "encrypted_credentials",
        }

        if "config" in kwargs and kwargs["config"] is not None:
            storage_type = (kwargs.get("storage_type") or loc.storage_type or "").lower()
            config = {**(loc.config or {}), **kwargs["config"]}
            _ssrf_validate_storage_cfg(storage_type, config)
            validate_policy(storage_type, config)
            kwargs["config"] = config

        # If config is being updated, split out sensitive keys and
        # rotate the encrypted_credentials blob.
        if "config" in kwargs and kwargs["config"] is not None:
            public, sensitive = self._extract_sensitive(kwargs["config"])
            kwargs["config"] = public
        else:
            sensitive: dict[str, Any] = {}

        # handle the explicit ``credentials`` kwarg from
        # StorageLocationUpdate.credentials.  Merge on top of anything split
        # from ``config`` (explicit creds win on key conflicts) so the caller
        # can update just the credential portion without touching ``config``.
        explicit_creds: dict[str, Any] = kwargs.pop("credentials", None) or {}
        if any(key not in self._SENSITIVE_STORAGE_FIELDS for key in explicit_creds):
            raise StorageConfigurationError("Credentials contain unsupported fields.")
        sensitive.update(explicit_creds)

        if sensitive:
            from app.core.crypto import encrypt_credential

            previous = self._storage_config(loc) if loc.encrypted_credentials else {}
            credentials = {k: v for k, v in previous.items() if k in self._SENSITIVE_STORAGE_FIELDS}
            credentials.update(sensitive)
            kwargs["encrypted_credentials"] = encrypt_credential(
                json.dumps(credentials, separators=(",", ":"))
            )

        for k, v in kwargs.items():
            if v is not None and k in _ALLOWED and hasattr(loc, k):
                setattr(loc, k, v)
        await self.db.commit()
        await self.db.refresh(loc)
        return loc

    async def delete_storage_location(self, loc_id: UUID) -> bool:
        loc = await self.db.get(StorageLocation, loc_id)
        if not loc:
            return False
        await self.db.delete(loc)
        await self.db.commit()
        return True

    @complete_before_cancellation
    async def test_storage_location(
        self,
        loc_id: UUID,
        *,
        created_by_id: UUID | None = None,
        authorize: Callable[[], Awaitable[None]] | None = None,
        authorize_native: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Require a byte-for-byte round trip and truthful cleanup acknowledgement."""
        loc = await self.db.get(StorageLocation, loc_id)
        if not loc or (self.org_id is not None and loc.organization_id != self.org_id):
            return {"success": False, "message": "Storage location not found"}
        started = time.monotonic()
        path = None
        backend = None
        remote_write = None
        remote_recovery = None
        authorization_ended = False
        cleanup = "not_created"
        success = False
        message = "Storage verification failed; check destination permissions and connectivity."

        async def checkpoint():
            if authorize is not None:
                await authorize()

        try:
            await checkpoint()
            if loc.is_active is False:
                raise StorageConfigurationError("Storage location is disabled.")
            backend = get_storage_backend(loc.storage_type, self._storage_config(loc))
            await checkpoint()
            if isinstance(backend, (SFTPStorageBackend, FTPStorageBackend)):
                if authorize is None or authorize_native is None:
                    raise HTTPException(403, "Current probe authority is required")
                backend._probe_authorize = authorize
                backend._probe_native_check = authorize_native
            # Avoid leaving undeletable probe objects on append-only destinations.
            if not backend.SUPPORTS_DELETE:
                raise StorageConfigurationError(
                    "This destination cannot delete probe files. Use a managed backup and "
                    "restore validation; a non-destructive connection test is unavailable."
                )
            payload = b"freesdn-connectivity-test-" + uuid4().hex.encode("ascii")
            if isinstance(backend, (SFTPStorageBackend, FTPStorageBackend)):
                from app.services.remote_write_coordination import RemoteBackupWrite

                probe_id = uuid4()
                plan = backend.prepare_save(str(probe_id), payload, "connectivity_test.txt")
                # Retain candidates before the independent reserve/dispatch
                # commits. An ambiguous receipt may leave history even when
                # the owner was never returned to this request.
                remote_recovery = {
                    "purpose": "connectivity_probe",
                    "operation_id": str(plan.operation_id),
                    "possible_storage_paths": [plan.location, plan.temporary_location],
                    "payload_sha256": plan.payload_sha256,
                    "payload_size": plan.payload_size,
                    "recovery_required": True,
                    "automatic_retry_allowed": False,
                }
                remote_write = await RemoteBackupWrite.reserve(
                    self.db,
                    backend,
                    plan,
                    backup_id=probe_id,
                    organization_id=loc.organization_id,
                    storage_location_id=loc.id,
                    created_by_id=created_by_id,
                    schedule_id=None,
                    include_secrets=False,
                    purpose="connectivity_probe",
                )
                await checkpoint()
                await remote_write.dispatch()
                await checkpoint()
                cleanup = "unknown"
                path = await backend.save_prepared(plan, payload)
                await remote_write.acknowledge()
            else:
                path = await backend.save("test_" + uuid4().hex, payload, "connectivity_test.txt")
            await checkpoint()
            if not await backend.exists(path):
                raise StorageConfigurationError("Uploaded probe could not be found.")
            await checkpoint()
            if await backend.load(path) != payload:
                raise StorageConfigurationError(
                    "Downloaded probe content does not match the upload."
                )
            await checkpoint()
            if remote_write is not None:
                await remote_write.check_destination()
            success = True
            message = "Upload and byte-for-byte download verified."
        except HTTPException:
            authorization_ended = True
            success = False
            raise
        except RemotePublicationError:
            # Either name may exist. Neither is safe to erase or retry merely
            # because this request lost the server's acknowledgment.
            cleanup = "unknown"
            message = (
                "Probe publication could not be confirmed; inspect retained recovery information."
            )
        except BackupPublicationError as exc:
            # Even a failed acknowledgement may have left the owned probe.
            # Preserve its locator for the same finally-cleanup path.
            path = exc.storage_path
            message = "Probe publication could not be confirmed; storage is not verified."
        except StorageConfigurationError as exc:
            message = str(exc)
        except Exception as exc:
            # Provider exceptions may echo a URL, credential or SMTP/HTTP response.
            logger.warning("Storage probe %s failed (%s)", loc.id, type(exc).__name__)
        finally:
            if (
                not authorization_ended
                and path is not None
                and backend is not None
                and (remote_recovery is None or success)
            ):
                try:
                    await checkpoint()
                    if remote_write is not None:
                        await remote_write.check_destination()
                    cleanup = "acknowledged" if await backend.delete(path) else "failed"
                    await checkpoint()
                except HTTPException:
                    success = False
                    raise
                except Exception:
                    cleanup = "failed"
                if cleanup != "acknowledged":
                    success = False
                    message += " Probe cleanup failed; remove the test object on the destination."
        if remote_recovery is not None:
            # A cleanup response is only a statement about this completed
            # request. The durable acknowledged phase remains conservatively
            # inspectable; it does not prove deletion or grant replay authority.
            remote_recovery["recovery_required"] = not (success and cleanup == "acknowledged")
            if remote_recovery["recovery_required"]:
                message += " Recovery reference: " + remote_recovery["operation_id"] + "."
        await checkpoint()
        latency = round((time.monotonic() - started) * 1000, 1)
        loc.last_test_at = datetime.now(UTC)
        loc.last_test_status = "success" if success else "failed"
        loc.last_test_message = message
        await self.db.commit()
        await checkpoint()
        return {
            "success": success,
            "message": message,
            "latency_ms": latency,
            "details": {
                "round_trip_verified": success,
                "cleanup": cleanup,
                **({"remote_write": remote_recovery} if remote_recovery is not None else {}),
            },
        }

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------

    async def cleanup_expired_backups(self) -> int:
        """Delete expired backups. Returns count of deleted."""
        now = datetime.now(UTC)
        query = select(Backup.id).where(
            Backup.expires_at.isnot(None),
            Backup.expires_at < now,
            Backup.status == BackupStatus.COMPLETED,
        )
        result = await self.db.execute(query)
        expired = result.scalars().all()

        deleted = 0
        for backup_id in expired:
            try:
                if await self.delete_backup(backup_id):
                    deleted += 1
            except Exception as exc:
                # A failed database delete must not poison the remaining batch.
                # Iterate UUIDs, not ORM instances expired by this rollback.
                await self.db.rollback()
                logger.warning(
                    "Failed to delete expired backup %s (%s)",
                    backup_id,
                    type(exc).__name__,
                )

        return deleted
