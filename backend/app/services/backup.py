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
import ftplib
import gzip
import hashlib
import io
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES, escape_like, resolve_and_pin_host
from app.core.site_access import site_ids_for_request
from app.modules.backup.models import (
    Backup,
    BackupSchedule,
    BackupStatus,
    RestoreJob,
    StorageLocation,
)

logger = logging.getLogger(__name__)


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
            raise ValueError(
                f"Decompressed backup exceeds {limit // (1024 * 1024)} MB limit "
                "— refusing to inflate (possible decompression bomb)"
            )
    out += dec.flush()
    if len(out) > limit:
        raise ValueError("Decompressed backup exceeds size limit")
    return bytes(out)


# =============================================================================
# Encryption
# =============================================================================


# Controller secret config keys encrypted INDIVIDUALLY via encrypt_credential
# (see Controller.password / .client_secret). The vault export decrypts these into
# the passphrase-sealed payload; the vault restore re-encrypts them under the target
# instance's SECRET_KEY so the secret is portable + bound to the new instance.
CONTROLLER_SECRET_CONFIG_KEYS = ("password", "client_secret")


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
                raise ValueError(f"malformed v2 key_id (expected 'v2:<iter>:<salt>'): {key_id!r}")
            try:
                iterations = int(parts[1])
            except ValueError as exc:
                raise ValueError(f"v2 key_id has non-numeric iteration count: {key_id!r}") from exc
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


# =============================================================================
# Storage Backends
# =============================================================================


class BackupStorageBackend(ABC):
    """Abstract base for all backup storage backends."""

    @abstractmethod
    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        """Save data. Returns the storage path/URI."""

    @abstractmethod
    async def load(self, path: str) -> bytes:
        """Load data from path."""

    @abstractmethod
    async def delete(self, path: str) -> bool:
        """Delete file at path. Returns success."""

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

    def _safe_path(self, path: str) -> Path:
        """Resolve path and ensure it stays within base_path (prevent traversal)."""
        resolved = (self.base_path / path).resolve()
        if not resolved.is_relative_to(self.base_path.resolve()):
            raise ValueError("Path traversal detected")
        return resolved

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        # Atomic write — write to .tmp then os.replace() so a
        # crash mid-write never leaves a partial backup file in place.
        rel = f"{self._date_prefix()}/{backup_id}_{filename}"
        full = self._safe_path(rel)
        full.parent.mkdir(parents=True, exist_ok=True)
        tmp = full.with_suffix(full.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, full)
        return str(rel)

    async def load(self, path: str) -> bytes:
        return self._safe_path(path).read_bytes()

    async def delete(self, path: str) -> bool:
        fp = self._safe_path(path)
        if fp.exists():
            fp.unlink()
            return True
        return False

    async def exists(self, path: str) -> bool:
        return self._safe_path(path).exists()

    async def get_size(self, path: str) -> int:
        return self._safe_path(path).stat().st_size


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


class SFTPStorageBackend(BackupStorageBackend):
    """Store backups via SFTP."""

    def __init__(self, config: dict[str, Any]):
        # pin host to a validated IP literal at init time so
        # paramiko.Transport never performs a second DNS lookup.
        self.host = resolve_and_pin_host(config["host"], allow_private=False)
        self.port = int(config.get("port", 22))
        self.username = config["username"]
        self.password = config.get("password")
        # NOTE H6: validate the key path lives in the sandboxed keys dir.
        # Rejects operator-supplied paths like "/etc/shadow".
        raw_key = config.get("private_key_path")
        self.private_key_path = _validate_private_key_path(raw_key) if raw_key else None
        self.remote_path = config.get("remote_path", "/backups")
        self._transport: Any = None
        self._sftp: Any = None

    def _connect(self) -> None:
        import paramiko

        if self._sftp is not None:
            return
        transport = paramiko.Transport((self.host, self.port))
        if self.private_key_path:
            pkey = paramiko.RSAKey.from_private_key_file(
                self.private_key_path,
                password=self.password,
            )
            transport.connect(username=self.username, pkey=pkey)
        else:
            transport.connect(username=self.username, password=self.password)
        self._transport = transport
        self._sftp = paramiko.SFTPClient.from_transport(transport)

    def _close(self) -> None:
        if self._sftp:
            self._sftp.close()
        if self._transport:
            self._transport.close()
        self._sftp = None
        self._transport = None

    def _ensure_dirs(self, remote: str) -> None:
        """Recursively create remote directories."""
        parts = remote.split("/")
        current = ""
        for part in parts:
            if not part:
                continue
            current += f"/{part}"
            try:
                self._sftp.stat(current)
            except FileNotFoundError:
                self._sftp.mkdir(current)

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        self._connect()
        try:
            rel = f"{self._date_prefix()}/{backup_id}_{filename}"
            remote = f"{self.remote_path}/{rel}"
            self._ensure_dirs(str(Path(remote).parent))
            with self._sftp.open(remote, "wb") as f:
                f.write(data)
            return f"sftp://{self.host}{remote}"
        finally:
            self._close()

    async def load(self, path: str) -> bytes:
        self._connect()
        try:
            remote = path
            if path.startswith("sftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            buf = io.BytesIO()
            self._sftp.getfo(remote, buf)
            return buf.getvalue()
        finally:
            self._close()

    async def delete(self, path: str) -> bool:
        self._connect()
        try:
            remote = path
            if path.startswith("sftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            self._sftp.remove(remote)
            return True
        except Exception:
            return False
        finally:
            self._close()

    async def exists(self, path: str) -> bool:
        self._connect()
        try:
            remote = path
            if path.startswith("sftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            self._sftp.stat(remote)
            return True
        except Exception:
            return False
        finally:
            self._close()

    async def get_size(self, path: str) -> int:
        self._connect()
        try:
            remote = path
            if path.startswith("sftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            return self._sftp.stat(remote).st_size or 0
        finally:
            self._close()


class FTPStorageBackend(BackupStorageBackend):
    """Store backups via FTP/FTPS."""

    def __init__(self, config: dict[str, Any]):
        # pin host to a validated IP literal at init time so
        # ftplib.FTP.connect() never performs a second DNS lookup.
        self.host = resolve_and_pin_host(config["host"], allow_private=False)
        self.port = int(config.get("port", 21))
        self.username = config.get("username", "anonymous")
        self.password = config.get("password", "")
        self.remote_path = config.get("remote_path", "/backups")
        self.use_tls = config.get("use_tls", False)

    def _connect(self) -> ftplib.FTP:
        ftp: ftplib.FTP
        ftp = ftplib.FTP_TLS() if self.use_tls else ftplib.FTP()
        ftp.connect(self.host, self.port)
        ftp.login(self.username, self.password)
        if self.use_tls and isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()
        return ftp

    def _ensure_dirs(self, ftp: ftplib.FTP, path: str) -> None:
        parts = path.strip("/").split("/")
        current = ""
        for part in parts:
            current += f"/{part}"
            try:
                ftp.cwd(current)
            except ftplib.error_perm:
                ftp.mkd(current)

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        ftp = self._connect()
        try:
            rel = f"{self._date_prefix()}/{backup_id}_{filename}"
            remote = f"{self.remote_path}/{rel}"
            self._ensure_dirs(ftp, str(Path(remote).parent))
            ftp.storbinary(f"STOR {remote}", io.BytesIO(data))
            return f"ftp://{self.host}{remote}"
        finally:
            ftp.quit()

    async def load(self, path: str) -> bytes:
        ftp = self._connect()
        try:
            remote = path
            if path.startswith("ftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            buf = io.BytesIO()
            ftp.retrbinary(f"RETR {remote}", buf.write)
            return buf.getvalue()
        finally:
            ftp.quit()

    async def delete(self, path: str) -> bool:
        ftp = self._connect()
        try:
            remote = path
            if path.startswith("ftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            ftp.delete(remote)
            return True
        except Exception:
            return False
        finally:
            ftp.quit()

    async def exists(self, path: str) -> bool:
        ftp = self._connect()
        try:
            remote = path
            if path.startswith("ftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            ftp.size(remote)
            return True
        except Exception:
            return False
        finally:
            ftp.quit()

    async def get_size(self, path: str) -> int:
        ftp = self._connect()
        try:
            remote = path
            if path.startswith("ftp://"):
                remote = "/" + "/".join(path.split("/")[3:])
            return ftp.size(remote) or 0
        finally:
            ftp.quit()


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
    """Store backups via WebDAV (fully async via httpx)."""

    def __init__(self, config: dict[str, Any]):
        from urllib.parse import urlparse, urlunparse

        import httpx

        # resolve_and_pin_host once at __init__ time and rebuild
        # base_url from the IP literal. The long-lived AsyncClient then
        # connects to a fixed address for every request — no second DNS
        # lookup can rebind the hostname to 127.0.0.1 / 169.254.169.254.
        # The Host header is set per-request (in _url) so TLS SNI and
        # HTTP vhost routing continue to work against the original hostname.
        raw_url = (config["url"] or "").rstrip("/")
        _validate_endpoint_url(raw_url)  # scheme + reachability check
        parsed_raw = urlparse(raw_url)
        raw_host = parsed_raw.hostname or ""
        pinned_ip = resolve_and_pin_host(raw_host, allow_private=False)
        # Store original hostname for Host header injection.
        self._orig_hostname = raw_host
        port = parsed_raw.port
        if ":" in pinned_ip:
            netloc_ip = f"[{pinned_ip}]:{port}" if port else f"[{pinned_ip}]"
        else:
            netloc_ip = f"{pinned_ip}:{port}" if port else pinned_ip
        self.base_url = urlunparse(
            (
                parsed_raw.scheme,
                netloc_ip,
                parsed_raw.path,
                parsed_raw.params,
                parsed_raw.query,
                parsed_raw.fragment,
            )
        ).rstrip("/")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.path_prefix = config.get("path", "/backups")
        auth = httpx.BasicAuth(self.username, self.password) if self.username else None
        # Inject Host header so HTTP vhost routing works against the original
        # hostname while the TCP connection goes to the pinned IP.
        default_port = 443 if parsed_raw.scheme == "https" else 80
        host_header = raw_host if port in (None, default_port) else f"{raw_host}:{port}"
        self._client = httpx.AsyncClient(
            auth=auth,
            timeout=60.0,
            headers={"Host": host_header},
        )
        # preserve the original hostname for TLS SNI so
        # httpcore verifies the certificate against the hostname (not the
        # pinned IP).  ``sni_hostname`` is passed per-request via extensions
        # (httpx/httpcore API) only when the scheme is HTTPS.
        self._sni_extensions: dict[str, Any] = (
            {"sni_hostname": raw_host} if parsed_raw.scheme == "https" and raw_host else {}
        )

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def _ensure_dirs(self, path: str) -> None:
        parts = path.strip("/").split("/")
        current = ""
        for part in parts:
            current += f"/{part}"
            await self._client.request("MKCOL", self._url(current), extensions=self._sni_extensions)

    async def save(self, backup_id: str, data: bytes, filename: str) -> str:
        rel = f"{self.path_prefix}/{self._date_prefix()}/{backup_id}_{filename}"
        await self._ensure_dirs(str(Path(rel).parent))
        resp = await self._client.put(self._url(rel), content=data, extensions=self._sni_extensions)
        resp.raise_for_status()
        return f"webdav://{self.base_url.split('://', 1)[-1]}{rel}"

    async def load(self, path: str) -> bytes:
        if path.startswith("webdav://"):
            remote_part = path.replace("webdav://", "")
            url = f"https://{remote_part}" if "://" not in remote_part else remote_part
        else:
            url = self._url(path)
        resp = await self._client.get(url, extensions=self._sni_extensions)
        resp.raise_for_status()
        return bytes(resp.content)

    async def delete(self, path: str) -> bool:
        if path.startswith("webdav://"):
            remote_part = path.replace("webdav://", "")
            url = f"https://{remote_part}"
        else:
            url = self._url(path)
        resp = await self._client.request("DELETE", url, extensions=self._sni_extensions)
        return bool(resp.status_code < 400)

    async def exists(self, path: str) -> bool:
        if path.startswith("webdav://"):
            remote_part = path.replace("webdav://", "")
            url = f"https://{remote_part}"
        else:
            url = self._url(path)
        resp = await self._client.request(
            "PROPFIND", url, headers={"Depth": "0"}, extensions=self._sni_extensions
        )
        return bool(resp.status_code < 400)

    async def get_size(self, path: str) -> int:
        if path.startswith("webdav://"):
            remote_part = path.replace("webdav://", "")
            url = f"https://{remote_part}"
        else:
            url = self._url(path)
        resp = await self._client.request(
            "PROPFIND", url, headers={"Depth": "0"}, extensions=self._sni_extensions
        )
        # Parse content-length from PROPFIND response
        return int(resp.headers.get("content-length", "0"))

    async def close(self) -> None:
        """Close the httpx client to release resources."""
        if self._client:
            await self._client.aclose()
            self._client = None  # type: ignore[assignment]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


# =============================================================================
# Storage Factory
# =============================================================================


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
        "name": "FTP / FTPS",
        "description": "Store backups via FTP with optional TLS",
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
                "label": "Use TLS",
                "required": False,
                "default": "false",
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

        for contrib in registry.topological_order():
            try:
                payload = await contrib.collect(
                    self.db,
                    organization_id,
                    options,
                )
            except Exception:
                logger.exception(
                    "contributor %s collect() raised; omitting from backup",
                    contrib.contributor_id,
                )
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
                    except Exception:
                        logger.exception(
                            "contributor %s migrate_from(%s) raised",
                            cid,
                            entry.schema_version,
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
                    async with self.db.begin_nested():
                        result = await contrib.restore(
                            self.db,
                            organization_id,
                            payload,
                            dry_run=False,
                            options=restore_options,
                        )
            except Exception as exc:
                logger.exception(
                    "contributor %s restore raised; rolling back savepoint",
                    cid,
                )
                result = RestoreResult(
                    contributor_id=cid,
                    status="error",
                    errors=[str(exc)[:500]],
                )

            results.append(result)

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
            config = dict(loc.config or {})
            if loc.encrypted_credentials:
                try:
                    from app.core.crypto import decrypt_credential

                    creds = json.loads(decrypt_credential(loc.encrypted_credentials))
                    # Decrypted credentials override anything in plaintext config.
                    config.update(creds)
                except Exception:
                    logger.exception(
                        "Failed to decrypt storage credentials for location %s",
                        loc.id,
                    )
            return get_storage_backend(loc.storage_type, config), loc.id

        # Default local
        config = {"path": "/data/backups"}
        return get_storage_backend(storage_type, config), None

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
            Device,
            Site,
            User,
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
            elif site_id:
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
                    "ip_address": str(getattr(d, "ip_address", "")),
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

        # --- Users ---
        if include_users:
            result = await self.db.execute(
                select(User).where(User.organization_id == org_id, User.deleted_at.is_(None))
            )
            users = result.scalars().all()
            data["users"] = [
                {
                    "id": str(u.id),
                    "username": getattr(u, "username", None),
                    "email": u.email,
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

        # --- Automation rules ---
        if include_automation:
            try:
                from app.models.automation import AutomationRule

                # NOTE H2: filter automation rules by org if the model has
                # that column; tolerate older schema gracefully.
                ar_q = select(AutomationRule)
                if hasattr(AutomationRule, "organization_id"):
                    ar_q = ar_q.where(AutomationRule.organization_id == org_id)
                result = await self.db.execute(ar_q)
                rules = result.scalars().all()
                data["automation_rules"] = [
                    {
                        "id": str(r.id),
                        "name": getattr(r, "name", ""),
                        "description": getattr(r, "description", None),
                        "trigger_type": getattr(r, "trigger_type", None),
                        "conditions": getattr(r, "conditions", None),
                        "actions": getattr(r, "actions", None),
                        "is_enabled": getattr(r, "is_enabled", True),
                    }
                    for r in rules
                ]
            except Exception:
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

        # A secure (vault) backup carries decrypted secrets, so it MUST be encrypted
        # under a strong operator passphrase — reject rather than silently write a
        # leaky/instance-bound file. The passphrase (not SECRET_KEY) is what makes the
        # archive portable across instances (proven by the re-key drill).
        if include_secrets:
            if not passphrase or len(passphrase) < 12:
                raise ValueError(
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
                "include_vlans": include_vlans,
                "include_ssids": include_ssids,
                "include_users": include_users,
                "include_automation": include_automation,
                # When True, contributors emit DECRYPTED secret material (creds, VPN
                # keys, password hashes) into the payload — which is then sealed under
                # the passphrase below. Contributors ignore this key for a config snapshot.
                "include_secrets": include_secrets,
            }
            archive = await self._assemble_backup_archive(
                backup_id=backup.id,
                organization_id=organization_id,
                options=collect_options,
            )
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
            backup.progress = 70

            # 5. Store
            backend, loc_id = await self._resolve_storage(storage_type, storage_location_id)
            ext = "fsdnvault" if include_secrets else "fsdn"
            filename = f"backup_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{ext}"
            storage_path = await backend.save(str(backup.id), final_data, filename)
            backup.progress = 90

            # 6. Update record
            backup.storage_path = storage_path
            backup.file_size = len(final_data)
            backup.status = BackupStatus.COMPLETED
            backup.completed_at = datetime.now(UTC)
            backup.progress = 100
            if loc_id:
                backup.storage_location_id = loc_id

            await self.db.commit()
            await self.db.refresh(backup)
            logger.info(
                "Backup %s completed: %s (%d bytes)", backup.id, storage_path, len(final_data)
            )
            return backup

        except Exception as e:
            backup.status = BackupStatus.FAILED
            backup.error_message = str(e)[:2000]
            backup.completed_at = datetime.now(UTC)
            await self.db.commit()
            logger.error("Backup %s failed: %s", backup.id, e)
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

        from app.models import Controller, Device, Site, User

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
            return {
                "success": False,
                "dry_run": dry_run,
                "message": (
                    f"Invalid .fsdn file: {e}. Only the .fsdn format with a "
                    "verified SHA-256 checksum is accepted."
                ),
            }

        data = config.get("data", config)
        summary: dict[str, Any] = {}

        # NOTE C4/H3: Organization is intentionally NOT in the import map —
        # we never let an import create or modify orgs.
        model_map = {
            "sites": (Site, "id"),
            "controllers": (Controller, "id"),
            "devices": (Device, "id"),
            "users": (User, "id"),
        }

        # NOTE H4/H5: identical blocked-field set applied on BOTH insert and
        # update branches. Previously the insert branch silently accepted
        # hashed_password / role / is_superuser if the model had those columns.
        _BLOCKED_FIELDS = {
            "id",
            "hashed_password",
            "password_hash",
            "role",
            "is_superuser",
            "mfa_secret",
            "organization_id",  # H4: caller is the source of truth, not file
        }

        for key, (model_cls, pk_field) in model_map.items():
            records = data.get(key, [])
            if not records:
                continue
            created = 0
            updated = 0
            skipped = 0
            rejected_org = 0
            for record in records:
                # NOTE H4: reject records that originated in a different org.
                rec_org = record.get("organization_id")
                if rec_org and str(rec_org) != str(organization_id):
                    rejected_org += 1
                    skipped += 1
                    continue

                pk_val = record.get(pk_field)
                if not pk_val:
                    skipped += 1
                    continue

                result = await self.db.execute(
                    select(model_cls).where(getattr(model_cls, pk_field) == pk_val)
                )
                existing = result.scalars().first()

                if existing:
                    # H4: do not touch rows belonging to a different org.
                    existing_org = getattr(existing, "organization_id", None)
                    if existing_org and existing_org != organization_id:
                        rejected_org += 1
                        skipped += 1
                        continue
                    if overwrite_existing and not dry_run:
                        for k, v in record.items():
                            if k != pk_field and hasattr(existing, k) and k not in _BLOCKED_FIELDS:
                                setattr(existing, k, v)
                        updated += 1
                    else:
                        skipped += 1
                else:
                    if not dry_run:
                        # NOTE H5: apply _BLOCKED_FIELDS on insert too.
                        clean = {
                            k: v
                            for k, v in record.items()
                            if hasattr(model_cls, k) and k not in _BLOCKED_FIELDS
                        }
                        # H4: force the inserted record into the caller's org
                        if hasattr(model_cls, "organization_id"):
                            clean["organization_id"] = organization_id
                        try:
                            obj = model_cls(**clean)
                            self.db.add(obj)
                        except Exception:
                            skipped += 1
                            continue
                    created += 1

            summary[key] = {
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "rejected_cross_org": rejected_org,
            }

        if not dry_run:
            try:
                await self.db.commit()
            except Exception as e:
                await self.db.rollback()
                return {
                    "success": False,
                    "dry_run": False,
                    "message": f"Import failed: {e}",
                }

        return {
            "success": True,
            "dry_run": dry_run,
            "would_import" if dry_run else "imported": summary,
            "message": "Dry run complete — no changes applied"
            if dry_run
            else "Import completed successfully",
            "metadata": {
                "version": config.get("version"),
                "schema_version": config.get("schema_version"),
                "created_at": config.get("created_at"),
                # ``freesdn_version`` is the key written by collect_backup_data()
                # at export time (see _settings.APP_VERSION). Surface it as
                # ``product_version`` so the import-preview UI can show which
                # FreeSDN build produced the archive.
                "product_version": config.get("freesdn_version"),
            },
        }

    def _parse_fsdn_file(self, raw: bytes) -> dict[str, Any]:
        """Parse our binary .fsdn backup format."""
        header_len = int.from_bytes(raw[:4], "big")
        header = json.loads(raw[4 : 4 + header_len].decode("utf-8"))
        payload = raw[4 + header_len :]

        # Verify checksum
        if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
            raise ValueError("Checksum verification failed — file may be corrupted")

        # Decrypt if needed
        if header.get("encrypted"):
            raise ValueError(
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

        backend, _ = await self._resolve_storage(backup.storage_type, backup.storage_location_id)
        raw = await backend.load(backup.storage_path)

        header_len = int.from_bytes(raw[:4], "big")
        header = json.loads(raw[4 : 4 + header_len].decode("utf-8"))
        payload = raw[4 + header_len :]

        if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
            raise ValueError("Checksum verification failed")
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
            backend, _ = await self._resolve_storage(
                backup.storage_type, backup.storage_location_id
            )
            raw = await backend.load(backup.storage_path)

            # Parse .fsdn
            header_len = int.from_bytes(raw[:4], "big")
            header = json.loads(raw[4 : 4 + header_len].decode("utf-8"))
            payload = raw[4 + header_len :]

            # Verify checksum
            if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
                raise ValueError("Checksum verification failed")

            # Decrypt. A vault (.fsdnvault) is sealed under the operator PASSPHRASE
            # (portable across instances); a config snapshot uses the instance
            # SECRET_KEY. The passphrase is required for a vault restore. Prefer the
            # key_id embedded in the file header (self-describing / portable), falling
            # back to the DB row for legacy archives written before key_id was embedded.
            key_id = header.get("key_id") or backup.encryption_key_id
            if header.get("encrypted") and key_id:
                if backup.include_secrets:
                    if not passphrase:
                        raise ValueError(
                            "this is a secure (full) backup — a passphrase is required to restore it"
                        )
                    payload = BackupEncryption(master_key=passphrase).decrypt(payload, key_id)
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
                    logger.exception(
                        "pre-restore rollback slot capture failed for "
                        "RestoreJob %s; refusing to proceed without undo support",
                        job.id,
                    )
                    raise RuntimeError(
                        "Pre-restore rollback snapshot could not be captured; "
                        "refusing to perform a destructive restore without an "
                        "undo point. Resolve the snapshot failure and retry."
                    ) from exc
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
            job.items_failed = summary.get("total_skipped", 0)
            job.status = "completed"
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
            job.error_message = str(e)[:2000]
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
        from app.models.core import Organization
        from app.services.backup_contributors import (
            BackupArchive,
            is_legacy_v1_payload,
            wrap_legacy_v1_as_archive,
        )

        # 1. Parse + decrypt (key_id from the self-describing header — portable).
        if len(file_bytes) < 4:
            raise ValueError("not a FreeSDN backup file")
        header_len = int.from_bytes(file_bytes[:4], "big")
        try:
            header = json.loads(file_bytes[4 : 4 + header_len].decode("utf-8"))
        except Exception as exc:
            raise ValueError("unrecognized backup file") from exc
        payload = file_bytes[4 + header_len :]
        if hashlib.sha256(payload).hexdigest() != header.get("checksum"):
            raise ValueError("checksum verification failed — the file is corrupt")
        if not header.get("secrets"):
            raise ValueError(
                "this is a config snapshot (.fsdn), not a full backup — first-install "
                "restore needs a secure .fsdnvault that carries your accounts + credentials"
            )
        if header.get("encrypted"):
            key_id = header.get("key_id")
            if not key_id:
                raise ValueError("encrypted file is missing its key descriptor — cannot restore")
            if not passphrase:
                raise ValueError("a passphrase is required to restore a secure backup")
            try:
                payload = BackupEncryption(master_key=passphrase).decrypt(payload, key_id)
            except Exception as exc:
                raise ValueError("could not decrypt — wrong passphrase?") from exc
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
            raise ValueError("backup contains no organization-scoped data to restore")

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
        await self.db.flush()
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
        """Restore data into DB, respecting FK order: Sites → Controllers → Devices.

        NOTE H4: organization_id is forced to ``self.org_id`` on every insert.
        Records whose stored organization_id doesn't match are REJECTED
        (not silently rewritten — the rewriter policy is risky because it
        masks restore-into-wrong-tenant mistakes).
        NOTE H8: caller wraps this in ``self.db.begin()`` so a half-applied
        restore rolls back cleanly.
        """
        # NOTE C4/H3: Organization is intentionally excluded from the restore
        # map. A restore must NEVER create or modify Organization rows.
        from app.models import Controller, Device, Site, User

        if self.org_id is None:
            raise ValueError("BackupService.org_id must be set before _restore_data")

        # NOTE H4/H5: identical blocked-field set on BOTH update and insert.
        # A config-snapshot restore blocks identity/secret fields (they're never in the
        # payload anyway). A VAULT restore (include_secrets) intentionally restores them
        # so old logins survive — controller ``config`` secrets are RE-ENCRYPTED under
        # THIS instance's key in the loop below before they touch the DB.
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
            }
        )

        result: dict[str, Any] = {}
        restore_map = [
            ("sites", Site),
            ("controllers", Controller),
        ]
        if restore_devices:
            restore_map.append(("devices", Device))
        if restore_users:
            restore_map.append(("users", User))

        for key, model_cls in restore_map:
            records = data.get(key, [])
            created = 0
            updated = 0
            skipped = 0
            rejected_org = 0

            for record in records:
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

                existing = await self.db.get(model_cls, pk)
                if existing:
                    # H4: never touch a row owned by a different org.
                    existing_org = getattr(existing, "organization_id", None)
                    if existing_org and existing_org != self.org_id:
                        rejected_org += 1
                        skipped += 1
                        continue
                    if overwrite_existing and not dry_run:
                        for k, v in record.items():
                            if k != "id" and hasattr(existing, k) and k not in _BLOCKED_FIELDS:
                                setattr(existing, k, v)
                        updated += 1
                    else:
                        skipped += 1
                else:
                    if not dry_run:
                        # NOTE H5: apply _BLOCKED_FIELDS on insert too.
                        clean = {
                            k: v
                            for k, v in record.items()
                            if hasattr(model_cls, k) and k not in _BLOCKED_FIELDS
                        }
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
                        try:
                            self.db.add(model_cls(**clean))
                        except Exception:
                            skipped += 1
                            continue
                    created += 1

            result[key] = {
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "rejected_cross_org": rejected_org,
            }

        if not dry_run:
            await self.db.flush()
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
    ) -> dict[str, Any]:
        """Paginated backup listing with filters."""
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

    async def delete_backup(self, backup_id: UUID) -> bool:
        """Delete backup record and storage file."""
        backup = await self.db.get(Backup, backup_id)
        if not backup:
            return False

        # Delete from storage
        if backup.storage_path:
            try:
                backend, _ = await self._resolve_storage(
                    backup.storage_type, backup.storage_location_id
                )
                await backend.delete(backup.storage_path)
            except Exception as e:
                logger.warning("Failed to delete storage for backup %s: %s", backup_id, e)

        await self.db.delete(backup)
        await self.db.commit()
        return True

    async def download_backup(self, backup_id: UUID) -> tuple[bytes, str] | None:
        """Download a backup file. Returns (data, filename) or None."""
        backup = await self.db.get(Backup, backup_id)
        if not backup or not backup.storage_path:
            return None

        backend, _ = await self._resolve_storage(backup.storage_type, backup.storage_location_id)
        data = await backend.load(backup.storage_path)
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
        for k, v in kwargs.items():
            if v is not None and k in _ALLOWED and hasattr(schedule, k):
                setattr(schedule, k, v)
        # Recalculate next_run if cron changed
        if "cron_expression" in kwargs or "timezone" in kwargs:
            schedule.next_run_at = self._calculate_next_run(
                schedule.cron_expression or "0 2 * * *",
                schedule.timezone or "UTC",
            )
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
        schedule.is_enabled = is_enabled
        if is_enabled:
            schedule.next_run_at = self._calculate_next_run(
                schedule.cron_expression or "0 2 * * *",
                schedule.timezone or "UTC",
            )
        await self.db.commit()
        await self.db.refresh(schedule)
        return schedule

    def _calculate_next_run(self, cron_expr: str, tz: str = "UTC") -> datetime:
        """Calculate the next run time from a cron expression."""
        try:
            from croniter import croniter  # type: ignore[import-untyped]

            now = datetime.now(UTC)
            cron = croniter(cron_expr, now)
            next_dt: datetime = cron.get_next(datetime)
            return next_dt
        except Exception:
            # Fallback: next day at 2 AM UTC
            now = datetime.now(UTC)
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run

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

        cfg = kwargs.get("config") or {}
        # SSRF guard at create time: backends re-check at client-construction
        # but rejecting at create-time gives the operator immediate feedback
        # and prevents persisting a stash of internal-IP locations that fail
        # mysteriously later.  Validate the ACTUAL field each backend uses:
        # - webdav uses ``url``
        # - s3 uses ``endpoint_url`` (optional S3-compatible override)
        # - ftp / sftp use ``host``
        storage_type = (kwargs.get("storage_type") or "").lower()
        _ssrf_validate_storage_cfg(storage_type, cfg)

        public, sensitive = self._extract_sensitive(cfg)
        kwargs["config"] = public

        # Merge the explicit credentials dict on top of
        # anything split from config.  Explicit credentials win on key conflicts.
        explicit_creds: dict[str, Any] = kwargs.pop("credentials", None) or {}
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

        # SSRF guard on update — the original create guard
        # only ran at create time so a PATCH could silently change
        # endpoint_url / host to an internal address.
        if "config" in kwargs and kwargs["config"] is not None:
            storage_type = (
                kwargs.get("storage_type") or (loc.storage_type if loc else "") or ""
            ).lower()
            _ssrf_validate_storage_cfg(storage_type, kwargs["config"])

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
        sensitive.update(explicit_creds)

        if sensitive:
            from app.core.crypto import encrypt_credential

            kwargs["encrypted_credentials"] = encrypt_credential(
                json.dumps(sensitive, separators=(",", ":"))
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

    async def test_storage_location(self, loc_id: UUID) -> dict[str, Any]:
        """Test connectivity for a storage location.

        use the same decrypt-and-merge path as
        ``_resolve_storage`` so the connectivity test exercises the ACTUAL
        credentials stored in ``encrypted_credentials``, not just the
        plaintext ``config`` blob (which never contains secrets).
        """
        loc = await self.db.get(StorageLocation, loc_id)
        if not loc:
            return {"success": False, "message": "Storage location not found"}

        start = time.time()
        try:
            # Merge decrypted credentials into config exactly as _resolve_storage does.
            config = dict(loc.config or {})
            if loc.encrypted_credentials:
                try:
                    from app.core.crypto import decrypt_credential

                    creds = json.loads(decrypt_credential(loc.encrypted_credentials))
                    config.update(creds)
                except Exception:
                    logger.exception(
                        "Failed to decrypt storage credentials for location %s",
                        loc.id,
                    )
            backend = get_storage_backend(loc.storage_type, config)
            # Try a simple save/exists/delete cycle
            test_id = f"test_{uuid4().hex[:8]}"
            test_data = b"freesdn-connectivity-test"
            test_path = await backend.save(test_id, test_data, "connectivity_test.txt")
            exists = await backend.exists(test_path)
            await backend.delete(test_path)

            latency = round((time.time() - start) * 1000, 1)

            loc.last_test_at = datetime.now(UTC)
            loc.last_test_status = "success"
            loc.last_test_message = f"OK — {latency}ms"
            await self.db.commit()

            return {
                "success": True,
                "message": f"Connection successful ({latency}ms)",
                "latency_ms": latency,
                "details": {"exists_check": exists},
            }
        except Exception as e:
            latency = round((time.time() - start) * 1000, 1)
            loc.last_test_at = datetime.now(UTC)
            loc.last_test_status = "failed"
            loc.last_test_message = str(e)[:500]
            await self.db.commit()
            return {
                "success": False,
                "message": f"Connection failed: {e}",
                "latency_ms": latency,
            }

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------

    async def cleanup_expired_backups(self) -> int:
        """Delete expired backups. Returns count of deleted."""
        now = datetime.now(UTC)
        query = select(Backup).where(
            Backup.expires_at.isnot(None),
            Backup.expires_at < now,
            Backup.status == BackupStatus.COMPLETED,
        )
        result = await self.db.execute(query)
        expired = result.scalars().all()

        deleted = 0
        for backup in expired:
            try:
                await self.delete_backup(backup.id)
                deleted += 1
            except Exception as e:
                logger.warning("Failed to delete expired backup %s: %s", backup.id, e)

        return deleted
