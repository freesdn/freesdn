# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Authenticated, bounded remote backup connections. No plaintext fallback."""

from __future__ import annotations

import base64
import contextlib
import ftplib
import hashlib
import hmac
import posixpath
import re
import socket
import ssl
from collections.abc import Iterator, Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID

TIMEOUT = 30


class StorageConfigurationView(Protocol):
    """Read-only fields supplied by a stored location or a validated snapshot."""

    @property
    def config(self) -> Mapping[str, Any] | None: ...

    @property
    def encrypted_credentials(self) -> str | None: ...

    @property
    def storage_type(self) -> str: ...

    @property
    def organization_id(self) -> UUID | None: ...


class RemoteDestinationView(Protocol):
    """Already constructed transport fields bound into remote-write metadata."""

    @property
    def scheme(self) -> str: ...

    @property
    def host(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def hostname(self) -> str: ...

    @property
    def config(self) -> dict[str, Any]: ...


class StorageConfigurationError(ValueError):
    """Operator-actionable messages which contain no provider response or secret."""


class LocalBackupPathError(StorageConfigurationError):
    """A local/NFS backup path outside the allowed roots; the message is shown as is."""


#: The backup_data volume, mounted at this path in api, worker and worker-io.
DEFAULT_LOCAL_BACKUP_ROOT = "/data/backups"

#: Storage types whose ``path`` is a directory on this server.
LOCAL_PATH_STORAGE_TYPES = frozenset({"local", "nfs"})


def allowed_local_backup_roots() -> tuple[str, ...]:
    """/data/backups plus BACKUP_LOCAL_EXTRA_ROOTS, each resolved.

    The extra roots come only from the server's environment, never from the web
    UI or the API: a storage location's path is chosen by an org admin, and the
    backup writer runs as the application user, so an unconfined path would let
    that admin place files anywhere the application can write (its own code
    tree, the VPN sidecar's config volumes).
    """
    import logging
    import os

    from app.core.config import settings

    roots = [DEFAULT_LOCAL_BACKUP_ROOT]
    for item in str(getattr(settings, "BACKUP_LOCAL_EXTRA_ROOTS", "") or "").split(","):
        item = item.strip()
        if not item:
            continue
        if not os.path.isabs(item):
            logging.getLogger(__name__).warning(
                "BACKUP_LOCAL_EXTRA_ROOTS entry %r ignored: it must be an absolute path", item
            )
            continue
        roots.append(item)
    return tuple(os.path.realpath(root) for root in roots)


def confine_local_backup_path(path: object) -> str:
    """Return ``path`` if it resolves inside an allowed root, else refuse.

    Resolved with realpath, so ``..`` and symlinks cannot step outside a root.
    The path is returned AS GIVEN, not resolved: the file layer opens it with
    O_NOFOLLOW and must keep refusing a symlinked directory itself.
    """
    import os

    raw = str(path or DEFAULT_LOCAL_BACKUP_ROOT)
    roots = allowed_local_backup_roots()
    if os.path.isabs(raw):
        real = os.path.realpath(raw)
        for root in roots:
            if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
                return raw
    raise LocalBackupPathError(
        f"Local backup path {raw!r} is outside the allowed backup storage "
        f"({', '.join(roots)}). Use a folder under {DEFAULT_LOCAL_BACKUP_ROOT}, or ask the "
        "server administrator to add the path to BACKUP_LOCAL_EXTRA_ROOTS."
    )


def require_tls(value: object) -> None:
    # Form fields are strings; bool("false") must never enable a security option.
    if value is not True and value != "true":
        raise StorageConfigurationError(
            "Plaintext FTP is disabled. Review this destination and set use_tls=true; "
            "the server must support explicit FTPS with a trusted certificate."
        )


def require_host_key(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value):
        raise StorageConfigurationError(
            "SFTP requires host_key_sha256 in OpenSSH SHA256 fingerprint format. "
            "Obtain it from a trusted server administrator before enabling backups."
        )
    return value


def validate_policy(storage_type: str, config: dict[str, Any], *, creating: bool = False) -> None:
    if storage_type == "ftp":
        if creating:
            config.setdefault("use_tls", True)
        require_tls(config.get("use_tls"))
    elif storage_type == "sftp":
        require_host_key(config.get("host_key_sha256"))


def remote_path(path: str, root: str, hostname: str, pinned_ip: str, port: int) -> str:
    """Accept legacy stored URLs but never let them select a different server/root."""
    if "://" in path:
        parsed = urlsplit(path)
        if (
            parsed.scheme not in {"ftp", "ftps", "sftp"}
            or parsed.hostname not in {hostname.lower(), pinned_ip}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, port}
            or parsed.query
            or parsed.fragment
        ):
            raise StorageConfigurationError("Backup URL does not match this storage destination.")
        path = parsed.path
    if (
        not path.startswith("/")
        or ".." in path.split("/")
        or any(ord(c) < 32 or ord(c) == 127 for c in path)
        or "\\" in path
    ):
        raise StorageConfigurationError("Backup path must be absolute and inside the storage root.")
    normalized = posixpath.normpath(path)
    base = posixpath.normpath(root)
    if normalized == base or posixpath.commonpath([normalized, base]) != base:
        raise StorageConfigurationError("Backup path must name a file inside the storage root.")
    return normalized


class PinnedFTP_TLS(ftplib.FTP_TLS):
    """TLS authenticates the configured hostname; sockets use the validated IP."""

    _prot_p: bool

    def makepasv(self) -> tuple[str, int]:
        _advertised_host, port = super().makepasv()
        if port < 1024:
            raise StorageConfigurationError("FTPS data connection requires an unprivileged port.")
        assert self.sock is not None
        # A server cannot redirect the data connection to a different host.
        return str(self.sock.getpeername()[0]), port

    def ntransfercmd(
        self, cmd: str, rest: int | str | None = None
    ) -> tuple[socket.socket, int | None]:
        if not self._prot_p or not self.passiveserver:
            raise StorageConfigurationError("FTPS requires protected passive data connections.")
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        try:
            return self.context.wrap_socket(conn, server_hostname=self.host), size
        except BaseException:
            conn.close()
            raise


@contextlib.contextmanager
def ftps_connection(
    hostname: str, pinned_ip: str, port: int, username: str, password: str, use_tls: object
) -> Iterator[PinnedFTP_TLS]:
    require_tls(use_tls)
    client = PinnedFTP_TLS(context=ssl.create_default_context(), timeout=TIMEOUT)
    try:
        client.connect(pinned_ip, port)
        client.host = hostname  # SNI/certificate name, never used to resolve a data socket.
        client.auth()
        client.login(username, password)
        client.prot_p()
        yield client
    finally:
        # QUIT failure must not turn an acknowledged write into an apparent failure.
        with contextlib.suppress(Exception):
            client.close()


@contextlib.contextmanager
def sftp_connection(
    pinned_ip: str,
    port: int,
    username: str,
    password: str | None,
    private_key_path: str | None,
    host_key_sha256: object,
) -> Iterator[Any]:
    import paramiko

    expected = require_host_key(host_key_sha256)
    transport = None
    client = None
    sock = socket.create_connection((pinned_ip, port), timeout=TIMEOUT)
    try:
        transport = paramiko.Transport(sock)
        transport.banner_timeout = TIMEOUT
        transport.auth_timeout = TIMEOUT
        transport.channel_timeout = TIMEOUT
        transport.start_client(timeout=TIMEOUT)
        actual = "SHA256:" + base64.b64encode(
            hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()
        ).decode("ascii").rstrip("=")
        if not hmac.compare_digest(actual, expected):
            raise StorageConfigurationError(
                "SFTP server host key does not match the trusted fingerprint. "
                "No credentials were sent; verify the server identity before retrying."
            )
        if private_key_path:
            key = paramiko.PKey.from_path(
                private_key_path, password=password.encode("utf-8") if password else None
            )
            transport.auth_publickey(username, key)
        else:
            transport.auth_password(username, password or "", fallback=False)
        if not transport.is_authenticated():
            raise StorageConfigurationError("SFTP authentication did not complete.")
        client = paramiko.SFTPClient.from_transport(transport)
        if client is None:
            raise StorageConfigurationError("SFTP subsystem is unavailable.")
        client.get_channel().settimeout(TIMEOUT)
        yield client
    finally:
        for resource in (client, transport, sock):
            if resource is not None:
                with contextlib.suppress(Exception):
                    resource.close()
