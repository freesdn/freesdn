"""Private permission-to-archive integration; no public route imports this.

All factory types retain a copied destination constructor. Streaming preparation
currently integrates local/NFS, WebDAV, SFTP, FTPS and client-free S3/Dropbox/Google Drive/TrueNAS source APIs;
remaining providers need their bounded transport before this policy can ship.
No unbounded load() fallback substitutes for that unfinished work.
"""

from __future__ import annotations

import hmac
import json
import time
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import anyio
from fastapi import HTTPException

from app.adapters.truenas.adapter import TrueNASAdapter
from app.core.backup_artifacts import BackupArtifactError, recorded_identity
from app.core.backup_downloads import DownloadPool, DownloadSnapshot
from app.core.owned_async import complete_before_cancellation
from app.models.core import Controller
from app.services.adapter_truenas_storage import build_truenas_adapter
from app.services.backup import (
    BackupService,
    BackupStorageBackend,
    FTPStorageBackend,
    LocalStorageBackend,
    SFTPStorageBackend,
    TrueNASStorageBackend,
    WebDAVStorageBackend,
    get_storage_backend,
)
from app.services.vault_dropbox_stream import PreparedDropboxDownload, prepare_dropbox_download
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_operation_state import ExportIntent, ResolvedExportOperation
from app.services.vault_export_permission import (
    ConsumedExportPermission,
    consume_export_permission,
    issue_after_legacy_observation,
)
from app.services.vault_gdrive_single_stream import (
    PreparedGoogleDriveSingleDownload,
    prepare_gdrive_single_download,
)
from app.services.vault_s3_factory import PreparedS3Download, prepare_s3_download
from app.services.vault_snapshot_response import LocalDownloadSource, RemoteDownloadResponse
from app.services.vault_truenas_stream import PreparedTrueNASDownload, prepare_truenas_download

# Per-process admission, not global deployment capacity. Native remote DNS has
# its own bounded child lifetime; local filesystem construction remains owned
# worker work. Only constructors without persistent clients are admitted here.
_CONSTRUCTION_ADMISSION = anyio.CapacityLimiter(2)
_CONSTRUCTION_THREADS = anyio.CapacityLimiter(2)
_CONSTRUCTION_SECONDS = 5.0


class _SnapshotTrueNASBackend(TrueNASStorageBackend):
    """Do not re-read a controller and adopt new credentials after permission.

    Its existing adapter protocol/connection ownership remains unqualified for
    the new streaming path. This only preserves the checked constructor input.
    """

    def __init__(self, config: dict[str, Any], controller_json: str) -> None:
        super().__init__(config)
        self._controller_json = controller_json

    async def _adapter(self) -> TrueNASAdapter:
        values = json.loads(self._controller_json)
        if (
            UUID(values.pop("organization_id")) != UUID(self._organization_id)
            or values.pop("site_deleted_at") is not None
            or UUID(values["id"]) != self.controller_id
        ):
            raise HTTPException(409, "Vault export destination changed")
        for name in ("id", "site_id", "credential_id"):
            if values[name] is not None:
                values[name] = UUID(values[name])
        # A detached actual model preserves the existing decryption properties;
        # no ORM lookup, API-key auth commit or controller credential swap.
        return await build_truenas_adapter(Controller(**values))


def _config_from_snapshot(state: ResolvedExportOperation) -> dict[str, Any]:
    """Decode exactly the copied configuration, without constructing a client."""
    plan = state.storage
    return BackupService._storage_config(
        SimpleNamespace(
            config=json.loads(plan.config_json),
            encrypted_credentials=plan.encrypted_credentials,
            storage_type=plan.descriptor.storage_type,
            organization_id=plan.descriptor.organization_id,
        )
    )


def backend_from_snapshot(state: ResolvedExportOperation) -> BackupStorageBackend:
    """Construct only from the validated copied row, after permission checks."""
    plan = state.storage
    config = _config_from_snapshot(state)
    if plan.descriptor.storage_type == "truenas":
        if plan.controller_json is None:
            raise HTTPException(409, "Vault export destination changed")
        return _SnapshotTrueNASBackend(config, plan.controller_json)
    return get_storage_backend(plan.descriptor.storage_type, config)


def _recorded(state: ResolvedExportOperation) -> dict[str, Any] | None:
    value = (
        json.loads(state.artifact_identity_json)
        if state.artifact_identity_json is not None
        else None
    )
    result = recorded_identity({"artifact_identity": value}) if value is not None else None
    if (state.intent.operation == "download_recorded") != (result is not None):
        raise HTTPException(409, "Vault export file identity changed")
    return result


def _verify_snapshot(state: ResolvedExportOperation, snapshot: DownloadSnapshot) -> None:
    """Compare legacy observations without relabelling historical authenticity."""
    expected = _recorded(state)
    _, observed = state.intent.checked()
    if state.intent.operation == "download_legacy":
        expected = observed
    required_label = (
        "verified" if state.intent.operation == "download_recorded" else "legacy_unverified"
    )
    if snapshot._fd < 0 or snapshot.integrity != required_label:
        raise BackupArtifactError("Vault export snapshot did not complete its identity check.")
    if expected is not None and (
        snapshot.size != expected["bytes"]
        or not hmac.compare_digest(snapshot._digest.hexdigest(), expected["sha256"])
    ):
        raise BackupArtifactError("Vault export file no longer matches the confirmed identity.")


class VaultArchiveResponse(RemoteDownloadResponse):
    """Own proof consumption, a pinned source and disk snapshot in one ASGI call.

    Construction has no file access or durable consumption. A legacy observation
    emits JSON only. Real downloads compare the recorded or observed identity
    before headers; late authority/expiry refusal leaves the proof spent.
    """

    def __init__(
        self,
        authority: VaultExportAuthority,
        intent: ExportIntent,
        proof: str,
        pool: DownloadPool,
        *,
        seconds: float = 900,
    ) -> None:
        if intent.operation not in {"download_recorded", "observe_legacy", "download_legacy"}:
            raise HTTPException(409, "This export permission is not an archive download")
        # Filename comes from a validated UUID, never an operator path/header.
        intent.checked()
        super().__init__(
            self._copy,
            pool,
            f"backup_{intent.backup_id}.fsdnvault",
            seconds=seconds,
            authorize=self._authorize,
        )
        self.authority, self.intent, self.proof = authority, intent, proof
        self.permission: ConsumedExportPermission | None = None
        self.current: ResolvedExportOperation | None = None
        self.backend: (
            BackupStorageBackend
            | PreparedS3Download
            | PreparedDropboxDownload
            | PreparedGoogleDriveSingleDownload
            | PreparedTrueNASDownload
            | None
        ) = None
        self._observation_body: bytes | None = None
        self._observation_sent = False
        self.headers["Cache-Control"] = "no-store"

    async def _prepare_owned(self) -> None:
        try:
            self.permission = await consume_export_permission(
                self.authority, self.intent, self.proof
            )
        finally:
            # The proof does not need to survive this boundary in request memory.
            self.proof = ""
        self.current = await self.permission.check()
        _recorded(self.current)
        # Refuse unfinished transports before their constructors can perform
        # DNS or allocate a persistent SDK client. This private flow must not
        # replace public support until those providers are integrated.
        if self.current.storage.descriptor.storage_type not in {
            "local",
            "nfs",
            "webdav",
            "ftp",
            "sftp",
            "s3",
            "dropbox",
            "google_drive",
            "truenas",
        }:
            raise HTTPException(
                503, "This vault export transport still requires bounded integration"
            )
        await self._construct_owned()
        # The owned child drains cancellation before returning. AnyIO may still
        # have a pending enclosing cancellation: observe it before allocating.
        await anyio.lowlevel.checkpoint()
        current = await self.permission.check()
        if current.binding != self.current.binding or current.storage != self.current.storage:
            raise HTTPException(409, "Vault export destination changed")
        self.current = current
        await anyio.lowlevel.checkpoint()
        await super()._prepare_owned()

    async def _construct_owned(self) -> None:
        if self.current is None or self.permission is None:
            raise HTTPException(401, "Vault export permission is unavailable")
        try:
            _CONSTRUCTION_ADMISSION.acquire_nowait()
        except anyio.WouldBlock:
            raise HTTPException(
                503,
                "Vault export destination capacity is unavailable; retry later",
                headers={"Retry-After": "5"},
            ) from None
        try:
            started = time.monotonic()
            if self.current.storage.descriptor.storage_type in {
                "webdav",
                "ftp",
                "sftp",
                "s3",
                "dropbox",
                "google_drive",
                "truenas",
            }:
                config = await self._remote_config_owned()
                await anyio.lowlevel.checkpoint()
                current = await self.permission.check()
                if (
                    current.binding != self.current.binding
                    or current.storage != self.current.storage
                ):
                    raise HTTPException(409, "Vault export destination changed")
                # Do not shield the whole DNS await: the resolver owns cleanup,
                # so request cancellation can stop the child promptly.
                if current.storage.descriptor.storage_type == "truenas":
                    self.backend = await prepare_truenas_download(
                        config,
                        current.storage.controller_json,
                        revalidate=self._check_preparation_authority,
                    )
                elif current.storage.descriptor.storage_type == "s3":
                    self.backend = await prepare_s3_download(
                        config, revalidate=self._check_preparation_authority
                    )
                elif current.storage.descriptor.storage_type == "dropbox":
                    self.backend = await prepare_dropbox_download(
                        config, revalidate=self._check_preparation_authority
                    )
                elif current.storage.descriptor.storage_type == "google_drive":
                    self.backend = await prepare_gdrive_single_download(
                        config, revalidate=self._check_preparation_authority
                    )
                else:
                    backend_classes: dict[
                        str,
                        type[WebDAVStorageBackend]
                        | type[FTPStorageBackend]
                        | type[SFTPStorageBackend],
                    ] = {
                        "webdav": WebDAVStorageBackend,
                        "ftp": FTPStorageBackend,
                        "sftp": SFTPStorageBackend,
                    }
                    self.backend = await backend_classes[
                        current.storage.descriptor.storage_type
                    ].create_bounded(config)
            else:
                await self._construct_thread_owned()
            if time.monotonic() - started >= _CONSTRUCTION_SECONDS:
                raise HTTPException(503, "Vault export destination preparation took too long")
            if not isinstance(
                self.backend,
                (
                    LocalStorageBackend,
                    WebDAVStorageBackend,
                    FTPStorageBackend,
                    SFTPStorageBackend,
                    PreparedS3Download,
                    PreparedDropboxDownload,
                    PreparedGoogleDriveSingleDownload,
                    PreparedTrueNASDownload,
                ),
            ):
                raise HTTPException(503, "Vault export destination is unavailable")
        finally:
            _CONSTRUCTION_ADMISSION.release()

    async def _check_preparation_authority(self) -> None:
        if self.permission is None or self.current is None:
            raise HTTPException(401, "Vault export permission is unavailable")
        current = await self.permission.check()
        if current.binding != self.current.binding or current.storage != self.current.storage:
            raise HTTPException(409, "Vault export destination changed")

    @complete_before_cancellation
    async def _construct_thread_owned(self) -> None:
        self.backend = await anyio.to_thread.run_sync(
            backend_from_snapshot,
            cast(ResolvedExportOperation, self.current),
            limiter=_CONSTRUCTION_THREADS,
        )

    @complete_before_cancellation
    async def _remote_config_owned(self) -> dict[str, Any]:
        return await anyio.to_thread.run_sync(
            _config_from_snapshot,
            cast(ResolvedExportOperation, self.current),
            limiter=_CONSTRUCTION_THREADS,
        )

    @staticmethod
    @complete_before_cancellation
    async def _copy_local(source: LocalDownloadSource, snapshot: DownloadSnapshot) -> None:
        await anyio.to_thread.run_sync(source.copy_into, snapshot)

    async def _copy(self, snapshot: DownloadSnapshot) -> None:
        if self.permission is None or self.current is None or self.backend is None:
            raise HTTPException(401, "Vault export permission is unavailable")
        # Pool acquisition may wait. Recheck before touching the source, while
        # retaining the exact copied destination already used for construction.
        current = await self.permission.check()
        if current.binding != self.current.binding or current.storage != self.current.storage:
            raise HTTPException(409, "Vault export destination changed")
        if current.backup_path is None:
            raise HTTPException(409, "Vault archive location is unavailable")
        expected = _recorded(current)
        if isinstance(self.backend, LocalStorageBackend):
            source = LocalDownloadSource(
                self.backend.base_path,
                current.backup_path,
                {"artifact_identity": expected} if expected is not None else {},
                snapshot.limit,
            )
            await self._copy_local(source, snapshot)
        elif isinstance(
            self.backend,
            (
                WebDAVStorageBackend,
                FTPStorageBackend,
                SFTPStorageBackend,
                PreparedS3Download,
                PreparedDropboxDownload,
                PreparedGoogleDriveSingleDownload,
                PreparedTrueNASDownload,
            ),
        ):
            await self.backend.copy_download_into(current.backup_path, expected, snapshot)
        else:
            raise HTTPException(
                503, "This vault export transport still requires bounded integration"
            )
        _verify_snapshot(current, snapshot)

    async def _authorize(self) -> None:
        if self.permission is None or self.snapshot is None:
            raise HTTPException(401, "Vault export permission is unavailable")
        self.current = await self.permission.check()
        _verify_snapshot(self.current, self.snapshot)

    async def _prepare_headers(self) -> None:
        if self.intent.operation != "observe_legacy":
            await super()._prepare_headers()
            return
        if self.permission is None or self.snapshot is None:
            raise HTTPException(401, "Vault export permission is unavailable")
        proof = await issue_after_legacy_observation(self.permission, self.snapshot)
        self._observation_body = json.dumps(
            {
                "operation": "download_legacy",
                "proof": proof,
                "artifact_integrity": "legacy_unverified",
                "observed_identity": {
                    "version": 1,
                    "bytes": self.snapshot.size,
                    "sha256": self.snapshot._digest.hexdigest(),
                },
                "authentication_expires_at": min(
                    self.permission.verified.expires_at,
                    self.permission.verified.authentication_expires_at,
                ),
            },
            separators=(",", ":"),
        ).encode()
        del self.headers["Content-Disposition"]
        self.headers["Content-Type"] = "application/json"
        self.headers["Content-Length"] = str(len(self._observation_body))
        self.headers["X-FreeSDN-Artifact-Integrity"] = "legacy_unverified"
        self.headers["Cache-Control"] = "no-store"

    async def _read_owned(self) -> bytes:
        if self.intent.operation != "observe_legacy":
            return await super()._read_owned()
        if self._observation_body is None:
            raise HTTPException(401, "Legacy observation is unavailable")
        if self._observation_sent:
            return b""
        self._observation_sent = True
        return self._observation_body
