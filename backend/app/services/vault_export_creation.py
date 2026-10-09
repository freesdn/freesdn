"""Private fresh-permission connection for the existing vault creation service.

The request consumes one durable proof before collection and retains its copied
destination through completion. Existing remote writers still require bounded
native qualification; this is not permission to publish the unfinished flow.
"""

from __future__ import annotations

import time
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.dependencies import CurrentUser
from app.core.owned_async import complete_before_cancellation
from app.modules.backup.models import Backup
from app.schemas.backup import BackupCreate
from app.services.backup import (
    BackupService,
    BackupStorageBackend,
    DropboxStorageBackend,
    GoogleDriveStorageBackend,
    S3StorageBackend,
    WebDAVStorageBackend,
)
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_download import backend_from_snapshot
from app.services.vault_export_operation_state import ExportIntent, ResolvedExportOperation
from app.services.vault_export_permission import ConsumedExportPermission, consume_export_permission

_CREATION_ADMISSION = anyio.CapacityLimiter(2)
_CONSTRUCTOR_THREADS = anyio.CapacityLimiter(2)


def request_proof(request: Request) -> str:
    values = request.headers.getlist("X-FreeSDN-Vault-Proof")
    if len(values) != 1 or not 1 <= len(values[0]) <= 8192 or not values[0].isascii():
        raise HTTPException(401, "Fresh vault export authorization is required")
    return values[0]


class _Creation:
    def __init__(self, permission: ConsumedExportPermission) -> None:
        self.permission = permission
        self.state = permission.state
        self._backend: BackupStorageBackend | None = None

    async def check(self) -> ResolvedExportOperation:
        current = await self.permission.check()
        if current.binding != self.state.binding or current.storage != self.state.storage:
            raise HTTPException(409, "Vault export destination changed")
        return current

    async def backend(self) -> tuple[BackupStorageBackend, UUID | None]:
        await self.check()
        if self._backend is None:
            started = time.monotonic()
            # The enclosing owned operation drains construction and cleanup.
            # This is an acceptance bound, not a hard native DNS/I/O deadline.
            self._backend = await anyio.to_thread.run_sync(
                backend_from_snapshot,
                self.state,
                limiter=_CONSTRUCTOR_THREADS,
            )
            if time.monotonic() - started >= 5:
                raise HTTPException(503, "Vault destination preparation took too long")
        await self.check()
        return self._backend, self.state.storage.descriptor.location_id

    async def close(self) -> None:
        # Per-operation transports own their connections. These three SDKs
        # retain clients; close only the client this request constructed.
        if isinstance(self._backend, S3StorageBackend):
            await anyio.to_thread.run_sync(self._backend.client.close, limiter=_CONSTRUCTOR_THREADS)
        elif isinstance(self._backend, DropboxStorageBackend):
            await anyio.to_thread.run_sync(self._backend.dbx.close, limiter=_CONSTRUCTOR_THREADS)
        elif (
            isinstance(self._backend, GoogleDriveStorageBackend)
            and self._backend._service is not None
        ):
            await anyio.to_thread.run_sync(
                self._backend._service.close, limiter=_CONSTRUCTOR_THREADS
            )
        elif isinstance(self._backend, WebDAVStorageBackend):
            await self._backend.close()

    @complete_before_cancellation
    async def run(self, session: AsyncSession) -> Backup:
        try:
            await self.check()
            data, _ = self.state.intent.checked()
            if data is None:
                raise HTTPException(409, "Vault creation intent is unavailable")
            result = await BackupService(session).create_backup(
                **data.model_dump(mode="python"),
                created_by_id=self.state.authority.actor_id,
                organization_id=self.state.authority.organization_id,
                creation_guard=self,
            )
            await self.check()
            return result
        finally:
            await self.close()


async def create_confirmed_vault(
    session: AsyncSession,
    request: Request,
    user: CurrentUser,
    data: BackupCreate,
) -> Backup:
    """Consume before a pending catalogue row, collection or storage access.

    Claim cancellation stays outside the owned creation window. Once creation is
    admitted, cancellation drains the established write/catalogue path and does not
    mean rollback. Independent permission checks do not commit the caller session.
    """
    token = request_proof(request)
    intent = ExportIntent.creation(data)
    authority = await VaultExportAuthority.capture(
        request,
        user,
        action="create",
        secret_key=get_settings().SECRET_KEY.encode("utf-8"),
    )
    try:
        _CREATION_ADMISSION.acquire_nowait()
    except anyio.WouldBlock:
        raise HTTPException(
            503, "Vault creation capacity is busy", headers={"Retry-After": "5"}
        ) from None
    try:
        try:
            permission = await consume_export_permission(authority, intent, token)
        finally:
            token = ""
        await anyio.lowlevel.checkpoint()
        return await _Creation(permission).run(session)
    finally:
        _CREATION_ADMISSION.release()
