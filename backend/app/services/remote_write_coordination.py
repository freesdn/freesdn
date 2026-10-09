# SPDX-License-Identifier: AGPL-3.0-only
"""Durable pre-dispatch reservation for the existing remote backup writer.

This is not operator recovery authorization or a native-operation deadline.
The caller retains its existing authority checkpoints, including fresh vault
permission. Configuration/scheduled credential concurrency still needs its
separate current-authority contract; a journal entry grants no permission.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, overload
from uuid import UUID

import anyio
from sqlalchemy import Text, cast, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from app.core.config import get_settings
from app.core.owned_async import complete_before_cancellation
from app.core.remote_write_intent import RemoteProbeIntent, RemoteWriteIntent
from app.core.remote_write_plan import RemoteSavePlan
from app.modules.backup.models import StorageLocation
from app.services.backup_transport import RemoteDestinationView, StorageConfigurationError
from app.services.remote_write_journal import RemoteWriteJournal


@overload
def _uuid(value: UUID | str) -> UUID: ...


@overload
def _uuid(value: None) -> None: ...


def _uuid(value: UUID | str | None) -> UUID | None:
    return UUID(str(value)) if value is not None else None


@dataclass(repr=False)
class RemoteBackupWrite:
    journal: RemoteWriteJournal
    intent: RemoteWriteIntent
    backend: RemoteDestinationView = field(repr=False)
    key: bytes = field(repr=False)

    @classmethod
    async def reserve(
        cls,
        session: AsyncSession,
        backend: RemoteDestinationView,
        plan: RemoteSavePlan,
        *,
        backup_id: UUID | str,
        organization_id: UUID | str,
        storage_location_id: UUID | str | None,
        created_by_id: UUID | str | None,
        schedule_id: UUID | str | None,
        include_secrets: bool,
        purpose: str = "backup",
    ) -> RemoteBackupWrite:
        if purpose not in {"backup", "connectivity_probe"}:
            raise StorageConfigurationError("Invalid remote write purpose")
        engine = session.bind
        if isinstance(engine, AsyncConnection):
            engine = engine.engine
        if not isinstance(engine, AsyncEngine) or storage_location_id is None:
            raise StorageConfigurationError(
                "Remote recovery requires a configured destination and database"
            )
        key = hmac.digest(
            get_settings().SECRET_KEY.encode(), b"FreeSDN/remote-write-destination/v1", "sha256"
        )
        original = cls._binding(key, backend, backend.config)
        intent_type = RemoteProbeIntent if purpose == "connectivity_probe" else RemoteWriteIntent
        intent = intent_type(
            plan.operation_id,
            _uuid(backup_id),
            _uuid(organization_id),
            _uuid(storage_location_id),
            None if schedule_id is not None else _uuid(created_by_id),
            _uuid(schedule_id),
            include_secrets,
            plan.location,
            plan.temporary_location,
            original,
            plan.payload_sha256,
            plan.payload_size,
        )
        owner = cls(RemoteWriteJournal(engine), intent, backend, key)
        await owner.check_destination()
        await owner.journal.reserve(intent)
        return owner

    @staticmethod
    def _binding(key: bytes, backend: RemoteDestinationView, config: dict[str, Any]) -> str:
        try:
            raw = json.dumps(
                {
                    "scheme": backend.scheme,
                    "pinned_host": backend.host,
                    "port": backend.port,
                    "hostname": backend.hostname,
                    "config": config,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            if len(raw) > 262144:
                raise ValueError
        except (TypeError, ValueError, UnicodeError):
            raise StorageConfigurationError(
                "Remote recovery destination cannot be bounded"
            ) from None
        return hmac.digest(key, raw, "sha256").hex()

    @complete_before_cancellation
    async def check_destination(self) -> None:
        from app.services.backup import BackupService

        loc = StorageLocation.__table__.c
        statement = select(loc.storage_type, loc.config, loc.encrypted_credentials).where(
            loc.id == self.intent.storage_location_id,
            loc.organization_id == self.intent.organization_id,
            loc.is_active.is_(True),
            func.octet_length(cast(loc.config, Text)) <= 131072,
            or_(
                loc.encrypted_credentials.is_(None),
                func.octet_length(loc.encrypted_credentials) <= 262144,
            ),
        )
        with anyio.fail_after(6):
            async with self.journal.engine.begin() as connection:
                await connection.execute(text("SET LOCAL statement_timeout = '5s'"))
                row = (await connection.execute(statement)).mappings().one_or_none()
        if row is None or row.storage_type != ("sftp" if self.backend.scheme == "sftp" else "ftp"):
            raise StorageConfigurationError("Remote backup destination changed or is unavailable")
        config = BackupService._storage_config(
            SimpleNamespace(
                storage_type=row.storage_type,
                config=row.config,
                encrypted_credentials=row.encrypted_credentials,
                organization_id=self.intent.organization_id,
            )
        )
        if not hmac.compare_digest(
            self._binding(self.key, self.backend, config), self.intent.destination_binding
        ) or not hmac.compare_digest(
            self._binding(self.key, self.backend, self.backend.config),
            self.intent.destination_binding,
        ):
            raise StorageConfigurationError("Remote backup destination changed or is unavailable")

    async def dispatch(self) -> None:
        await self.check_destination()
        await self.journal.advance(self.intent, "dispatch")
        # A refusal here leaves conservative dispatched/unknown history and
        # sends no remote bytes. Never infer mutation from this phase alone.
        await self.check_destination()

    async def acknowledge(self) -> None:
        # Record the actual network acknowledgment even if authority ends next.
        # It is not file verification or permission to publish the catalogue.
        await self.journal.advance(self.intent, "acknowledge")
        await self.check_destination()
