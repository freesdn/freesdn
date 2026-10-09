"""Purpose-bound vault responses for the existing backup API.

Recorded archives retain the existing GET URL. Legacy archives require an
explicit observation POST and a subsequent identity-bound download POST. The
observation labels current bytes, never historical authenticity, and it does
not renew the original fresh authentication window.
"""

import json
import threading
from pathlib import Path
from typing import Any, NoReturn
from uuid import UUID

import anyio
from fastapi import HTTPException, Request

from app.api.v1.endpoints.vault_export import _browser_context
from app.core.backup_artifacts import BackupArtifactError, recorded_identity
from app.core.backup_downloads import DownloadPool
from app.core.config import get_settings
from app.core.dependencies import CurrentUser
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from app.modules.backup.models import Backup
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_creation import request_proof
from app.services.vault_export_download import VaultArchiveResponse
from app.services.vault_export_operation_state import ExportIntent

_READERS = threading.BoundedSemaphore(8)
_MAX_BODY = 2048


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate command field")
        result[key] = value
    return result


def _constant(_value: str) -> NoReturn:
    raise ValueError("Nonfinite command field")


async def _legacy_command(request: Request, backup_id: UUID | None, operation: str) -> ExportIntent:
    types = request.headers.getlist("content-type")
    encodings = request.headers.getlist("content-encoding")
    lengths = request.headers.getlist("content-length")
    if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Legacy vault commands require application/json")
    if len(encodings) > 1 or (encodings and encodings[0].strip().lower() != "identity"):
        raise HTTPException(415, "Encoded legacy vault commands are not supported")
    if len(lengths) > 1 or (
        lengths and (not lengths[0].isascii() or not lengths[0].isdecimal() or len(lengths[0]) > 10)
    ):
        raise HTTPException(400, "Invalid legacy vault command length")
    if lengths and int(lengths[0]) > _MAX_BODY:
        raise HTTPException(413, "Legacy vault command exceeds its bound")
    if not _READERS.acquire(blocking=False):
        raise HTTPException(
            503, "Legacy vault command capacity is busy", headers={"Retry-After": "1"}
        )
    try:
        raw = bytearray()
        try:
            with anyio.fail_after(10):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > _MAX_BODY:
                        raise HTTPException(413, "Legacy vault command exceeds its bound")
                    raw.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, "Legacy vault command deadline exceeded") from None
        if lengths and len(raw) != int(lengths[0]):
            raise HTTPException(400, "Legacy vault command differs from its declared length")
        try:
            value = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
            )
            required = {"legacy_acknowledged"} | (
                {"observed_identity"} if operation == "download_legacy" else set()
            )
            if (
                type(value) is not dict
                or set(value) != required
                or value["legacy_acknowledged"] is not True
            ):
                raise ValueError("Explicit legacy acknowledgment required")
            return ExportIntent.download(
                backup_id,
                operation=operation,
                legacy_acknowledged=True,
                observed_identity=value.get("observed_identity"),
            )
        except Exception:
            # Never serialize input, a proof, a parser fragment or a traceback.
            raise HTTPException(422, "Invalid legacy vault command") from None
    finally:
        _READERS.release()


async def confirmed_vault_download(
    request: Request,
    user: CurrentUser,
    backup: Backup,
    *,
    operation: str = "download_recorded",
) -> VaultArchiveResponse:
    """Construct only a response plan; claim and storage work belong to ASGI.

    The initial request-session row is an admission hint. The response independently
    rechecks actual account, credential, catalogue and destination state before and
    after waits/reads; no current-authority transaction is committed here.
    """
    _browser_context(request, user)
    token = request_proof(request)
    if backup.include_secrets is not True:
        raise HTTPException(409, "This command requires a full vault archive")
    try:
        recorded = recorded_identity(backup.metadata_json)
    except BackupArtifactError:
        raise HTTPException(409, "Vault archive identity is invalid") from None
    if operation == "download_recorded":
        if recorded is None:
            raise HTTPException(
                409, "Legacy vault requires an explicit observation and confirmed download"
            )
        intent = ExportIntent.download(backup.id, operation=operation)
    elif operation in {"observe_legacy", "download_legacy"}:
        if recorded is not None:
            raise HTTPException(
                409, "Recorded vault archives use the ordinary download URL with fresh permission"
            )
        intent = await _legacy_command(request, backup.id, operation)
    else:
        raise HTTPException(409, "Unsupported vault download command")
    settings = get_settings()
    authority = await VaultExportAuthority.capture(
        request,
        user,
        action="download",
        secret_key=settings.SECRET_KEY.encode("utf-8"),
    )
    return VaultArchiveResponse(
        authority,
        intent,
        token,
        DownloadPool(
            Path(settings.BACKUP_DOWNLOAD_SPOOL),
            slots=settings.BACKUP_DOWNLOAD_SLOTS,
            limit=MAX_BACKUP_IMPORT_BYTES,
            free_floor=settings.BACKUP_DOWNLOAD_FREE_BYTES,
        ),
        seconds=settings.BACKUP_DOWNLOAD_SECONDS,
    )
