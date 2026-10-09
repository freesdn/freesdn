# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Explicit platform signing inspection and fresh local confirmation.

The private integrated application mounts this router. It does not initialize
keys on import/startup, accept browser factor receipts, or substitute local
passwords for external-provider confirmation. Deployment and UI qualification
remain required before public release.
"""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.api.v1.endpoints.auth import check_auth_rate_limit
from app.core.agent_signing_binding import SigningCommand
from app.core.config import settings
from app.core.dependencies import CurrentUser, get_current_user
from app.core.owned_async import complete_before_cancellation
from app.schemas.agent_signing import LocalSigningExecutionRequest, SigningCommandRequest
from app.services.agent_signing_authority import SigningLifecycleAuthority
from app.services.agent_signing_lifecycle import SigningOperationResult, execute_signing_lifecycle
from app.services.agent_signing_status import (
    INSPECTION_COMMAND,
    inspect_signing_state,
    preflight_signing_command,
)

router = APIRouter()
PlatformUser = Annotated[CurrentUser, Depends(get_current_user)]


async def _authority(
    request: Request, user: CurrentUser, command: SigningCommand
) -> SigningLifecycleAuthority:
    # Ordinary authentication (including API-key last_used) has finished before
    # any owned signing transaction. Never rerun that committing dependency
    # inside the coordinator's account/credential critical sections.
    try:
        key = settings.SECRET_KEY.encode("utf-8")
        return await SigningLifecycleAuthority.capture(
            request, user, command=command, secret_key=key
        )
    except (ValueError, UnicodeError):
        raise HTTPException(503, "Signing authority configuration is unavailable") from None


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@router.get("/status", response_model=None)
async def signing_status(
    request: Request, response: Response, user: PlatformUser
) -> dict[str, Any]:
    authority = await _authority(request, user, INSPECTION_COMMAND)
    snapshot = await inspect_signing_state(authority)
    _no_store(response)
    return snapshot.public()


@router.get("/operations/{operation_id}", response_model=None)
async def signing_operation(
    operation_id: UUID, request: Request, response: Response, user: PlatformUser
) -> dict[str, Any]:
    authority = await _authority(request, user, INSPECTION_COMMAND)
    snapshot = await inspect_signing_state(authority, operation_id=operation_id)
    if snapshot.selected is None:
        raise HTTPException(
            404, "Signing operation not found; this does not establish initialization safety"
        )
    _no_store(response)
    return snapshot.public()


@router.post("/preflight", response_model=None)
async def signing_preflight(
    body: SigningCommandRequest, request: Request, response: Response, user: PlatformUser
) -> dict[str, Any]:
    command = body.command()
    authority = await _authority(request, user, command)
    snapshot = await inspect_signing_state(authority, operation_id=command.operation_id)
    _no_store(response)
    method = user.user.auth_provider or "local"
    return {
        **preflight_signing_command(snapshot, command),
        "confirmation_method": method,
        "local_confirmation_available": method == "local",
    }


@router.post("/execute-local", response_model=None)
@complete_before_cancellation
async def signing_execute_local(
    body: LocalSigningExecutionRequest, request: Request, response: Response, user: PlatformUser
) -> SigningOperationResult:
    command = body.command()
    authority = await _authority(request, user, command)
    if user.user.auth_provider not in (None, "local"):
        raise HTTPException(
            409,
            "Fresh external-provider confirmation is required; local confirmation cannot replace it",
        )
    # Fixed auth namespace keeps this shared distributed limiter fail-closed,
    # including custom API-prefix deployments. Account failures also commit in
    # the independent local-factor transaction. No public proof is accepted.
    await check_auth_rate_limit(
        request.client.host if request.client else "unknown",
        path="/api/v1/auth/agent-signing/execute-local",
    )
    snapshot = await inspect_signing_state(authority, operation_id=command.operation_id)
    if not preflight_signing_command(snapshot, command)["database_eligible"]:
        raise HTTPException(409, "Signing command conflicts with retained state; inspect preflight")
    factor = await authority.confirm_local(
        command=command,
        password=body.password.get_secret_value(),
        code=body.code.get_secret_value() if body.code is not None else None,
    )
    result = await execute_signing_lifecycle(factor=factor, command=command)
    _no_store(response)
    return result
