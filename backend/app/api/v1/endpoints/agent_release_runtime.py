# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Authenticated startup diagnostics, never a release-operation capability."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from app.core.dependencies import CurrentUser, require_permissions
from app.services.agent_release_startup import ReleaseStartupObservation

router = APIRouter()
_NO_STORE = {"Cache-Control": "private, no-store", "Pragma": "no-cache"}


class ReleaseRuntimeResponse(BaseModel):
    checked_at: datetime
    storage: Literal["observed", "unavailable"]
    reference_schema: Literal["observed", "unavailable"]
    signing_identity: Literal["observed", "unavailable"]
    observation_only: Literal[True]
    actions_revalidate_current_state: Literal[True]


@router.get("/release-runtime", response_model=ReleaseRuntimeResponse)
async def release_runtime_status(
    request: Request,
    response: Response,
    user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
) -> dict[str, str | bool]:
    observation = getattr(request.app.state, "agent_release_startup", None)
    if type(observation) is not ReleaseStartupObservation:
        raise HTTPException(503, "Release startup observation is unavailable", headers=_NO_STORE)
    response.headers.update(_NO_STORE)
    return observation.public()
