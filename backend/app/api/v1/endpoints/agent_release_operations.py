# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private explicit release-operation API factory, deliberately unregistered.

Enablement requires qualified native guards, old-writer draining, supported
upload/legacy/recovery workflows and deployment acceptance. This factory alone
does not convert existing public upload/delete/download endpoints.
"""

import threading
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any, Literal
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import ResponseValidationError
from fastapi.routing import APIRoute

from app.core.config import settings
from app.core.dependencies import CurrentUser, get_current_user
from app.schemas.agent_release_operation_contract import (
    ERROR_RESPONSES,
    IntentReviewResponse,
    OperationResponse,
    OperationStatusResponse,
    UploadResponse,
    command_body_contract,
    release_context_contract,
    upload_body_contract,
)
from app.schemas.agent_release_operations import MAX_COMMAND_BYTES, decode_release_command
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_browser_context import (
    check_release_browser_context as _check_browser_context,
)
from app.services.agent_release_cleanup_coordinator import (
    ReleaseCleanupResult,
    execute_managed_release_cleanup,
)
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_deletion import ReleaseDeletionResult, execute_release_deletion
from app.services.agent_release_intent_review import review_deletion_target, review_release_intent
from app.services.agent_release_operation_status import inspect_release_operation
from app.services.agent_release_preparation import (
    ReleasePreparationResult,
    execute_release_preparation,
)
from app.services.agent_release_publication import (
    ReleasePublicationResult,
    execute_release_publication,
)
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget
from app.services.agent_release_reservation import (
    ReleaseReservationResult,
    execute_release_reservation,
)
from app.services.agent_release_upload_stream import owned_upload_stream

Operator = Annotated[CurrentUser, Depends(get_current_user)]
Action = Literal["reserve", "resume", "publish", "delete", "cancel", "cleanup"]
type OperationCommand = ReleasePublicationRequest | ReleaseDeletionRequest
type OperationResult = (
    ReleaseCleanupResult
    | ReleaseDeletionResult
    | ReleasePreparationResult
    | ReleasePublicationResult
    | ReleaseReservationResult
)
_BODY_READERS = threading.BoundedSemaphore(8)
_NO_STORE = {"Cache-Control": "private, no-store", "Pragma": "no-cache"}


@dataclass(frozen=True)
class ReleaseOperationPolicy:
    """Trusted startup input, not a request field or a runtime enablement claim."""

    root: str
    budget: ReleaseReservationBudget

    def __post_init__(self) -> None:
        if (
            type(self.root) is not str
            or not self.root.startswith("/")
            or "\x00" in self.root
            or type(self.budget) is not ReleaseReservationBudget
        ):
            raise ValueError("Explicit server release storage and reservation policy required")


async def _authority(request: Request, user: CurrentUser) -> ReleaseMutationAuthority:
    _check_browser_context(request, user)
    # Ordinary API-key authentication may commit bookkeeping before this call.
    # Never invoke it again inside an operation's locked SQL phase.
    try:
        return await ReleaseMutationAuthority.capture(
            request, user, secret_key=settings.SECRET_KEY.encode("utf-8")
        )
    except (ValueError, UnicodeError):
        raise HTTPException(503, "Release authority configuration unavailable") from None


async def _body(request: Request) -> OperationCommand:
    # Read only after authentication. No multipart parser, spool or caller path
    # is involved in these JSON commands. Upload ingress remains a separate gate.
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Release commands require application/json")
    if request.headers.get("content-encoding", "identity").strip().lower() != "identity":
        raise HTTPException(415, "Encoded release commands are not supported")
    declared = request.headers.get("content-length")
    if declared is not None and (
        not declared.isascii() or not declared.isdecimal() or len(declared) > 10
    ):
        raise HTTPException(400, "Invalid command content length")
    if declared is not None and int(declared) > MAX_COMMAND_BYTES:
        raise HTTPException(413, "Release command exceeds its bound")
    if not _BODY_READERS.acquire(blocking=False):
        raise HTTPException(503, "Release command capacity is busy", headers={"Retry-After": "1"})
    try:
        body = bytearray()
        try:
            with anyio.fail_after(10):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_COMMAND_BYTES:
                        raise HTTPException(413, "Release command exceeds its bound")
                    body.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, "Release command body deadline exceeded") from None
        if declared is not None and len(body) != int(declared):
            raise HTTPException(400, "Release command length differs from its declaration")
        try:
            return decode_release_command(bytes(body))
        except (ValueError, TypeError, RecursionError):
            # Do not include Pydantic input/errors or echo arbitrary command data.
            raise HTTPException(422, "Invalid release operation intent") from None
    finally:
        _BODY_READERS.release()


async def _dispatch(
    authority: ReleaseMutationAuthority,
    command: OperationCommand,
    policy: ReleaseOperationPolicy,
    action: Action,
) -> OperationResult:
    if action == "cleanup":
        return await execute_managed_release_cleanup(
            authority=authority, request=command, root=policy.root
        )
    if type(command) is ReleaseDeletionRequest:
        if action not in ("reserve", "delete", "cancel"):
            raise HTTPException(422, "Action does not apply to this deletion intent")
        return await execute_release_deletion(
            authority=authority, request=command, budget=policy.budget, action=action
        )
    if type(command) is not ReleasePublicationRequest:
        raise HTTPException(422, "Validated release intent required")
    if action in ("reserve", "cancel"):
        return await execute_release_reservation(
            authority=authority, request=command, budget=policy.budget, action=action
        )
    if action == "publish":
        return await execute_release_publication(
            authority=authority,
            request=command,
            budget=policy.budget,
            root=policy.root if command.storage_kind == "owned" else None,
        )
    if action == "resume" and command.storage_kind == "owned":
        return await execute_release_preparation(
            authority=authority,
            request=command,
            budget=policy.budget,
            root=policy.root,
            mode="resume",
        )
    raise HTTPException(422, "Action does not apply to this publication intent")


class _ReleaseContractRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def checked(request: Request) -> Response:
            try:
                return await original(request)
            except ResponseValidationError:
                # Validation may fail AFTER a confirmed mutation. Do not leak
                # response inputs into generic exception logs or claim rollback.
                raise HTTPException(
                    503,
                    "Release result could not be confirmed; retain the original intent and inspect the same operation",
                    headers=_NO_STORE,
                ) from None

        return checked


def create_release_operation_router(policy: ReleaseOperationPolicy) -> APIRouter:
    if type(policy) is not ReleaseOperationPolicy:
        raise ValueError("Explicit server release operation policy required")
    router = APIRouter(route_class=_ReleaseContractRoute)

    @router.post(
        "/release-operation-intents/review",
        response_model=IntentReviewResponse,
        openapi_extra={**command_body_contract(), **release_context_contract()},
        responses=ERROR_RESPONSES,
    )
    async def intent_review(
        request: Request, response: Response, user: Operator
    ) -> dict[str, object]:
        try:
            authority = await _authority(request, user)
            command = await _body(request)
            result = await review_release_intent(authority, command=command)
        except HTTPException as error:
            error.headers = {**(error.headers or {}), **_NO_STORE}
            raise
        response.headers.update(_NO_STORE)
        return result.public()

    @router.get(
        "/releases/{release_id}/deletion-intent/{operation_id}",
        response_model=IntentReviewResponse,
        openapi_extra=release_context_contract(),
        responses=ERROR_RESPONSES,
    )
    async def deletion_review(
        release_id: UUID, operation_id: UUID, request: Request, response: Response, user: Operator
    ) -> dict[str, object]:
        try:
            authority = await _authority(request, user)
            result = await review_deletion_target(
                authority, release_id=release_id, operation_id=operation_id
            )
        except HTTPException as error:
            error.headers = {**(error.headers or {}), **_NO_STORE}
            raise
        response.headers.update(_NO_STORE)
        return result.public()

    @router.get(
        "/release-operations/{operation_id}",
        response_model=OperationStatusResponse,
        openapi_extra=release_context_contract(),
        responses=ERROR_RESPONSES,
    )
    async def operation_status(
        operation_id: UUID, request: Request, response: Response, user: Operator
    ) -> dict[str, object]:
        try:
            authority = await _authority(request, user)
            snapshot = await inspect_release_operation(authority, operation_id=operation_id)
        except HTTPException as error:
            error.headers = {**(error.headers or {}), **_NO_STORE}
            raise
        response.headers.update(_NO_STORE)
        return snapshot.public()

    # Register the explicit path first so the Literal action route cannot
    # intercept multipart upload and reject it during parameter validation.
    @router.post(
        "/release-operations/{operation_id}/upload",
        response_model=UploadResponse,
        openapi_extra={**upload_body_contract(), **release_context_contract()},
        responses=ERROR_RESPONSES,
    )
    async def operation_upload(
        operation_id: UUID, request: Request, response: Response, user: Operator
    ) -> dict[str, object]:
        try:
            authority = await _authority(request, user)
            async with owned_upload_stream(request, operation_id) as stream:
                command = await stream.read_intent()
                result = await execute_release_preparation(
                    authority=authority,
                    request=command,
                    budget=policy.budget,
                    root=policy.root,
                    mode="upload",
                    source=stream.chunks(),
                )
                authority.validate(await authority._read())
        except HTTPException as error:
            error.headers = {**(error.headers or {}), **_NO_STORE}
            raise
        response.headers.update(_NO_STORE)
        return {
            "operation_id": command.operation_id,
            "release_id": command.release_id,
            "intent_sha256": command.request_sha256(),
            "result": result,
            "historical_observation": True,
            "authorization_granted": False,
            "retry_requires_identical_intent_and_current_authority": True,
        }

    @router.post(
        "/release-operations/{operation_id}/{action}",
        response_model=OperationResponse,
        openapi_extra={**command_body_contract(), **release_context_contract()},
        responses=ERROR_RESPONSES,
    )
    async def operation_command(
        operation_id: UUID, action: Action, request: Request, response: Response, user: Operator
    ) -> dict[str, object]:
        try:
            authority = await _authority(request, user)
            command = await _body(request)
            if command.operation_id != operation_id:
                raise HTTPException(422, "Path and release operation identities differ")
            # The captured credential may have changed while the body arrived.
            # Coordinator admission and each phase independently revalidate it.
            result = await _dispatch(authority, command, policy, action)
            authority.validate(await authority._read())
        except HTTPException as error:
            error.headers = {**(error.headers or {}), **_NO_STORE}
            raise
        response.headers.update(_NO_STORE)
        return {
            "operation_id": command.operation_id,
            "release_id": command.release_id,
            "intent_sha256": command.request_sha256(),
            "result": result,
            "historical_observation": True,
            "authorization_granted": False,
            "retry_requires_identical_intent_and_current_authority": True,
        }

    return router
