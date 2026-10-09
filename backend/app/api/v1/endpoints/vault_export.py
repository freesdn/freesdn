# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fresh confirmation factory registered by the actual application constructor.

This router verifies factors and issues short-lived purpose-bound permissions.
It performs no secret collection or archive transfer. Converted backup routes
must still revalidate current authority and consume permission durably.
"""

import logging
import threading
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any, Literal, cast
from urllib.parse import urlsplit
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict

from app.core.config import get_settings
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.vault_identity_proof import InvalidIdentityConfirmation, verify_identity_confirmation
from app.core.vault_ldap_reauthentication import LDAPConfirmationError
from app.core.vault_oidc_reauthentication import OIDCConfirmationError
from app.models.core import User
from app.schemas.vault_export import (
    MAX_CONFIRMATION_BYTES,
    ConfirmationAction,
    VaultConfirmationCommand,
    decode_vault_confirmation,
)
from app.schemas.vault_export_openapi import confirmation_openapi, requirements_openapi
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_factors import (
    complete_external_factors,
    complete_oidc_identity,
    confirm_ldap_identity,
)
from app.services.vault_export_oidc import create_oidc_confirmation
from app.services.vault_export_operation_state import (
    ResolvedExportOperation,
    resolve_current_operation,
)
from app.services.vault_export_permission import issue_after_factors

Operator = Annotated[CurrentUser, Depends(get_current_active_user)]
_READERS = threading.BoundedSemaphore(8)
_NO_STORE = {"Cache-Control": "private, no-store", "Pragma": "no-cache"}
log = logging.getLogger(__name__)


class _ConfirmationRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handle(request: Request) -> Response:
            try:
                response = await original(request)
            except RequestValidationError:
                # Query/dependency validation must not become a server error or
                # echo rejected input in a secret-confirmation response.
                response = JSONResponse(
                    {"detail": "Invalid vault confirmation request"}, status_code=422
                )
            except HTTPException as error:
                response = JSONResponse(
                    {"detail": error.detail}, status_code=error.status_code, headers=error.headers
                )
            except Exception as error:
                # No traceback or request body: provider and validation errors
                # can contain credentials. Cancellation remains a BaseException.
                log.error("Vault confirmation failed (%s)", type(error).__name__)
                response = JSONResponse(
                    {"detail": "Vault confirmation is unavailable"}, status_code=500
                )
            response.headers.update(_NO_STORE)
            return response

        return handle


@dataclass(frozen=True)
class VaultConfirmationPolicy:
    """Trusted explicit UI callback; never derive it from request Host/Origin."""

    oidc_redirect_uri: str | None = None

    def __post_init__(self) -> None:
        if self.oidc_redirect_uri is None:
            return
        value = self.oidc_redirect_uri
        if type(value) is not str or not 1 <= len(value) <= 2048:
            raise ValueError("Explicit HTTPS vault callback required")
        try:
            parts = urlsplit(value)
            port = parts.port
            if (
                parts.scheme != "https"
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
                or parts.query
                or parts.fragment
                or (port is not None and not 1 <= port <= 65535)
                or any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or "\\" in value
            ):
                raise ValueError("Invalid callback")
        except ValueError:
            raise ValueError("Explicit HTTPS vault callback required") from None


def _browser_context(request: Request, user: CurrentUser | User) -> None:
    # Optional for nonbrowser API callers. Browser code must send both captured
    # identities; these express equality only and cannot grant tenant authority.
    actor = request.headers.getlist("X-FreeSDN-Vault-Actor")
    organization = request.headers.getlist("X-FreeSDN-Vault-Organization")
    if not actor and not organization:
        return
    if len(actor) != 1 or len(organization) != 1:
        raise HTTPException(400, "Complete vault browser context required")
    try:
        for value in (actor[0], organization[0]):
            if len(value) != 36 or str(UUID(value)) != value or UUID(value).int == 0:
                raise ValueError("Invalid context")
    except ValueError:
        raise HTTPException(400, "Invalid vault browser context") from None
    if actor[0] != str(user.id) or organization[0] != str(user.organization_id):
        raise HTTPException(409, "Vault browser account changed; start a new confirmation")


async def _body(request: Request, action: ConfirmationAction) -> VaultConfirmationCommand:
    types = request.headers.getlist("content-type")
    if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Vault confirmations require application/json")
    encodings = request.headers.getlist("content-encoding")
    if len(encodings) > 1 or (encodings and encodings[0].strip().lower() != "identity"):
        raise HTTPException(415, "Encoded vault confirmation is not supported")
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        raise HTTPException(400, "Invalid confirmation content length")
    declared = lengths[0] if lengths else None
    if declared is not None and (
        not declared.isascii() or not declared.isdecimal() or len(declared) > 10
    ):
        raise HTTPException(400, "Invalid confirmation content length")
    if declared is not None and int(declared) > MAX_CONFIRMATION_BYTES:
        raise HTTPException(413, "Vault confirmation exceeds its bound")
    if not _READERS.acquire(blocking=False):
        raise HTTPException(
            503, "Vault confirmation capacity is busy", headers={"Retry-After": "1"}
        )
    try:
        body = bytearray()
        try:
            with anyio.fail_after(10):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_CONFIRMATION_BYTES:
                        raise HTTPException(413, "Vault confirmation exceeds its bound")
                    body.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, "Vault confirmation body deadline exceeded") from None
        if declared is not None and len(body) != int(declared):
            raise HTTPException(400, "Vault confirmation differs from declared length")
        try:
            return decode_vault_confirmation(bytes(body), action)
        except ValueError:
            raise HTTPException(422, "Invalid vault confirmation command") from None
    finally:
        _READERS.release()


class VaultConfirmationRequestError(BaseModel):
    """Sanitized framework validation error; rejected inputs are never echoed."""

    model_config = ConfigDict(extra="forbid")
    detail: str


class VaultFactorRequirements(BaseModel):
    """A current UI hint, never a permission or a provider-connectivity guarantee."""

    model_config = ConfigDict(extra="forbid")
    method: Literal["local", "ldap", "oidc"]
    mfa_required: bool
    oidc_redirect_uri: str | None


def create_vault_confirmation_router(policy: VaultConfirmationPolicy) -> APIRouter:
    if type(policy) is not VaultConfirmationPolicy:
        raise ValueError("Explicit vault confirmation policy required")
    router = APIRouter(route_class=_ConfirmationRoute)

    async def dispatch(
        request: Request, user: CurrentUser, action: ConfirmationAction
    ) -> JSONResponse:
        try:
            # Reject unsupported authority before reading an operator's secrets.
            if user.is_scoped or user.role != "super_admin" or user.organization_id is None:
                raise HTTPException(403, "Unscoped platform administrator required")
            _browser_context(request, user)
            command = await _body(request, action)
            authority = await VaultExportAuthority.capture(
                request,
                user,
                action="create" if command.intent.operation == "create" else "download",
                secret_key=get_settings().SECRET_KEY.encode("utf-8"),
            )
            original = await resolve_current_operation(authority, command.intent)
            if action == "local":
                factor = await authority.confirm_local(
                    password=cast(str, command.password), code=command.mfa_code
                )
            elif action == "ldap":
                token = await confirm_ldap_identity(
                    authority,
                    request_binding=original.binding,
                    password=cast(str, command.password),
                )
                return await identity_response(authority, command, original, user, token, "ldap")
            elif action in {"oidc_start", "oidc_complete"}:
                redirect = policy.oidc_redirect_uri
                if redirect is None:
                    raise HTTPException(503, "A vault OIDC callback must be configured")
                if action == "oidc_start":
                    service = await create_oidc_confirmation(
                        authority,
                        request_binding=original.binding,
                        redirect_uri=redirect,
                        allowed_redirect_uris=(redirect,),
                    )
                    start = await service.begin()
                    await resolve_current_operation(
                        authority, command.intent, expected_binding=original.binding
                    )
                    if time.time() >= start.expires_at:
                        raise HTTPException(401, "Vault confirmation expired; start again")
                    return JSONResponse(
                        {
                            "authorize_url": start.authorize_url,
                            "state": start.state,
                            "expires_at": start.expires_at,
                        },
                        headers=_NO_STORE,
                    )
                token = await complete_oidc_identity(
                    authority,
                    request_binding=original.binding,
                    redirect_uri=redirect,
                    allowed_redirect_uris=(redirect,),
                    state=cast(str, command.state),
                    code=cast(str, command.code),
                )
                return await identity_response(authority, command, original, user, token, "oidc")
            else:
                factor = await complete_external_factors(
                    authority,
                    request_binding=original.binding,
                    identity_token=cast(str, command.identity_token),
                    code=command.mfa_code,
                )
            proof = await issue_after_factors(
                factor, command.intent, initiating_binding=original.binding
            )
            return JSONResponse({"proof": proof}, headers=_NO_STORE)
        except (InvalidIdentityConfirmation, LDAPConfirmationError, OIDCConfirmationError):
            return JSONResponse(
                {"detail": "Fresh identity confirmation failed; start again"},
                status_code=401,
                headers=_NO_STORE,
            )
        except HTTPException as error:
            return JSONResponse(
                {"detail": error.detail},
                status_code=error.status_code,
                headers={**(error.headers or {}), **_NO_STORE},
            )

    async def identity_response(
        authority: VaultExportAuthority,
        command: VaultConfirmationCommand,
        original: ResolvedExportOperation,
        user: CurrentUser,
        token: str,
        protocol: Literal["ldap", "oidc"],
    ) -> JSONResponse:
        # A destination change during an IdP exchange does not grant a final
        # export proof. Refuse it here too, then verify original freshness after
        # this last SQL wait without renewing its authentication timestamps.
        await resolve_current_operation(
            authority, command.intent, expected_binding=original.binding
        )
        try:
            provider_id = UUID(str(user.user.sso_provider_id))
        except (ValueError, TypeError, AttributeError):
            raise InvalidIdentityConfirmation("Existing provider identity unavailable") from None
        verified = verify_identity_confirmation(
            token,
            authority.context,
            request_binding=original.binding,
            provider_id=provider_id,
            protocol=protocol,
            server_key=authority.secret_key,
        )
        return JSONResponse(
            {"identity_token": token, "expires_at": verified.expires_at}, headers=_NO_STORE
        )

    @router.get(
        "/requirements",
        response_model=VaultFactorRequirements,
        responses={422: {"model": VaultConfirmationRequestError}},
        openapi_extra=requirements_openapi(),
    )
    async def requirements(
        request: Request, user: Operator, action: Literal["create", "download"] = "create"
    ) -> JSONResponse:
        """Observe current supported factors; grant no identity or export proof.

        Browser callers send their captured account and organization headers.
        OIDC uses only the factory's explicit callback. No provider secrets or
        remote requests are needed to choose the appropriate confirmation UI.
        """
        _browser_context(request, user)
        authority = await VaultExportAuthority.capture(
            request,
            user,
            action=action,
            secret_key=get_settings().SECRET_KEY.encode("utf-8"),
        )
        method, mfa_required = await authority.confirmation_requirements()
        value = VaultFactorRequirements(
            method=method,
            mfa_required=mfa_required,
            oidc_redirect_uri=policy.oidc_redirect_uri if method == "oidc" else None,
        )
        return JSONResponse(value.model_dump(), headers=_NO_STORE)

    @router.post("/authorize/local", openapi_extra=confirmation_openapi("local"))
    async def local(request: Request, user: Operator) -> JSONResponse:
        return await dispatch(request, user, "local")

    @router.post("/identity/ldap", openapi_extra=confirmation_openapi("ldap"))
    async def ldap(request: Request, user: Operator) -> JSONResponse:
        return await dispatch(request, user, "ldap")

    @router.post("/identity/oidc/start", openapi_extra=confirmation_openapi("oidc_start"))
    async def oidc_start(request: Request, user: Operator) -> JSONResponse:
        return await dispatch(request, user, "oidc_start")

    @router.post("/identity/oidc/complete", openapi_extra=confirmation_openapi("oidc_complete"))
    async def oidc_complete(request: Request, user: Operator) -> JSONResponse:
        return await dispatch(request, user, "oidc_complete")

    @router.post("/authorize/external", openapi_extra=confirmation_openapi("external"))
    async def external(request: Request, user: Operator) -> JSONResponse:
        return await dispatch(request, user, "external")

    return router
