# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fresh existing-identity confirmation followed by applicable local MFA.

Private workflow integration, not public endpoints or archive permission. Only
the verifier results can issue the intermediate token; it is separate from both
ordinary authentication and the final operation/artifact-bound export proof.
"""

from __future__ import annotations

import time
from typing import cast
from uuid import UUID

import anyio

from app.core.owned_async import complete_before_cancellation
from app.core.token_blacklist import claim_token_jti
from app.core.vault_identity_proof import (
    InvalidIdentityConfirmation,
    create_identity_confirmation,
    verify_identity_confirmation,
)
from app.services.vault_export_authority import (
    FreshLocalFactor,
    VaultAuthorityRow,
    VaultExportAuthority,
)
from app.services.vault_export_ldap import create_ldap_confirmation
from app.services.vault_export_oidc import create_oidc_confirmation


def _refuse() -> InvalidIdentityConfirmation:
    return InvalidIdentityConfirmation(
        "Fresh identity confirmation is invalid; start a new confirmation"
    )


async def _issue(
    authority: VaultExportAuthority,
    *,
    request_binding: str,
    provider_id: UUID,
    protocol: str,
    authenticated_at: int,
    flow_expires_at: int,
) -> str:
    await authority.check()
    expiry = flow_expires_at
    if authority.expiry is not None:
        expiry = min(expiry, int(authority.expiry))
    result = create_identity_confirmation(
        authority.context,
        request_binding=request_binding,
        provider_id=provider_id,
        protocol=protocol,
        authenticated_at=authenticated_at,
        flow_expires_at=expiry,
        server_key=authority.secret_key,
    )
    await anyio.lowlevel.checkpoint()
    # Inspect the actual clamped expiry after the final checkpoint as well.
    verify_identity_confirmation(
        result,
        authority.context,
        request_binding=request_binding,
        provider_id=provider_id,
        protocol=protocol,
        server_key=authority.secret_key,
    )
    return result


async def confirm_ldap_identity(
    authority: VaultExportAuthority,
    *,
    request_binding: str,
    password: str,
) -> str:
    """No caller-supplied identity receipt, provider or alternate username."""
    service = await create_ldap_confirmation(authority, request_binding=request_binding)
    receipt = await service.confirm(password)
    return await _issue(
        authority,
        request_binding=request_binding,
        provider_id=receipt.provider_id,
        protocol="ldap",
        authenticated_at=receipt.authenticated_at,
        flow_expires_at=receipt.authenticated_at + 120,
    )


async def complete_oidc_identity(
    authority: VaultExportAuthority,
    *,
    request_binding: str,
    redirect_uri: str,
    allowed_redirect_uris: tuple[str, ...],
    state: str,
    code: str,
) -> str:
    """Only a fresh purpose-bound signed OIDC exchange can reach issuance."""
    service = await create_oidc_confirmation(
        authority,
        request_binding=request_binding,
        redirect_uri=redirect_uri,
        allowed_redirect_uris=allowed_redirect_uris,
    )
    receipt = await service.complete(state=state, code=code)
    return await _issue(
        authority,
        request_binding=request_binding,
        provider_id=receipt.provider_id,
        protocol="oidc",
        authenticated_at=receipt.authenticated_at,
        flow_expires_at=receipt.flow_expires_at,
    )


async def complete_external_factors(
    authority: VaultExportAuthority,
    *,
    request_binding: str,
    identity_token: str,
    code: str | None = None,
) -> FreshLocalFactor:
    result = await _consume_external_factors(
        authority,
        request_binding=request_binding,
        identity_token=identity_token,
        code=code,
    )
    await anyio.lowlevel.checkpoint()
    if time.time() >= result.expires_at:
        raise _refuse()
    return result


@complete_before_cancellation
async def _consume_external_factors(
    authority: VaultExportAuthority,
    *,
    request_binding: str,
    identity_token: str,
    code: str | None,
) -> FreshLocalFactor:
    row = await authority._current()
    authority._validate(row)
    row = cast(VaultAuthorityRow, row)
    try:
        verified = verify_identity_confirmation(
            identity_token,
            authority.context,
            request_binding=request_binding,
            provider_id=UUID(str(row["p_id"])),
            protocol=row["a_auth_provider"],
            server_key=authority.secret_key,
        )
        # The independent durable claim must complete before the MFA transaction.
        # It cannot commit caller work or release an account lock held by us.
        with anyio.fail_after(5):
            won = await claim_token_jti(verified.jti, verified.expires_at)
        if not won or time.time() >= verified.expires_at:
            raise _refuse()
        await authority.check()
        if time.time() >= verified.expires_at:
            raise _refuse()
    except Exception:
        raise _refuse() from None
    result = await authority._confirm_external_mfa(verified, code=code)
    # Factor consumption and session close may have waited after the earlier
    # checks. The original authentication time never slides forward.
    await result.authority.check()
    if time.time() >= verified.expires_at:
        raise _refuse()
    return result
