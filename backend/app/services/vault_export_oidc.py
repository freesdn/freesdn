# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Join existing-account OIDC confirmation to current SQL authority.

Private integration, not an export endpoint. The caller still needs any local
MFA step, exact operation/artifact authorization and final proof consumption.
"""

from __future__ import annotations

from typing import cast
from uuid import UUID

from app.core.security_utils import decrypt_field
from app.core.vault_oidc_reauthentication import (
    OIDCConfirmationError,
    OIDCExportBinding,
    VaultOIDCReauthentication,
)
from app.services.vault_export_authority import VaultAuthorityRow, VaultExportAuthority


async def create_oidc_confirmation(
    authority: VaultExportAuthority,
    *,
    request_binding: str,
    redirect_uri: str,
    allowed_redirect_uris: tuple[str, ...],
) -> VaultOIDCReauthentication:
    """Read provider configuration from current owned rows, never the request.

    ``redirect_uri`` and its allowlist must come from server configuration, and
    ``request_binding`` from the separately validated operation descriptor.
    Neither a protocol receipt nor this factory grants access to vault bytes.
    """
    try:
        row = await authority._current()
        authority._validate(row)
        row = cast(VaultAuthorityRow, row)
        if row["a_auth_provider"] != "oidc" or authority.provider_digest is None:
            raise ValueError("An existing OIDC binding is required")
        extra = row["p_extra_settings"]
        if type(extra) is not dict:
            raise ValueError("Invalid provider configuration")
        method = extra.get("vault_export_client_auth_method", "client_secret_post")
        issuer = row["p_oidc_issuer"]
        if type(issuer) is not str:
            raise ValueError("Invalid provider issuer")
        encrypted = row["p_oidc_client_secret"]
        # Public clients must have no configured secret. The binding validator
        # checks the selected method and Discovery must explicitly support it.
        secret = decrypt_field(encrypted) if encrypted is not None else ""
        binding = OIDCExportBinding(
            context=authority.context,
            request_binding=request_binding,
            provider_id=UUID(str(row["p_id"])),
            provider_digest=authority.provider_digest,
            issuer=issuer,
            discovery_url=row["p_oidc_discovery_url"]
            or issuer.rstrip("/") + "/.well-known/openid-configuration",
            client_id=row["p_oidc_client_id"],
            client_secret=secret,
            subject=row["a_external_id"],
            redirect_uri=redirect_uri,
            allowed_redirect_uris=allowed_redirect_uris,
            client_auth_method=method,
        )
        return VaultOIDCReauthentication(
            binding=binding,
            server_key=authority.secret_key,
            check_current=authority.check,
        )
    except Exception:
        raise OIDCConfirmationError(
            "Fresh identity confirmation failed; start a new confirmation"
        ) from None
