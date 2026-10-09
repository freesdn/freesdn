# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Map current existing-account LDAP authority to fresh bind configuration."""

from typing import cast
from uuid import UUID

from app.core.vault_ldap_reauthentication import (
    LDAPConfirmationError,
    LDAPExportBinding,
    VaultLDAPReauthentication,
)
from app.services.vault_export_authority import VaultAuthorityRow, VaultExportAuthority


async def create_ldap_confirmation(
    authority: VaultExportAuthority, *, request_binding: str
) -> VaultLDAPReauthentication:
    """No user-submitted provider, alternate username, search or JIT identity."""
    try:
        row = await authority._current()
        authority._validate(row)
        row = cast(VaultAuthorityRow, row)
        if row["a_auth_provider"] != "ldap" or authority.provider_digest is None:
            raise ValueError("Existing LDAP binding required")
        return VaultLDAPReauthentication(
            binding=LDAPExportBinding(
                context=authority.context,
                request_binding=request_binding,
                provider_id=UUID(str(row["p_id"])),
                provider_digest=authority.provider_digest,
                url=row["p_ldap_url"],
                subject_dn=row["a_external_id"],
                require_tls=row["p_ldap_use_tls"],
                ca_pem=row["p_ldap_tls_ca_cert"],
            ),
            check_current=authority.check,
        )
    except Exception:
        raise LDAPConfirmationError(
            "Fresh identity confirmation failed; start a new confirmation"
        ) from None
