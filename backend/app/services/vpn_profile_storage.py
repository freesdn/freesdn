# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, explicit maintenance of legacy site OpenVPN credentials."""

from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.models.vpn import SiteVPNConfiguration


async def encrypt_legacy_profile_batch(
    session: AsyncSession,
    *,
    apply: bool = False,
    after_id: UUID | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Inspect one ordered page; callers own commit/rollback and maintenance scope.

    No values or credentials are returned. Validate every existing ciphertext in
    the page before writing anything. Application writers must already run the
    corrected version; this is not a live upgrade/fencing mechanism.
    """
    if not 1 <= limit <= 1000:
        raise ValueError("Batch size must be 1..1000")
    query = (
        select(
            SiteVPNConfiguration.id,
            SiteVPNConfiguration.openvpn_config_content,
        )
        .where(
            SiteVPNConfiguration.openvpn_config_content.is_not(None),
            SiteVPNConfiguration.openvpn_config_content != "",
        )
        .order_by(SiteVPNConfiguration.id)
        .limit(limit)
    )
    if after_id is not None:
        query = query.where(SiteVPNConfiguration.id > after_id)
    if apply:
        query = query.with_for_update(nowait=True)
    rows = (await session.execute(query)).all()
    plaintext = []
    for row in rows:
        value = row.openvpn_config_content
        if is_encrypted(value) or value.startswith("gAAAA"):
            # A malformed/foreign-key token must not be re-encrypted as text.
            decrypt_credential(value)
        else:
            plaintext.append((row.id, value))
    if apply:
        for profile_id, value in plaintext:
            await session.execute(
                update(SiteVPNConfiguration)
                .where(
                    SiteVPNConfiguration.id == profile_id,
                )
                .values(openvpn_config_content=encrypt_credential(value))
            )
    return {
        "examined": len(rows),
        "plaintext": len(plaintext),
        "already_encrypted": len(rows) - len(plaintext),
        "updated": len(plaintext) if apply else 0,
        "last_id": str(rows[-1].id) if rows else (str(after_id) if after_id else None),
    }
