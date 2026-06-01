# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""VPN backup contributor — VPN connection records (the connectivity-fabric
overlay / site VPNs: Tailscale / WireGuard / OpenVPN / NetBird).

Closes the gap (found in the backup audit) where ``VPNConnectionRecord`` was
captured by NO contributor — so a restore brought back everything except VPN.

Scope:
  * CONFIG snapshot (.fsdn): VPN connection config WITHOUT secrets — the
    per-field-encrypted ``openvpn_config_content`` / ``wireguard_config_content``
    / ``netbird_setup_key`` are excluded (the operator re-enters them).
  * FULL / vault (.fsdnvault): those secret fields are DECRYPTED into the
    passphrase-sealed payload and RE-ENCRYPTED under the target instance's
    SECRET_KEY at restore — portable + re-keyed (mirrors the controller-config
    handling in core).

Tenant scoping: ``VPNConnectionRecord`` carries a DIRECT ``organization_id``;
collect filters by it and restore forces it. depends_on=("core",) so it runs
after the core contributor.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select

from app.services.backup_contributors import (
    ContributorPayload,
    RestoreResult,
    restore_records,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# Secret columns on VPNConnectionRecord, each encrypted INDIVIDUALLY via
# encrypt_credential (see app/models/vpn.py). Decrypted into a vault payload;
# re-encrypted under the target instance's key at restore.
_VPN_SECRET_FIELDS = (
    "openvpn_config_content",
    "wireguard_config_content",
    "netbird_setup_key",
)
# Non-secret columns captured for BOTH config snapshots and vault backups.
_VPN_PLAIN_FIELDS = (
    "name",
    "vpn_type",
    "status",
    "endpoint",
    "port",
    "local_ip",
    "remote_ip",
    "allowed_ips",
    "dns_servers",
    "rx_bytes",
    "tx_bytes",
    "extra_data",
    "openvpn_config_path",
    "openvpn_protocol",
    "netbird_management_url",
)


class VpnBackupContributor:
    """Backup/restore for VPN connection records (config-portable + vault)."""

    contributor_id: str = "vpn"
    schema_version: str = "1.0.0"
    depends_on: tuple[str, ...] = ("core",)
    default_included: bool = True

    async def collect(
        self,
        session: AsyncSession,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> ContributorPayload:
        from app.models.vpn import VPNConnectionRecord

        include_secrets = bool(options.get("include_secrets", False))
        rows = (
            (
                await session.execute(
                    select(VPNConnectionRecord).where(
                        VPNConnectionRecord.organization_id == organization_id
                    )
                )
            )
            .scalars()
            .all()
        )

        if include_secrets:
            from app.core.crypto import decrypt_credential, is_encrypted

        data: list[dict[str, Any]] = []
        for r in rows:
            d: dict[str, Any] = {
                "id": str(r.id),
                "organization_id": str(r.organization_id) if r.organization_id else None,
            }
            for f in _VPN_PLAIN_FIELDS:
                d[f] = getattr(r, f, None)
            if include_secrets:
                for f in _VPN_SECRET_FIELDS:
                    v = getattr(r, f, None)
                    d[f] = decrypt_credential(v) if (isinstance(v, str) and is_encrypted(v)) else v
            data.append(d)

        return ContributorPayload(
            schema_version=self.schema_version,
            counts={"vpn_connections": len(data)},
            data={"vpn_connections": data},
            metadata={
                "captured_at": time.time(),
                "source": "vpn_contributor.collect",
                "secrets_excluded": not include_secrets,
            },
        )

    async def restore(
        self,
        session: AsyncSession,
        organization_id: UUID,
        payload: ContributorPayload,
        *,
        dry_run: bool,
        options: dict[str, Any],
    ) -> RestoreResult:
        from app.models.vpn import VPNConnectionRecord

        include_secrets = bool(options.get("include_secrets", False))
        result = RestoreResult(
            contributor_id=self.contributor_id,
            status="dry_run_ok" if dry_run else "ok",
        )
        records = [dict(r) for r in payload.data.get("vpn_connections", [])]

        if include_secrets:
            from app.core.crypto import encrypt_credential, is_encrypted

            # Re-encrypt the decrypted secret fields under THIS instance's key
            # before they touch the DB (mirrors the controller-config re-key).
            for rec in records:
                for f in _VPN_SECRET_FIELDS:
                    v = rec.get(f)
                    if isinstance(v, str) and v and not is_encrypted(v):
                        rec[f] = encrypt_credential(v)

        # Config snapshot never restores secret columns; vault restores them
        # (re-encrypted above).
        blocked = set() if include_secrets else set(_VPN_SECRET_FIELDS)
        await restore_records(
            session,
            model_cls=VPNConnectionRecord,
            records=records,
            result=result,
            resource="vpn_connections",
            dry_run=dry_run,
            overwrite=bool(options.get("overwrite_existing", False)),
            force_org=organization_id,
            blocked_fields=blocked,
        )
        return result
