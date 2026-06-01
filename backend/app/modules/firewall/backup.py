# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Firewall backup contributor — devices, rules, NAT, VPN tunnels,
gateway connections (NOT sync logs / IDS alerts / traffic logs).

Third module-owned contributor. Reuses the shared ``restore_records``
helper. Closes the audit's "Firewall — devices, rules, NAT, aliases"
item (FreeSDN has no separate alias model; rule source/dest addresses
inline the address objects, so they're captured with the rules).

Scope:

  Included (portable configuration):
    - firewall.devices              (UTM / firewall device records)
    - firewall.rules                (firewall rules)
    - firewall.nat_rules            (NAT / port-forward rules)
    - firewall.vpn_tunnels          (VPN tunnel config; PSK redacted)
    - firewall.gateway_connections  (external-gateway integration;
                                     credentials stripped)

  Excluded:
    - firewall.gateway_sync_logs    (sync telemetry)
    - firewall.ids_alerts           (IDS/IPS event telemetry)
    - firewall.firewall_logs        (traffic-log telemetry)
    - GatewayConnection.credentials (API keys / passwords — operator
                                     re-enters after restore)
    - any secret-shaped key in settings JSONB (e.g. VPN PSK)

Tenant scoping: FirewallDevice carries ``site_id`` (→ org via site).
GatewayConnection carries a DIRECT ``org_id`` column. Rules / NAT / VPN
FK to ``device_id``. collect filters by org; restore rejects
cross-tenant + orphan references and strips secrets.

Restore order (FK dependency): FirewallDevice → (rules, nat, vpn —
device_id) → GatewayConnection (org_id direct; site_id + device_id are
nullable FKs). depends_on=("core",) so sites exist first.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select

from app.services.backup_contributors import (
    ContributorPayload,
    NullableFK,
    RejectGuard,
    RestoreResult,
    restore_records,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


_SECRET_SETTINGS_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "api_secret",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "psk",
        "pre_shared_key",
        "presharedkey",
        "auth_password",
        "admin_password",
    }
)


def _redact(blob: Any) -> Any:
    if isinstance(blob, dict):
        return {k: _redact(v) for k, v in blob.items() if k.lower() not in _SECRET_SETTINGS_KEYS}
    if isinstance(blob, list):
        return [_redact(v) for v in blob]
    return blob


def _settings_for(blob: Any, include_secrets: bool) -> Any:
    """Vault keeps settings intact (sealed, e.g. VPN tunnel PSK); config snapshot redacts."""
    return (blob or {}) if include_secrets else _redact(blob or {})


def _vault_decrypt_dict(blob: Any) -> dict:
    """GatewayConnection.credentials is a WHOLE-dict encrypted via encrypt_dict
    ({"_encrypted": ...}). Decrypt it for a vault payload (no-op for a plain dict)."""
    from app.core.crypto import decrypt_dict

    return decrypt_dict(blob or {})


class FirewallBackupContributor:
    """Backup/restore for the Firewall module's portable configuration."""

    contributor_id: str = "firewall"
    schema_version: str = "1.0.0"
    depends_on: tuple[str, ...] = ("core",)
    default_included: bool = True

    # ── collect ────────────────────────────────────────────────────────

    async def collect(
        self,
        session: AsyncSession,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> ContributorPayload:
        from app.models.core import Site
        from app.modules.firewall.models import (
            FirewallDevice,
            FirewallRule,
            GatewayConnection,
            NATRule,
            VPNTunnel,
        )

        site_filter = options.get("site_id")
        include_secrets = bool(options.get("include_secrets", False))

        # --- Firewall devices (org-scoped via Site join) ---
        dev_q = (
            select(FirewallDevice)
            .join(Site, FirewallDevice.site_id == Site.id)
            .where(
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
                FirewallDevice.deleted_at.is_(None),
            )
        )
        if site_filter:
            dev_q = dev_q.where(FirewallDevice.site_id == site_filter)
        dev_rows = (await session.execute(dev_q)).scalars().all()
        dev_ids = [d.id for d in dev_rows]
        dev_data = [
            {
                "id": str(d.id),
                "site_id": str(d.site_id),
                "controller_id": str(d.controller_id) if d.controller_id else None,
                "name": d.name,
                "description": d.description,
                "device_type": d.device_type,
                "ip_address": d.ip_address,
                "port": d.port,
                "vendor": d.vendor,
                "model": d.model,
                "firmware_version": d.firmware_version,
                "serial_number": d.serial_number,
                "supports_ids": d.supports_ids,
                "supports_vpn": d.supports_vpn,
                "default_policy": d.default_policy,
                "settings": _settings_for(d.settings, include_secrets),
            }
            for d in dev_rows
        ]

        # --- Rules / NAT / VPN (scoped via device_id) ---
        rule_data: list[dict[str, Any]] = []
        nat_data: list[dict[str, Any]] = []
        vpn_data: list[dict[str, Any]] = []
        if dev_ids:
            rule_rows = (
                (
                    await session.execute(
                        select(FirewallRule).where(
                            FirewallRule.device_id.in_(dev_ids),
                            FirewallRule.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            rule_data = [
                {
                    "id": str(r.id),
                    "device_id": str(r.device_id),
                    "name": r.name,
                    "description": r.description,
                    "rule_order": r.rule_order,
                    "source_address": r.source_address,
                    "source_port": r.source_port,
                    "source_zone": r.source_zone,
                    "dest_address": r.dest_address,
                    "dest_port": r.dest_port,
                    "dest_zone": r.dest_zone,
                    "protocol": r.protocol,
                    "action": r.action,
                    "log_enabled": r.log_enabled,
                    "is_enabled": r.is_enabled,
                }
                for r in rule_rows
            ]

            nat_rows = (
                (
                    await session.execute(
                        select(NATRule).where(
                            NATRule.device_id.in_(dev_ids),
                            NATRule.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            nat_data = [
                {
                    "id": str(n.id),
                    "device_id": str(n.device_id),
                    "name": n.name,
                    "description": n.description,
                    "nat_type": n.nat_type,
                    "original_address": n.original_address,
                    "original_port": n.original_port,
                    "translated_address": n.translated_address,
                    "translated_port": n.translated_port,
                    "protocol": n.protocol,
                    "interface": n.interface,
                    "is_enabled": n.is_enabled,
                }
                for n in nat_rows
            ]

            vpn_rows = (
                (
                    await session.execute(
                        select(VPNTunnel).where(
                            VPNTunnel.device_id.in_(dev_ids),
                            VPNTunnel.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            vpn_data = [
                {
                    "id": str(v.id),
                    "device_id": str(v.device_id),
                    "name": v.name,
                    "description": v.description,
                    "vpn_type": v.vpn_type,
                    "remote_address": v.remote_address,
                    "remote_id": v.remote_id,
                    "local_address": v.local_address,
                    "local_id": v.local_id,
                    "local_subnets": v.local_subnets or [],
                    "remote_subnets": v.remote_subnets or [],
                    "auth_type": v.auth_type,
                    "is_enabled": v.is_enabled,
                    # settings may hold the PSK — redacted.
                    "settings": _settings_for(v.settings, include_secrets),
                }
                for v in vpn_rows
            ]

        # --- Gateway connections (org-scoped via org_id; creds stripped) ---
        gw_rows = (
            (
                await session.execute(
                    select(GatewayConnection).where(
                        GatewayConnection.org_id == organization_id,
                        GatewayConnection.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        gw_data = [
            {
                "id": str(g.id),
                "org_id": str(g.org_id),
                "site_id": str(g.site_id) if g.site_id else None,
                "device_id": str(g.device_id) if g.device_id else None,
                "name": g.name,
                "description": g.description,
                "vendor": g.vendor,
                "host": g.host,
                "port": g.port,
                "verify_ssl": g.verify_ssl,
                # Config snapshot: credentials (API keys/passwords) NEVER exported.
                # Vault: the whole credentials dict is decrypted into the sealed payload
                # (re-encrypted under the target key at restore).
                **({"credentials": _vault_decrypt_dict(g.credentials)} if include_secrets else {}),
                "sync_enabled": g.sync_enabled,
                "sync_interval_seconds": g.sync_interval_seconds,
                "capabilities": g.capabilities or [],
                "settings": _settings_for(g.settings, include_secrets),
            }
            for g in gw_rows
        ]

        data = {
            "devices": dev_data,
            "rules": rule_data,
            "nat_rules": nat_data,
            "vpn_tunnels": vpn_data,
            "gateway_connections": gw_data,
        }
        counts = {k: len(v) for k, v in data.items()}

        return ContributorPayload(
            schema_version=self.schema_version,
            counts=counts,
            data=data,
            metadata={
                "captured_at": time.time(),
                "source": "firewall_contributor.collect",
                "secrets_excluded": True,
            },
        )

    # ── restore ────────────────────────────────────────────────────────

    async def restore(
        self,
        session: AsyncSession,
        organization_id: UUID,
        payload: ContributorPayload,
        *,
        dry_run: bool,
        options: dict[str, Any],
    ) -> RestoreResult:
        from app.models.core import Site
        from app.modules.firewall.models import (
            FirewallDevice,
            FirewallRule,
            GatewayConnection,
            NATRule,
            VPNTunnel,
        )

        start = time.monotonic()
        result = RestoreResult(
            contributor_id=self.contributor_id,
            status="dry_run_ok" if dry_run else "ok",
        )
        overwrite = options.get("overwrite_existing", False)
        include_secrets = bool(options.get("include_secrets", False))
        data = payload.data

        # Vault restore: GatewayConnection.credentials arrived as a DECRYPTED dict in the
        # passphrase-sealed payload — re-encrypt it whole (encrypt_dict) under THIS
        # instance's key before it touches the DB.
        if include_secrets:
            from app.core.crypto import encrypt_dict

            for rec in data.get("gateway_connections", []):
                creds = rec.get("credentials")
                if isinstance(creds, dict) and creds and "_encrypted" not in creds:
                    rec["credentials"] = encrypt_dict(creds)

        org_site_ids = {
            str(s)
            for s in (
                await session.execute(
                    select(Site.id).where(
                        Site.organization_id == organization_id,
                        Site.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        }

        # --- Firewall devices first (FK target for rules/nat/vpn) ---
        restored_dev_ids = await restore_records(
            session,
            model_cls=FirewallDevice,
            records=data.get("devices", []),
            result=result,
            resource="devices",
            dry_run=dry_run,
            overwrite=overwrite,
            reject_guards=[RejectGuard("site_id", org_site_ids, "cross-tenant")],
        )

        # --- Rules / NAT / VPN (device_id must be among restored devices) ---
        for resource, model_cls in (
            ("rules", FirewallRule),
            ("nat_rules", NATRule),
            ("vpn_tunnels", VPNTunnel),
        ):
            await restore_records(
                session,
                model_cls=model_cls,
                records=data.get(resource, []),
                result=result,
                resource=resource,
                dry_run=dry_run,
                overwrite=overwrite,
                reject_guards=[
                    RejectGuard("device_id", restored_dev_ids, "orphan"),
                ],
            )

        # --- Gateway connections (org_id direct; site_id + device_id
        #     nullable; credentials column blocked) ---
        await restore_records(
            session,
            model_cls=GatewayConnection,
            records=data.get("gateway_connections", []),
            result=result,
            resource="gateway_connections",
            dry_run=dry_run,
            overwrite=overwrite,
            # GatewayConnection uses ``org_id`` (not organization_id), so
            # force_org's hasattr check won't fire — guard cross-tenant via
            # an explicit reject on org_id instead.
            reject_guards=[
                RejectGuard("org_id", {str(organization_id)}, "cross-tenant"),
            ],
            nullable_fks=[
                NullableFK("site_id", org_site_ids),
                NullableFK("device_id", restored_dev_ids),
            ],
            # Config snapshot: credentials are stripped at collect; block on
            # insert/update too. Vault: restore the credentials dict (re-encrypted above).
            blocked_fields=(set() if include_secrets else {"credentials"}),
        )

        if not dry_run:
            await session.flush()
        result.duration_sec = time.monotonic() - start
        return result


__all__ = ["FirewallBackupContributor"]
