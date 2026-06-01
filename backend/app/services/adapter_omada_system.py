# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway system service.

Covers controller-level + site-level + monitoring management:
  - Controller backups (list/download/restore/delete)
  - Controller SMTP + notifications + SSL cert + admins
  - Controller global settings + maintenance window + cloud-access
  - Site time/NTP + LED schedule + reboot schedules + notifications
  - SNMP + syslog exporters

Reads run live; writes stage. Backup downloads are a special case —
they return raw bytes, so the endpoint streams them directly without
going through staging.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

_APPLY: dict[tuple[str, str], str] = {
    # Controller backup
    ("system.backup", "create"): "create_controller_backup",
    ("system.backup", "delete"): "delete_controller_backup",
    ("system.backup.restore", "create"): "restore_controller_backup",
    # SMTP + notifications
    ("system.smtp", "update"): "update_controller_smtp_config",
    ("system.smtp.test", "create"): "test_controller_smtp",
    ("system.notifications", "update"): "update_controller_notification_settings",
    # SSL cert
    ("system.ssl_cert", "update"): "upload_controller_ssl_cert",
    # Controller admins
    ("system.admin", "create"): "create_controller_admin",
    ("system.admin", "update"): "update_controller_admin",
    ("system.admin", "delete"): "delete_controller_admin",
    # Global + maintenance + cloud
    ("system.global", "update"): "update_controller_global_settings",
    ("system.maintenance", "update"): "update_controller_maintenance_window",
    ("system.cloud_access", "update"): "update_cloud_access",
    # Site time + LED + reboot schedules + notifications subscription
    ("site.time", "update"): "update_site_time_config",
    ("site.led_schedule", "update"): "update_led_schedule",
    ("site.reboot_schedule", "create"): "create_reboot_schedule",
    ("site.reboot_schedule", "update"): "update_reboot_schedule",
    ("site.reboot_schedule", "delete"): "delete_reboot_schedule",
    ("site.notifications", "update"): "update_site_notifications_subscription",
    # Monitoring exporters (site-scoped)
    ("monitoring.snmp", "update"): "update_snmp_config",
    ("monitoring.syslog", "update"): "update_syslog_config",
}


# Read-config method map: name → client method
_READ_CONTROLLER: dict[str, str] = {
    "smtp": "get_controller_smtp_config",
    "notifications": "get_controller_notification_settings",
    "ssl_cert": "get_controller_ssl_cert",
    "global": "get_controller_global_settings",
    "maintenance": "get_controller_maintenance_window",
    "cloud_access": "get_cloud_access_status",
}

_READ_SITE: dict[str, str] = {
    "time": "get_site_time_config",
    "led_schedule": "get_led_schedule",
    "notifications": "get_site_notifications_subscription",
    "snmp": "get_snmp_config",
    "syslog": "get_syslog_config",
}


# Keys that may carry secrets in the Omada response and must NEVER be
# returned to the UI. Matched case-insensitively against dict keys at
# every level. Conservative: better to redact a non-secret like
# ``apiKey`` than to leak a real one.
_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "passwordhash",
    "password_hash",
    "secret",
    "clientsecret",
    "client_secret",
    "apikey",
    "api_key",
    "token",
    "accesstoken",
    "access_token",
    "refreshtoken",
    "refresh_token",
    "privatekey",
    "private_key",
    "key_pem",
    "keypem",
    "sshkey",
    "ssh_key",
    "psk",
    "snmp_community",
    "community",
    "authpassword",
    "auth_password",
    "privpassword",
    "priv_password",
}


_SCRUB_MAX_DEPTH = 64


def _scrub(value: Any, _depth: int = 0) -> Any:
    """Recursively redact sensitive keys in dicts and lists.

    Returns a new structure; does not mutate the input. Strings whose
    *parent key* is sensitive get replaced with the literal
    ``"***redacted***"`` so the UI can show that the field exists
    without leaking it.

    Depth-bounded to avoid stack overflow if the Omada controller (or
    a malicious response) returns pathologically nested data.
    """
    if _depth >= _SCRUB_MAX_DEPTH:
        # Refuse rather than recurse; surface as a 502 upstream.
        raise HTTPException(
            502,
            detail="controller response is too deeply nested to sanitize",
        )
    if isinstance(value, dict):
        return {
            k: (
                "***redacted***"
                if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS
                else _scrub(v, _depth + 1)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item, _depth + 1) for item in value]
    return value


class GatewaySystemService(GatewayServiceBase):
    """Live reads + staged writes for system / site / monitoring config."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def get_controller_config(
        self,
        controller_id: UUID,
        organization_id: UUID,
        config_name: str,
    ) -> dict[str, Any]:
        method_name = _READ_CONTROLLER.get(config_name)
        if method_name is None:
            raise HTTPException(
                400,
                detail=(
                    f"unknown controller config={config_name!r}; expected "
                    f"one of {sorted(_READ_CONTROLLER)}"
                ),
            )
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await getattr(client, method_name)()
        # Strip secrets before returning. The Omada response for
        # smtp/ssl_cert/notifications routinely carries password +
        # private-key fields; we never want those reaching the UI.
        return {
            "controller_id": controller_id,
            "config_name": config_name,
            "item": _scrub(item),
            "fetched_at": datetime.now(UTC),
        }

    async def get_site_config(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        config_name: str,
    ) -> dict[str, Any]:
        method_name = _READ_SITE.get(config_name)
        if method_name is None:
            raise HTTPException(
                400,
                detail=(
                    f"unknown site config={config_name!r}; expected one of {sorted(_READ_SITE)}"
                ),
            )
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = await getattr(client, method_name)(omada_site_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "config_name": config_name,
            "item": _scrub(item),
            "fetched_at": datetime.now(UTC),
        }

    async def list_backups(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.list_controller_backups()
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def download_backup(
        self, controller_id: UUID, organization_id: UUID, backup_id: str
    ) -> bytes:
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        return await client.download_controller_backup(backup_id)

    async def list_admins(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_controller_admins()
        # Strip password / passwordHash / apiKey from each admin record.
        return {
            "controller_id": controller_id,
            "items": _scrub(items),
            "fetched_at": datetime.now(UTC),
        }

    async def list_reboot_schedules(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_reboot_schedules(omada_site_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name)

            # Controller-scoped (no site arg)
            controller_features = (
                "system.backup",
                "system.backup.restore",
                "system.smtp",
                "system.smtp.test",
                "system.notifications",
                "system.ssl_cert",
                "system.admin",
                "system.global",
                "system.maintenance",
                "system.cloud_access",
            )
            if c.feature in controller_features:
                if c.feature == "system.backup" and c.operation == "create":
                    return await method()
                if c.feature == "system.backup" and c.operation == "delete":
                    return await method(target_id)
                if c.feature == "system.backup.restore":
                    return await method(payload["backup_id"])
                if c.feature == "system.smtp.test":
                    return await method(payload["recipient"])
                if c.feature == "system.ssl_cert":
                    return await method(
                        cert_pem=payload["cert_pem"],
                        key_pem=payload["key_pem"],
                        ca_chain_pem=payload.get("ca_chain_pem"),
                    )
                if c.feature == "system.admin":
                    if c.operation == "create":
                        return await method(payload)
                    if c.operation == "update":
                        return await method(target_id, payload)
                    if c.operation == "delete":
                        return await method(target_id)
                    # Defensive: stage_change validates op ∈ create|update|
                    # delete, so this is unreachable. Guard explicitly so
                    # a future schema change cannot fall through to the
                    # generic ``method(payload)`` below with the wrong
                    # arg shape.
                    raise HTTPException(
                        400,
                        detail=(f"unsupported operation={c.operation!r} for system.admin"),
                    )
                # All remaining controller-level updates take just payload
                return await method(payload)

            # Site-scoped
            if c.feature == "site.reboot_schedule":
                if c.operation == "create":
                    return await method(omada_site_id, payload)
                if c.operation == "update":
                    return await method(omada_site_id, target_id, payload)
                if c.operation == "delete":
                    return await method(omada_site_id, target_id)
            # Generic site-update endpoints (time, led, notifications, snmp, syslog)
            return await method(omada_site_id, payload)

        return _apply
