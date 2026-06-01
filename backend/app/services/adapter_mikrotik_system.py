# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik System / Operations service
========================================================

Read-and-stage for the MikroTik operations surface. Covers system
utilities, backup / export, services, logs, switch chip / SwOS-lite,
and tools (bandwidth-test, fetch).

Supported features::

    mikrotik.system.reboot                create
    mikrotik.system.shutdown              create
    mikrotik.system.backup_create         create   (payload: {name, password?})
    mikrotik.system.backup_load           create   (payload: {name, password?})
    mikrotik.system.export_config         create   (payload: {file?})
    mikrotik.system.file_delete           delete   (target_id = file id)
    mikrotik.system.service_toggle        update   (target_id = service name; payload {disabled})
    mikrotik.system.switch_port           update   (target_id, payload)
    mikrotik.system.switch_vlan           create | delete
    mikrotik.system.switch_rule           create | delete
    mikrotik.system.tool_bandwidth_test   create   (non-mutating measurement, but POST → still gated)
    mikrotik.system.tool_fetch            create   (POST /tool/fetch)

Production safety: every write is staged. The applier passes
``force=True`` so the read-only gate at the client layer lets the
sanctioned write through. Bandwidth-test and fetch are read-shaped
operationally but use POST and so still flow through the gate — that
is intentional, the gate is method-driven not semantic.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse, urlunparse
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# RouterOS REST API supported version range. The reboot/shutdown
# endpoints are not exposed on every 7.x build — some early 7.0 / 7.1
# images return 404 from /system/reboot. We translate those to a
# clear "unsupported on this firmware" message instead of leaking
# the raw HTTP status to the operator.
_MIKROTIK_SUPPORTED_REST_VERSION = "RouterOS 7.1+"

# ``mikrotik.system.tool_fetch`` payload allowlist. RouterOS will
# happily accept arbitrary keys (RouterOS-side validation is loose);
# we lock the contract down to the keys we've reviewed for safety so
# an operator can't slip e.g. ``http-method=POST`` + ``http-data=…``
# past us via the staged-change UI.
_TOOL_FETCH_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "url",
        "mode",  # http | https | ftp
        "dst-path",
        "user",
        "keep-result",
    }
)
_TOOL_FETCH_ALLOWED_MODES: frozenset[str] = frozenset({"http", "https", "ftp"})
_TOOL_FETCH_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp"})
# Forbidden destinations — cloud metadata services + loopback. We
# intentionally do NOT block RFC1918: routers commonly fetch from a
# LAN-side artifact server and that's a legitimate use of /tool/fetch.
_TOOL_FETCH_FORBIDDEN_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / OpenStack / Azure metadata
        "metadata.google.internal",
        "localhost",
    }
)


def _validate_tool_fetch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Reject tool_fetch payloads that target metadata services or
    expose unreviewed RouterOS keys, and PIN a hostname URL to the
    validated IP literal so RouterOS cannot re-resolve it.

    Returns the (possibly URL-rewritten) payload. Raises
    ``HTTPException(400)`` so the staged-change applier surfaces the
    rejection to the operator rather than letting the router 200 OK
    on a SSRF attempt.

    the earlier fix validated every resolved address but
    sent the original HOSTNAME url to RouterOS, which performs its OWN
    DNS lookup at fetch time — so a low-TTL rebinding domain that
    answered a safe IP during validation could rebind to
    loopback/metadata/internal at fetch time. We now substitute the
    validated IP literal into the url host, so RouterOS fetches the
    exact address we checked and cannot re-resolve.
    """
    bad_keys = [k for k in payload if k not in _TOOL_FETCH_ALLOWED_KEYS]
    if bad_keys:
        raise HTTPException(
            400,
            detail=(
                f"tool_fetch payload has disallowed keys: "
                f"{sorted(bad_keys)!r}; allowed = "
                f"{sorted(_TOOL_FETCH_ALLOWED_KEYS)!r}"
            ),
        )

    mode = payload.get("mode")
    if mode is not None and mode not in _TOOL_FETCH_ALLOWED_MODES:
        raise HTTPException(
            400,
            detail=(
                f"tool_fetch mode {mode!r} not allowed; "
                f"must be one of {sorted(_TOOL_FETCH_ALLOWED_MODES)!r}"
            ),
        )

    url = payload.get("url")
    if not url or not isinstance(url, str):
        raise HTTPException(400, detail="tool_fetch payload requires a non-empty 'url' string")

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise HTTPException(400, detail=f"tool_fetch URL is unparseable: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _TOOL_FETCH_ALLOWED_SCHEMES:
        raise HTTPException(
            400,
            detail=(
                f"tool_fetch URL scheme {scheme!r} not allowed; "
                f"must be one of {sorted(_TOOL_FETCH_ALLOWED_SCHEMES)!r}"
            ),
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(400, detail="tool_fetch URL has no hostname")
    # reuse the CENTRAL SSRF blocklist instead of an ad-hoc set.
    # is_ssrf_blocked_ip covers loopback / link-local / multicast / reserved /
    # unspecified AND every cloud-metadata literal (AWS/GCP/Azure 169.254.169.254,
    # Alibaba 100.100.100.200, Oracle 192.0.0.192, AWS IPv6 fd00:ec2::254). RFC1918
    # stays allowed — RouterOS legitimately fetches from LAN artifact servers.
    from app.core.security_utils import is_ssrf_blocked_ip

    if host in _TOOL_FETCH_FORBIDDEN_HOSTS or host in {"metadata.goog"}:
        raise HTTPException(
            400,
            detail=(f"tool_fetch refused for forbidden host {host!r} (cloud metadata service)"),
        )
    try:
        ipaddress.ip_address(host)
        if is_ssrf_blocked_ip(host):
            raise HTTPException(400, detail=f"tool_fetch refused for blocked address {host!r}")
        # Already an IP literal — RouterOS performs no DNS lookup, nothing to pin.
        return payload
    except ValueError:
        # hostname → resolve every answer and reject if any is SSRF-unsafe
        import socket

        try:
            resolved = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        except OSError:
            resolved = set()
        # fail CLOSED on a hostname we can't resolve — we cannot
        # verify it isn't an SSRF target, and RouterOS performs the final fetch
        # (its DNS may differ from / change after ours), so an unresolved name
        # must not be allowed through.
        if not resolved:
            raise HTTPException(
                400,
                detail=(
                    f"tool_fetch refused: hostname {host!r} did not resolve "
                    "(cannot verify it is not an internal/metadata target)"
                ),
            )
        for addr in resolved:
            if is_ssrf_blocked_ip(addr):
                raise HTTPException(
                    400,
                    detail=f"tool_fetch refused: {host!r} resolves to blocked address {addr!r}",
                )
        # PIN the URL to one validated IP literal so RouterOS cannot
        # re-resolve the hostname to a different (rebind) address at fetch time.
        # Sort for determinism; preserve scheme/userinfo/port/path/query/fragment.
        pinned_ip = sorted(resolved)[0]
        host_part = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        netloc = host_part
        if parsed.port is not None:
            netloc = f"{host_part}:{parsed.port}"
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo = f"{userinfo}:{parsed.password}"
            netloc = f"{userinfo}@{netloc}"
        payload = dict(payload)
        payload["url"] = urlunparse(parsed._replace(netloc=netloc))
        return payload


def _validate_export_config_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Force ``hide-sensitive=yes`` on /export and validate the file kw.

    RouterOS' /export emits the running config; with
    ``hide-sensitive=no`` it includes credentials in plain text, so
    we overwrite any operator-supplied value to ``yes`` even if a
    staged change tries to disable it. The output is persisted in
    ``adapter_pending_changes.applied_response`` and may be visible to
    operators downstream — never let it carry plaintext secrets.

    The ``file`` kw lands as a filename on the router's flash. Reject
    anything containing ``..`` or path separators; only bare filenames
    are accepted (RouterOS will append the .rsc extension).
    """
    cleaned: dict[str, Any] = dict(payload)
    # Hard-force the safety flag regardless of operator intent.
    cleaned["hide-sensitive"] = "yes"
    file_name = cleaned.get("file")
    if file_name is not None:
        if not isinstance(file_name, str) or not file_name:
            raise HTTPException(400, detail="export_config 'file' must be a non-empty string")
        if ".." in file_name or "/" in file_name or "\\" in file_name:
            raise HTTPException(
                400,
                detail=(
                    f"export_config 'file' must be a bare filename "
                    f"(no path separators or '..'); got {file_name!r}"
                ),
            )
    return cleaned


# Allowlist of payload keys for ``mikrotik.system.switch_vlan`` and
# ``mikrotik.system.switch_rule`` create operations. RouterOS' switch
# chip path accepts a fixed schema; rejecting anything else closes a
# passthrough hole that would let an operator inject arbitrary
# RouterOS attributes via the staged-change UI.
_SWITCH_VLAN_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "switch",
        "vlan-id",
        "ports",
        "comment",
        "disabled",
        "learn",
        "qos",
        "isolation-leakless",
        "priority",
    }
)

_SWITCH_RULE_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "switch",
        "ports",
        "chain",
        "action",
        "mac-protocol",
        "src-address",
        "dst-address",
        "src-mac-address",
        "dst-mac-address",
        "vlan-id",
        "vlan-priority",
        "new-vlan-id",
        "new-vlan-priority",
        "new-dst-ports",
        "src-port",
        "dst-port",
        "ip-protocol",
        "protocol",
        "comment",
        "disabled",
        "redirect-to-cpu",
        "rate",
    }
)


# ``shared_secret`` is now covered by the central
# ``redact_secrets`` strip-list. The per-service ``_mask_routeros``
# helper was deleted — single-pass redaction here closes the
# double-walk perf cost.


def _redact_items(items: list[Any]) -> list[Any]:
    return [redact_secrets(i) for i in items]


def _redact_item(item: Any) -> Any:
    return redact_secrets(item)


_APPLY: dict[tuple[str, str], str] = {
    # Power management
    ("mikrotik.system.reboot", "create"): "reboot_router",
    ("mikrotik.system.shutdown", "create"): "shutdown_router",
    # Identity (rename) + NTP client config
    ("mikrotik.system.identity", "update"): "set_system_identity",
    ("mikrotik.system.ntp", "update"): "set_ntp_client",
    # Backup / export / file management (legacy v1 names)
    ("mikrotik.system.backup_create", "create"): "create_backup",
    ("mikrotik.system.backup_load", "create"): "load_backup",
    ("mikrotik.system.export_config", "create"): "export_config",
    ("mikrotik.system.file_delete", "delete"): "delete_file",
    # Services (toggle disabled / port / address)
    ("mikrotik.system.service_toggle", "update"): "update_service",
    # Switch chip
    ("mikrotik.system.switch_port", "update"): "update_switch_port",
    ("mikrotik.system.switch_vlan", "create"): "add_switch_vlan",
    ("mikrotik.system.switch_vlan", "delete"): "delete_switch_vlan",
    ("mikrotik.system.switch_rule", "create"): "add_switch_rule",
    ("mikrotik.system.switch_rule", "delete"): "delete_switch_rule",
    # Tools
    ("mikrotik.system.tool_bandwidth_test", "create"): "run_bandwidth_test",
    ("mikrotik.system.tool_fetch", "create"): "fetch_url",
    # ── firmware / package / backup / neighbor lifecycle ──
    # Firmware update path. Each verb maps to a distinct RouterOS
    # action. ``firmware.install`` is dual-gated (catastrophic role +
    # controller:write) at the endpoint layer.
    ("mikrotik.system.firmware.check", "create"): "check_for_updates",
    ("mikrotik.system.firmware.channel", "update"): "set_update_channel",
    ("mikrotik.system.firmware.download", "create"): "download_update",
    ("mikrotik.system.firmware.install", "create"): "download_and_install_update",
    ("mikrotik.system.firmware.cancel", "create"): "cancel_update_download",
    # Package lifecycle. ``uninstall`` is catastrophic.
    ("mikrotik.system.package.enable", "update"): "enable_package",
    ("mikrotik.system.package.disable", "update"): "disable_package",
    ("mikrotik.system.package.uninstall", "delete"): "uninstall_package",
    # Backup lifecycle (dotted namespace; legacy ``backup_*``
    # codes above remain for compatibility with already-queued changes).
    ("mikrotik.system.backup.create_binary", "create"): "create_backup",
    ("mikrotik.system.backup.export_text", "create"): "export_config_to_text",
    ("mikrotik.system.backup.upload", "create"): "upload_backup_content",
    ("mikrotik.system.backup.delete", "delete"): "delete_backup",
    ("mikrotik.system.backup.restore", "create"): "restore_backup",
    # Neighbor discovery singleton.
    ("mikrotik.system.neighbor.settings", "update"): "update_neighbor_discovery_settings",
}

# NTP payload allowlist — RouterOS will happily accept arbitrary
# kebab-case keys on /system/ntp/client. Lock down the surface to
# the four fields a UI is realistically going to need; reject any
# extras so a staged change can't smuggle in a non-NTP attribute.
_NTP_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "primary-ntp",
        "secondary-ntp",
        "enabled",
        "servers",  # RouterOS 7.10+ canonical name (list of servers)
    }
)


class GatewayMikrotikSystemService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik operations surface."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_system_info(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Identity + resource + routerboard + license + clock + health
        rolled into a single read so a UI panel can fetch once."""
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "identity": _redact_item(await client.get_system_identity()),
            "resource": _redact_item(await client.get_system_resource()),
            "routerboard": _redact_item(await client.get_system_routerboard()),
            "license": _redact_item(await client.get_system_license()),
            "clock": _redact_item(await client.get_system_clock()),
            "health": _redact_items(await client.get_system_health()),
            "packages": _redact_items(await client.get_packages()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_services(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_services()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_files(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_files()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_logs(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_logs()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_switch_chips(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_switch_chips()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_switch_ports(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_switch_ports()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_switch_vlans(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_switch_vlans()),
            "fetched_at": datetime.now(UTC),
        }

    async def list_switch_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": _redact_items(await client.get_switch_rules()),
            "fetched_at": datetime.now(UTC),
        }

    # ── reads: firmware / packages / backups / neighbors ──

    async def get_firmware_status(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_item(await client.get_update_status())

    async def list_packages(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> list[dict[str, Any]]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_items(await client.get_installed_packages())

    async def list_backups(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> list[dict[str, Any]]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_items(await client.list_backups())

    async def get_backup_metadata(
        self,
        controller_id: UUID,
        organization_id: UUID,
        name: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_item(await client.get_backup_metadata(name))

    async def stream_backup_content(
        self,
        controller_id: UUID,
        organization_id: UUID,
        name: str,
        *,
        is_superuser: bool = False,
    ) -> tuple[str, str]:
        """Return ``(name, contents)`` for a backup file.

        Used by the streaming download endpoint. The contents may be
        empty when the file is too large for the inline REST path —
        operators are expected to use FTP/SCP for large binaries.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        contents = await client.download_backup_content(name)
        return name, contents

    async def list_neighbors(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> list[dict[str, Any]]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_items(await client.get_neighbors())

    async def get_neighbor_settings(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_item(await client.get_neighbor_discovery_settings())

    async def list_lldp_interfaces(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> list[dict[str, Any]]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return _redact_items(await client.get_lldp_interfaces())

    async def get_topology(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        # Topology is composed from identity + interfaces + neighbors;
        # the client method already returns the {nodes, edges} shape.
        return await client.build_topology()

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Each branch knows the unique calling shape for its system
        operation (some take a payload, some take target_id, some take
        both, some take neither).
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"MikroTik adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # Identity (rename) — singleton PATCH, payload {name: str}.
            if c.feature == "mikrotik.system.identity":
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                name = payload.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise HTTPException(
                        400,
                        detail=("identity update requires payload {name: non-empty-string}"),
                    )
                # RouterOS identity max length is 32 chars in 7.x;
                # printable ASCII only — reject control / newline so
                # a staged change can't embed a CR-LF and influence
                # downstream logs.
                if len(name) > 32:
                    raise HTTPException(
                        400,
                        detail=(f"identity name too long ({len(name)} > 32)"),
                    )
                if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
                    raise HTTPException(
                        400,
                        detail="identity name contains control characters",
                    )
                return await method(name, force=True)

            # NTP client config — singleton PATCH. Allowlist payload
            # keys so a staged change can't smuggle in non-NTP keys.
            if c.feature == "mikrotik.system.ntp":
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                bad = [k for k in payload if k not in _NTP_ALLOWED_KEYS]
                if bad:
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} payload has disallowed keys: "
                            f"{sorted(bad)!r}; allowed = "
                            f"{sorted(_NTP_ALLOWED_KEYS)!r}"
                        ),
                    )
                return await method(payload, force=True)

            # Power management — no args. Some early RouterOS 7.x
            # builds don't expose /system/reboot via REST (404). Catch
            # the 404 + translate to a clear "unsupported" message so
            # the operator doesn't see a raw HTTP code.
            if c.feature in (
                "mikrotik.system.reboot",
                "mikrotik.system.shutdown",
            ):
                from app.adapters.mikrotik.client import MikroTikAPIError

                try:
                    return await method(force=True)
                except MikroTikAPIError as exc:
                    if exc.error_code == 404:
                        raise HTTPException(
                            501,
                            detail=(
                                f"RouterOS REST does not expose "
                                f"{c.feature!r} on this firmware version. "
                                f"Supported: {_MIKROTIK_SUPPORTED_REST_VERSION}."
                            ),
                        ) from exc
                    raise

            # Backup create / load — kwargs name + optional password.
            if c.feature in (
                "mikrotik.system.backup_create",
                "mikrotik.system.backup_load",
            ):
                name = payload.get("name") or "freesdn"
                password = payload.get("password")
                return await method(name, password, force=True)

            # Export config — optional file kw. We force
            # ``hide-sensitive=yes`` here regardless of any operator
            # input; ``applied_response`` persists the result and we
            # don't want plaintext credentials landing in the staging
            # table. ``_validate_export_config_payload`` also rejects
            # path-traversal in the filename.
            if c.feature == "mikrotik.system.export_config":
                cleaned = _validate_export_config_payload(payload)
                # The client's export_config(file=...) signature only
                # takes ``file`` positional/kw, but RouterOS accepts
                # ``hide-sensitive``. We pass it via the underlying
                # POST body — at the client level, export_config is a
                # thin wrapper that builds {"file": ..., ...}. To get
                # hide-sensitive into that body we go through the raw
                # post() instead.
                fetch_path = "/export"
                body: dict[str, Any] = {"hide-sensitive": "yes"}
                if cleaned.get("file") is not None:
                    body["file"] = cleaned["file"]
                return await client.post(fetch_path, body, force=True)

            # File delete — single id.
            if c.feature == "mikrotik.system.file_delete":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires target_id (file id)"),
                    )
                return await method(target_id, force=True)

            # Service toggle — patches /ip/service/{name}.
            # target_id holds the service name (telnet, ssh, www, …).
            if c.feature == "mikrotik.system.service_toggle":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires target_id (service name)"),
                    )
                return await method(target_id, payload, force=True)

            # Switch chip — port / vlan / rule.
            if c.feature == "mikrotik.system.switch_port":
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"update on {c.feature!r} requires target_id"),
                    )
                return await method(target_id, payload, force=True)

            if c.feature in (
                "mikrotik.system.switch_vlan",
                "mikrotik.system.switch_rule",
            ):
                if c.operation == "create":
                    # Reject unknown payload keys — switch_vlan and
                    # switch_rule each have a tight RouterOS schema.
                    allowed = (
                        _SWITCH_VLAN_ALLOWED_KEYS
                        if c.feature == "mikrotik.system.switch_vlan"
                        else _SWITCH_RULE_ALLOWED_KEYS
                    )
                    bad = [k for k in payload if k not in allowed]
                    if bad:
                        raise HTTPException(
                            400,
                            detail=(
                                f"{c.feature!r} payload has disallowed "
                                f"keys: {sorted(bad)!r}; allowed = "
                                f"{sorted(allowed)!r}"
                            ),
                        )
                    return await method(payload, force=True)
                if c.operation == "delete":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(f"delete on {c.feature!r} requires target_id"),
                        )
                    return await method(target_id, force=True)

            # Tools — payload-shaped POSTs.
            if c.feature == "mikrotik.system.tool_bandwidth_test":
                return await method(payload, force=True)
            if c.feature == "mikrotik.system.tool_fetch":
                # Validate URL + payload keys BEFORE reaching the
                # router. Even though the controller-tier gate
                # already required site_admin, the URL is operator-
                # controlled and could SSRF the cloud-metadata
                # service if not constrained. The validator also pins
                # a hostname url to the validated IP so
                # RouterOS cannot re-resolve it — use the returned payload.
                payload = _validate_tool_fetch_payload(payload)
                return await method(payload, force=True)

            # ── firmware / package / backup / neighbor ──
            #
            # Firmware actions. ``check`` / ``download`` / ``install``
            # / ``cancel`` take no args; ``channel`` takes the channel
            # name as a positional from payload.
            if c.feature == "mikrotik.system.firmware.channel":
                channel = payload.get("channel")
                if not isinstance(channel, str) or not channel:
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} requires payload "
                            "{channel: 'stable'|'long-term'|'testing'|'development'}"
                        ),
                    )
                return await method(channel, force=True)

            if c.feature in (
                "mikrotik.system.firmware.check",
                "mikrotik.system.firmware.download",
                "mikrotik.system.firmware.install",
                "mikrotik.system.firmware.cancel",
            ):
                return await method(force=True)

            # Package enable / disable / uninstall — target_id is the
            # RouterOS package row id (e.g. ".0" or a uuid-shaped key).
            if c.feature in (
                "mikrotik.system.package.enable",
                "mikrotik.system.package.disable",
                "mikrotik.system.package.uninstall",
            ):
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires target_id (package id)"),
                    )
                return await method(target_id, force=True)

            # Backup lifecycle (dotted namespace).
            if c.feature == "mikrotik.system.backup.create_binary":
                name = payload.get("name") or "freesdn"
                password = payload.get("password")
                return await method(name, password, force=True)
            if c.feature == "mikrotik.system.backup.export_text":
                file = payload.get("file")
                return await method(file=file, force=True)
            if c.feature == "mikrotik.system.backup.upload":
                name = payload.get("name")
                contents = payload.get("contents")
                if not isinstance(name, str) or not isinstance(contents, str):
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires payload {{name: str, contents: str}}"),
                    )
                # a network:write operator must not be able to
                # plant an auto-executing RouterOS script. Reject path traversal,
                # script/import extensions (.rsc / .auto.rsc), and oversize bodies;
                # allow only bare backup-style filenames.
                import re as _re

                if "/" in name or "\\" in name or ".." in name:
                    raise HTTPException(400, detail="upload name must be a bare filename")
                if not _re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name):
                    raise HTTPException(400, detail="upload name has invalid characters")
                if name.lower().endswith((".rsc", ".auto.rsc", ".scr")):
                    raise HTTPException(
                        400,
                        detail="script/import filenames (.rsc) are not allowed for upload",
                    )
                if len(contents) > 8 * 1024 * 1024:
                    raise HTTPException(413, detail="upload contents exceed 8 MiB cap")
                return await method(name, contents, force=True)
            if c.feature == "mikrotik.system.backup.delete":
                # target_id holds the backup file name.
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires target_id (backup file name)"),
                    )
                return await method(target_id, force=True)
            if c.feature == "mikrotik.system.backup.restore":
                name = payload.get("name") or target_id
                password = payload.get("password")
                if not isinstance(name, str) or not name:
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} requires payload {{name: str}} or target_id"),
                    )
                return await method(name, password=password, force=True)

            # Neighbor discovery singleton.
            if c.feature == "mikrotik.system.neighbor.settings":
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                return await method(payload, force=True)

            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply
