# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox Container service
=============================================

Read-and-stage for Proxmox LXC container lifecycle. Mirrors the shape
of ``adapter_proxmox_vm.py`` so the same Pending Changes UX works for
containers as it does for QEMU VMs.

Production-safety contract:

- Reads run live against the Proxmox cluster.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

The Proxmox adapter does not expose a ``delete_container`` method
distinct from ``delete_vm`` — both VM and CT destroy go through
``delete_vm(node, vmid, vm_type=...)``. We pass ``vm_type="lxc"`` for
container destroy.

Supported features::

    proxmox.container.create        create
    proxmox.container.config        update
    proxmox.container.destroy       delete   (irreversible)
    proxmox.container.clone         create
    proxmox.container.start         create
    proxmox.container.stop          create
    proxmox.container.shutdown      create
    proxmox.container.reboot        create
    proxmox.container.migrate       create
    proxmox.container.remote_migrate create
    proxmox.container.resize_disk   update
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.validation import validate_id
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_proxmox_vm import build_proxmox_adapter
from app.services.adapter_redaction import redact_list, redact_secrets

logger = logging.getLogger(__name__)

# (feature, operation) → adapter method name. Same dispatch shape as
# the VM service, scoped to LXC. ``destroy`` reuses ``delete_vm`` with
# ``vm_type="lxc"``.
_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.container.create", "create"): "create_container",
    ("proxmox.container.config", "update"): "update_container_config",
    # destroy reuses delete_vm with vm_type="lxc" — irreversible.
    ("proxmox.container.destroy", "delete"): "delete_vm",
    ("proxmox.container.clone", "create"): "clone_container",
    ("proxmox.container.start", "create"): "start_container",
    ("proxmox.container.stop", "create"): "stop_container",
    ("proxmox.container.shutdown", "create"): "shutdown_container",
    ("proxmox.container.reboot", "create"): "reboot_container",
    ("proxmox.container.migrate", "create"): "migrate_container",
    ("proxmox.container.remote_migrate", "create"): "remote_migrate_container",
    ("proxmox.container.resize_disk", "update"): "resize_container_disk",
}

# Proxmox disk-size grammar — ``<+|->NN<K|M|G|T>`` (same
# pattern the VM service uses).
_DISK_SIZE_RE = re.compile(r"^[+-]?\d+[KMGT]$")


def _validate_disk_size(size: str) -> str:
    if not _DISK_SIZE_RE.match(size or ""):
        raise HTTPException(
            400,
            detail=("invalid disk size — expected ``<+|->NN<K|M|G|T>`` (e.g. ``+10G``, ``8G``)"),
        )
    return size


# payload allow-list for container create / clone / config
# kwargs. Matches the documented Proxmox LXC create grammar — anything
# else (e.g. ``script``, ``hookscript``) is dropped.
_CT_CREATE_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        # Identity / metadata
        "hostname",
        "description",
        "tags",
        "pool",
        "ostype",
        "ostemplate",
        "template",
        # Resources
        "cores",
        "cpulimit",
        "cpuunits",
        "memory",
        "swap",
        "rootfs",
        # Boot / lifecycle
        "onboot",
        "start",
        "startup",
        "protection",
        "unprivileged",
        "features",
        "console",
        "tty",
        "arch",
        "force",  # filtered separately below — kept for documentation
        # Network — wildcard prefix below
        "nameserver",
        "searchdomain",
        # Cloud-init / SSH (operator-set; stripped from reads)
        "ssh-public-keys",
        "password",
        # Clone-only
        "newid",
        "snapname",
        "storage",
        "full",
        "target",
    }
)

# LXC numbered-resource prefixes — net0..net31, mp0..mp255, etc.
_CT_CREATE_ALLOWED_PREFIXES: tuple[str, ...] = (
    "net",
    "mp",
    "unused",
    "dev",
    "ipconfig",
)


def _filter_ct_create_payload(payload: dict[str, Any]) -> dict[str, Any]:
    filtered: dict[str, Any] = {}
    for k, v in payload.items():
        if k == "force":
            continue
        if k in _CT_CREATE_ALLOWED_KEYS:
            filtered[k] = v
            continue
        if any(
            k.startswith(prefix) and k[len(prefix) :].isdigit()
            for prefix in _CT_CREATE_ALLOWED_PREFIXES
        ):
            filtered[k] = v
    return filtered


class GatewayProxmoxContainerService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox LXC containers."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    # ── Adapter resolution ───────────────────────────────────────────
    # Same canonical pattern as ``adapter_proxmox_vm.py`` — the Proxmox
    # adapter is the public API, not the low-level client returned by
    # ``GatewayServiceBase._get_client``.

    @staticmethod
    async def _get_proxmox_adapter(controller: Controller) -> ProxmoxAdapter:
        """Item 9: forwards to the shared ``build_proxmox_adapter`` helper."""
        return await build_proxmox_adapter(controller)

    # ── Live reads ───────────────────────────────────────────────────

    async def list_containers(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_containers(node)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    async def get_container_status(
        self, controller_id: UUID, organization_id: UUID, node: str, vmid: int
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_container_status(node, vmid)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "item": redact_secrets(result.data),
            "fetched_at": datetime.now(UTC),
        }

    async def get_container_config(
        self, controller_id: UUID, organization_id: UUID, node: str, vmid: int
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_container_config(node, vmid)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "item": redact_secrets(result.data or {}),
            "fetched_at": datetime.now(UTC),
        }

    async def get_container_pending_config(
        self, controller_id: UUID, organization_id: UUID, node: str, vmid: int
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_container_pending_config(node, vmid)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    async def get_container_rrd(
        self,
        controller_id: UUID,
        organization_id: UUID,
        node: str,
        vmid: int,
        timeframe: str = "hour",
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        timeframe = validate_id(timeframe, label="timeframe")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_container_rrd(node, vmid, timeframe)
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "node": node,
            "vmid": vmid,
            "timeframe": timeframe,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to Proxmox.

        Every call passes ``force=True`` to the Proxmox adapter — that
        adapter is the reference write path; the read-only gate
        sits below it on the client.
        """

        async def _apply(c: Any) -> Any:
            adapter: ProxmoxAdapter | None = None
            try:
                ctrl = await self._get_controller(c.controller_id, c.organization_id)
                adapter = await self._get_proxmox_adapter(ctrl)
                payload = c.payload or {}
                target_id = c.target_id

                method_name = _APPLY.get((c.feature, c.operation))
                if method_name is None:
                    raise HTTPException(
                        400,
                        detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                    )
                method = getattr(adapter, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(
                            f"Proxmox adapter has no method {method_name!r}; missing implementation"
                        ),
                    )

                node = validate_id(str(payload.get("node", "")), label="node")
                vmid = self._coerce_vmid(target_id, payload)

                # Pre-flight safety: classify destructiveness + run READ-ONLY
                # impact checks; a CATASTROPHIC op is BLOCKED unless the staged
                # payload carries confirmed=true. Mirrors adapter_proxmox_vm.py
                # so container.destroy (operation=delete → catastrophic-by-default
                # in classify()) is never applied blind. A SAFE/DESTRUCTIVE op
                # (create/start/stop/migrate/resize…) passes straight through.
                from app.services.adapter_proxmox_preflight import preflight_gate

                await preflight_gate(adapter, c.feature, c.operation, payload)

                f = c.feature
                if f == "proxmox.container.create":
                    if not payload.get("ostemplate"):
                        raise HTTPException(
                            400,
                            detail="container.create requires ostemplate",
                        )
                    raw = {k: v for k, v in payload.items() if k not in ("node", "vmid")}
                    kwargs = _filter_ct_create_payload(raw)
                    return await method(node, vmid, force=True, **kwargs)
                if f == "proxmox.container.config":
                    config = payload.get("config") or {
                        k: v for k, v in payload.items() if k not in ("node", "vmid")
                    }
                    if isinstance(config, dict):
                        config = _filter_ct_create_payload(config)
                    return await method(node, vmid, config, force=True)
                if f == "proxmox.container.destroy":
                    # delete_vm reuses for LXC — pass vm_type="lxc"
                    return await method(node, vmid, "lxc", force=True)
                if f == "proxmox.container.clone":
                    newid = int(payload.get("newid", 0))
                    if newid <= 0:
                        raise HTTPException(400, detail="clone payload requires newid")
                    raw = {k: v for k, v in payload.items() if k not in ("node", "vmid", "newid")}
                    kwargs = _filter_ct_create_payload(raw)
                    return await method(node, vmid, newid, force=True, **kwargs)
                if f in (
                    "proxmox.container.start",
                    "proxmox.container.stop",
                    "proxmox.container.shutdown",
                    "proxmox.container.reboot",
                ):
                    return await method(node, vmid, force=True)
                if f == "proxmox.container.migrate":
                    target = validate_id(str(payload.get("target", "")), label="target")
                    online = bool(payload.get("online", False))
                    return await method(node, vmid, target, online, force=True)
                if f == "proxmox.container.remote_migrate":
                    target_endpoint = payload.get("target_endpoint", "")
                    target_storage = payload.get("target_storage", "")
                    if not target_endpoint or not target_storage:
                        raise HTTPException(
                            400,
                            detail=("remote_migrate requires target_endpoint and target_storage"),
                        )
                    return await method(
                        node,
                        vmid,
                        target_endpoint,
                        target_storage,
                        target_bridge=payload.get("target_bridge"),
                        online=bool(payload.get("online", True)),
                        delete_source=bool(payload.get("delete_source", True)),
                        restart=bool(payload.get("restart", False)),
                        force=True,
                    )
                if f == "proxmox.container.resize_disk":
                    disk = validate_id(str(payload.get("disk", "")), label="disk")
                    size = str(payload.get("size", ""))
                    if not size:
                        raise HTTPException(400, detail="resize_disk requires size")
                    size = _validate_disk_size(size)
                    return await method(node, vmid, disk, size, force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _coerce_vmid(target_id: str | None, payload: dict[str, Any]) -> int:
        """Extract the VMID from target_id or payload (Item 18: bound check)."""
        candidate = target_id if target_id is not None else payload.get("vmid")
        if candidate is None:
            raise HTTPException(400, detail="vmid is required")
        try:
            vmid = int(str(candidate))
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, detail="vmid must be an integer") from exc
        if vmid < 100 or vmid > 999_999_999:
            raise HTTPException(400, detail="vmid out of range (100..999999999)")
        return vmid
