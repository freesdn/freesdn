# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Proxmox VM service
======================================

Read-and-stage for Proxmox QEMU virtual machine lifecycle. Mirrors the
shape of ``adapter_opnsense_firewall.py`` so the same Pending Changes
UX works for VMs as it does for firewall rules.

Production-safety contract:

- Reads run live against the Proxmox cluster.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

On a production Proxmox cluster, VM destroy and guest agent code-exec
are the most catastrophic writes in the platform; the dual-gate is
most valuable here. Default config has
``ADAPTER_READ_ONLY=True`` so production is safe out-of-the-box even
without staging.

Supported features::

    proxmox.vm.create                 create
    proxmox.vm.config                 update
    proxmox.vm.destroy                delete   (irreversible)
    proxmox.vm.clone                  create
    proxmox.vm.convert_to_template    create
    proxmox.vm.start                  create
    proxmox.vm.stop                   create
    proxmox.vm.shutdown               create
    proxmox.vm.reboot                 create
    proxmox.vm.suspend                create
    proxmox.vm.resume                 create
    proxmox.vm.migrate                create
    proxmox.vm.remote_migrate         create
    proxmox.vm.resize_disk            update
    proxmox.vm.cloudinit              update
    proxmox.vm.cloudinit_regenerate   create
    proxmox.vm.guest_agent_exec       create   (EXTRA-SENSITIVE: arbitrary code execution on the guest)
    proxmox.vm.guest_agent_file_write create   (EXTRA-SENSITIVE: arbitrary write to guest filesystem)

The applier passes ``force=True`` to the Proxmox adapter so writes
reach the cluster — every write outside the applier is refused at the
client layer by the ``ADAPTER_READ_ONLY`` gate.
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
from app.core.crypto import decrypt_credential
from app.models.core import Controller
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

logger = logging.getLogger(__name__)

# (feature, operation) → adapter method name. The applier uses this
# to dispatch — same pattern Omada / OPNsense services use, except
# we dispatch to the high-level adapter (not the low-level client)
# because the Proxmox adapter is the wrapping layer with the
# ``AdapterResult`` envelope and decoded payloads.
_APPLY: dict[tuple[str, str], str] = {
    ("proxmox.vm.create", "create"): "create_vm",
    ("proxmox.vm.config", "update"): "update_vm_config",
    # destroy is irreversible — the dual-gate is the last guardrail.
    ("proxmox.vm.destroy", "delete"): "delete_vm",
    ("proxmox.vm.clone", "create"): "clone_vm",
    ("proxmox.vm.convert_to_template", "create"): "convert_to_template",
    ("proxmox.vm.start", "create"): "start_vm",
    ("proxmox.vm.stop", "create"): "stop_vm",
    ("proxmox.vm.shutdown", "create"): "shutdown_vm",
    ("proxmox.vm.reboot", "create"): "reboot_vm",
    ("proxmox.vm.suspend", "create"): "suspend_vm",
    ("proxmox.vm.resume", "create"): "resume_vm",
    ("proxmox.vm.migrate", "create"): "migrate_vm",
    ("proxmox.vm.remote_migrate", "create"): "remote_migrate_vm",
    ("proxmox.vm.resize_disk", "update"): "resize_vm_disk",
    ("proxmox.vm.cloudinit", "update"): "update_guest_cloudinit",
    ("proxmox.vm.cloudinit_regenerate", "create"): "regenerate_cloudinit",
    # EXTRA-SENSITIVE — the staging row IS the audit trail. These
    # features execute arbitrary guest-side commands / writes. Anyone
    # reviewing pending changes should treat these as the highest
    # tier of change.
    ("proxmox.vm.guest_agent_exec", "create"): "agent_exec",
    ("proxmox.vm.guest_agent_file_write", "create"): "agent_file_write",
}

# Proxmox disk-size grammar — ``<+|->NN<K|M|G|T>``. The
# leading sign is optional (absolute resize) and the suffix is one of
# the documented unit chars. Anything outside this shape is rejected
# so a hostile staging payload can't smuggle shell metacharacters or
# malformed values through to the cluster.
_DISK_SIZE_RE = re.compile(r"^[+-]?\d+[KMGT]$")


# single source of truth for ProxmoxAdapter construction.
# All 12 adapter_proxmox_* services used to ship near-identical
# copies of this helper (drift risk + a hard time updating auth
# behaviour across the board). Co-located here in vm because it's
# the most-used Proxmox service; the other 11 services import this
# helper rather than redefining their own.
async def build_proxmox_adapter(ctrl: Controller) -> ProxmoxAdapter:
    """Build a connected ProxmoxAdapter from a controller record.

    Mirrors the canonical pattern used by ``app.modules.hypervisor.service``
    — pulls token_id / token_secret / realm / use_ssl from
    ``controller.config`` so API-token auth works alongside the
    legacy username/password mode.
    """
    config = ctrl.config or {}

    token_id = config.get("token_id", "")
    token_secret_raw = config.get("token_secret", "")
    username = config.get("username", ctrl.username or "")
    password_raw = config.get("password", "") or ctrl.password or ""

    token_secret = decrypt_credential(token_secret_raw) if token_secret_raw else ""
    password = decrypt_credential(password_raw) if password_raw else ""

    use_ssl_attr = getattr(ctrl, "use_ssl", None)
    use_ssl = True if use_ssl_attr is None else bool(use_ssl_attr)

    adapter = ProxmoxAdapter(
        host=ctrl.host,
        username=username,
        password=password,
        port=ctrl.port or 8006,
        use_ssl=use_ssl,
        verify_ssl=getattr(ctrl, "verify_ssl", False),
        token_id=token_id,
        token_secret=token_secret,
        realm=config.get("realm", "pam"),
    )
    connected = await adapter.connect()
    if not connected:
        raise HTTPException(
            502,
            detail=f"failed to connect to Proxmox at {ctrl.host}",
        )
    return adapter


def _validate_disk_size(size: str) -> str:
    if not _DISK_SIZE_RE.match(size or ""):
        raise HTTPException(
            400,
            detail=("invalid disk size — expected ``<+|->NN<K|M|G|T>`` (e.g. ``+10G``, ``8G``)"),
        )
    return size


# Guest-agent file-write defense.
# The QEMU guest agent runs as root on most cloud images, so an
# unvalidated ``file`` parameter on ``guest_agent_file_write`` is
# direct privilege escalation INSIDE the guest. The feature itself
# already requires ``site_admin`` at apply time, but "trusted to
# admin VMs" ≠ "trusted to overwrite /etc/sudoers." Defense in depth:
# reject path traversal, null bytes, relative paths, and a deny-list
# of paths whose overwrite has obvious lateral-movement payoff.
_GUEST_FILE_FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/",
    "/root/.ssh/",
    "/root/.bash_history",
    "/proc/",
    "/sys/",
    "/dev/",
    "/boot/",
    "/var/log/auth.log",
    "/var/log/secure",
)


# Guest-agent command-exec defense.
# ``guest_agent_exec`` is, by design, arbitrary code execution on the
# guest — an allow-list of *which* commands is intentionally NOT
# imposed (operators legitimately run arbitrary admin commands; that
# is the documented purpose of the feature, and the staging row is the
# audit trail). What we DO enforce is shape sanity so a hostile /
# malformed staging row can't smuggle a non-string, a null byte
# (truncates the command at the C boundary inside the guest), or a
# multi-megabyte blob through to the QEMU agent. Mirrors the
# defense-in-depth posture of ``_validate_guest_file_path``.
_GUEST_COMMAND_MAX_BYTES = 64 * 1024


def _validate_guest_command(command: Any) -> str:
    """Validate a guest-agent exec command before it reaches the agent.

    Enforces type + non-empty + no-null-byte + a byte cap. Deliberately
    does NOT restrict *which* command runs — that is the feature's whole
    point — but ensures a malformed payload surfaces a 400 here rather
    than an opaque error (or worse) inside the guest.
    """
    if not isinstance(command, str):
        raise HTTPException(400, detail="guest_agent_exec command must be a string")
    if not command:
        raise HTTPException(400, detail="guest_agent_exec requires command")
    if "\x00" in command:
        raise HTTPException(
            400,
            detail="guest_agent_exec command must not contain null bytes",
        )
    if len(command.encode("utf-8", "surrogatepass")) > _GUEST_COMMAND_MAX_BYTES:
        raise HTTPException(
            400,
            detail=(f"guest_agent_exec command exceeds the {_GUEST_COMMAND_MAX_BYTES}-byte limit"),
        )
    return command


def _validate_guest_file_path(path: str) -> None:
    """Reject obviously-dangerous paths before they reach the guest
    agent. Operators with legitimate need to overwrite (say)
    /etc/sudoers should do it via cloud-init or shell access — not
    via the staging pipeline.
    """
    if not isinstance(path, str) or not path:
        raise HTTPException(400, detail="guest file path must be non-empty")
    if "\x00" in path:
        raise HTTPException(400, detail="guest file path must not contain null bytes")
    if not path.startswith("/"):
        raise HTTPException(
            400,
            detail=(
                "guest file path must be absolute (start with /) — "
                "relative paths resolve unpredictably inside the guest"
            ),
        )
    # ``..`` defends against caller stripping a prefix then walking up.
    if ".." in path.split("/"):
        raise HTTPException(
            400,
            detail="guest file path must not contain path traversal (..)",
        )
    lowered = path.lower()
    for forbidden in _GUEST_FILE_FORBIDDEN_PREFIXES:
        if lowered.startswith(forbidden):
            raise HTTPException(
                400,
                detail=(
                    f"guest file path is on the denylist ({forbidden}) — "
                    "use cloud-init or shell access instead"
                ),
            )


# payload allow-list for VM create / clone / config kwargs.
# Restricts what a hostile staging row can smuggle into the Proxmox
# cluster. ``force`` is excluded because the applier always passes it
# as a keyword arg — duplicating it via **kwargs would TypeError but
# we filter defensively.
#
# ``cipassword`` and ``sshkeys`` are allowed at create-time (operators
# legitimately set them when provisioning a VM via cloud-init) — at
# read time they're stripped by ``redact_secrets``. The risk: a
# staging row's payload is visible to anyone with audit-log access
# until it's applied, so cloud-init secrets in payload should be
# treated as transient and not stored long-term.
_VM_CREATE_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        # Identity / metadata
        "name",
        "description",
        "tags",
        "pool",
        "ostype",
        "template",
        # CPU / memory
        "cores",
        "sockets",
        "cpu",
        "numa",
        "vcpus",
        "memory",
        "balloon",
        "shares",
        # Boot / lifecycle
        "boot",
        "bootdisk",
        "bootorder",
        "onboot",
        "agent",
        "start",
        "startup",
        "protection",
        "reboot",
        # Hardware
        "bios",
        "machine",
        "vga",
        "tablet",
        "acpi",
        "kvm",
        "smbios1",
        "hotplug",
        "freeze",
        "watchdog",
        "rng0",
        "audio0",
        "spice_enhancements",
        # Storage / networking — wildcard prefixes handled below.
        "cdrom",
        "scsihw",
        "efidisk0",
        "tpmstate0",
        # Cloud-init (operator-set; stripped from reads)
        "ciuser",
        "cipassword",
        "sshkeys",
        "ipconfig0",
        "ipconfig1",
        "ipconfig2",
        "ipconfig3",
        "searchdomain",
        "nameserver",
        # Migration / clone-only
        "snapname",
        "storage",
        "format",
        "full",
        "newid",
        "target",
    }
)

# Wildcards — Proxmox names disks / NICs / serial / parallel etc. with
# numbered suffixes. Allow the documented prefixes only.
_VM_CREATE_ALLOWED_PREFIXES: tuple[str, ...] = (
    "net",  # net0..net31
    "scsi",  # scsi0..scsi30
    "virtio",  # virtio0..virtio15
    "ide",  # ide0..ide3
    "sata",  # sata0..sata5
    "usb",  # usb0..usb14
    "hostpci",  # hostpci0..15
    "serial",  # serial0..serial3
    "parallel",  # parallel0..parallel2
    "unused",  # unused0..unused256
    "numa",  # numa0..numa7
    "ipconfig",  # ipconfig0..31 (also explicit above)
    "mp",  # LXC mount points; harmless on QEMU
)


def _filter_vm_create_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop unknown keys from a VM create/clone/config payload.

    Keeps the allow-listed scalar keys plus any key starting with one
    of the documented numbered-resource prefixes. Always strips
    ``force`` so it can't collide with the applier's keyword-only
    ``force=True``.
    """
    filtered: dict[str, Any] = {}
    for k, v in payload.items():
        if k == "force":
            continue
        if k in _VM_CREATE_ALLOWED_KEYS:
            filtered[k] = v
            continue
        if any(
            k.startswith(prefix) and k[len(prefix) :].isdigit()
            for prefix in _VM_CREATE_ALLOWED_PREFIXES
        ):
            filtered[k] = v
    return filtered


# cloudinit-only allow-list. The general ``proxmox.vm.config``
# update accepts the full create grammar — the cloudinit branch must
# be tighter so a hostile payload can't smuggle ``hookscript`` /
# ``args`` / disk re-assignments through a feature that's marketed
# as "just cloud-init". The cloudinit feature is in the catastrophic
# prefix list (Wave A), so any payload here lands as a high-tier
# pending change; the allow-list is the secondary chokepoint.
_VM_CLOUDINIT_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "ciuser",
        "cipassword",
        "sshkeys",
        "searchdomain",
        "nameserver",
        "cicustom",
    }
)
_VM_CLOUDINIT_ALLOWED_PREFIXES: tuple[str, ...] = ("ipconfig",)


def _filter_cloudinit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Restrict cloudinit-feature payloads to documented cloud-init keys.

    Rejects (raises 400) on any key outside the allow-list so the
    operator sees the shape mismatch at apply time rather than having
    foreign keys silently dropped — silent-drop hides intent in the
    audit trail.
    """
    allowed: dict[str, Any] = {}
    rejected: list[str] = []
    for k, v in payload.items():
        if k == "force":
            continue
        if k in _VM_CLOUDINIT_ALLOWED_KEYS:
            allowed[k] = v
            continue
        if any(
            k.startswith(prefix) and k[len(prefix) :].isdigit()
            for prefix in _VM_CLOUDINIT_ALLOWED_PREFIXES
        ):
            allowed[k] = v
            continue
        rejected.append(k)
    if rejected:
        raise HTTPException(
            400,
            detail=(
                "cloudinit payload contains keys outside the cloud-init "
                f"allow-list: {sorted(rejected)!r}. Use proxmox.vm.config "
                "for general VM updates."
            ),
        )
    return allowed


class GatewayProxmoxVmService(GatewayServiceBase):
    """Live reads + staged writes for Proxmox QEMU VMs."""

    SUPPORTED_CONTROLLER_TYPE = "proxmox"

    # ── Adapter resolution ───────────────────────────────────────────
    # The Proxmox adapter is the public API (high-level methods like
    # ``delete_vm`` that wrap the low-level HTTP client and emit
    # ``AdapterResult``). ``GatewayServiceBase._get_client`` returns
    # ``adapter.client`` — too low-level here. Mirror the canonical
    # adapter-creation pattern from ``app.modules.hypervisor.service``
    # so we hit the same auth path (token vs username/password).

    @staticmethod
    async def _get_proxmox_adapter(controller: Controller) -> ProxmoxAdapter:
        """Thin shim around the shared ``build_proxmox_adapter`` helper.

        kept as a method for backward-compat with existing
        callers in this module — the actual logic now lives in the
        module-level ``build_proxmox_adapter`` function so the other
        11 adapter_proxmox_* services can share it.
        """
        return await build_proxmox_adapter(controller)

    # ── Live reads ───────────────────────────────────────────────────

    async def list_vms_on_node(
        self, controller_id: UUID, organization_id: UUID, node: str
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_vms(node)
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

    async def list_all_vms(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_all_vms()
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "items": redact_list(result.data or []),
            "fetched_at": datetime.now(UTC),
        }

    async def get_vm_status(
        self, controller_id: UUID, organization_id: UUID, node: str, vmid: int
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_vm_status(node, vmid)
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

    async def get_vm_config(
        self, controller_id: UUID, organization_id: UUID, node: str, vmid: int
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_vm_config(node, vmid)
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

    async def get_vm_pending_config(
        self, controller_id: UUID, organization_id: UUID, node: str, vmid: int
    ) -> dict[str, Any]:
        node = validate_id(node, label="node")
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_vm_pending_config(node, vmid)
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

    async def get_vm_rrd(
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
            result = await adapter.get_vm_rrd(node, vmid, timeframe)
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

    async def get_next_vmid(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._get_controller(controller_id, organization_id)
        adapter = await self._get_proxmox_adapter(ctrl)
        try:
            result = await adapter.get_next_vmid()
        finally:
            await adapter.disconnect()
        if not result.success:
            raise HTTPException(502, detail=result.error or "proxmox error")
        return {
            "controller_id": controller_id,
            "vmid": result.data,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to Proxmox.

        Every call passes ``force=True`` to the Proxmox adapter — that
        adapter is the reference write path; the read-only gate
        sits below it on the client. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the gate
        via ``AdapterStagingService.apply_change``'s dual-gate check.
        """

        async def _apply(c: Any) -> Any:
            # Adapter assignment INSIDE try so a raise in
            # ``_get_controller`` / ``_get_proxmox_adapter`` doesn't
            # leak a half-built adapter.
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

                # All VM-write features carry ``node`` in payload. Validate
                # it here at dispatch time so a malformed staging row
                # surfaces a 400 (not a 500 from the adapter URL).
                node = validate_id(str(payload.get("node", "")), label="node")
                vmid = self._coerce_vmid(target_id, payload)

                # Pre-flight safety: classify destructiveness + run READ-ONLY
                # impact checks (is the VM running? etc.); a CATASTROPHIC op
                # (e.g. destroy) is BLOCKED unless the staged payload carries
                # confirmed=true — a mission-critical write is never applied blind.
                from app.services.adapter_proxmox_preflight import preflight_gate

                await preflight_gate(adapter, c.feature, c.operation, payload)

                # Dispatch by feature. Each branch knows the arg shape.
                f = c.feature
                if f == "proxmox.vm.create":
                    # create takes node + vmid + many kwargs from payload.
                    # Allow-list filter (Item 9) drops any payload key
                    # outside the documented Proxmox create grammar so a
                    # malicious staging row can't smuggle ``script`` or
                    # similar arbitrary-execution flags.
                    raw = {k: v for k, v in payload.items() if k not in ("node", "vmid")}
                    kwargs = _filter_vm_create_payload(raw)
                    return await method(node, vmid, force=True, **kwargs)
                if f == "proxmox.vm.config":
                    config = payload.get("config") or {
                        k: v for k, v in payload.items() if k not in ("node", "vmid")
                    }
                    if isinstance(config, dict):
                        config = _filter_vm_create_payload(config)
                    return await method(node, vmid, config, force=True)
                if f == "proxmox.vm.destroy":
                    vm_type = payload.get("vm_type", "qemu")
                    if vm_type not in ("qemu", "lxc"):
                        raise HTTPException(400, detail="vm_type must be 'qemu' or 'lxc'")
                    return await method(node, vmid, vm_type, force=True)
                if f == "proxmox.vm.clone":
                    newid = int(payload.get("newid", 0))
                    if newid <= 0:
                        raise HTTPException(400, detail="clone payload requires newid")
                    raw = {k: v for k, v in payload.items() if k not in ("node", "vmid", "newid")}
                    kwargs = _filter_vm_create_payload(raw)
                    return await method(node, vmid, newid, force=True, **kwargs)
                if f == "proxmox.vm.convert_to_template":
                    vm_type = payload.get("vm_type", "qemu")
                    if vm_type not in ("qemu", "lxc"):
                        raise HTTPException(400, detail="vm_type must be 'qemu' or 'lxc'")
                    return await method(node, vmid, vm_type, force=True)
                if f in (
                    "proxmox.vm.start",
                    "proxmox.vm.stop",
                    "proxmox.vm.shutdown",
                    "proxmox.vm.reboot",
                    "proxmox.vm.suspend",
                    "proxmox.vm.resume",
                ):
                    return await method(node, vmid, force=True)
                if f == "proxmox.vm.migrate":
                    target = validate_id(str(payload.get("target", "")), label="target")
                    online = bool(payload.get("online", True))
                    return await method(node, vmid, target, online, force=True)
                if f == "proxmox.vm.remote_migrate":
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
                        force=True,
                    )
                if f == "proxmox.vm.resize_disk":
                    disk = validate_id(str(payload.get("disk", "")), label="disk")
                    size = str(payload.get("size", ""))
                    if not size:
                        raise HTTPException(400, detail="resize_disk requires size")
                    size = _validate_disk_size(size)
                    return await method(node, vmid, disk, size, force=True)
                if f == "proxmox.vm.cloudinit":
                    config = payload.get("config") or {
                        k: v for k, v in payload.items() if k not in ("node", "vmid")
                    }
                    if not isinstance(config, dict):
                        raise HTTPException(400, detail="cloudinit config must be a dict")
                    # cloudinit-only allow-list. Reject any
                    # non-cloud-init key — operators who need general
                    # VM updates use proxmox.vm.config which has the
                    # broader (still allow-listed) grammar.
                    config = _filter_cloudinit_payload(config)
                    return await method(node, vmid, config, force=True)
                if f == "proxmox.vm.cloudinit_regenerate":
                    return await method(node, vmid, force=True)
                if f == "proxmox.vm.guest_agent_exec":
                    command = _validate_guest_command(payload.get("command", ""))
                    return await method(
                        node,
                        vmid,
                        command,
                        payload.get("input_data"),
                        force=True,
                    )
                if f == "proxmox.vm.guest_agent_file_write":
                    file = payload.get("file", "")
                    content = payload.get("content", "")
                    if not file:
                        raise HTTPException(
                            400,
                            detail="guest_agent_file_write requires file",
                        )
                    _validate_guest_file_path(file)
                    return await method(node, vmid, file, content, force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                if adapter is not None:
                    await adapter.disconnect()

        return _apply

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _coerce_vmid(target_id: str | None, payload: dict[str, Any]) -> int:
        """Extract the VMID from target_id (preferred) or payload.

        For create, the new vmid lives in payload. For everything else
        the staging row's ``target_id`` is the vmid.

        bound-checks the result to the documented Proxmox VMID
        range (100..999_999_999). Below 100 is reserved by Proxmox for
        internal IDs; above the upper bound is a hostile / malformed
        value that wouldn't survive the adapter URL anyway.
        """
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
