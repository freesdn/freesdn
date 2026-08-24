# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Which controllers count as storage, and how each reports its health.

The storage module was the TrueNAS module. ``_fabric_storage_health_handler``
selected controllers with ``Controller.controller_type == "truenas"`` and called
``build_truenas_adapter`` directly, so "storage health across the org" meant
"health of the org's TrueNAS boxes" and a second vendor could not be added
without rewriting the handler.

That is the actual barrier to storage being an ecosystem rather than one
appliance, so this is the seam: a provider knows how to turn one controller into
the three things ``summarize_health`` consumes, and the handler iterates the
registry instead of naming a vendor.

Proxmox is the second provider, chosen deliberately over a NAS nobody here can
test. Its storage reads are already implemented and already exercised against
the maintainer's live cluster, so this is a vendor whose numbers can be checked
rather than one whose adapter would ship mock-only and unproven. It is
read-only, which also respects the standing rule that Proxmox writes stay off.

``summarize_health`` is duck-typed -- it reads ``.name``, ``.status`` and
``.usage.size``/``.allocated`` -- so a provider adapts its vendor's shape to
that rather than the summariser growing a branch per vendor.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

logger = logging.getLogger(__name__)

__all__ = [
    "STORAGE_PROVIDERS",
    "StorageProvider",
    "StorageReading",
    "storage_controller_types",
]


@dataclass(frozen=True)
class _Usage:
    size: int
    allocated: int


@dataclass(frozen=True)
class _Pool:
    """The shape ``summarize_health`` reads, whatever the vendor calls it."""

    name: str
    status: str
    usage: _Usage


@dataclass(frozen=True)
class StorageReading:
    """One controller's contribution to the org-wide rollup."""

    pools: list[Any]
    alerts: list[dict[str, Any]]
    disk_temps: dict[str, Any]


class StorageProvider(Protocol):
    """Turns one controller into a :class:`StorageReading`."""

    async def read(self, controller: Any) -> StorageReading: ...


class _TrueNASProvider:
    """ZFS appliances. The original behaviour, unchanged in substance."""

    async def read(self, controller: Any) -> StorageReading:
        from app.services.adapter_truenas_storage import build_truenas_adapter

        adapter = await build_truenas_adapter(controller)
        try:
            return StorageReading(
                pools=await adapter.get_pools(),
                alerts=await adapter.get_alerts(),
                disk_temps=await adapter.get_disk_temperatures(),
            )
        finally:
            import contextlib

            with contextlib.suppress(Exception):
                await adapter.disconnect()


class _ProxmoxProvider:
    """Hypervisor-attached storage, per node.

    A Proxmox storage has no ZFS-style status word -- it reports capacity plus
    ``active`` and ``enabled`` flags. Those map onto the same vocabulary the
    summariser already understands, which is what lets one rollup span both
    vendors:

    * not ``enabled`` -> ``OFFLINE``. The operator turned it off; it is not a
      fault, but a storage that is administratively down is not holding
      anything either, and silently reporting it healthy is how a backup target
      turns out to have been disabled for a month.
    * enabled but not ``active`` -> ``UNAVAIL``. Configured and not answering,
      which is the ZFS meaning of that word almost exactly.
    * otherwise ``ONLINE``, and capacity does the rest.

    Read-only by construction: nothing here writes, which keeps the standing
    rule that Proxmox writes stay off.
    """

    async def read(self, controller: Any) -> StorageReading:
        from app.services.adapter_proxmox_vm import build_proxmox_adapter

        adapter = await build_proxmox_adapter(controller)
        pools: list[Any] = []
        try:
            nodes_result = await adapter.get_nodes()
            nodes = getattr(nodes_result, "data", None) or []
            for node in nodes:
                node_name = getattr(node, "node", None) or (
                    node.get("node") if isinstance(node, dict) else None
                )
                if not node_name:
                    continue
                result = await adapter.get_storage(str(node_name))
                for row in getattr(result, "data", None) or []:
                    pools.append(self._to_pool(str(node_name), row))
        finally:
            import contextlib

            with contextlib.suppress(Exception):
                await adapter.disconnect()

        # Proxmox exposes no per-disk SMART temperature through this path and
        # its alerts are not storage-scoped, so both are empty rather than
        # fabricated. A zero that means "not reported" is worse than an absence.
        return StorageReading(pools=pools, alerts=[], disk_temps={})

    @staticmethod
    def _to_pool(node_name: str, row: Any) -> _Pool:
        def field(name: str, default: Any = 0) -> Any:
            if isinstance(row, dict):
                return row.get(name, default)
            return getattr(row, name, default)

        enabled = bool(field("enabled", True))
        active = bool(field("active", True))
        status = "ONLINE" if (enabled and active) else ("UNAVAIL" if enabled else "OFFLINE")

        total = int(field("total", 0) or 0)
        used = int(field("used", 0) or 0)
        # Namespaced by node: two nodes commonly both have "local-lvm", and
        # collapsing them would report one pool's capacity for both.
        name = f"{node_name}/{field('storage', '') or 'storage'}"
        return _Pool(name=name, status=status, usage=_Usage(size=total, allocated=used))


#: controller_type -> provider. Adding a vendor is an entry here plus a class;
#: the Fabric handler and the monitoring task both read this and neither names
#: a vendor.
STORAGE_PROVIDERS: dict[str, StorageProvider] = {
    "truenas": _TrueNASProvider(),
    "proxmox": _ProxmoxProvider(),
}


def storage_controller_types() -> list[str]:
    """Controller types the storage rollup covers.

    Used to build the query filter, so a newly registered provider is picked up
    without touching the query -- which is where the hardcoded ``"truenas"``
    lived.
    """
    return sorted(STORAGE_PROVIDERS)


async def read_controller_storage(controller: Any) -> StorageReading | None:
    """Read one controller through its provider, or None if it is not storage.

    Never raises: one unreachable appliance must not empty an org-wide rollup.
    The caller counts what it got against what it asked for, so a partial
    answer is visible as a partial answer.
    """
    provider = STORAGE_PROVIDERS.get(str(getattr(controller, "controller_type", "")).lower())
    if provider is None:
        return None
    try:
        return await provider.read(controller)
    except Exception as exc:
        logger.warning(
            "storage: controller %s (%s) did not answer: %s",
            getattr(controller, "id", "?"),
            getattr(controller, "controller_type", "?"),
            exc,
        )
        return None


def controller_id_of(controller: Any) -> UUID | None:
    raw = getattr(controller, "id", None)
    return raw if isinstance(raw, UUID) else None
