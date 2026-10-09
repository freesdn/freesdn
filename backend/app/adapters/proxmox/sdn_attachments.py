# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded guest/host observations, never an SDN apply or connectivity verdict.

Native inventories and bridge lists are ACL filtered. Guest current and pending-
merged configurations, SDN catalogues and host reports are independent reads.
Raw guest configuration, host options, addresses and diagnostics are withheld.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from app.adapters.proxmox import sdn
from app.modules.hypervisor.sdn_schemas import (
    SdnAttachmentInspection,
    SdnAttachmentInventory,
    SdnAttachmentMatch,
    SdnAttachmentRead,
    SdnAttachmentVnets,
    SdnGuestAttachments,
    SdnHostInterface,
    SdnHostInterfaces,
    SdnNicAttachment,
)

MAX_GUESTS = 32
MAX_NODES = 8
MAX_REQUESTS = 4 + MAX_GUESTS * 2 + MAX_NODES
DEADLINE_SECONDS = 20
MAX_ITEMS = 2048
MAX_BYTES = 1048576
Parser = Callable[[Any], tuple[list[dict[str, Any]], int]]


def bounded(raw: Any) -> None:
    # ProxmoxClient has already decoded the response; this is not a streaming cap.
    if len(json.dumps(raw, allow_nan=False)) > 262144:
        raise ValueError("Oversized native observation")


def interface_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}", value)
        or ".." in value
    ):
        raise ValueError("Invalid interface identity")
    return value


def inventory(raw: Any, kind: str) -> tuple[list[dict[str, Any]], int]:
    bounded(raw)
    if not isinstance(raw, list) or len(raw) > 1024:
        raise ValueError("Invalid inventory")
    rows, seen, omitted = [], set(), 0
    for row in raw:
        if not isinstance(row, dict) or row.get("type") not in (
            ("qemu", "lxc") if kind == "vm" else ("node",)
        ):
            raise ValueError("Invalid inventory row")
        node = row.get("node")
        if not isinstance(node, str):
            raise ValueError("Missing node identity")
        sdn.validate_node(node)
        clean = {"node": node, "type": row["type"]}
        identity: Any = node
        if kind == "vm":
            identity = row.get("vmid")
            if type(identity) is not int or not 100 <= identity <= 999999999:
                raise ValueError("Invalid guest identity")
            clean["vmid"] = identity
        if identity in seen:
            raise ValueError("Duplicate inventory identity")
        seen.add(identity)
        omitted += len(set(row) - set(clean))
        rows.append(clean)
    return sorted(rows, key=lambda r: r["vmid"] if kind == "vm" else r["node"]), omitted


def vnets(raw: Any) -> tuple[list[dict[str, Any]], int]:
    bounded(raw)
    if not isinstance(raw, list) or len(raw) > 512:
        raise ValueError("Invalid VNet catalogue")
    rows, seen, omitted = [], set(), 0
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("Invalid VNet")
        name = row.get("vnet")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
            or name in seen
        ):
            raise ValueError("Invalid VNet identity")
        seen.add(name)
        rows.append({"vnet": name})
        omitted += len(row) - 1
    return sorted(rows, key=lambda r: r["vnet"]), omitted


def nics(raw: Any) -> tuple[list[dict[str, Any]], int]:
    bounded(raw)
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("digest"), str)
        or not re.fullmatch(r"[0-9a-fA-F]{40}", raw["digest"])
    ):
        raise ValueError("Invalid guest configuration")
    rows, omitted = [], 0
    for key, value in raw.items():
        if not re.fullmatch(r"net[0-9]+", key):
            omitted += 1
            continue
        if not re.fullmatch(r"net(?:0|[1-9][0-9]{0,2})", key) or int(key[3:]) > 255:
            raise ValueError("Invalid NIC identity")
        if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid NIC config")
        fields = {}
        for part in value.split(","):
            name, sep, item = part.partition("=")
            if not sep and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", part):
                name, sep, item = "model", "=", part
            if (
                not sep
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name)
                or name in fields
                or not item
            ):
                raise ValueError("Ambiguous NIC config")
            fields[name] = item
        row: dict[str, Any] = {"key": key}
        for name, item in fields.items():
            if name == "bridge":
                row[name] = interface_name(item)
            elif name == "tag":
                if not re.fullmatch(r"[0-9]{1,4}", item) or not 1 <= int(item) <= 4094:
                    raise ValueError("Invalid VLAN tag")
                row[name] = int(item)
            elif name == "trunks":
                for trunk in item.split(";"):
                    if not re.fullmatch(r"[0-9]{1,4}(?:-[0-9]{1,4})?", trunk):
                        raise ValueError("Invalid VLAN trunks")
                    parts = [int(p) for p in trunk.split("-")]
                    if not 1 <= parts[0] <= parts[-1] <= 4094:
                        raise ValueError("Invalid VLAN range")
                row[name] = item
            elif name in ("link_down", "firewall"):
                row[name] = sdn.native_flag(item)
        row["omitted_options"] = len(
            set(fields) - {"bridge", "tag", "trunks", "link_down", "firewall"}
        )
        rows.append(row)
    if len(rows) > 64:
        raise ValueError("NIC inventory too large")
    return sorted(rows, key=lambda r: int(r["key"][3:])), omitted


def interfaces(raw: Any) -> tuple[list[dict[str, Any]], int]:
    bounded(raw)
    if not isinstance(raw, list) or len(raw) > 256:
        raise ValueError("Invalid interface inventory")
    rows, seen, omitted = [], set(), 0
    for source in raw:
        if not isinstance(source, dict):
            raise ValueError("Invalid interface row")
        name = interface_name(source.get("iface"))
        kind = source.get("type")
        if (
            name in seen
            or not isinstance(kind, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", kind)
        ):
            raise ValueError("Invalid interface type/identity")
        seen.add(name)
        row: dict[str, Any] = {"iface": name, "interface_type": kind}
        retained = {"iface", "type"}
        for field in (
            "active",
            "exists",
            "bridge_ports",
            "slaves",
            "ovs_ports",
            "ovs_bonds",
            "vlan-raw-device",
        ):
            if field not in source:
                continue
            retained.add(field)
            value = source[field]
            if value is None:
                continue
            if field in ("active", "exists"):
                row[field] = sdn.native_flag(value)
            elif field == "vlan-raw-device":
                row["vlan_raw_device"] = interface_name(value)
            else:
                if not isinstance(value, str) or len(value) > 4096:
                    raise ValueError("Invalid interface members")
                # Proxmox may use 'none' for a bridge without physical ports.
                row[field] = (
                    []
                    if value.strip() in ("", "none")
                    else [interface_name(v) for v in value.split()]
                )
        omitted += len(set(source) - retained)
        rows.append(row)
    return sorted(rows, key=lambda r: r["iface"]), omitted


class Reader:
    def __init__(self, client: Any):
        self.client = client
        self.deadline = asyncio.get_running_loop().time() + DEADLINE_SECONDS
        self.semaphore = asyncio.Semaphore(3)
        self.requests = self.items = self.bytes = 0
        self.limited = False

    async def read(
        self, path: str, params: dict[str, Any], parser: Parser
    ) -> tuple[SdnAttachmentRead, list[dict[str, Any]] | None]:
        result = SdnAttachmentRead(status="not_observed", observed_at=datetime.now(UTC))
        items = None
        try:
            async with asyncio.timeout_at(self.deadline), self.semaphore:
                if asyncio.get_running_loop().time() >= self.deadline:
                    raise TimeoutError
                self.requests += 1
                assert self.requests <= MAX_REQUESTS
                result.status, raw = await sdn._read(self.client, path, params or None)
            if result.status == "available":
                items, result.omitted_fields = parser(raw)
                size = len(json.dumps(items).encode())
                if self.items + len(items) > MAX_ITEMS or self.bytes + size > MAX_BYTES:
                    items, result.omitted_fields = None, 0
                    result.status, result.reason = "not_observed", "response_limit"
                    self.limited = True
                else:
                    self.items += len(items)
                    self.bytes += size
        except TimeoutError:
            result.status, result.reason = "not_observed", "inspection_deadline"
        except (ValueError, TypeError, KeyError, UnicodeError):
            items, result.omitted_fields, result.status = None, 0, "invalid"
        result.observed_at = datetime.now(UTC)
        return result, items


def match(
    bridge: str | None, read: SdnAttachmentRead | None, names: list[str] | None
) -> SdnAttachmentMatch:
    if bridge is None:
        return "no_bridge"
    if read is None:
        return "not_observed"
    if read.status != "available":
        return "target_unavailable"
    return "visible" if bridge in (names or []) else "not_visible"


async def inspect_attachments(client: Any, controller_id: UUID) -> SdnAttachmentInspection:
    started = datetime.now(UTC)
    reader = Reader(client)
    guest_result, node_result, configured, running = await asyncio.gather(
        reader.read("/cluster/resources", {"type": "vm"}, lambda r: inventory(r, "vm")),
        reader.read("/cluster/resources", {"type": "node"}, lambda r: inventory(r, "node")),
        reader.read("/cluster/sdn/vnets", {}, vnets),
        reader.read("/cluster/sdn/vnets", {"running": 1}, vnets),
    )
    guest_read, guests = guest_result
    node_read, nodes = node_result
    selected_guests, selected_nodes = (guests or [])[:MAX_GUESTS], (nodes or [])[:MAX_NODES]
    catalogue_views: tuple[Literal["configured", "running"], ...] = ("configured", "running")
    catalogues = [
        SdnAttachmentVnets(
            **read.model_dump(),
            view=view,
            identities=None if rows is None else [r["vnet"] for r in rows],
        )
        for view, (read, rows) in zip(catalogue_views, (configured, running), strict=True)
    ]

    async def guest(row: dict[str, Any], current: bool) -> SdnGuestAttachments:
        read, items = await reader.read(
            f"/nodes/{row['node']}/{row['type']}/{row['vmid']}/config",
            {"current": 1} if current else {},
            nics,
        )
        return SdnGuestAttachments(
            **read.model_dump(),
            node=row["node"],
            vmid=row["vmid"],
            guest_type=row["type"],
            view="current" if current else "pending_merged",
            nics=None if items is None else [SdnNicAttachment(**item) for item in items],
        )

    async def host(row: dict[str, Any]) -> SdnHostInterfaces:
        read, items = await reader.read(
            f"/nodes/{row['node']}/network", {"type": "include_sdn"}, interfaces
        )
        return SdnHostInterfaces(
            **read.model_dump(),
            node=row["node"],
            interfaces=None if items is None else [SdnHostInterface(**item) for item in items],
        )

    # Host reads first so the guest fan-out cannot starve the small host sample.
    host_reads, guest_reads = await asyncio.gather(
        asyncio.gather(*(host(row) for row in selected_nodes)),
        asyncio.gather(
            *(guest(row, current) for row in selected_guests for current in (True, False))
        ),
    )
    hosts = {h.node: h for h in host_reads}
    for observation in guest_reads:
        target = hosts.get(observation.node)
        for nic in observation.nics or []:
            nic.configured_vnet = match(nic.bridge, catalogues[0], catalogues[0].identities)
            nic.running_vnet = match(nic.bridge, catalogues[1], catalogues[1].identities)
            nic.host_interface = match(
                nic.bridge,
                target if target else node_read if node_read.status != "available" else None,
                [i.iface for i in target.interfaces or []] if target else None,
            )

    def summary(
        read: SdnAttachmentRead, rows: list[dict[str, Any]] | None, limit: int
    ) -> SdnAttachmentInventory:
        return SdnAttachmentInventory(
            **read.model_dump(),
            visible_count=None if rows is None else len(rows),
            selected=min(len(rows or []), limit),
            omitted_by_limit=max(0, len(rows or []) - limit),
            selection_limit=limit,
        )

    return SdnAttachmentInspection(
        controller_id=controller_id,
        started_at=started,
        finished_at=datetime.now(UTC),
        guest_inventory=summary(guest_read, guests, MAX_GUESTS),
        node_inventory=summary(node_read, nodes, MAX_NODES),
        vnets=catalogues,
        guests=list(guest_reads),
        hosts=list(host_reads),
        request_limit=MAX_REQUESTS,
        requests_made=reader.requests,
        response_limit_reached=reader.limited,
    )
