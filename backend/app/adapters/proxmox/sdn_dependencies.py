# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Read-only dependency observations, never an apply plan or a complete graph.

PVE filters collections by ACL. DNS/IPAM expose configured state only. Routing
catalogues and allowlisted nested rules are independent, incomplete observations;
neither proves native policy evaluation or live enforcement.
Never follow provider-supplied URLs, fetch remote IPAM/DNS services, or expose
raw plugin configuration. Fixed paths and validated VNet identities bound reads.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.adapters.proxmox import sdn, sdn_fabrics, sdn_policies
from app.modules.hypervisor.sdn_schemas import (
    SdnDependencyCollection,
    SdnDependencyInspection,
    SdnDependencyReference,
    SdnDependencyResource,
    SdnView,
)

MAX_VNETS = 32
# Logical collection calls, not wire attempts: the shared client may retry GETs.
MAX_REQUESTS = 25 + 3 * MAX_VNETS
MAX_ITEMS = 256
MAX_TOTAL_ITEMS = 2048
MAX_RESULT_BYTES = 1048576
DEADLINE_SECONDS = 20
VIEWS: tuple[SdnView, ...] = ("configured", "running", "pending")
IDENTITY: dict[SdnDependencyResource, str] = {
    "zones": "zone",
    "vnets": "vnet",
    "controllers": "controller",
    "subnets": "subnet",
    "ipams": "ipam",
    "dns": "dns",
    "fabrics": "id",
    "fabric-nodes": "node_key",
    "prefix-lists": "id",
    "route-maps": "id",
    "prefix-list-entries": "id",
    "route-map-entries": "entry_id",
}
REFERENCES: dict[SdnDependencyResource, dict[str, SdnDependencyResource]] = {
    "zones": {"controller": "controllers", "ipam": "ipams", "dns": "dns", "reversedns": "dns"},
    "vnets": {"zone": "zones"},
    "subnets": {"vnet": "vnets"},
    "fabric-nodes": {"fabric_id": "fabrics"},
    "fabrics": {
        "route_filter": "prefix-lists",
        "route_map_in": "route-maps",
        "route_map_out": "route-maps",
    },
    "controllers": {"route-map-in": "route-maps", "route-map-out": "route-maps"},
}


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Invalid dependency identity")
    return value


def subnet_identifier(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 160:
        raise ValueError("Invalid subnet identity")
    if "/" in value:
        ipaddress.ip_network(value, strict=False)
    else:
        zone, address, prefix = value.rsplit("-", 2)
        identifier(zone)
        ipaddress.ip_network(address + "/" + prefix, strict=False)
    return value


def _fields(
    raw: dict[str, Any], resource: SdnDependencyResource, pending: bool
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    allowed = set(REFERENCES.get(resource, {})) | {"type", "protocol"}
    if resource == "subnets":
        allowed |= {"gateway", "snat"}
    if resource in ("prefix-lists", "route-maps"):
        allowed = set()  # Catalogue identities are not nested policy contents.
    for key, value in raw.items():
        if key not in allowed:
            continue
        if value is None or (pending and value == "deleted"):
            result[key] = value
        elif key == "snat":
            result[key] = sdn.native_flag(value)
        elif key == "gateway":
            if not isinstance(value, str):
                raise ValueError("Invalid subnet gateway")
            result[key] = str(ipaddress.ip_address(value))
        else:
            result[key] = identifier(value)
    return result, len(set(raw) - allowed)


def collection(
    raw: Any, resource: SdnDependencyResource, parent: str | None = None
) -> tuple[list[dict[str, Any]], int]:
    if (
        not isinstance(raw, list)
        or len(raw) > MAX_ITEMS
        or len(json.dumps(raw, allow_nan=False)) > 262144
    ):
        raise ValueError("Invalid or oversized dependency collection")
    if resource in sdn_policies.POLICIES:
        return sdn_policies.collection(raw, resource)
    if resource in ("fabrics", "fabric-nodes"):
        return sdn_fabrics.collection(raw, resource)
    identity = IDENTITY[resource]
    rows, seen, omitted = [], set(), 0
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("Invalid dependency row")
        if resource == "subnets":
            name = subnet_identifier(row.get(identity))
        else:
            name = identifier(row.get(identity))
        if name in seen:
            raise ValueError("Duplicate dependency identity")
        seen.add(name)
        if resource in sdn.IDENTITY:
            values, count = sdn.collection([row], resource)
            result = values[0]
            # References must be resource identifiers, not arbitrary display text.
            for source in (result, result.get("pending", {})):
                for field in REFERENCES.get(resource, {}):
                    if source.get(field) not in (None, "", "deleted"):
                        identifier(source[field])
        else:
            fields, count = _fields(
                {k: v for k, v in row.items() if k not in {identity, "digest", "state", "pending"}},
                resource,
                False,
            )
            result = {identity: name, **fields}
            if row.get("state") is not None:
                if row["state"] not in ("new", "changed", "deleted"):
                    raise ValueError("Invalid pending state")
                result["state"] = row["state"]
            if row.get("pending") is not None:
                if not isinstance(row["pending"], dict):
                    raise ValueError("Invalid pending fields")
                result["pending"], extra = _fields(row["pending"], resource, True)
                count += extra
        if resource == "subnets":
            # PVE filters this collection by its URL VNet. Reject mixed parents.
            if result.get("vnet") != parent and result.get("pending", {}).get("vnet") != parent:
                raise ValueError("Subnet belongs to another VNet")
            # The removal marker is meaningful only in the pending overlay.
            # A configured VNet literally named "deleted" is a real identity.
            if result.get("vnet") not in (None, parent) or result.get("pending", {}).get(
                "vnet"
            ) not in (None, "deleted", parent):
                raise ValueError("Ambiguous subnet parent")
        rows.append(result)
        omitted += count
    return sorted(rows, key=lambda row: row[identity]), omitted


class Reader:
    def __init__(self, client: Any) -> None:
        self.client = client
        self.semaphore = asyncio.Semaphore(3)
        self.deadline = asyncio.get_running_loop().time() + DEADLINE_SECONDS
        self.requests = 0
        self.items = 0
        self.bytes = 0
        self.limited = False

    async def read(
        self, resource: SdnDependencyResource, view: SdnView, parent: str | None = None
    ) -> list[SdnDependencyCollection]:
        common: dict[str, Any] = {"resource": resource, "view": view, "parent_id": parent}
        if resource in ("prefix-lists", "route-maps"):
            common["content_scope"] = "identities_only"
        status: Any = "not_observed"
        reason: Any = None
        raw: Any = None
        if (resource in ("ipams", "dns") and view != "configured") or (
            resource == "route-maps" and view == "pending"
        ):
            reason = "view_not_exposed"
        else:
            path = f"/cluster/sdn/{resource}"
            if resource == "subnets":
                path = f"/cluster/sdn/vnets/{identifier(parent)}/subnets"
            if resource == "fabrics":
                path += "/all"
            params: dict[str, Any] = {} if view == "configured" else {view: 1}
            if resource in ("prefix-lists", "prefix-list-entries"):
                path = "/cluster/sdn/prefix-lists"
                params["verbose"] = int(resource == "prefix-list-entries")
            if resource == "route-map-entries":
                path = "/cluster/sdn/route-maps/entries"
            try:
                async with asyncio.timeout_at(self.deadline), self.semaphore:
                    if asyncio.get_running_loop().time() >= self.deadline:
                        raise TimeoutError
                    self.requests += 1
                    assert self.requests <= MAX_REQUESTS
                    status, raw = await sdn._read(self.client, path, params or None)
            except TimeoutError:
                reason = "inspection_deadline"
        resources: list[SdnDependencyResource] = [resource]
        if resource == "fabrics":
            resources.append("fabric-nodes")
            if status == "available" and (
                not isinstance(raw, dict) or set(raw) != {"fabrics", "nodes"}
            ):
                status = "invalid"
        observations = []
        for name in resources:
            items, omitted, item_status, item_reason = None, 0, status, reason
            if status == "available":
                try:
                    value = (
                        raw["nodes" if name == "fabric-nodes" else "fabrics"]
                        if resource == "fabrics"
                        else raw
                    )
                    items, omitted = collection(value, name, parent)
                    size = len(json.dumps(items).encode())
                    retained = sdn_policies.retained_objects(items)
                    if (
                        self.items + retained > MAX_TOTAL_ITEMS
                        or self.bytes + size > MAX_RESULT_BYTES
                    ):
                        items, omitted, item_status, item_reason = (
                            None,
                            0,
                            "not_observed",
                            "response_limit",
                        )
                        self.limited = True
                    else:
                        self.items += retained
                        self.bytes += size
                except (ValueError, TypeError, KeyError, UnicodeError):
                    items, omitted, item_status = None, 0, "invalid"
            observations.append(
                SdnDependencyCollection(
                    **{**common, "resource": name},
                    status=item_status,
                    reason=item_reason,
                    items=items,
                    omitted_fields=omitted,
                    observed_at=datetime.now(UTC),
                )
            )
        return observations


def references(collections: list[SdnDependencyCollection]) -> list[SdnDependencyReference]:
    targets = {(c.resource, c.view): c for c in collections if c.parent_id is None}
    result = []
    for source in collections:
        if source.status != "available" or source.view == "pending":
            continue
        if source.resource == "fabric-nodes":
            sdn_fabrics.annotate_interfaces(source.items or [])
        for row in source.items or []:
            candidates = [
                (field, resource, row.get(field))
                for field, resource in REFERENCES.get(source.resource, {}).items()
            ]
            if source.resource == "route-map-entries":
                candidates.extend(sdn_policies.references(row))
            if source.resource == "fabric-nodes":
                candidates.extend(sdn_fabrics.references(row))
            for field, resource, name in candidates:
                # "deleted" is a marker only inside pending overlays. In the
                # configured/running catalogue it can be a valid resource ID.
                if not name:
                    continue
                view: Any = "configured" if resource in ("ipams", "dns") else source.view
                target = targets.get((resource, view))
                state: Any = "target_unavailable"
                if target and target.status == "available":
                    state = (
                        "visible"
                        if any(r[IDENTITY[resource]] == name for r in target.items or [])
                        else "not_visible"
                    )
                result.append(
                    SdnDependencyReference(
                        source_resource=source.resource,
                        source_id=row[IDENTITY[source.resource]],
                        field=field,
                        view=source.view,
                        target_resource=resource,
                        target_id=name,
                        target_view=view,
                        status=state,
                    )
                )
    return result


async def inspect_dependencies(client: Any, controller_id: UUID) -> SdnDependencyInspection:
    started = datetime.now(UTC)
    reader = Reader(client)
    top: tuple[SdnDependencyResource, ...] = (
        "zones",
        "vnets",
        "controllers",
        "ipams",
        "dns",
        "fabrics",
        "prefix-lists",
        "route-maps",
        "prefix-list-entries",
        "route-map-entries",
    )
    groups = await asyncio.gather(*(reader.read(name, view) for name in top for view in VIEWS))
    observations = [item for group in groups for item in group]
    parents = sorted(
        {
            row["vnet"]
            for c in observations
            if c.resource == "vnets" and c.status == "available"
            for row in c.items or []
        }
    )
    selected = parents[:MAX_VNETS]
    children = await asyncio.gather(
        *(reader.read("subnets", view, parent) for parent in selected for view in VIEWS)
    )
    observations.extend(item for group in children for item in group)
    if any(c.status != "available" for c in observations if c.resource == "vnets"):
        observations.extend(
            SdnDependencyCollection(
                resource="subnets",
                view=view,
                status="not_observed",
                reason="parent_inventory_unavailable",
                observed_at=datetime.now(UTC),
            )
            for view in VIEWS
        )
    changed = any(
        row.get("state") or row.get("pending")
        for c in observations
        if c.view == "pending"
        for row in c.items or []
    )
    by_view = {(c.resource, c.parent_id, c.view): c for c in observations}
    for c in observations:
        running = by_view.get((c.resource, c.parent_id, "running"))
        if (
            c.view == "configured"
            and c.status == "available"
            and running
            and running.status == "available"
        ):
            changed |= c.items != running.items
    return SdnDependencyInspection(
        controller_id=controller_id,
        started_at=started,
        finished_at=datetime.now(UTC),
        collections=observations,
        references=references(observations),
        pending_state="changes_detected" if changed else "unknown",
        subnet_parent_limit=MAX_VNETS,
        subnet_parents_selected=len(selected),
        subnet_parents_omitted_by_limit=max(0, len(parents) - len(selected)),
        requests_made=reader.requests,
        request_limit=MAX_REQUESTS,
        response_limit_reached=reader.limited,
    )
