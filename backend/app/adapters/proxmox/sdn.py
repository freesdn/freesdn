# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded, read-only SDN observations. Never return provider secrets/errors.

Proxmox collection endpoints filter by ACL. A successful read, including an
empty list, cannot establish complete visibility. Sequential views are not an
atomic snapshot, and running config is not node connectivity evidence.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

import httpx

from app.adapters.exceptions import AdapterError
from app.adapters.proxmox.client import ProxmoxApiError
from app.modules.hypervisor.sdn_schemas import (
    SdnCollection,
    SdnDiffSummary,
    SdnDryRunObservation,
    SdnInspection,
    SdnReadStatus,
    SdnResourceObservation,
)

WRITE_BLOCKED = "SDN writes require a qualified reviewed lock/apply workflow; use native Proxmox management with independent recovery access"
SdnResourceName = Literal["zones", "vnets", "controllers"]
IDENTITY: dict[SdnResourceName, str] = {
    "zones": "zone",
    "vnets": "vnet",
    "controllers": "controller",
}
TEXT = {
    "type",
    "nodes",
    "node",
    "bridge",
    "zone",
    "alias",
    "dns",
    "reversedns",
    "dnszone",
    "ipam",
    "dhcp",
    "controller",
    "peers",
    "exitnodes",
    "exitnodes-primary",
    "vlan-protocol",
    "mac",
    "rt-import",
    "loopback",
    "bgp-mode",
    "peer-group-name",
    "route-map-in",
    "route-map-out",
    "isis-domain",
    "isis-ifaces",
    "isis-net",
}
NUMBERS = {"mtu", "tag", "vxlan-port", "vrf-vxlan", "asn", "ebgp-multihop"}
FLAGS = {
    "vlanaware",
    "ebgp",
    "bgp-multipath-as-relax",
    "bridge-disable-mac-learning",
    "exitnodes-local-routing",
    "advertise-subnets",
    "disable-arp-nd-suppression",
}
READ_TIMEOUT = 6


def native_flag(value: Any) -> bool:
    if type(value) in (int, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value in ("0", "1"):
        return value == "1"
    raise ValueError("Invalid native boolean")


def _text(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid SDN text")
    return value


def _fields(raw: dict[str, Any], *, pending: bool = False) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    omitted = 0
    for key, value in raw.items():
        if key not in TEXT | NUMBERS | FLAGS:
            omitted += 1
            continue
        if value is None or (pending and value == "deleted"):
            result[key] = value
        elif key in TEXT:
            result[key] = _text(value)
        elif key in FLAGS:
            result[key] = native_flag(value)
        elif type(value) is int and 0 <= value <= 4294967295:
            result[key] = value
        else:
            raise ValueError("Invalid SDN number")
    return result, omitted


def collection(raw: Any, resource: str) -> tuple[list[dict[str, Any]], int]:
    """Allowlist displayed fields; do not guess secret key spellings."""
    identity = {"zones": "zone", "vnets": "vnet", "controllers": "controller"}[resource]
    if not isinstance(raw, list) or len(raw) > 512:
        raise ValueError("Invalid SDN collection")
    if len(json.dumps(raw, allow_nan=False)) > 262144:
        raise ValueError("SDN collection too large")
    rows, seen, omitted = [], set(), 0
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("Invalid SDN row")
        name = row.get(identity)
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
            or name in seen
        ):
            raise ValueError("Invalid SDN identity")
        seen.add(name)
        fields, count = _fields(
            {k: v for k, v in row.items() if k not in {identity, "pending", "state", "digest"}}
        )
        result = {identity: name, **fields}
        omitted += count
        if "state" in row and row["state"] is not None:
            if row["state"] not in ("new", "changed", "deleted"):
                raise ValueError("Invalid SDN state")
            result["state"] = row["state"]
        if row.get("pending") is not None:
            if not isinstance(row["pending"], dict):
                raise ValueError("Invalid SDN pending state")
            result["pending"], count = _fields(row["pending"], pending=True)
            omitted += count
        rows.append(result)
    return sorted(rows, key=lambda r: r[identity]), omitted


async def _read(
    client: Any, path: str, params: dict[str, Any] | None = None
) -> tuple[SdnReadStatus, Any]:
    try:
        async with asyncio.timeout(READ_TIMEOUT):
            return "available", await client.get(path, params=params)
    except ProxmoxApiError as exc:
        if exc.status_code in (401, 403):
            return "denied", None
        if exc.status_code in (404, 501):
            return "unsupported_or_missing", None
        return "unavailable", None
    except (TimeoutError, httpx.HTTPError, AdapterError):
        return "unavailable", None
    except (ValueError, TypeError):
        return "invalid", None


async def observe_collection(client: Any, resource: str, view: str) -> SdnCollection:
    if resource not in IDENTITY or view not in ("configured", "running", "pending"):
        raise ValueError("Unsupported SDN observation")
    status, raw = await _read(
        client, f"/cluster/sdn/{resource}", None if view == "configured" else {view: 1}
    )
    items, omitted = None, 0
    if status == "available":
        try:
            items, omitted = collection(raw, resource)
        except (ValueError, TypeError):
            status = "invalid"
    return SdnCollection(
        status=status, items=items, omitted_fields=omitted, observed_at=datetime.now(UTC)
    )


async def inspect_sdn(client: Any, controller_id: UUID) -> SdnInspection:
    started = datetime.now(UTC)

    # At most three concurrent requests; a timed-out view does not erase other observations.
    async def resource(name: SdnResourceName) -> SdnResourceObservation:
        views = {}
        for view in ("configured", "running", "pending"):
            views[view] = await observe_collection(client, name, view)
        return SdnResourceObservation(resource=name, **views)

    resources = await asyncio.gather(*(resource(name) for name in IDENTITY))
    status, raw = await _read(client, "/access/permissions", {"path": "/sdn"})
    audit, allocate, audit_propagates, allocate_propagates = None, None, None, None
    if status == "available":
        try:
            if not isinstance(raw, dict) or set(raw) - {"/sdn"}:
                raise ValueError("Invalid permission paths")
            privileges = raw.get("/sdn", {})
            if not isinstance(privileges, dict):
                raise ValueError("Invalid privileges")
            # /access/permissions maps granted privilege names to PROPAGATION
            # flags. A present value of 0 is still granted at this exact path.
            audit = "SDN.Audit" in privileges
            allocate = "SDN.Allocate" in privileges
            audit_propagates = native_flag(privileges["SDN.Audit"]) if audit else None
            allocate_propagates = native_flag(privileges["SDN.Allocate"]) if allocate else None
        except (TypeError, KeyError, ValueError):
            status, audit, allocate = "invalid", None, None
            audit_propagates, allocate_propagates = None, None
    # Missing views mean unknown, never clean. A visible change is still useful
    # evidence when another resource is unavailable or filtered by native ACLs.
    pending: Any = "no_visible_changes"
    changed = False
    for res in resources:
        if any(v.status != "available" for v in (res.configured, res.running, res.pending)):
            pending = "unknown"
        if res.configured.status == res.running.status == "available":
            changed |= res.configured.items != res.running.items
        changed |= any(r.get("state") or r.get("pending") for r in (res.pending.items or []))
    if changed:
        pending = "changes_detected"
    return SdnInspection(
        controller_id=controller_id,
        started_at=started,
        finished_at=datetime.now(UTC),
        resources=resources,
        permissions_status=status,
        audit_at_sdn=audit,
        allocate_at_sdn=allocate,
        audit_propagates=audit_propagates,
        allocate_propagates=allocate_propagates,
        pending_state=pending,
    )


def validate_node(node: str) -> None:
    if (
        not isinstance(node, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node)
        or ".." in node
    ):
        raise ValueError("Invalid Proxmox node")


async def dry_run(client: Any, controller_id: UUID, node: str) -> SdnDryRunObservation:
    validate_node(node)
    status, raw = await _read(client, "/cluster/sdn/dry-run", {"node": node})
    summaries: dict[str, SdnDiffSummary] = {}
    if status == "available":
        try:
            if not isinstance(raw, dict) or set(raw) - {"interfaces-diff", "frr-diff"}:
                raise ValueError("Invalid dry-run")
            for name in ("interfaces", "frr"):
                diff = raw.get(name + "-diff")
                if diff is None:
                    diff = ""
                if not isinstance(diff, str) or len(diff.encode()) > 131072:
                    raise ValueError("Invalid diff")
                # Generated FRR and interfaces files can contain credentials or
                # commands. Expose counts only, never a raw diff or secret hash.
                lines = diff.splitlines()
                summaries[name] = SdnDiffSummary(
                    changed=bool(diff),
                    added_lines=sum(s.startswith("+") and not s.startswith("+++") for s in lines),
                    removed_lines=sum(s.startswith("-") and not s.startswith("---") for s in lines),
                )
        except (ValueError, TypeError, UnicodeError):
            status, summaries = "invalid", {}
    return SdnDryRunObservation(
        controller_id=controller_id,
        node=node,
        status=status,
        observed_at=datetime.now(UTC),
        interfaces=summaries.get("interfaces"),
        frr=summaries.get("frr"),
    )
