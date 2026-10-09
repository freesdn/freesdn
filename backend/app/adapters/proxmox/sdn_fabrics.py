# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded native fabric identities/interfaces/peers, never runtime proof."""

from __future__ import annotations

import re
from typing import Any, Literal

from app.adapters.proxmox import sdn
from app.adapters.proxmox import sdn_policies as native

PROTOCOLS = {"openfabric", "ospf", "bgp", "wireguard"}
MAX_DETAILS = 64
FABRIC_REFERENCES = {"route_filter", "route_map_in", "route_map_out"}


def node_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", value):
        raise ValueError("Invalid fabric node identity")
    return value


def interface_id(value: Any, protocol: str) -> str:
    limit = 8 if protocol == "wireguard" else 15
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= limit
        or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*", value)
    ):
        raise ValueError("Unsupported fabric interface identity")
    return value


def property_flag(value: str) -> bool:
    # Rust property-string serialization uses textual booleans; Perl-backed
    # native configurations can also return numeric flag strings.
    if value in ("true", "false"):
        return value == "true"
    return sdn.native_flag(value)


def detail_list(raw: Any, kind: str, protocol: str) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(raw, list) or len(raw) > MAX_DETAILS:
        raise ValueError("Invalid fabric detail list")
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    omitted = 0
    for item in raw:
        fields = native.properties(item)
        clean: dict[str, Any]
        identity: tuple[str, ...]
        if kind == "interfaces":
            clean = {"name": interface_id(fields.get("name"), protocol)}
            allowed = {"name"}
            if protocol == "openfabric":
                allowed.add("hello_multiplier")
                if "hello_multiplier" in fields:
                    clean["hello_multiplier"] = native.number(fields["hello_multiplier"], 100, 2)
            elif protocol == "ospf":
                allowed.add("network_type")
                if "network_type" in fields:
                    if fields["network_type"] not in {
                        "broadcast",
                        "non-broadcast",
                        "point-to-multipoint",
                        "point-to-point",
                    }:
                        raise ValueError("Invalid OSPF network type")
                    clean["network_type"] = fields["network_type"]
            elif protocol == "wireguard":
                allowed |= {"listen_port", "ip6_ll"}
                if "listen_port" in fields:
                    clean["listen_port"] = native.number(fields["listen_port"], 65535)
                if "ip6_ll" in fields:
                    clean["ip6_ll"] = property_flag(fields["ip6_ll"])
            identity = (clean["name"],)
        else:
            if protocol != "wireguard" or fields.get("type") not in {
                "internal",
                "external",
            }:
                raise ValueError("Invalid fabric peer type")
            clean = {
                "type": fields["type"],
                "node": node_id(fields.get("node")),
                "iface": interface_id(fields.get("iface"), protocol),
            }
            allowed = {"type", "node", "iface", "skip_route_generation"}
            if clean["type"] == "internal":
                allowed.add("node_iface")
                clean["node_iface"] = interface_id(fields.get("node_iface"), protocol)
            if "skip_route_generation" in fields:
                clean["skip_route_generation"] = property_flag(fields["skip_route_generation"])
            identity = (
                clean["type"],
                clean["node"],
                clean["iface"],
                clean.get("node_iface", ""),
            )
        if identity in seen:
            raise ValueError("Duplicate fabric detail identity")
        seen.add(identity)
        omitted += len(set(fields) - allowed)
        rows.append(clean)
    return rows, omitted


def fields(
    raw: dict[str, Any], resource: str, protocol: str, *, pending: bool
) -> tuple[dict[str, Any], int]:
    allowed = {"protocol"}
    if resource == "fabrics":
        allowed |= FABRIC_REFERENCES
    elif protocol in PROTOCOLS:
        allowed.add("interfaces")
        if protocol in {"wireguard", "bgp"}:
            allowed.add("role")
        if protocol == "wireguard":
            allowed.add("peers")
        if protocol == "bgp":
            allowed.add("asn")
    clean: dict[str, Any] = {}
    omitted = len(set(raw) - allowed)
    for key in allowed & raw.keys():
        value = raw[key]
        if pending and value in (None, "deleted"):
            clean[key] = value
        elif key in {"interfaces", "peers"}:
            clean[key], extra = detail_list(value, key, protocol)
            omitted += extra
        elif key == "role":
            if value not in ("internal", "external"):
                raise ValueError("Invalid fabric node role")
            clean[key] = value
        elif key == "asn":
            clean[key] = native.number(value, 4294967295)
        else:
            clean[key] = native.identity(value)
    return clean, omitted


def collection(raw: list[Any], resource: str) -> tuple[list[dict[str, Any]], int]:
    # Caller checks decoded collection size and aggregate retention budgets.
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    omitted = 0
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("Invalid fabric row")
        state = row.get("state")
        if state is not None and state not in ("new", "changed", "deleted"):
            raise ValueError("Invalid pending state")
        overlay = row.get("pending")
        if overlay is None:
            overlay = {}
        if not isinstance(overlay, dict):
            raise ValueError("Invalid fabric pending overlay")
        keys = ("id",) if resource == "fabrics" else ("fabric_id", "node_id")
        ids: dict[str, Any] = {}
        from_pending = False
        for key in keys:
            validate = node_id if key == "node_id" else native.identity
            value = row.get(key)
            if value is None and state == "new":
                value = overlay.get(key)
                from_pending = True
            ids[key] = validate(value)
            if key in overlay and validate(overlay[key]) != ids[key]:
                raise ValueError("Conflicting fabric identity")
        identity = ids["id"] if resource == "fabrics" else f"{ids['fabric_id']}_{ids['node_id']}"
        if identity in seen:
            raise ValueError("Duplicate fabric identity")
        seen.add(identity)
        protocol = row.get("protocol")
        if protocol is None and state == "new":
            protocol = overlay.get("protocol")
        protocol = native.identity(protocol)
        clean, count = fields(
            {k: v for k, v in row.items() if k not in {*keys, "state", "pending", "digest"}},
            resource,
            protocol,
            pending=False,
        )
        result = {**ids, **clean}
        if resource == "fabric-nodes":
            result["node_key"] = identity
        if from_pending:
            result["identity_source"] = "pending"
        if protocol not in PROTOCOLS:
            result["details_status"] = "unsupported_protocol"
        if state is not None:
            result["state"] = state
        if "pending" in row:
            pending_protocol = overlay.get("protocol", protocol)
            if pending_protocol not in (None, "deleted"):
                pending_protocol = native.identity(pending_protocol)
            else:
                pending_protocol = ""  # No valid native identity can collide with this marker.
            result["pending"], extra = fields(
                {k: v for k, v in overlay.items() if k not in keys},
                resource,
                pending_protocol,
                pending=True,
            )
            if pending_protocol and pending_protocol not in PROTOCOLS:
                result["pending"]["details_status"] = "unsupported_protocol"
            count += extra
        rows.append(result)
        omitted += count
    return sorted(
        rows, key=lambda row: row["id"] if resource == "fabrics" else row["node_key"]
    ), omitted


def references(row: dict[str, Any]) -> list[tuple[str, Literal["fabric-nodes"], str]]:
    return [
        (f"peers[{i}].node", "fabric-nodes", f"{row['fabric_id']}_{peer['node']}")
        for i, peer in enumerate(row.get("peers", []))
    ]


def annotate_interfaces(rows: list[dict[str, Any]]) -> None:
    """Annotate sanitized configured/running rows from one visible collection.

    Caller must not use this for a pending view. Names refer to fabric
    configuration, not physical host inventory, sessions or live connectivity.
    """
    nodes = {row["node_key"]: row for row in rows}
    for row in rows:
        local = {item["name"] for item in row.get("interfaces", [])}
        for peer in row.get("peers", []):
            peer["local_interface_visibility"] = (
                "visible" if peer["iface"] in local else "not_visible"
            )
            remote = nodes.get(f"{row['fabric_id']}_{peer['node']}")
            if peer["type"] == "external":
                peer["remote_interface_visibility"] = "not_applicable"
            elif remote is None or remote.get("protocol") != "wireguard":
                peer["remote_interface_visibility"] = "not_observed"
            else:
                remote_names = {item["name"] for item in remote.get("interfaces", [])}
                peer["remote_interface_visibility"] = (
                    "visible" if peer["node_iface"] in remote_names else "not_visible"
                )
