# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Allowlisted native routing-policy observations, not a policy evaluator.

Native prefix-list rules and route-map clauses are property strings, not raw
FRR commands. New pending objects may carry identities only in their overlay.
Unknown fields/clauses and unconstrained peer text are withheld, never executed.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal

POLICIES = {"prefix-list-entries", "route-map-entries"}
PREFIX_MATCHES = {
    "ip-address-prefix-list",
    "ip6-address-prefix-list",
    "ip-next-hop-prefix-list",
    "ip6-next-hop-prefix-list",
}
NO_VALUE = {
    "ip-next-hop-peer-address",
    "ip-next-hop-unchanged",
    "ip6-next-hop-peer-address",
    "ip6-next-hop-prefer-global",
}
MATCH_KEYS = PREFIX_MATCHES | {
    "route-type",
    "vni",
    "ip-next-hop-address",
    "ip6-next-hop-address",
    "metric",
    "local-preference",
    "peer",
    "tag",
}
SET_KEYS = NO_VALUE | {
    "ip-next-hop",
    "ip6-next-hop",
    "local-preference",
    "tag",
    "weight",
    "metric",
    "src",
}
MAX_ROWS = 256
MAX_CLAUSES = 64


def identity(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise ValueError("Invalid policy identity")
    return value


def number(value: Any, maximum: int, minimum: int = 0) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
        result = int(value)
    else:
        raise ValueError("Invalid policy number")
    if not minimum <= result <= maximum:
        raise ValueError("Policy number out of range")
    return result


def properties(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("Invalid property string")
    result: dict[str, str] = {}
    offset = 0
    while offset < len(value):
        match = re.match(r"([A-Za-z][A-Za-z0-9_-]*)=", value[offset:])
        if not match or match[1] in result:
            raise ValueError("Ambiguous property string")
        key = match[1]
        offset += match.end()
        if offset < len(value) and value[offset] == '"':
            # Proxmox quoting supports only escaped quote, backslash and newline.
            # Decode first, then apply the field allowlist; quoted commas never
            # become extra properties, even in an unknown/withheld clause.
            offset += 1
            content = []
            while offset < len(value) and value[offset] != '"':
                char = value[offset]
                if char == "\\":
                    offset += 1
                    if offset == len(value) or value[offset] not in {'"', "\\", "n"}:
                        raise ValueError("Invalid property escape")
                    char = "\n" if value[offset] == "n" else value[offset]
                content.append(char)
                offset += 1
            if offset == len(value):
                raise ValueError("Unterminated property quote")
            offset += 1
            result[key] = "".join(content)
        else:
            end = value.find(",", offset)
            end = len(value) if end < 0 else end
            if end == offset:
                raise ValueError("Empty unquoted property")
            result[key] = value[offset:end]
            offset = end
        if offset < len(value):
            if value[offset] != "," or offset + 1 == len(value):
                raise ValueError("Garbage after property value")
            offset += 1
    return result


def address(value: Any, version: int | None = None) -> str:
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        raise ValueError("Invalid policy address")
    parsed = ipaddress.ip_address(value)
    if version is not None and parsed.version != version:
        raise ValueError("Wrong address family")
    return str(parsed)


def modified_number(value: Any) -> str:
    if isinstance(value, str) and re.fullmatch(r"[+-][0-9]{1,10}", value):
        if not -2147483648 <= int(value) <= 2147483647:
            raise ValueError("Relative policy number out of range")
        return value
    return str(number(value, 4294967295))


def clause(value: Any, family: str) -> tuple[dict[str, Any] | None, int]:
    fields = properties(value)
    key, item = fields.get("key"), fields.get("value")
    if key is None:
        raise ValueError("Missing policy clause key")
    if key not in (MATCH_KEYS if family == "match" else SET_KEYS):
        return None, 1 + len(set(fields) - {"key", "value"})
    result: dict[str, Any] = {"key": key}
    if family == "set" and key in NO_VALUE:
        if item is not None:
            raise ValueError("Unexpected clause value")
    elif item is None:
        raise ValueError("Missing policy clause value")
    elif key in PREFIX_MATCHES:
        result["value"] = identity(item)
    elif key in {
        "ip-next-hop",
        "ip-next-hop-address",
        "ip6-next-hop",
        "ip6-next-hop-address",
        "src",
    }:
        result["value"] = address(
            item, None if key == "src" else 6 if key.startswith("ip6-") else 4
        )
    elif key == "route-type":
        if item not in {"ead", "macip", "multicast", "es", "prefix"}:
            raise ValueError("Invalid EVPN route type")
        result["value"] = item
    elif key == "vni":
        result["value"] = number(item, 16777215, 1)
    elif (
        key == "tag"
        and item == "untagged"
        or family == "set"
        and key == "metric"
        and item in {"rtt", "+rtt", "-rtt", "igp", "aigp"}
    ):
        result["value"] = item
    elif family == "set" and key in {"metric", "local-preference"}:
        result["value"] = modified_number(item)
    elif key == "peer":
        # Native peer is an unconstrained string. Observe IP/local forms only.
        try:
            result["value"] = "local" if item == "local" else address(item)
        except ValueError:
            return None, 1 + len(set(fields) - {"key", "value"})
    else:
        result["value"] = number(item, 4294967295)
    return result, len(set(fields) - {"key", "value"})


def prefix_entries(raw: Any) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(raw, list) or len(raw) > MAX_ROWS:
        raise ValueError("Invalid prefix entry list")
    rows, seen, omitted = [], set(), 0
    for value in raw:
        fields = properties(value)
        if fields.get("action") not in {"permit", "deny"}:
            raise ValueError("Invalid prefix action")
        prefix = fields.get("prefix")
        if not isinstance(prefix, str) or "/" not in prefix or "%" in prefix:
            raise ValueError("Invalid prefix")
        network = ipaddress.ip_network(prefix, strict=False)
        sequence = number(fields.get("seq"), 4294967295)
        if sequence in seen:
            raise ValueError("Duplicate prefix sequence")
        seen.add(sequence)
        row: dict[str, Any] = {"seq": sequence, "action": fields["action"], "prefix": str(network)}
        for key in ("ge", "le"):
            if key in fields:
                row[key] = number(fields[key], network.max_prefixlen, network.prefixlen)
        if row.get("ge", network.prefixlen) > row.get("le", network.max_prefixlen):
            raise ValueError("Inverted prefix-length range")
        omitted += len(set(fields) - {"seq", "action", "prefix", "ge", "le"})
        rows.append(row)
    return sorted(rows, key=lambda r: r["seq"]), omitted


def fields(raw: dict[str, Any], resource: str, *, pending: bool) -> tuple[dict[str, Any], int]:
    allowed = (
        {"entries"}
        if resource == "prefix-list-entries"
        else {"action", "match", "set", "call", "exit-action"}
    )
    result: dict[str, Any] = {}
    omitted = len(set(raw) - allowed)
    for key in allowed & raw.keys():
        value = raw[key]
        if pending and value in (None, "deleted"):
            result[key] = value
        elif key == "entries":
            result[key], extra = prefix_entries(value)
            omitted += extra
        elif key == "action":
            if value not in ("permit", "deny"):
                raise ValueError("Invalid route-map action")
            result[key] = value
        elif key == "call":
            result[key] = identity(value)
        elif key == "exit-action":
            props = properties(value)
            if props.get("key") not in {"on-match-next", "on-match-goto", "continue"}:
                omitted += 1
                continue
            exit_value: dict[str, Any] = {"key": props["key"]}
            if props["key"] == "on-match-next":
                if "value" in props:
                    raise ValueError("Unexpected exit-action value")
            else:
                exit_value["value"] = number(props.get("value"), 65535)
            result[key] = exit_value
            omitted += len(set(props) - {"key", "value"})
        else:
            if not isinstance(value, list) or len(value) > MAX_CLAUSES:
                raise ValueError("Invalid route-map clauses")
            decoded = []
            for entry in value:
                clean, extra = clause(entry, key)
                omitted += extra
                if clean is not None:
                    decoded.append(clean)
            result[key] = decoded
    return result, omitted


def collection(raw: Any, resource: str) -> tuple[list[dict[str, Any]], int]:
    if (
        resource not in POLICIES
        or not isinstance(raw, list)
        or len(raw) > MAX_ROWS
        or len(json.dumps(raw, allow_nan=False)) > 262144
    ):
        raise ValueError("Invalid or oversized policy collection")
    result, seen, omitted = [], set(), 0
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("Invalid policy row")
        state = row.get("state")
        if state is not None and state not in ("new", "changed", "deleted"):
            raise ValueError("Invalid policy pending state")
        overlay = row.get("pending", {})
        if overlay is None:
            overlay = {}
        if not isinstance(overlay, dict):
            raise ValueError("Invalid policy pending overlay")
        keys = ("id",) if resource == "prefix-list-entries" else ("route-map-id", "order")
        ids: dict[str, Any] = {}
        pending_identity = False
        for key in keys:
            value = row.get(key)
            if value is None and state == "new":
                value = overlay.get(key)
                pending_identity = True
            ids[key] = number(value, 65535) if key == "order" else identity(value)
            if key in overlay:
                other = number(overlay[key], 65535) if key == "order" else identity(overlay[key])
                if other != ids[key]:
                    raise ValueError("Conflicting policy identity")
        row_id = (
            ids["id"]
            if resource == "prefix-list-entries"
            else f"{ids['route-map-id']}_{ids['order']}"
        )
        if row_id in seen:
            raise ValueError("Duplicate policy identity")
        seen.add(row_id)
        clean, count = fields(
            {
                k: v
                for k, v in row.items()
                if k not in {*keys, "state", "pending", "digest", "type"}
            },
            resource,
            pending=False,
        )
        item = {**ids, **clean}
        if resource == "route-map-entries":
            item["entry_id"] = row_id
        if pending_identity:
            item["identity_source"] = "pending"
        if state is not None:
            item["state"] = state
        if "pending" in row:
            item["pending"], extra = fields(
                {k: v for k, v in overlay.items() if k not in keys}, resource, pending=True
            )
            count += extra
        if resource == "route-map-entries" and "action" not in clean:
            if state != "new" or item.get("pending", {}).get("action") not in ("permit", "deny"):
                raise ValueError("Missing route-map action")
        if resource == "prefix-list-entries" and state != "new" and "entries" not in item:
            item["entries"] = []  # Native serializer omits empty entry vectors.
        omitted += count
        result.append(item)
    return sorted(
        result,
        key=lambda r: (
            (r["id"], 0) if resource == "prefix-list-entries" else (r["route-map-id"], r["order"])
        ),
    ), omitted


def retained_objects(value: Any) -> int:
    """Include nested rules/clauses/overlays in the shared retention budget."""
    if isinstance(value, dict):
        return 1 + sum(retained_objects(v) for v in value.values())
    if isinstance(value, list):
        return sum(retained_objects(v) for v in value)
    return 0


def references(row: dict[str, Any]) -> list[tuple[str, Literal["route-maps", "prefix-lists"], str]]:
    result: list[tuple[str, Literal["route-maps", "prefix-lists"], str]] = [
        ("route-map-id", "route-maps", row["route-map-id"])
    ]
    if row.get("call"):
        result.append(("call", "route-maps", row["call"]))
    for index, match in enumerate(row.get("match", [])):
        if match["key"] in PREFIX_MATCHES:
            result.append((f"match[{index}].{match['key']}", "prefix-lists", match["value"]))
    return result
