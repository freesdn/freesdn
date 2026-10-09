"""Validate complete read inventories before preserving their public contents."""

from typing import Any

from app.adapters.opnsense.plugin_reads import object_at, recordset, text
from app.core.redaction import redact_secrets


def complete_rows(value: Any, *, identity: str | None = None) -> list[dict[str, Any]]:
    rows, _ = recordset(value)
    if identity is not None:
        seen: set[str] = set()
        for row in rows:
            key = text(row.get(identity))
            if not key.strip() or key != key.strip() or key in seen:
                raise ValueError("Missing or duplicate inventory identity")
            seen.add(key)
    return rows


def vpn_payload(
    settings: Any, peers: Any, servers: Any, providers: Any, instances: Any, sad: Any
) -> dict[str, Any]:
    """Keep existing aggregate envelope shapes after completeness checks."""
    from app.adapters.opnsense.plugin_reads import flag

    flag(object_at(settings, "general").get("enabled"))
    for value in [peers, servers, instances]:
        complete_rows(value, identity="uuid")
    complete_rows(sad)
    # PHP's empty provider array encodes as [] rather than an object.
    if providers != []:
        provider_map = object_at(providers)
        if any(not isinstance(row, dict) for row in provider_map.values()):
            raise ValueError("Invalid OpenVPN providers")
    return {
        "wireguard": redact_secrets({"status": settings, "peers": peers, "servers": servers}),
        "openvpn": redact_secrets({"providers": providers, "instances": instances}),
        "ipsec": redact_secrets(sad),
    }
