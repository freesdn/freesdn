# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Provisioning Authentication
==========================================

Shared authentication / authorization for the phone-provisioning HTTP
endpoints (Grandstream ``/cfg{MAC}.xml`` and FreePBX endpoint equivalents).

The provisioning endpoints CANNOT use cookie/JWT auth — the phone has
no user session and discovers its config on first boot before any
admin has interacted with it. That made the original implementation
effectively unauthenticated: anyone who knew (or guessed) a MAC could
pull SIP credentials, admin web passwords, and the XML provisioning
secret for any tenant.

This module fixes that by enforcing two cumulative checks:

1. **Tenant binding** — the MAC is resolved to a ``Phone`` row, and the
   tenant (``organization_id``) is taken from THAT row, never from
   request headers or query params. A request from a phone with a
   MAC that belongs to org-A and a spoofed ``?org_id=org-B`` is
   resolved to org-A.

2. **Source-IP allowlist** — the request's source IP must fall inside
   one of the configured ``Site.subnets`` CIDRs. The source IP is taken
   ONLY from ``request.client.host`` — the value uvicorn's ProxyHeaders
   middleware resolves against the ``FORWARDED_ALLOW_IPS`` trusted-proxy
   list — and NEVER from the caller-supplied ``X-Forwarded-For`` header.
   That closes, where a spoofed left-most XFF could fake subnet
   membership and skip HMAC. This subnet path is what lets a zero-touch
   LAN phone (DHCP option-66 → bare ``cfg<MAC>.xml``, no signature) pull
   its config without exposing it to the public internet.

3. **HMAC fallback** — when the source IP is outside the allowlist (or
   the site has no subnets configured), the URL must carry a valid
   ``sig`` parameter computed as
   ``hmac_sha256(SECRET_KEY + ENCRYPTION_SALT, mac.lower())``. This lets
   the provisioning workflow generate per-device URLs that work from
   anywhere without exposing the unauthenticated "any-MAC" endpoint.

The combination is conservative-by-default: an admin can grant subnet
trust to skip HMAC (now safe because the IP is the trusted-proxy-resolved
``request.client.host``, not a forgeable header), or generate HMAC URLs to
skip subnet trust, but neither shortcut alone leaks credentials cross-tenant.

All resolutions return a ``ProvisioningContext`` (Phone, Site,
organization_id) so the downstream provisioning code can scope its
behavior. Failure cases return ``None`` — callers raise a generic 404
rather than 403 to avoid leaking MAC-existence to attackers.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# MAC address validation pattern (12 hex chars, various separators)
_MAC_RE = re.compile(r"^[0-9a-fA-F]{12}$|^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


@dataclass
class ProvisioningContext:
    """Resolved provisioning request.

    Used by ``serve_phone_config`` and the Grandstream equivalent to scope
    the response to the tenant that actually owns the device. Constructed
    only after both the tenant resolution AND the source-IP /HMAC check
    pass — getting an instance is itself the authorization signal.
    """

    phone: Any  # voip.Phone ORM object
    site: Any  # core.Site ORM object
    organization_id: UUID
    mac: str  # normalized colon-form MAC
    auth_method: str  # "subnet" | "hmac"


def normalize_mac(raw: str) -> str | None:
    """Normalize MAC to colon-form lowercase (``aa:bb:cc:dd:ee:ff``).

    Accepts the formats Grandstream / Yealink phones request:
      - ``cfg000b82123456.xml`` (12 hex chars)
      - ``00:0B:82:12:34:56`` (colon-separated)
      - ``00-0B-82-12-34-56`` (hyphen-separated)

    Returns None for invalid input — callers MUST treat None as 400/404.
    """
    if not raw or not _MAC_RE.match(raw):
        return None
    clean = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(clean) != 12:
        return None
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def _client_ip(request: Request) -> str | None:
    """Return the verified source IP for provisioning auth decisions.

    We MUST NOT read ``X-Forwarded-For`` here: that header is attacker-
    controlled and can be spoofed to make an external request appear to
    originate from a Site subnet. Instead we rely exclusively
    on ``request.client.host``, which uvicorn's ``ProxyHeadersMiddleware``
    has already resolved from XFF using the operator-configured
    ``FORWARDED_ALLOW_IPS`` allowlist. That value is trustworthy because
    uvicorn only accepts forwarded IPs from explicitly trusted upstreams.

    ``X-Real-IP`` is similarly attacker-controllable unless the deployment
    guarantees it is stripped by the reverse proxy — so we ignore it here
    and rely solely on the uvicorn-resolved value.
    """
    if request.client:
        return request.client.host
    return None


def _ip_in_subnets(ip_str: str, subnets: list[dict[str, Any]]) -> bool:
    """Check if ``ip_str`` falls inside any of the site's configured subnets.

    ``subnets`` is the JSONB shape from ``Site.subnets``:
    ``[{"cidr": "192.168.1.0/24", "name": "..."}]``. Unknown entries
    (missing ``cidr`` key) are skipped silently.
    """
    if not subnets:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in subnets:
        cidr = entry.get("cidr") if isinstance(entry, dict) else None
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        # ignore an unsafe stored CIDR (e.g. 0.0.0.0/0 from
        # a pre-validation row or a compromised agent) so it can never grant the
        # unauthenticated, secret-bearing provisioning context.
        from app.schemas.core import is_safe_site_cidr

        if not is_safe_site_cidr(net):
            logger.warning("Ignoring unsafe site provisioning subnet %s (fail-closed)", cidr)
            continue
        if ip in net:
            return True
    return False


def _hmac_for_mac(mac: str) -> str:
    """Compute the HMAC-SHA256 signature for a normalized MAC.

    Uses ``SECRET_KEY + ENCRYPTION_SALT`` as the key so the signature
    rotates with the same cadence as the credential-encryption key.
    Returned as lowercase hex (no separators) for clean URL embedding.
    """
    from app.core.config import settings as app_settings

    key = (app_settings.SECRET_KEY + app_settings.ENCRYPTION_SALT).encode("utf-8")
    return hmac.new(key, mac.lower().encode("ascii"), hashlib.sha256).hexdigest()


def verify_hmac(mac: str, signature: str) -> bool:
    """Constant-time HMAC comparison for the provisioning URL token.

    Used by the per-device-URL flow (when subnet trust isn't available
    or the phone is on a transient network).
    """
    if not mac or not signature:
        return False
    expected = _hmac_for_mac(mac)
    return hmac.compare_digest(expected.lower(), signature.lower())


def generate_provisioning_signature(mac: str) -> str:
    """Generate a signature suitable for embedding in the provisioning URL.

    Public helper — the onboarding flow calls this to construct a
    URL like ``/voip/provisioning/cfg<MAC>.xml?sig=<hex>``. The
    Grandstream phone treats query params transparently.
    """
    normalized = normalize_mac(mac)
    if not normalized:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return _hmac_for_mac(normalized)


async def resolve_provisioning_request(
    request: Request,
    session: AsyncSession,
    mac_address: str,
) -> ProvisioningContext | None:
    """Resolve a provisioning request to its (Phone, Site, Org) context.

    Returns ``None`` on any failure — auth, validation, or missing
    device. Callers should map ``None`` to ``HTTPException(404)`` so an
    attacker cannot distinguish "MAC doesn't exist" from "MAC exists
    but you're not allowed".

    Auth resolution order:
        1. Validate MAC format. Reject malformed.
        2. Look up Phone by MAC (org-agnostic — we use the row's own
           ``site_id`` to scope, never request input).
        3. Load the Site → tenant.
        4. Source-IP (from ``request.client.host`` — NEVER raw
           ``X-Forwarded-For``,) must match ``Site.subnets`` OR a
           valid HMAC ``sig`` must be present.
    """
    from app.models.core import Site
    from app.modules.voip.models import Phone

    normalized = normalize_mac(mac_address)
    if not normalized:
        return None

    # ── Resolve phone by MAC. NO org filter here on purpose: the tenant
    # is whatever the device's site declares. ───────────────────────
    phone_q = await session.execute(
        select(Phone).where(
            Phone.mac_address == normalized,
            Phone.deleted_at.is_(None),
        )
    )
    phone = phone_q.scalar_one_or_none()
    if not phone:
        return None

    site_q = await session.execute(
        select(Site).where(
            Site.id == phone.site_id,
            Site.deleted_at.is_(None),
        )
    )
    site = site_q.scalar_one_or_none()
    if not site or not site.organization_id:
        logger.warning(
            "Provisioning request for phone %s — site missing or detached",
            normalized,
        )
        return None

    # ── Auth check 1: source-IP in Site.subnets ──
    # client_ip comes from request.client.host (uvicorn-resolved against the
    # FORWARDED_ALLOW_IPS trusted-proxy list), NEVER from the caller-supplied
    # X-Forwarded-For header — see _client_ip. This closes a spoofed
    # XFF can no longer fake subnet membership to skip HMAC.
    client_ip = _client_ip(request)
    subnets = list(site.subnets or [])
    if client_ip and _ip_in_subnets(client_ip, subnets):
        return ProvisioningContext(
            phone=phone,
            site=site,
            organization_id=site.organization_id,
            mac=normalized,
            auth_method="subnet",
        )

    # ── Auth check 2: HMAC signature in URL ──
    sig = request.query_params.get("sig") or request.headers.get("X-Provisioning-Signature")
    if sig and verify_hmac(normalized, sig):
        return ProvisioningContext(
            phone=phone,
            site=site,
            organization_id=site.organization_id,
            mac=normalized,
            auth_method="hmac",
        )

    # Both checks failed — log at WARNING (cardinality is per-MAC, low volume,
    # and operators NEED to see provisioning rejections to diagnose NAT issues).
    logger.warning(
        "Provisioning request rejected for MAC %s from %s — "
        "no subnet match and no valid HMAC signature",
        normalized,
        client_ip or "<unknown-ip>",
    )
    return None


__all__ = [
    "ProvisioningContext",
    "generate_provisioning_signature",
    "normalize_mac",
    "resolve_provisioning_request",
    "verify_hmac",
]
