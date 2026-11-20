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

   The subnet path is also bounded in TIME (26.11.3). A factory phone
   cannot prove who it is, so any other device on the subnet that knows a
   phone's MAC could fetch that phone's SIP password. An unsigned subnet
   fetch is now served only while ``Phone.provisioning_open_until`` lies
   in the future; the Provision actions open that window for
   :data:`PROVISIONING_WINDOW`, the time a phone needs to reboot and pull.

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
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# How long after a Provision action an unsigned fetch from the site subnet
# may pull the phone's config. A Grandstream phone reboots and pulls within
# a few minutes; the rest is slack for "press Provision, then power it on".
PROVISIONING_WINDOW = timedelta(minutes=15)


def open_provisioning_window(phone: Any, now: datetime | None = None) -> datetime:
    """Let an unsigned subnet fetch pull ``phone``'s config for a while.

    The caller commits. Returns the moment the window closes.
    """
    until = (now or datetime.now(UTC)) + PROVISIONING_WINDOW
    phone.provisioning_open_until = until
    return until


def zero_touch_enabled(site: Any) -> bool:
    """Whether the site lets phones on its subnets provision without a signature.

    ``Site.voip_zero_touch_provisioning``: off for new sites; migration 036
    turned it on for sites that already provisioned phones that way.
    """
    return getattr(site, "voip_zero_touch_provisioning", False) is True


def _is_the_phones_address(phone: Any, client_ip: str | None) -> bool:
    """True only when ``client_ip`` is the phone's recorded address.

    A phone with no recorded address is never served unsigned: anything on the
    subnet that knew its MAC could take the fetch (found in review of 26.11.3).
    Discovery records a new phone's address, or an operator's connection test.
    """
    known = getattr(phone, "ip_address", None)
    if not isinstance(known, str) or not known.strip():
        return False
    try:
        return client_ip is not None and ipaddress.ip_address(
            known.strip()
        ) == ipaddress.ip_address(client_ip)
    except ValueError:
        return False


async def _claim_window(session: AsyncSession, phone: Any) -> bool:
    """Close the phone's open window and say whether this request closed it.

    One UPDATE, so of two concurrent fetches exactly one is served; the
    caller's transaction commits it with the config pull.
    """
    from sqlalchemy import update

    from app.modules.voip.models import Phone

    claimed = await session.execute(
        update(Phone)
        .where(
            Phone.id == phone.id,
            Phone.deleted_at.is_(None),
            Phone.provisioning_open_until > datetime.now(UTC),
        )
        .values(provisioning_open_until=None)
        .returning(Phone.id)
        .execution_options(synchronize_session=False)
    )
    if claimed.scalar_one_or_none() is None:
        return False
    phone.provisioning_open_until = None
    return True


def provisioning_window_open(phone: Any, now: datetime | None = None) -> bool:
    until = getattr(phone, "provisioning_open_until", None)
    return isinstance(until, datetime) and until > (now or datetime.now(UTC))


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


# How long a signed provisioning URL works. A signature used to be a
# permanent per-MAC token: one copied from a proxy log or a phone's settings
# fetched that phone's SIP password forever (found in review of 26.11.3).
SIGNATURE_MAX_LIFETIME = timedelta(hours=24)


def _hmac_for_mac(mac: str, expires: int) -> str:
    """HMAC-SHA256 over the normalized MAC and the expiry (Unix seconds).

    Keyed with ``SECRET_KEY + ENCRYPTION_SALT``, so signatures rotate with the
    credential-encryption key.
    """
    from app.core.config import settings as app_settings

    key = (app_settings.SECRET_KEY + app_settings.ENCRYPTION_SALT).encode("utf-8")
    message = f"{mac.lower()}|{expires}".encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(mac: str, signature: str, now: datetime | None = None) -> bool:
    """Whether ``signature`` (``<expiry>.<hex>``) is valid for ``mac`` right now.

    Refuses an expired token, one valid for longer than
    :data:`SIGNATURE_MAX_LIFETIME`, and the old expiry-less format.
    """
    if not mac or not signature or "." not in signature:
        return False
    expires_text, _, digest = signature.partition(".")
    if not expires_text.isdigit():
        return False
    expires = int(expires_text)
    current = (now or datetime.now(UTC)).timestamp()
    if not current < expires <= current + SIGNATURE_MAX_LIFETIME.total_seconds() + 60:
        return False
    return hmac.compare_digest(_hmac_for_mac(mac, expires), digest.lower())


def generate_provisioning_signature(
    mac: str, valid_for: timedelta = SIGNATURE_MAX_LIFETIME, now: datetime | None = None
) -> str:
    """A signature for ``/voip/provisioning/cfg<MAC>.xml?sig=<token>``.

    The token is ``<expiry>.<hex>`` and works until ``valid_for`` from now (at
    most :data:`SIGNATURE_MAX_LIFETIME`).
    """
    normalized = normalize_mac(mac)
    if not normalized:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    lifetime = min(valid_for, SIGNATURE_MAX_LIFETIME)
    expires = int(((now or datetime.now(UTC)) + lifetime).timestamp())
    return f"{expires}.{_hmac_for_mac(normalized, expires)}"


async def live_phones_with_mac(
    session: AsyncSession,
    mac: str,
    *,
    exclude_id: UUID | None = None,
    limit: int = 5,
) -> list[Any]:
    """Live (not soft-deleted) phones whose stored MAC is ``mac``, org-agnostic.

    ``mac`` is the canonical form (see :func:`normalize_mac`); MACs are stored
    that way since migration 032. Phones it flagged as sharing a MAC can both
    be live, so callers that expect one row must not use scalar_one_or_none().
    """
    from app.modules.voip.models import Phone

    query = select(Phone).where(Phone.mac_address == mac, Phone.deleted_at.is_(None))
    if exclude_id is not None:
        query = query.where(Phone.id != exclude_id)
    rows = await session.execute(query.order_by(Phone.created_at).limit(limit))
    return list(rows.scalars().all())


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

    normalized = normalize_mac(mac_address)
    if not normalized:
        return None

    # ── Resolve phone by MAC. NO org filter here on purpose: the tenant
    # is whatever the device's site declares. ───────────────────────
    from sqlalchemy.exc import MultipleResultsFound

    from app.modules.voip.models import Phone

    phone_q = await session.execute(
        select(Phone).where(
            Phone.mac_address == normalized,
            Phone.deleted_at.is_(None),
        )
    )
    try:
        phone = phone_q.scalar_one_or_none()
    except MultipleResultsFound:
        # Two live phones claim this MAC (flagged by migration 032). Serving
        # either would hand one phone the other's credentials; refuse both
        # until the operator deletes one.
        logger.warning("Provisioning request for MAC %s refused: phones share it", normalized)
        return None
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

    # Source address for the subnet check below. client_ip comes from request.client.host (uvicorn-resolved against the
    # FORWARDED_ALLOW_IPS trusted-proxy list), NEVER from the caller-supplied
    # X-Forwarded-For header — see _client_ip. This closes a spoofed
    # XFF can no longer fake subnet membership to skip HMAC.
    client_ip = _client_ip(request)
    subnets = list(site.subnets or [])
    in_subnet = bool(client_ip and _ip_in_subnets(client_ip, subnets))

    # ── Auth check 1: HMAC signature in URL (any time, any address) ──
    sig = request.query_params.get("sig") or request.headers.get("X-Provisioning-Signature")
    if sig and verify_hmac(normalized, sig):
        return ProvisioningContext(
            phone=phone,
            site=site,
            organization_id=site.organization_id,
            mac=normalized,
            auth_method="hmac",
        )

    # ── Auth check 2: ONE unsigned fetch from the site subnet, while the
    # window a Provision action opened lasts, and from the phone's own
    # address when FreeSDN knows it. A factory phone cannot prove who it is,
    # so this is as narrow as zero-touch allows: the first fetch closes the
    # window, so a device that races the phone leaves the phone without its
    # config (and the operator sees it), and a known phone is served only at
    # its address.
    if (
        in_subnet
        and zero_touch_enabled(site)
        and provisioning_window_open(phone)
        and _is_the_phones_address(phone, client_ip)
        and await _claim_window(session, phone)
    ):
        # A config, SIP password included, released without a signature:
        # always on record, at the default log level.
        logger.warning(
            "Zero-touch provisioning served phone %s (MAC %s) its configuration at %s",
            phone.id,
            normalized,
            client_ip,
        )
        return ProvisioningContext(
            phone=phone,
            site=site,
            organization_id=site.organization_id,
            mac=normalized,
            auth_method="subnet",
        )

    # Both checks failed — log at WARNING (cardinality is per-MAC, low volume,
    # and operators NEED to see provisioning rejections to diagnose NAT issues).
    if in_subnet and not zero_touch_enabled(site):
        logger.warning(
            "Provisioning request for MAC %s from %s refused: zero-touch "
            "provisioning is off for this site (turn it on for the site, or use "
            "a signed URL)",
            normalized,
            client_ip,
        )
        return None
    if in_subnet:
        logger.warning(
            "Provisioning request for MAC %s from %s refused: no provisioning "
            "window is open, it was used, or the phone is known at another address "
            "(press Provision on the phone, then let it reboot)",
            normalized,
            client_ip,
        )
        return None
    logger.warning(
        "Provisioning request rejected for MAC %s from %s — "
        "no subnet match and no valid HMAC signature",
        normalized,
        client_ip or "<unknown-ip>",
    )
    return None


__all__ = [
    "PROVISIONING_WINDOW",
    "SIGNATURE_MAX_LIFETIME",
    "ProvisioningContext",
    "generate_provisioning_signature",
    "normalize_mac",
    "open_provisioning_window",
    "provisioning_window_open",
    "resolve_provisioning_request",
    "verify_hmac",
    "zero_touch_enabled",
]
