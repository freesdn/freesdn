# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Shared base for gateway-feature services
====================================================

Every gateway-feature service (VPN, firewall, profiles, WiFi advanced,
firmware, insights, …) needs the same plumbing: resolve a controller by
ID, decrypt its credentials, build an Omada client, and translate
FreeSDN site UUIDs to Omada-side site IDs. This base class centralises
all of that so each feature module can focus on its own logic.
"""

from __future__ import annotations

import contextlib
import ipaddress
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters import AdapterError, get_adapter
from app.adapters.validation import validate_id, validate_mac
from app.core.crypto import decrypt_credential, decrypt_dict, is_encrypted
from app.core.security_utils import resolve_and_pin_host, validate_target_host
from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.services.adapter_staging import AdapterStagingService

if TYPE_CHECKING:
    from app.core.dependencies import CurrentUser

# Vendor → controller_type mapping used when constructing a Controller
# facade from a firewall.gateway_connections row. The facade just
# re-uses the existing ``_get_client`` plumbing — the strings here
# must match the controller_type strings the adapter registry knows
# (see app.adapters.registry).
_GATEWAY_VENDOR_TO_CONTROLLER_TYPE: dict[str, str] = {
    "mikrotik": "mikrotik",
    "opnsense": "opnsense",
    "pfsense": "pfsense",
    "openwrt": "openwrt",
}

# Hostnames / IPs that must NEVER be a controller target. Cloud
# metadata endpoints (169.254.169.254, GCP, Azure) and the FreeSDN
# host's own loopback are the high-value SSRF targets — RFC1918
# is intentionally allowed because legitimate gateways live on
# private LANs (the whole point of an SDN platform).
_FORBIDDEN_CONTROLLER_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / GCP IPv4 metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
        "metadata.google.internal",
        "metadata",  # short-form GCP
        "localhost",
        "ip6-localhost",
    }
)

# Backwards-compat aliases. The canonical helpers live in
# ``app.adapters.validation`` so future adapters (MikroTik, UniFi,
# OPNsense, …) share the same input-validation surface. Existing
# callers that imported from this module keep working.
validate_omada_id = validate_id

__all__ = [
    "GatewayServiceBase",
    "validate_mac",
    "validate_id",
    "validate_omada_id",
]


def _decrypt(value: str | None) -> str:
    if not value:
        return ""
    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except ValueError as exc:
        # Previously this silently returned the ciphertext, which then
        # became "the password" — yielding a confusing 401 from the
        # controller. Surface a clear error instead so the operator
        # knows the credential is corrupted and needs to be re-entered.
        raise HTTPException(
            500,
            detail=(
                "controller credential is corrupted and could not be "
                "decrypted; re-enter the credential"
            ),
        ) from exc


class GatewayServiceBase:
    """Shared plumbing for adapter-fronted gateway services.

    Subclasses build their own read/stage methods on top.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.staging = AdapterStagingService(db)
        # Request-scoped resolver cache.
        # Each FastAPI request constructs a fresh service via the
        # ``Depends(get_session)`` dependency, so caching on ``self``
        # is naturally request-scoped — no cross-request leakage.
        # Keyed on (entity_id, organization_id, is_superuser) to keep
        # the super-admin bypass path's result distinct.
        self._resolved_cache: dict[
            tuple[UUID, UUID, bool],
            Controller,
        ] = {}

    async def _get_controller(self, controller_id: UUID, organization_id: UUID) -> Controller:
        """Tenant-scoped controller lookup. Raises 404 if missing or
        not owned by the organization.

        Single-query implementation: joins Controller→Site and filters
        by ``Site.organization_id`` in one round-trip. Previously
        issued two sequential SELECTs (Controller, then Site), which
        with 13+ feature services per UI page meant 12+ DB hops
        before the first read.

        This helper queries ONLY ``core.controllers``. For per-vendor
        gateway services (MikroTik / OPNsense / pfSense) that must also
        accept a ``firewall.gateway_connections.id``, use
        :meth:`_resolve_controller_or_gateway` instead — it falls back
        to the gateway table and returns a Controller-shaped facade.
        """
        stmt = (
            select(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(
                Controller.id == controller_id,
                Controller.deleted_at.is_(None),
                Site.organization_id == organization_id,
            )
        )
        ctrl = (await self.db.execute(stmt)).scalar_one_or_none()
        if ctrl is None:
            raise HTTPException(404, detail="controller not found")
        # FSDN-SG-001: per-user site-grant chokepoint. The org filter above only
        # enforces TENANT isolation; a site-limited caller holding a sibling-site
        # controller UUID (same org) must still be denied. This mirrors the guard
        # already present in _resolve_controller_or_gateway / _resolve_site_context
        # and closes the ~50 controller-scoped service call sites (Omada
        # system/raw/open_api/bulk/vpn/firmware/wifi + every Proxmox service) in
        # one place. No-op for super_admin/org_admin/grant-less users and in
        # background/apply context (contextvar unset).
        assert_site_access_for_request(ctrl.site_id, detail="controller not found")
        return ctrl

    async def _resolve_controller_or_gateway(
        self,
        entity_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> Controller:
        """Polymorphic resolver that accepts EITHER a ``core.controllers``
        row id OR a ``firewall.gateway_connections`` row id.

        Background. FreeSDN historically grew two parallel
        tables for what is functionally the same thing for vendor-
        specific gateway services:

        * ``core.controllers``           — the generic adapter-aware
          SDN controller; created via ``POST /api/v1/controllers/``.
        * ``firewall.gateway_connections`` — the Firewall-module
          gateway; created via ``POST /api/v1/firewall/gateways``.
          Used by the GatewayDetailPage in the frontend.

        Both rows produce the same vendor adapter (mikrotik, opnsense,
        pfsense). The per-vendor service layer (``adapter_mikrotik_*``,
        ``adapter_opnsense_*``, ``adapter_pfsense_*``) used to only
        query the first table, so the GatewayDetailPage's tabs all
        returned 404 against any newly-created gateway row.

        This helper resolves either id transparently:

        1. Try ``core.controllers`` — keeps the existing fast path.
        2. If missing, try ``firewall.gateway_connections`` (scoped to
           ``organization_id``).
        3. If found in the gateway table, hydrate a transient
           Controller instance from the gateway fields so the rest of
           ``_get_client`` works unchanged. The transient Controller is
           **detached** — never added to the session, never persisted.
        4. If missing from both tables, raise 404.

        Vendor-credential mapping for the facade:

        * ``mikrotik`` / ``openwrt`` → ``config["username"]`` and
          ``config["password"]`` from the gateway's encrypted JSONB.
        * ``opnsense`` / ``pfsense`` → adapter expects
          ``username=api_key`` and ``password=api_secret``, so we map
          the gateway's ``api_key`` / ``api_secret`` into those slots.

        The facade is intentionally lightweight: only the fields
        ``_get_client`` reads off the controller are populated.

        Cached per-request on ``self._resolved_cache`` — when several
        helpers on the same service all need the same controller
        (common for multi-step appliers), the lookup runs once. The
        cache lifetime is the request because the service is built
        from a per-request session dependency.
        """
        # Lazy-init the cache so test subclasses or factory paths that
        # bypass ``__init__`` (constructed via ``object.__new__`` etc.)
        # don't blow up on the attribute access. The cache is still
        # per-request — production paths always hit ``__init__``.
        if not hasattr(self, "_resolved_cache"):
            self._resolved_cache = {}
        cache_key = (entity_id, organization_id, is_superuser)
        cached = self._resolved_cache.get(cache_key)
        if cached is not None:
            return cached

        # Fast path: lookup in core.controllers.
        # Super-admins bypass the org filter to match the behaviour of
        # ``unifi_deps.load_unifi_controller`` and other modern lookup
        # helpers. Operator-facing endpoints already enforce the
        # ``controller:read`` permission via FastAPI dependencies, so
        # the bypass here only widens what super-admins can reach —
        # not who can call this code path.
        ctrl_stmt = (
            select(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(
                Controller.id == entity_id,
                Controller.deleted_at.is_(None),
            )
        )
        # a SCOPED super_admin credential (explicit API-key scope
        # ceiling) must NOT bypass the org filter — only an UNSCOPED super_admin
        # may reach any org's controller. The ~97 endpoint call sites forward a
        # role-only ``is_superuser`` bool, so enforce scope here at the shared
        # chokepoint: read the request principal's scope flag from the contextvar
        # (None for background/system → unchanged) and re-apply the org filter
        # for a scoped principal regardless of the forwarded bool.
        from app.core.site_access import current_user_var

        _principal = current_user_var.get()
        if not is_superuser or bool(getattr(_principal, "_scoped", False)):
            ctrl_stmt = ctrl_stmt.where(Site.organization_id == organization_id)
        ctrl = (await self.db.execute(ctrl_stmt)).scalar_one_or_none()
        if ctrl is not None:
            # Per-user site grant (chokepoint): a site-limited caller must hold a
            # grant for the controller's site, even with a valid sibling-site
            # controller id in the same org. No-op for super_admin/org_admin and
            # in system context. Mirrors _resolve_site_context.
            assert_site_access_for_request(ctrl.site_id, detail="controller not found")
            self._resolved_cache[cache_key] = ctrl
            return ctrl

        # Fallback path: lookup in firewall.gateway_connections.
        # Import locally to avoid a module-import-time circular between
        # the core gateway base and the firewall module's models.
        from app.modules.firewall.models import GatewayConnection

        gw_stmt = select(GatewayConnection).where(
            GatewayConnection.id == entity_id,
            GatewayConnection.org_id == organization_id,
            GatewayConnection.deleted_at.is_(None),
        )
        gw = (await self.db.execute(gw_stmt)).scalar_one_or_none()
        if gw is None:
            raise HTTPException(404, detail="controller not found")

        # Build the Controller-shaped facade.
        facade = self._gateway_to_controller_facade(gw)
        # Same per-user site-grant chokepoint for the firewall-gateway path.
        assert_site_access_for_request(facade.site_id, detail="controller not found")
        self._resolved_cache[cache_key] = facade
        return facade

    @staticmethod
    def _gateway_to_controller_facade(gw: Any) -> Controller:
        """Hydrate a transient :class:`Controller` from a GatewayConnection.

        The facade carries exactly the fields ``_get_client`` reads:
        ``id``, ``host``, ``port``, ``use_ssl``, ``verify_ssl``,
        ``controller_type``, ``site_id``, and a synthetic ``config``
        JSONB containing the decrypted vendor credentials.

        The decrypted password lives in ``config["password"]`` as
        **plaintext**. The downstream ``_decrypt`` helper in this
        module is a no-op on non-Fernet strings, so this works without
        re-encrypting on the way through.
        """
        vendor = (gw.vendor or "").lower()
        controller_type = _GATEWAY_VENDOR_TO_CONTROLLER_TYPE.get(
            vendor,
            vendor,
        )

        creds_plain = decrypt_dict(gw.credentials or {}) or {}
        if vendor in ("opnsense", "pfsense"):
            # OPNsense / pfSense adapters accept username=api_key,
            # password=api_secret. Map the gateway's credential keys
            # into the slots the adapter expects.
            username = creds_plain.get("api_key", "")
            password = creds_plain.get("api_secret", "")
        else:
            # mikrotik / openwrt
            username = creds_plain.get("username", "")
            password = creds_plain.get("password", "")

        # GatewayConnection has no dedicated ``use_ssl`` column — but
        # some lab gateways (notably MikroTik CHR on port 80) speak
        # plain HTTP. We honour two opt-outs:
        #
        # 1. ``gw.settings["use_ssl"] = False`` (explicit operator opt-out
        #    via the settings JSONB on POST /firewall/gateways).
        # 2. ``gw.port == 80`` (heuristic — RouterOS REST defaults to
        #    HTTP on 80 when ``www-ssl`` is disabled).
        #
        # OPNsense / pfSense ship HTTPS-only by default; we leave the
        # default at True for those.
        settings = gw.settings or {}
        if "use_ssl" in settings:
            use_ssl = bool(settings["use_ssl"])
        elif vendor in ("mikrotik", "openwrt") and gw.port == 80:
            use_ssl = False
        else:
            use_ssl = True

        facade = Controller(
            id=gw.id,
            site_id=gw.site_id,
            name=gw.name,
            controller_type=controller_type,
            host=gw.host,
            port=gw.port,
            use_ssl=use_ssl,
            verify_ssl=bool(gw.verify_ssl),
            status="unknown",
            config={
                "username": username,
                "password": password,
                "connection_mode": "local",
            },
        )
        # Mark explicitly so downstream code that inspects the facade
        # (e.g. logging) can tell it apart from a real Controller row.
        facade._is_gateway_facade = True  # type: ignore[attr-defined]
        return facade

    async def _auto_pair_controller_for_gateway(
        self,
        gateway_id: UUID,
        organization_id: UUID,
    ) -> Controller:
        """Create a Controller row paired 1:1 with a Gateway, lazily.

        Called from ``stage_change`` when the incoming id resolves to
        a ``firewall.gateway_connections`` row but no ``core.controllers``
        row exists yet for the same UUID. The FK on
        ``adapter_pending_changes.controller_id`` requires a real Controller
        row before the staging insert can succeed.

        The paired Controller carries the SAME UUID as the gateway so:
        - The polymorphic ``_resolve_controller_or_gateway`` keeps
          finding the same entity on subsequent calls (fast-path hit
          on the Controller table, no double lookup).
        - Any future cross-page navigation (Controllers list, etc.)
          surfaces the same entity.
        - Cascading delete from the Gateway side can be wired later
          via a CASCADE or a service-layer hook.

        Idempotent: if the Controller already exists (e.g. race or
        retry), returns it unchanged.
        """
        from app.modules.firewall.models import GatewayConnection

        # Fast path: maybe we lost a race and a controller already exists.
        existing = await self.db.get(Controller, gateway_id)
        if existing is not None and existing.deleted_at is None:
            return existing

        # Fetch the gateway row (we just resolved it but didn't keep
        # the ORM object — re-fetch with tenant scope to be safe).
        gw = await self.db.get(GatewayConnection, gateway_id)
        if gw is None or gw.org_id != organization_id:
            raise HTTPException(404, detail="gateway not found")

        facade = self._gateway_to_controller_facade(gw)
        # Promote the facade to a real persisted row by adding it to
        # the session. The facade's ``id`` already equals the gateway's
        # id, so the FK on adapter_pending_changes will resolve.
        # Strip the facade marker — this is now a real Controller.
        if hasattr(facade, "_is_gateway_facade"):
            delattr(facade, "_is_gateway_facade")
        self.db.add(facade)
        # Concurrent first-stage on the same never-paired gateway: two
        # requests both pass the `existing is None` check and both call
        # `self.db.add(facade)` with the same PK. The first wins; the
        # second hits a PK unique-violation here. Catch it, roll back the
        # failed INSERT, and re-read the row the winner just persisted —
        # the loser gets the same Controller and the stage proceeds. Pre-
        # fix this raised IntegrityError → 500 on the second operator's
        # screen.
        try:
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            winner = await self.db.get(Controller, gateway_id)
            if winner is not None and winner.deleted_at is None:
                return winner
            # Someone else inserted-and-deleted between our two reads
            # (vanishingly rare). Surface a clean 409 rather than a 500.
            raise HTTPException(
                409,
                detail="gateway pair-up raced and was rolled back; retry",
            )
        return facade

    @staticmethod
    def _validate_controller_host(host: str) -> None:
        """Refuse controllers pointing at cloud metadata or the
        FreeSDN host's own loopback.

        RFC1918 ranges (192.168/16, 10/8, 172.16/12) are intentionally
        allowed — legitimate gateways live on private LANs in nearly
        every deployment, so blocking RFC1918 would make the platform
        unusable. The narrow targets here are:

        * cloud metadata endpoints (169.254.169.254, GCP, Azure) —
          never a legitimate gateway
        * 127.0.0.0/8 / ::1 — pointing at FreeSDN's own loopback
          would let a tenant who can create controllers hit FreeSDN's
          internal admin surface
        * 169.254.0.0/16 link-local more broadly — no legitimate
          gateway speaks here
        """
        if not host:
            return  # downstream get_adapter will reject empty
        h = host.strip().strip("[]").lower()
        if h in _FORBIDDEN_CONTROLLER_HOSTS:
            raise HTTPException(
                400,
                detail=(
                    "controller host targets a forbidden destination (loopback / cloud metadata)"
                ),
            )
        try:
            addr = ipaddress.ip_address(h)
        except ValueError:
            # Hostname (not a literal IP): resolve it and reject if ANY
            # resolved address is loopback / link-local / metadata /
            # unspecified. RFC1918 stays allowed (allow_private=True) so
            # legitimate gateways on private LANs work. This closes the
            # create-time vector of registering a name that resolves to
            # 127.0.0.1 / 169.254.169.254; the live connection is
            # additionally pinned to the resolved IP in _get_client /
            # _get_adapter (_pin_controller_host) to defeat DNS rebinding.
            try:
                validate_target_host(h, allow_private=True)
            except ValueError:
                raise HTTPException(
                    400,
                    detail=(
                        "controller host resolves to a forbidden destination "
                        "(loopback / link-local / cloud metadata)"
                    ),
                ) from None
            return
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            raise HTTPException(
                400,
                detail=(
                    "controller host targets a forbidden destination "
                    "(loopback / link-local / unspecified)"
                ),
            )

    @staticmethod
    def _pin_controller_host(controller: Controller) -> str:
        """Return the host to actually connect to, pinned against DNS rebinding.

        ``_validate_controller_host`` checks the name once, but httpx performs
        its OWN DNS lookup at connect time — a classic rebinding TOCTOU where a
        low-TTL name passes validation as a public IP and then resolves to
        127.0.0.1 / 169.254.169.254 when the socket is opened (cloud-metadata
        SSRF). We close it by resolving once here and connecting to the
        validated IP *literal*, which httpx cannot silently re-point.

        TLS subtlety: pinning swaps the hostname for an IP, which breaks SNI /
        certificate verification. But when ``verify_ssl`` is on, the cert check
        ITSELF defeats a rebind (a metadata/loopback host cannot present a valid
        cert for the original name), so we keep the hostname there to preserve
        SNI. We only pin for the genuinely exposed channels — plain http or
        https-without-verification — where pinning is also transparent (no cert
        to mismatch). Cloud mode does not connect to ``host`` at all, so it is
        left untouched.
        """
        host = (controller.host or "").strip()
        if not host:
            return host  # empty / cloud — downstream get_adapter handles it
        if (getattr(controller, "connection_mode", None) or "local") == "cloud":
            return host  # cloud mode dials the vendor cloud URL, not host
        try:
            pinned = resolve_and_pin_host(host, allow_private=True)
        except ValueError:
            raise HTTPException(
                400,
                detail=(
                    "controller host targets a forbidden destination "
                    "(loopback / link-local / cloud metadata)"
                ),
            ) from None
        use_ssl = bool(getattr(controller, "use_ssl", False))
        verify_ssl = bool(getattr(controller, "verify_ssl", False))
        if use_ssl and verify_ssl:
            return host  # verified TLS already blocks a rebind; keep SNI
        return pinned

    # Subclasses set this to the controller_type their service supports
    # (e.g. ``"omada"``, ``"opnsense"``). When None, any controller_type
    # is allowed — useful for shared services that dispatch by feature.
    SUPPORTED_CONTROLLER_TYPE: str | None = None

    async def _get_client(self, controller: Controller) -> Any:
        """Build (or reuse) the underlying vendor client and ensure it
        has a session.

        Adapter pooling (PERF-CRIT-1+2+6): a single
        ``(controller_id, controller_type)`` adapter is shared across
        every request that targets the same controller, eliminating the
        per-request TCP+TLS handshake + ``/system/resource`` probe +
        ``httpx.AsyncClient`` allocation that previously leaked ~50
        sockets per minute per active dashboard. Pool eviction is
        time-based (idle > 300s OR age > 3600s) plus an explicit
        ``invalidate_controller`` hook fired by the controllers endpoint
        on credential rotation / delete.

        Generalised for any vendor. When ``SUPPORTED_CONTROLLER_TYPE``
        is set on the subclass, refuses controllers of other types
        with a 400. Cloud-mode kwargs are still Omada-specific.
        """
        if (
            self.SUPPORTED_CONTROLLER_TYPE is not None
            and controller.controller_type != self.SUPPORTED_CONTROLLER_TYPE
        ):
            raise HTTPException(
                400,
                detail=(
                    f"this gateway feature requires a "
                    f"{self.SUPPORTED_CONTROLLER_TYPE!r} controller; "
                    f"got {controller.controller_type!r}"
                ),
            )
        # Belt-and-suspenders SSRF gate: even if a controller row was
        # somehow inserted with a forbidden host (DB seed, migration,
        # historical record before the validator existed), refuse to
        # build a client that points at it — and pin the connection to the
        # resolved IP literal so a DNS rebind cannot re-point it at connect
        # time (see _pin_controller_host).
        effective_host = self._pin_controller_host(controller)
        cloud_kwargs: dict[str, Any] = {}
        if controller.controller_type == "omada" and controller.connection_mode == "cloud":
            cloud_kwargs = {
                "client_id": controller.client_id or "",
                "client_secret": _decrypt(controller.client_secret),
                "omada_id": controller.omada_id or "",
                "cloud_region": controller.cloud_region or "us",
            }
        # Build the kwargs dict once — both the pool and the direct
        # ``get_adapter`` fallback below need the same arguments.
        common_kwargs: dict[str, Any] = {
            "port": controller.port,
            "use_ssl": controller.use_ssl,
            "verify_ssl": controller.verify_ssl,
            "mode": controller.connection_mode or "local",
            **cloud_kwargs,
        }
        username = controller.username or ""
        password = _decrypt(controller.password)

        # Pool path: shared adapter keyed on (controller.id, vendor).
        # Falls back to a fresh, un-pooled adapter ONLY when the pool machinery
        # itself errors, so a pool bug cannot fail every request. A genuine
        # device failure (unreachable / auth / timeout) is a typed AdapterError
        # — re-raise it so the central handler maps it (AdapterConnectionError →
        # 502, AdapterTimeoutError → 504, AdapterAuthenticationError → 502)
        # instead of letting the broad ``except`` swallow it. (Before this
        # re-raise, the broad except caught the AdapterError and the fallback's
        # mis-named, un-awaited get_adapter() raised TypeError → an opaque 500
        # for EVERY offline controller, masking the intended 502.)
        try:
            from app.adapters.pool import adapter_pool

            adapter = await adapter_pool.get_or_create_shared(
                adapter_id=controller.controller_type,
                controller_id=str(controller.id),
                host=effective_host,
                username=username,
                password=password,
                **common_kwargs,
            )
        except AdapterError:
            raise
        except Exception:
            # ``app.adapters.get_adapter`` is async and connects internally, so
            # await it (the belt-and-suspenders block below reconnects if a
            # disconnected adapter somehow slips through).
            adapter = await get_adapter(
                adapter_type=controller.controller_type,
                host=effective_host,
                username=username,
                password=password,
                **common_kwargs,
            )
            # Adopt the fallback adapter into the pool so the cleanup loop owns
            # its teardown — otherwise its httpx session / TOKEN cookie leaks per
            # request whenever the pool's own create path errored.
            with contextlib.suppress(Exception):
                from app.adapters.pool import adapter_pool

                await adapter_pool.adopt(
                    adapter,
                    adapter_id=controller.controller_type,
                    controller_id=str(controller.id),
                    host=effective_host,
                )
        # Pool already ran ``connect()`` on first creation; subsequent
        # reuses skip the probe. Belt-and-suspenders: if a pooled
        # adapter somehow ended up disconnected (e.g. the controller
        # restarted), reconnect on-demand here.
        if not getattr(adapter, "_connected", False):
            try:
                await adapter.connect()
            except Exception:
                # Reconnect failed — surface as a 502 rather than a 500
                # so the operator sees "controller offline" not a stack
                # trace. The pool will evict on its next cleanup pass.
                raise HTTPException(
                    502,
                    detail=("controller is unreachable — verify host / credentials and try again"),
                ) from None
        return adapter.client

    async def _get_adapter(self, controller: Controller) -> Any:
        """Return the **full adapter** instance (not its wrapped client).

        Most vendor services use :meth:`_get_client` because the
        underlying REST clients (MikroTikClient, OmadaClient, etc.)
        expose write helpers directly (``add_dns_static_entry``,
        ``set_filter_rule``, ...). UniFi is the odd one out: its
        write helpers (``block_client``, ``forget_client``,
        ``restart_device``) live on :class:`UniFiAdapter` so they
        can run the ``ADAPTER_READ_ONLY`` + ``force`` dual-gate
        + per-call audit emission. Those checks would be lost if
        the service called the lower-level ``UniFiClient.cmd_stamgr``
        directly.

        This helper reproduces the pool + connect flow from
        :meth:`_get_client` but returns the adapter wrapper itself.
        Add new callers sparingly — prefer ``_get_client`` for vendors
        whose write methods live on the REST client.
        """
        if (
            self.SUPPORTED_CONTROLLER_TYPE is not None
            and controller.controller_type != self.SUPPORTED_CONTROLLER_TYPE
        ):
            raise HTTPException(
                400,
                detail=(
                    f"this gateway feature requires a "
                    f"{self.SUPPORTED_CONTROLLER_TYPE!r} controller; "
                    f"got {controller.controller_type!r}"
                ),
            )
        effective_host = self._pin_controller_host(controller)
        common_kwargs: dict[str, Any] = {
            "port": controller.port,
            "use_ssl": controller.use_ssl,
            "verify_ssl": controller.verify_ssl,
            "mode": controller.connection_mode or "local",
        }
        username = controller.username or ""
        password = _decrypt(controller.password)
        # See _get_client for the full rationale: re-raise typed AdapterErrors
        # so the central handler maps them (502/504) and only fall back to a
        # direct, un-pooled adapter when the pool machinery itself errors.
        try:
            from app.adapters.pool import adapter_pool

            adapter = await adapter_pool.get_or_create_shared(
                adapter_id=controller.controller_type,
                controller_id=str(controller.id),
                host=effective_host,
                username=username,
                password=password,
                **common_kwargs,
            )
        except AdapterError:
            raise
        except Exception:
            # ``app.adapters.get_adapter`` is async and connects internally.
            adapter = await get_adapter(
                adapter_type=controller.controller_type,
                host=effective_host,
                username=username,
                password=password,
                **common_kwargs,
            )
            # Adopt the fallback adapter into the pool so the cleanup loop owns
            # its teardown — otherwise its httpx session / TOKEN cookie leaks per
            # request whenever the pool's own create path errored.
            with contextlib.suppress(Exception):
                from app.adapters.pool import adapter_pool

                await adapter_pool.adopt(
                    adapter,
                    adapter_id=controller.controller_type,
                    controller_id=str(controller.id),
                    host=effective_host,
                )
        if not getattr(adapter, "_connected", False):
            try:
                await adapter.connect()
            except Exception:
                raise HTTPException(
                    502,
                    detail=("controller is unreachable — verify host / credentials and try again"),
                ) from None
        return adapter

    @staticmethod
    def _resolve_omada_site_id(controller: Controller, site: Site | None) -> str | None:
        """Reverse-lookup the Omada-side site ID given a FreeSDN Site.

        ``Controller.site_mappings`` stores ``{omada_site_id: freesdn_site_uuid}``;
        we invert it. Returns None when the FreeSDN site has no mapping
        — callers should respond with a clear error.
        """
        if site is None:
            return None
        for omada_sid, freesdn_sid in (controller.site_mappings or {}).items():
            if str(freesdn_sid) == str(site.id):
                return omada_sid
        return None

    async def _resolve_site_context(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        current_user: CurrentUser | None = None,
    ) -> tuple[Controller, Any, str]:
        """Convenience: get controller + connected client + omada site ID
        in one call. Most read methods need all three.

        Tenant-scoped: refuses to resolve a site that does not belong to
        ``organization_id``. Without this check an org-A user could pass
        an org-B ``site_id`` and get back the controller's own org-A
        client paired with org-B's omada_site_id — weakening the
        structural multi-tenant invariant.

        Per-user site-grant scoped: when a
        ``current_user`` is supplied, also enforce the caller's per-user
        site grant via :func:`assert_can_access_site`. Without this a
        site-limited operator (granted Site A) could pass a sibling
        Site B uuid in the same org and read its live gateway config.
        The parameter defaults to ``None`` so existing callers that do not
        yet thread the principal keep their previous org-only behaviour;
        the canonical no-op rules for super_admin / org_admin / grant-less
        users still apply.
        """
        ctrl = await self._get_controller(controller_id, organization_id)
        client = await self._get_client(ctrl)
        site = await self.db.get(Site, site_id)
        if site is None or site.organization_id != organization_id or site.deleted_at is not None:
            raise HTTPException(404, detail="site not found")
        # Per-user site grant: enforce via the explicit current_user when a
        # caller threads it, else fall back to the request-scoped contextvar.
        # This guards ALL ~37 _resolve_site_context call sites across the sibling
        # adapter service modules at the chokepoint (not just the few that pass
        # current_user explicitly). No-op for super_admin/org_admin and in
        # system/background context where no request user is set.
        assert_site_access_for_request(site_id, detail="site not found", current_user=current_user)
        omada_site_id = self._resolve_omada_site_id(ctrl, site) or ""
        return ctrl, client, omada_site_id

    async def stage_change(
        self,
        *,
        feature: str,
        operation: str,
        payload: dict[str, Any],
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID | None,
        target_id: str | None = None,
        notes: str | None = None,
        actor_id: UUID | None = None,
    ) -> Any:
        """Record a write intent. Does NOT touch the controller.

        ``controller_id`` may be EITHER a ``core.controllers`` row id
        OR a ``firewall.gateway_connections`` row id. The polymorphic
        resolver below accepts both for the lookup, but the
        ``adapter_pending_changes`` table has a FK on
        ``core.controllers.id`` — so we only persist the staging row
        when the id resolves to a real Controller. For gateway-only
        ids we raise 501 with a clear message: the staging-table FK
        migration to support polymorphic ids is tracked separately
        (follow-up). The live reads / direct apply paths still
        work for gateway ids via the per-method polymorphic resolver
        the vendor services use.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
        )
        # Gateway facades carry an attribute flag so we can tell them
        # apart from a real Controller row. Previously this raised 501,
        # which broke the entire stage-and-apply UX for newly-created
        # gateways — Fix:
        # lazily auto-pair a Controller row with the SAME UUID as the
        # gateway on first stage attempt. That way the FK on
        # ``adapter_pending_changes.controller_id`` is satisfied AND the
        # frontend's stage→apply flow round-trips without any extra
        # operator action. Subsequent stages skip the pair (idempotent).
        if getattr(ctrl, "_is_gateway_facade", False):
            ctrl = await self._auto_pair_controller_for_gateway(
                controller_id,
                organization_id,
            )
        omada_site_id = None
        if site_id is not None:
            site = await self.db.get(Site, site_id)
            if site is None or site.organization_id != organization_id:
                raise HTTPException(404, detail="site not found")
            omada_site_id = self._resolve_omada_site_id(ctrl, site)
        return await self.staging.stage_change(
            organization_id=organization_id,
            controller_id=ctrl.id,
            site_id=site_id,
            omada_site_id=omada_site_id,
            feature=feature,
            operation=operation,
            payload=payload,
            target_id=target_id,
            notes=notes,
            actor_id=actor_id,
        )
