# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX Adapter
===============================

High-level adapter that orchestrates the three Asterisk/FreePBX communication
channels (AMI, ARI, FreePBX REST) through the standard BaseAdapter interface.

Hierarchy::

    FreePBXAdapter  (BaseAdapter)
        ├── AMIClient        (TCP:5038   — events, admin commands)
        ├── ARIClient        (HTTP:8088  — call control, WebSocket events)
        └── FreePBXRestClient(HTTPS:443  — config CRUD via FreePBX REST module)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from typing import Any

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import AdapterError
from app.adapters.http_utils import CircuitBreaker

from .ami_client import AMIClient
from .ari_client import ARIClient
from .constants import AMI_DEFAULT_PORT, ARI_DEFAULT_PORT, FREEPBX_WEB_PORT
from .exceptions import (
    AMIAuthError,
    AMIConnectionError,
    ARIAuthError,
    ARIConnectionError,
    FreePBXApiError,
    FreePBXAuthError,
    FreePBXConnectionError,
    FreePBXError,
)
from .rest_client import FreePBXRestClient

logger = logging.getLogger("freesdn.adapters.freepbx")


def _safe_error(exc: Exception) -> str:
    """Sanitize a FreePBX exception for client-facing ``AdapterResult.error``.

    ``FreePBXApiError`` carries the FreePBX/GraphQL *business-logic* message
    ("Extension 200 already exists", "Field destination of required type
    String! was not provided") — operator-useful for diagnosing a rejected
    apply, and free of credentials/internal URLs — so we surface it (bounded).

    Every other FreePBX error (connection / auth) can carry REST response
    bodies or AMI authentication strings in ``str(exc)``, so those stay
    sanitized to the class name; the full repr is preserved server-side via
    ``logger.exception`` upstream.
    """
    if isinstance(exc, FreePBXApiError):
        msg = str(exc).strip()
        if msg:
            return msg[:300]
    return f"FreePBXError: {type(exc).__name__}"


# ── Gold-standard adapter contract ─────────────────────────────────────────
# Mirror the Omada / Proxmox / OPNsense / pfSense / MikroTik pattern:
#
#   * Read-only default: ``ADAPTER_READ_ONLY=True`` blocks every write
#     unless the per-call ``force=True`` is set. Operators flip the env
#     var to opt out of dry-run mode globally.
#   * Tagged ``CircuitBreaker`` around every HTTP/AMI/ARI client so
#     dashboards can graph FreePBX alongside other adapters via the
#     ``freesdn_adapter_circuit_state{adapter,host}`` Prometheus gauge.
#
# ``ADAPTER_READ_ONLY`` defaults to True at module load — production
# deployments override it via env. (Same pattern the Omada adapter uses;
# see ``app/adapters/omada/adapter.py``.)


class FreePBXReadOnlyError(FreePBXError):
    """Raised when a write operation is attempted in read-only mode.

    Maps to HTTP 423 (Locked) at the API layer so the frontend can
    distinguish "adapter refused" from "PBX is broken".
    """


# ─── AMI Originate allowlist (toll-fraud + RCE hardening) ─────────────────
# AMI Originate accepts arbitrary applications including ``System``,
# ``Exec``, ``AGI`` and ``MixMonitor`` with caller-controlled paths.
# Restrict to a strict allowlist of safe dial-plan applications.
_SAFE_ORIGINATE_APPS: frozenset[str] = frozenset(
    {
        "Dial",
        "Playback",
        "Queue",
        "ConfBridge",
    }
)

# Toll-fraud guard: numbers that match these prefixes are rejected
# unless the tenant has explicitly added the prefix to
# ``pbx.settings.allowed_outbound_prefixes``. Premium-rate ranges,
# expensive international destinations, satellite ranges.
_PREMIUM_RATE_PREFIXES: tuple[str, ...] = (
    "1900",
    "1976",  # US/Canada premium rate
    "+1900",
    "+1976",
    "+883",
    "+882",
    "+870",  # Inmarsat / satellite
    "+999",
    "+979",  # Premium reserved
    "00",
    "011",  # Bare international prefixes — must be tenant-confirmed
)

# Destination number sanitisation: only digits, +, *, # allowed.
_SAFE_DEST_RE = re.compile(r"^\+?[\d*#]{1,40}$")


class FreePBXAdapter(BaseAdapter):
    """
    FreePBX / Asterisk adapter for FreeSDN.

    Connects to a FreePBX server using three interfaces:
    - **AMI** – persistent TCP connection for events + admin commands
    - **ARI** – REST + WebSocket for real-time call control
    - **REST** – FreePBX admin REST API for extension/trunk/queue CRUD

    Usage::

        adapter = FreePBXAdapter(
            host="198.51.100.10",
            username="admin",
            password="<PASSWORD>",
            ami_username="freesdn",
            ami_secret="<AMI_SECRET>",
            ari_username="freesdn",
            ari_password="<ARI_PASSWORD>",
        )
        await adapter.connect()
        devices = await adapter.discover_devices()
    """

    manifest = AdapterManifest(
        id="freepbx",
        name="FreePBX / Asterisk",
        vendor="Sangoma / Asterisk",
        version="1.0.0",
        description=(
            "PBX adapter for FreePBX and Asterisk servers. "
            "Manages extensions, trunks, queues, ring groups, "
            "call logs, voicemail, and real-time call control."
        ),
        controller_type="pbx",
        supports_controller=True,
        supports_direct=False,
        supported_versions=["FreePBX 15+", "Asterisk 16+"],
        device_types={
            "pbx": DeviceTypeCapabilities(
                module="voip",
                capabilities=[
                    Capability.PBX_EXTENSIONS,
                    Capability.PBX_TRUNKS,
                    Capability.PBX_ROUTES,
                    Capability.PBX_IVR,
                    Capability.PBX_QUEUES,
                    Capability.PBX_RING_GROUPS,
                    Capability.PBX_VOICEMAIL,
                    Capability.PBX_CALL_LOGS,
                    Capability.PBX_RECORDINGS,
                    Capability.PBX_CONFERENCE,
                ],
                models=["FreePBX", "Asterisk"],
            ),
        },
        auth_methods=["username_password"],
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=10,
        default_sync_interval=300,
        min_sync_interval=60,
        supports_webhooks=False,
        supports_real_time_events=True,  # via AMI + ARI WebSocket
        supports_bulk_operations=False,
    )

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        # AMI credentials (may differ from web UI)
        ami_username: str | None = None,
        ami_secret: str | None = None,
        ami_port: int = AMI_DEFAULT_PORT,
        # ARI credentials
        ari_username: str | None = None,
        ari_password: str | None = None,
        ari_port: int = ARI_DEFAULT_PORT,
        # FreePBX web
        web_port: int = FREEPBX_WEB_PORT,
        use_ssl: bool = True,
        # NOTE: ``verify_ssl`` now defaults to True. Brownfield installs
        # with self-signed certs MUST pass ``verify_ssl=False`` AND set
        # ``tls_verify_disabled_acknowledged=True`` on the PBX row
        # before the service layer is allowed to relax this. The bare
        # adapter constructor still respects whatever is passed, but
        # the FreePBX `_adapter_from_pbx` factory in the service layer
        # enforces the acknowledgement gate.
        verify_ssl: bool = True,
        # Per-tenant override for toll-fraud guard. Caller passes the
        # decrypted ``allowed_outbound_prefixes`` list from
        # ``pbx.settings`` so AMI Originate can validate against it.
        allowed_outbound_prefixes: tuple[str, ...] = (),
        # Read-only / write-gate ─ see reference contract above.
        read_only: bool | None = None,
        # ── OAuth2 client_credentials (FreePBX 16+ Admin API → M2M app) ──
        # When BOTH are set, the REST client uses the sanctioned
        # ``/admin/api/api/token`` flow + ``/admin/api/api/rest/...`` +
        # ``/admin/api/api/gql`` (78 query fields, 105 mutations).
        # When omitted, falls back to web-session login + legacy AJAX
        # — works on every FreePBX 15-17 install but limited surface.
        api_client_id: str | None = None,
        api_client_secret: str | None = None,
        **kwargs: Any,
    ):
        super().__init__(host, username, password, **kwargs)

        # None ⇒ the write gate resolves the LIVE runtime flag per call (so the
        # Settings-UI toggle works); an explicit bool pins it (tests/back-compat).
        self._read_only = read_only
        self._allowed_outbound_prefixes: tuple[str, ...] = tuple(
            p.strip() for p in (allowed_outbound_prefixes or ()) if p and p.strip()
        )

        # AMI client
        self._ami = AMIClient(
            host=host,
            username=ami_username or username,
            secret=ami_secret or password,
            port=ami_port,
            auto_reconnect=True,
        )

        # ARI client
        self._ari = ARIClient(
            host=host,
            username=ari_username or username,
            password=ari_password or password,
            port=ari_port,
            use_ssl=False,  # ARI default is HTTP
        )

        # FreePBX REST client. Passes OAuth2 client_credentials when
        # configured — the client picks the active auth mode based on
        # whether both client_id + client_secret are supplied.
        self._rest = FreePBXRestClient(
            host=host,
            username=username,
            password=password,
            port=web_port,
            use_ssl=use_ssl,
            verify_ssl=verify_ssl,
            api_client_id=api_client_id,
            api_client_secret=api_client_secret,
        )

        # State
        self._asterisk_version: str | None = None
        self._freepbx_version: str | None = None

        # Tagged circuit breaker — wraps every cross-network call so
        # dashboards graph FreePBX alongside Omada / Proxmox /
        # OPNsense via the shared ``freesdn_adapter_circuit_state``
        # gauge. After 5 consecutive failures the breaker fails fast
        # for 60s before allowing a single probe.
        self._circuit = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="freepbx",
            host=f"{host}:{web_port}",
        )

    # ── properties ─────────────────────────────────────────────────────

    @property
    def ami(self) -> AMIClient:
        """Direct access to the AMI client for advanced usage."""
        return self._ami

    @property
    def ari(self) -> ARIClient:
        """Direct access to the ARI client for advanced usage."""
        return self._ari

    @property
    def rest(self) -> FreePBXRestClient:
        """Direct access to the FreePBX REST client for advanced usage."""
        return self._rest

    @property
    def circuit(self) -> CircuitBreaker:
        """Tagged breaker used by the service layer for status pages."""
        return self._circuit

    # ── Write-gate (read-only mode + per-call force=True) ──────────────
    def _check_write_allowed(self, force: bool, op: str) -> None:
        """Raise ``FreePBXReadOnlyError`` when a write is blocked.

        ``ADAPTER_READ_ONLY=true`` blocks unless the caller passes ``force=True``.
        NOTE:
        FreePBX live call-control (AMI originate/hangup) is an OPERATIONAL action,
        not a device-config mutation, so it intentionally proceeds with
        ``force=True`` to keep working under the default read-only posture — i.e.
        ``force=True`` DOES override the env lock for these live actions. The
        cross-tenant / cross-site abuse vector is closed by the RBAC +
        per-user site-grant + operation-permission gates on EVERY caller
        (including the Fabric path, which now threads ``accessible_site_ids``),
        NOT by this env lock. Set ``ADAPTER_READ_ONLY`` and withhold the
        permission/grant to lock a tenant out.
        """
        # Resolve the LIVE runtime read-only flag (Settings-UI/Redis override,
        # env default fallback) when the caller didn't pin it — parity with the
        # omada/unifi/proxmox clients + the staging service, so an operator's
        # live "freeze writes" toggle is honored without a worker restart.
        if self._read_only is None:
            from app.core.runtime_flags import is_adapter_read_only

            effective_ro = is_adapter_read_only()
        else:
            effective_ro = self._read_only
        if effective_ro and not force:
            raise FreePBXReadOnlyError(
                f"Refusing {op}: adapter is in read-only mode "
                "(set ADAPTER_READ_ONLY=false and pass force=True to override)"
            )

    def _track(self) -> None:
        """Wrap a call with circuit-breaker state tracking.

        Returns ``True`` if the call should proceed. Adapter methods
        call this BEFORE sending and call ``_track_success()`` /
        ``_track_failure()`` after to update the breaker.
        """
        # No-op when the breaker is closed; service-layer code checks
        # ``self._circuit.allow_request()`` explicitly when it wants
        # the fast-fail behaviour.

    def _track_success(self) -> None:
        self._circuit.record_success()

    def _track_failure(self) -> None:
        self._circuit.record_failure()

    # ── Toll-fraud guard ───────────────────────────────────────────────
    def _check_destination_safe(self, destination: str) -> None:
        """Validate a dial destination against the toll-fraud allowlist.

        Raises ``FreePBXError`` (mapped to 502 / 422 by the service
        layer) when the destination is unsafe. The checks are:

        1. **Shape validation** — only digits + ``+ * #`` (max 40 chars).
        2. **Premium-rate / international block** — destinations
           matching ``_PREMIUM_RATE_PREFIXES`` are rejected unless the
           prefix is in the tenant's ``allowed_outbound_prefixes``
           allowlist.
        """
        if not destination or not _SAFE_DEST_RE.match(destination):
            raise FreePBXError(
                f"Unsafe dial destination: {destination!r} contains disallowed characters"
            )
        for blocked in _PREMIUM_RATE_PREFIXES:
            if destination.startswith(blocked):
                # Allowed only if tenant has explicitly whitelisted the prefix
                if not any(
                    destination.startswith(allowed) for allowed in self._allowed_outbound_prefixes
                ):
                    raise FreePBXError(
                        f"Refusing to dial {destination!r}: prefix {blocked!r} "
                        "is in the premium-rate blocklist. Add it to "
                        "pbx.settings.allowed_outbound_prefixes to opt in."
                    )

    # ═══════════════════════════════════════════════════════════════════
    # BaseAdapter — Connection lifecycle
    # ═══════════════════════════════════════════════════════════════════

    async def connect(self) -> bool:
        """
        Connect all three interfaces (AMI, ARI, REST).

        All interfaces use graceful degradation — the adapter succeeds as long
        as at least one interface connects.  Methods that need a specific
        interface already check availability before use.
        """
        if self._connected:
            return True

        # Tear down any already-connected interface if a LATER one fatally fails.
        # AMI.connect spawns _read_loop + _keepalive_loop tasks and a TCP socket;
        # if REST then raises FreePBXAuthError (or the all-failed check raises),
        # a bare `raise` would leak those AMI tasks/socket — and because
        # BaseAdapter.__aenter__ calls connect() but __aexit__ is NOT invoked when
        # __aenter__ raises, the documented `async with FreePBXAdapter(...)` usage
        # (live in 3 voip Celery tasks) leaked per failed connect.
        # disconnect() is idempotent, so calling it on a partial connect is safe.
        try:
            # Connect the three interfaces CONCURRENTLY. They are independent
            # endpoints, so a sequential connect made an OFFLINE PBX wait for AMI,
            # then ARI, then REST to each time out in turn (~20s). gather lets them
            # fail together (~one connect timeout). Graceful degradation is
            # preserved by the "at least one connected" check below; a REST auth
            # error is definitive (same creds everywhere) and still propagates.
            ami_res, ari_res, rest_res = await asyncio.gather(
                self._ami.connect(),
                self._ari.connect(),
                self._rest.connect(),
                return_exceptions=True,
            )
            if isinstance(rest_res, FreePBXAuthError):
                raise rest_res
            for _name, _res, _why in (
                ("AMI", ami_res, "real-time call control disabled"),
                ("ARI", ari_res, "call-control features disabled"),
                ("REST", rest_res, "config CRUD via REST disabled"),
            ):
                if isinstance(_res, Exception):
                    logger.warning("FreePBX %s connect failed (%s); %s", _name, _res, _why)

            # At least one interface must be available
            if not (self._ami.connected or self._ari.connected or self._rest.api_available):
                raise FreePBXConnectionError(
                    "All interfaces failed — AMI, ARI, and REST are all unreachable"
                )
        except Exception:
            with contextlib.suppress(Exception):
                await self.disconnect()
            raise

        # Gather version info
        try:
            if self._ami.connected:
                self._asterisk_version = await self._ami.get_version()
                logger.info("Asterisk version: %s", self._asterisk_version)
        except Exception:
            pass

        self._connected = True
        logger.info(
            "FreePBX adapter connected — AMI:%s ARI:%s REST:%s",
            self._ami.connected,
            self._ari.connected,
            self._rest.connected,
        )
        return True

    async def disconnect(self) -> None:
        """Disconnect all interfaces."""
        self._connected = False

        for client in (self._ami, self._ari, self._rest):
            try:
                await client.disconnect()
            except Exception as exc:
                logger.warning("Disconnect error: %s", exc)

        logger.info("FreePBX adapter disconnected from %s", self.host)

    async def test_connection(self) -> AdapterResult:
        """
        Non-destructive connection test.

        Tries AMI Ping, ARI /asterisk/info, and REST status endpoint.
        """
        results: dict[str, Any] = {}

        # Test AMI
        ami = AMIClient(
            host=self.host,
            username=self._ami.username,
            secret=self._ami.secret,
            port=self._ami.port,
            auto_reconnect=False,
        )
        try:
            await ami.connect()
            ok = await ami.ping()
            version = await ami.get_version()
            results["ami"] = {"connected": True, "ping": ok, "version": version}
        except (AMIConnectionError, AMIAuthError) as exc:
            results["ami"] = {"connected": False, "error": str(exc)}
        except Exception as exc:
            results["ami"] = {"connected": False, "error": str(exc)}
        finally:
            with contextlib.suppress(Exception):
                await ami.disconnect()

        # Test ARI
        ari = ARIClient(
            host=self.host,
            username=self._ari.username,
            password=self._ari.password,
            port=self._ari.port,
        )
        try:
            await ari.connect()
            info = await ari.get_asterisk_info(only="build")
            results["ari"] = {"connected": True, "info": info}
        except (ARIConnectionError, ARIAuthError) as exc:
            results["ari"] = {"connected": False, "error": str(exc)}
        except Exception as exc:
            results["ari"] = {"connected": False, "error": str(exc)}
        finally:
            with contextlib.suppress(Exception):
                await ari.disconnect()

        # Test REST
        rest = FreePBXRestClient(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self._rest.port,
            use_ssl=self._rest.use_ssl,
            verify_ssl=self._rest.verify_ssl,
        )
        try:
            await rest.connect()
            avail = await rest.check_availability()
            results["rest"] = {"connected": True, "modules": avail}
        except (FreePBXConnectionError, FreePBXAuthError) as exc:
            results["rest"] = {"connected": False, "error": str(exc)}
        except Exception as exc:
            results["rest"] = {"connected": False, "error": str(exc)}
        finally:
            with contextlib.suppress(Exception):
                await rest.disconnect()

        ami_ok = results.get("ami", {}).get("connected", False)
        rest_ok = results.get("rest", {}).get("connected", False)
        if ami_ok or rest_ok:
            return AdapterResult.ok(
                data=results,
                message="FreePBX connection successful",
            )
        return AdapterResult.fail(
            error="All interfaces failed — at least AMI or REST must connect",
            message=str(results),
        )

    # ═══════════════════════════════════════════════════════════════════
    # BaseAdapter — Discovery
    # ═══════════════════════════════════════════════════════════════════

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """
        Discover the PBX as a single "device".

        The FreePBX adapter treats the PBX server itself as the discovered
        device.  Individual extensions / phones are discovered by the
        Grandstream adapter or via future phone adapters.
        """
        devices: list[DiscoveredDevice] = []

        # The PBX itself
        pbx_device = DiscoveredDevice(
            mac_address="00:00:00:00:00:00",  # PBX has no MAC
            ip_address=self.host,
            name=f"FreePBX @ {self.host}",
            vendor="Sangoma / Asterisk",
            model="FreePBX",
            firmware_version=self._asterisk_version,
            device_type="pbx",
            status="online" if (self._ami.connected or self._rest.api_available) else "offline",
            serial_number=None,
            capabilities=[
                Capability.PBX_EXTENSIONS,
                Capability.PBX_TRUNKS,
                Capability.PBX_QUEUES,
                Capability.PBX_RING_GROUPS,
                Capability.PBX_VOICEMAIL,
                Capability.PBX_CALL_LOGS,
                Capability.PBX_RECORDINGS,
                Capability.PBX_CONFERENCE,
                Capability.PBX_IVR,
                Capability.PBX_ROUTES,
            ],
            raw_data={
                "asterisk_version": self._asterisk_version,
                "ami_connected": self._ami.connected,
                "ari_connected": self._ari.connected,
                "rest_available": self._rest.api_available,
            },
        )
        devices.append(pbx_device)

        # Optionally discover registered SIP endpoints as basic info
        if self._ami.connected:
            try:
                peers = await self._ami.get_sip_peers()
                for peer_msg in peers:
                    ip = peer_msg.headers.get("ObjectName", peer_msg.headers.get("IPaddress", ""))
                    name = peer_msg.headers.get(
                        "ObjectName", peer_msg.headers.get("Endpoint", "unknown")
                    )
                    devices.append(
                        DiscoveredDevice(
                            mac_address="",
                            ip_address=ip if ip and ip != "-none-" else None,
                            name=f"SIP/{name}",
                            vendor="SIP Endpoint",
                            model=peer_msg.headers.get("UserAgent", "unknown"),
                            firmware_version=None,
                            device_type="phone",
                            status="online"
                            if peer_msg.headers.get("Status", "").startswith("OK")
                            else "offline",
                            raw_data=dict(peer_msg.headers),
                        )
                    )
            except Exception as exc:
                logger.warning("Failed to discover SIP peers: %s", exc)

        return devices

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Get PBX or extension status."""
        # If device_id looks like an extension number, get extension state
        if device_id.isdigit():
            try:
                states = await self._ami.get_extension_states([device_id])
            except AdapterError:
                # AMI connection/auth/timeout/protocol errors are real
                # AdapterError subclasses — let them propagate so the
                # middleware maps them (conn → 502, timeout → 504) instead
                # of escaping as an opaque 500.
                raise
            except Exception as exc:
                # Truly unexpected AMI failure — degrade to a status dict
                # with an error field rather than a raw 500.
                logger.warning("AMI get_extension_states failed for %s: %s", device_id, exc)
                return {"extension": device_id, "state": "unknown", "error": str(exc)}
            if states:
                s = states[0]
                return {
                    "extension": device_id,
                    "state": s.get("Status", "unknown"),
                    "hint": s.get("Hint", ""),
                }
            return {"extension": device_id, "state": "unknown"}

        # Otherwise return PBX-level status
        return {
            "host": self.host,
            "ami_connected": self._ami.connected,
            "ari_connected": self._ari.connected,
            "rest_available": self._rest.api_available,
            "asterisk_version": self._asterisk_version,
        }

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get device info for PBX or endpoint."""
        # If the device_id matches our PBX host, return PBX info directly
        if device_id == self.host or device_id == "pbx":
            return DiscoveredDevice(
                mac_address="00:00:00:00:00:00",
                ip_address=self.host,
                name=f"FreePBX @ {self.host}",
                vendor="Sangoma / Asterisk",
                model="FreePBX",
                firmware_version=self._asterisk_version,
                device_type="pbx",
                status="online" if (self._ami.connected or self._rest.api_available) else "offline",
            )

        # Try to look up a SIP endpoint by name
        if self._ami.connected:
            try:
                resp = await self._ami.send_action(
                    "ExtensionState",
                    {"Exten": device_id, "Context": "default"},
                )
                if resp.is_success:
                    return DiscoveredDevice(
                        mac_address="",
                        ip_address=None,
                        name=f"SIP/{device_id}",
                        vendor="SIP Endpoint",
                        model="unknown",
                        firmware_version=None,
                        device_type="phone",
                        status="online" if resp.get("Status", "-1") != "-1" else "offline",
                    )
            except Exception:
                pass

        return None

    # ═══════════════════════════════════════════════════════════════════
    # PBX-specific high-level methods
    # ═══════════════════════════════════════════════════════════════════

    # ── Extensions ─────────────────────────────────────────────────────

    async def list_extensions(self) -> AdapterResult:
        """List all PBX extensions."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_extensions()
                return AdapterResult.ok(data=data)
            # Fallback to AMI
            peers = await self._ami.get_sip_peers()
            return AdapterResult.ok(
                data=[p.headers for p in peers],
                message="Extensions fetched via AMI (REST unavailable)",
            )
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def get_extension(self, ext_number: str) -> AdapterResult:
        """Get extension details."""
        try:
            if self._rest.api_available:
                data = await self._rest.get_extension(ext_number)
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def create_extension(
        self, ext_number: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Create a new extension (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "create extension")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to create extensions")
            result = await self._rest.create_extension(ext_number, data)
            return AdapterResult.ok(data=result, message=f"Extension {ext_number} created")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def update_extension(
        self, ext_number: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update an extension (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "update extension")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to update extensions")
            result = await self._rest.update_extension(ext_number, data)
            return AdapterResult.ok(data=result, message=f"Extension {ext_number} updated")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def delete_extension(self, ext_number: str, *, force: bool = False) -> AdapterResult:
        """Delete an extension (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "delete extension")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to delete extensions")
            await self._rest.delete_extension(ext_number)
            return AdapterResult.ok(message=f"Extension {ext_number} deleted")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Trunks ─────────────────────────────────────────────────────────

    async def list_trunks(self) -> AdapterResult:
        """List SIP trunks."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_trunks()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available for trunk listing")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def list_trunks_with_details(self) -> AdapterResult:
        """List SIP trunks with full PJSIP configuration scraped from config pages."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_trunks_with_details()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available for trunk listing")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def get_trunk(self, trunk_id: str) -> AdapterResult:
        """Get a specific trunk by ID."""
        try:
            if self._rest.api_available:
                data = await self._rest.get_trunk(trunk_id)
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def create_trunk(self, data: dict[str, Any], *, force: bool = False) -> AdapterResult:
        """Create a new SIP trunk (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "create trunk")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to create trunks")
            result = await self._rest.create_trunk(data)
            return AdapterResult.ok(data=result, message="Trunk created")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def update_trunk(
        self, trunk_id: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update a SIP trunk (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "update trunk")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to update trunks")
            result = await self._rest.update_trunk(trunk_id, data)
            return AdapterResult.ok(data=result, message=f"Trunk {trunk_id} updated")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def delete_trunk(self, trunk_id: str, *, force: bool = False) -> AdapterResult:
        """Delete a SIP trunk (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "delete trunk")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to delete trunks")
            await self._rest.delete_trunk(trunk_id)
            return AdapterResult.ok(message=f"Trunk {trunk_id} deleted")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Ring Groups ────────────────────────────────────────────────────

    async def list_ring_groups(self) -> AdapterResult:
        """List ring groups."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_ring_groups()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def create_ring_group(
        self, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Create a ring group (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "create ring group")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required")
            result = await self._rest.create_ring_group(data)
            return AdapterResult.ok(data=result, message="Ring group created")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def update_ring_group(
        self, grpnum: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update a ring group (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "update ring group")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to update ring groups")
            result = await self._rest.update_ring_group(grpnum, data)
            return AdapterResult.ok(data=result, message=f"Ring group {grpnum} updated")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def delete_ring_group(self, grpnum: str, *, force: bool = False) -> AdapterResult:
        """Delete a ring group (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "delete ring group")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to delete ring groups")
            await self._rest.delete_ring_group(grpnum)
            return AdapterResult.ok(message=f"Ring group {grpnum} deleted")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Queues ─────────────────────────────────────────────────────────

    async def list_queues(self) -> AdapterResult:
        """List call queues."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_queues()
                return AdapterResult.ok(data=data)
            # Fallback: AMI QueueStatus
            queue_events = await self._ami.get_queue_summary()
            return AdapterResult.ok(
                data=[e.headers for e in queue_events],
                message="Queues fetched via AMI",
            )
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def create_queue(self, data: dict[str, Any], *, force: bool = False) -> AdapterResult:
        """Create a call queue (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "create queue")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to create queues")
            result = await self._rest.create_queue(data)
            return AdapterResult.ok(data=result, message="Queue created")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def update_queue(
        self, queue_id: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update a call queue (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "update queue")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to update queues")
            result = await self._rest.update_queue(queue_id, data)
            return AdapterResult.ok(data=result, message=f"Queue {queue_id} updated")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def delete_queue(self, queue_id: str, *, force: bool = False) -> AdapterResult:
        """Delete a call queue (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "delete queue")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to delete queues")
            await self._rest.delete_queue(queue_id)
            return AdapterResult.ok(message=f"Queue {queue_id} deleted")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── IVR ────────────────────────────────────────────────────────────

    async def list_ivrs(self) -> AdapterResult:
        """List IVR menus."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_ivrs()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def create_ivr(self, data: dict[str, Any], *, force: bool = False) -> AdapterResult:
        """Create an IVR menu (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "create IVR")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to create IVRs")
            result = await self._rest.create_ivr(data)
            return AdapterResult.ok(data=result, message="IVR created")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def update_ivr(
        self, ivr_id: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update an IVR menu (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "update IVR")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to update IVRs")
            result = await self._rest.update_ivr(ivr_id, data)
            return AdapterResult.ok(data=result, message=f"IVR {ivr_id} updated")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def delete_ivr(self, ivr_id: str, *, force: bool = False) -> AdapterResult:
        """Delete an IVR menu (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "delete IVR")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to delete IVRs")
            await self._rest.delete_ivr(ivr_id)
            return AdapterResult.ok(message=f"IVR {ivr_id} deleted")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── DIDs ───────────────────────────────────────────────────────────

    async def list_dids(self) -> AdapterResult:
        """List DID / Inbound Routes."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_dids()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def create_did(self, data: dict[str, Any], *, force: bool = False) -> AdapterResult:
        """Create a DID / inbound route (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "create inbound route")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to create inbound routes")
            result = await self._rest.create_did(data)
            return AdapterResult.ok(data=result, message="Inbound route created")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def update_did(
        self, did_id: str, data: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update a DID / inbound route (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "update inbound route")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to update inbound routes")
            result = await self._rest.update_did(did_id, data)
            return AdapterResult.ok(data=result, message=f"Inbound route {did_id} updated")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    async def delete_did(self, did_id: str, *, force: bool = False) -> AdapterResult:
        """Delete a DID / inbound route (read-only + force dual-gated)."""
        try:
            self._check_write_allowed(force, "delete inbound route")
            if not self._rest.api_available:
                return AdapterResult.fail(error="REST API required to delete inbound routes")
            await self._rest.delete_did(did_id)
            return AdapterResult.ok(message=f"Inbound route {did_id} deleted")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Outbound Routes ────────────────────────────────────────────────

    async def list_outbound_routes(self) -> AdapterResult:
        """List outbound dial routes."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_outbound_routes()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Follow Me ──────────────────────────────────────────────────────

    async def list_followme(self) -> AdapterResult:
        """List Follow-Me / Find-Me-Follow-Me configurations."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_followme()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Announcements ──────────────────────────────────────────────────

    async def list_announcements(self) -> AdapterResult:
        """List announcement recordings."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_announcements()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Paging Groups ─────────────────────────────────────────────────

    async def list_paging_groups(self) -> AdapterResult:
        """List paging / intercom groups."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_paging_groups()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Day/Night Controls ─────────────────────────────────────────────

    async def list_daynight(self) -> AdapterResult:
        """List day/night toggle controls."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_daynight()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Blacklist ──────────────────────────────────────────────────────

    async def list_blacklist(self) -> AdapterResult:
        """List blacklisted caller numbers."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_blacklist()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Certificates ───────────────────────────────────────────────────

    async def list_certificates(self) -> AdapterResult:
        """List TLS/SSL certificates."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_certificates()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Admin Users ────────────────────────────────────────────────────

    async def list_admin_users(self) -> AdapterResult:
        """List FreePBX admin / operator accounts."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_admin_users()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Time Conditions ──────────────────────────────────────────────

    async def list_time_conditions(self) -> AdapterResult:
        """List time-based routing rules."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_time_conditions()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Contact Manager ──────────────────────────────────────────────

    async def list_contacts(self) -> AdapterResult:
        """List contacts from the contact manager."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_contacts()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── System Recordings ────────────────────────────────────────────

    async def list_system_recordings(self) -> AdapterResult:
        """List system recordings (prompts, greetings)."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_system_recordings()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Music on Hold ────────────────────────────────────────────────

    async def list_music_on_hold(self) -> AdapterResult:
        """List music-on-hold categories."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_music_on_hold()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── AMI Managers ─────────────────────────────────────────────────

    async def list_ami_managers(self) -> AdapterResult:
        """List AMI manager accounts."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_ami_managers()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Backup Jobs ──────────────────────────────────────────────────

    async def list_backup_jobs(self) -> AdapterResult:
        """List configured backup jobs."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_backup_jobs()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── SIP Settings ─────────────────────────────────────────────────

    async def get_sip_settings(self) -> AdapterResult:
        """Get SIP/PJSIP configuration settings."""
        try:
            if self._rest.api_available:
                data = await self._rest.get_sip_settings()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Parking ──────────────────────────────────────────────────────

    async def get_parking_config(self) -> AdapterResult:
        """Get parking lot configuration."""
        try:
            if self._rest.api_available:
                data = await self._rest.get_parking_config()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Feature Codes ────────────────────────────────────────────────

    async def get_feature_codes(self) -> AdapterResult:
        """Get configured feature (star) codes."""
        try:
            if self._rest.api_available:
                data = await self._rest.get_feature_codes()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Installed Modules ────────────────────────────────────────────

    async def get_installed_modules(self) -> AdapterResult:
        """Get list of installed FreePBX modules."""
        try:
            if self._rest.api_available:
                data = await self._rest.get_installed_modules()
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Call Logs / CDR ────────────────────────────────────────────────

    async def search_call_logs(
        self,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        src: str | None = None,
        dst: str | None = None,
        limit: int = 100,
    ) -> AdapterResult:
        """Search call detail records."""
        try:
            if self._rest.api_available:
                data = await self._rest.search_cdr(
                    start_date=start_date,
                    end_date=end_date,
                    src=src,
                    dst=dst,
                    limit=limit,
                )
                return AdapterResult.ok(data=data)
            return AdapterResult.fail(error="REST API not available for CDR")
        except AdapterError as exc:
            return AdapterResult.fail(error=_safe_error(exc))

    # ── Real-time call control ─────────────────────────────────────────

    async def originate_call(
        self,
        channel: str,
        exten: str,
        *,
        context: str = "from-internal",
        caller_id: str = "",
        application: str | None = None,
        force: bool = False,
    ) -> AdapterResult:
        """Originate a call via AMI.

        Now enforces three gates:
          1. Write-gate (read-only mode + per-call ``force=True``).
          2. Toll-fraud guard against the tenant's
             ``allowed_outbound_prefixes`` allowlist.
          3. AMI Originate application allowlist — if a caller passes
             ``application=``, it must be one of ``Dial``, ``Playback``,
             ``Queue``, ``ConfBridge``. ``System``/``Exec``/``AGI``/
             ``MixMonitor`` are rejected (RCE / arbitrary-write risk).
        """
        try:
            self._check_write_allowed(force, "AMI Originate")
            self._check_destination_safe(exten)
            if application and application not in _SAFE_ORIGINATE_APPS:
                raise FreePBXError(
                    f"AMI Originate application {application!r} is not in the "
                    f"safe allowlist {sorted(_SAFE_ORIGINATE_APPS)}"
                )
            if not self._circuit.allow_request():
                raise FreePBXConnectionError(f"FreePBX circuit breaker is open for {self.host}")
            resp = await self._ami.originate(
                channel=channel,
                exten=exten,
                context=context,
                caller_id=caller_id,
                application=application,
            )
            if resp.is_success:
                self._track_success()
                return AdapterResult.ok(
                    data=resp.headers,
                    message=f"Call originated to {exten}",
                )
            self._track_failure()
            return AdapterResult.fail(error=resp.message)
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            self._track_failure()
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            self._track_failure()
            return AdapterResult.fail(error=str(exc))

    async def hangup_call(self, channel: str, *, force: bool = False) -> AdapterResult:
        """Hang up a call via AMI.

        Gated by the read-only contract (hanging up someone else's
        call is a destructive op from the call participant's POV).
        """
        try:
            self._check_write_allowed(force, "AMI Hangup")
            if not self._circuit.allow_request():
                raise FreePBXConnectionError(f"FreePBX circuit breaker is open for {self.host}")
            resp = await self._ami.hangup(channel)
            if resp.is_success:
                self._track_success()
                return AdapterResult.ok(message="Channel hung up")
            self._track_failure()
            return AdapterResult.fail(error=resp.message)
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            self._track_failure()
            return AdapterResult.fail(error=str(exc))

    async def transfer_call(
        self,
        channel: str,
        dest_exten: str,
        context: str = "from-internal",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Transfer a call via AMI redirect.

        Same toll-fraud guard as ``originate_call`` — a transfer can dial
        a premium-rate number just as easily as an origination.
        """
        try:
            self._check_write_allowed(force, "AMI Redirect")
            self._check_destination_safe(dest_exten)
            if not self._circuit.allow_request():
                raise FreePBXConnectionError(f"FreePBX circuit breaker is open for {self.host}")
            resp = await self._ami.redirect(channel, dest_exten, context)
            if resp.is_success:
                self._track_success()
                return AdapterResult.ok(message=f"Call transferred to {dest_exten}")
            self._track_failure()
            return AdapterResult.fail(error=resp.message)
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except AdapterError as exc:
            self._track_failure()
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            self._track_failure()
            return AdapterResult.fail(error=str(exc))

    async def get_active_calls(self) -> AdapterResult:
        """Get all active calls via AMI."""
        try:
            channels = await self._ami.get_active_channels()
            return AdapterResult.ok(
                data=[c.headers for c in channels],
                message=f"{len(channels)} active channels",
            )
        except Exception as exc:
            return AdapterResult.fail(error=str(exc))

    # ── Queue management ───────────────────────────────────────────────

    async def queue_add_member(
        self, queue: str, interface: str, member_name: str = "", *, force: bool = False
    ) -> AdapterResult:
        """Add a member to a queue. Live AMI write — read-only gated."""
        try:
            self._check_write_allowed(force, "queue add member")
            resp = await self._ami.queue_add(queue, interface, member_name=member_name)
            return AdapterResult.ok(data=resp.headers)
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            return AdapterResult.fail(error=str(exc))

    async def queue_remove_member(
        self, queue: str, interface: str, *, force: bool = False
    ) -> AdapterResult:
        """Remove a member from a queue. Live AMI write — read-only gated."""
        try:
            self._check_write_allowed(force, "queue remove member")
            resp = await self._ami.queue_remove(queue, interface)
            return AdapterResult.ok(data=resp.headers)
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            return AdapterResult.fail(error=str(exc))

    async def queue_pause_member(
        self,
        queue: str,
        interface: str,
        paused: bool = True,
        reason: str = "",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Pause/unpause a queue member. Live AMI write — read-only gated."""
        try:
            self._check_write_allowed(force, "queue pause member")
            resp = await self._ami.queue_pause(queue, interface, paused, reason)
            return AdapterResult.ok(data=resp.headers)
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            return AdapterResult.fail(error=str(exc))

    # ── Voicemail ──────────────────────────────────────────────────────

    async def list_voicemail_boxes(self) -> AdapterResult:
        """List voicemail boxes."""
        try:
            if self._rest.api_available:
                data = await self._rest.list_voicemail_boxes()
                return AdapterResult.ok(data=data)
            # Fallback: AMI
            vms = await self._ami.get_voicemail_users()
            return AdapterResult.ok(
                data=[v.headers for v in vms],
                message="Voicemail fetched via AMI",
            )
        except Exception as exc:
            return AdapterResult.fail(error=str(exc))

    # ── System ─────────────────────────────────────────────────────────

    async def reload_pbx_config(self, *, force: bool = False) -> AdapterResult:
        """Apply pending configuration changes.

        Reloading the PBX config potentially activates pending writes
        from elsewhere (the FreePBX web UI also writes to the same
        config files), so it's a write op subject to the read-only
        gate.
        """
        try:
            self._check_write_allowed(force, "PBX reload")
            if self._rest.api_available:
                result = await self._rest.apply_config()
                return AdapterResult.ok(data=result, message="FreePBX config applied")
            # Fallback: AMI reload
            resp = await self._ami.reload_module()
            return AdapterResult.ok(data=resp.headers, message="Asterisk modules reloaded via AMI")
        except FreePBXReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except Exception as exc:
            return AdapterResult.fail(error=str(exc))

    async def get_system_info(self) -> AdapterResult:
        """Get combined PBX system information."""
        info: dict[str, Any] = {
            "host": self.host,
            "asterisk_version": self._asterisk_version,
            "ami_connected": self._ami.connected,
            "ari_connected": self._ari.connected,
            "rest_available": self._rest.api_available,
        }

        # ARI system info
        if self._ari.connected:
            try:
                ari_info = await self._ari.get_asterisk_info()
                info["ari_info"] = ari_info
            except Exception:
                pass

        # REST system status
        if self._rest.api_available:
            try:
                status = await self._rest.get_system_status()
                info["freepbx_status"] = status
            except Exception:
                pass

        return AdapterResult.ok(data=info)
