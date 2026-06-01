# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — TrueNAS WebSocket JSON-RPC client (API 25.04+ / 26.0).

TrueNAS SCALE 25.04 (Fangtooth) deprecated the REST v2.0 API and
later builds (25.10, 26.0) removed it entirely — ``/api/v2.0/*``
returns 404. The supported surface is now a **JSON-RPC 2.0 API over a
WebSocket** at ``/api/current``. This client speaks that protocol for
the read-only calls the adapter needs, mirroring the public method
names of the REST :class:`TrueNASClient` so the adapter + normalized
models work against either transport unchanged.

CRITICAL — TLS is mandatory for API-key auth
---------------------------------------------
TrueNAS 25.x **auto-revokes** an API key the instant it is used over a
plaintext (``ws://``) connection — the revoke reason is literally
"Attempt to use over an insecure transport". So this client connects
over ``wss://`` **only**, and maps the plain-HTTP port 80 to 443 (the
HTTPS listener carries the WS endpoint). Self-signed appliance certs
are the norm, so verification follows the adapter's ``verify_ssl``
flag (default False) rather than the system trust store.

Auth: ``auth.login_ex`` with the ``API_KEY_PLAIN`` mechanism — the
``username`` MUST be the key's owning account, and that account must be
login-enabled. On 25.x the ``root`` account is disabled by default, so
operators use a key owned by ``truenas_admin``.

Writes are NOT implemented (read-only adapter v1) — same scope as the
REST client.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
from typing import Any

import websockets
from websockets.exceptions import WebSocketException

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterTimeoutError,
)
from app.adapters.http_utils import CircuitBreaker
from app.adapters.truenas.client import TrueNASAPIError
from app.adapters.truenas.constants import (
    BREAKER_FAILURE_THRESHOLD,
    BREAKER_RESET_TIMEOUT_SEC,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    JOB_POLL_INTERVAL_SEC,
    JOB_POLL_TIMEOUT_SEC,
    MAX_RESPONSE_BYTES,
    UPLOAD_PATH,
    UPLOAD_POST_TIMEOUT_SEC,
    WS_METHOD_ALERTS,
    WS_METHOD_CLOUDSYNC,
    WS_METHOD_CORE_GET_JOBS,
    WS_METHOD_DATASETS,
    WS_METHOD_DISK_TEMPS,
    WS_METHOD_DISKS,
    WS_METHOD_FILESYSTEM_PUT,
    WS_METHOD_POOLS,
    WS_METHOD_REPLICATION,
    WS_METHOD_SERVICES,
    WS_METHOD_SNAPSHOT_TASKS,
    WS_METHOD_SNAPSHOTS,
    WS_METHOD_SNAPSHOTS_LEGACY,
    WS_METHOD_SYSTEM_INFO,
    WS_PATH,
)

logger = logging.getLogger(__name__)

# JSON-RPC / middleware error sentinels.
_JSONRPC_METHOD_NOT_FOUND = -32601
_ERRNAME_NOT_AUTHENTICATED = "ENOTAUTHENTICATED"


class TrueNASWSClient:
    """Async JSON-RPC-over-WebSocket client for TrueNAS 25.04+ / 26.0.

    Parameters mirror :class:`TrueNASClient` so the adapter can build
    either transport from the same kwargs.

    Notes
    -----
    A single WebSocket carries all calls, so requests are serialized
    behind a lock and matched to responses by JSON-RPC ``id`` (server
    event pushes — which arrive without a matching id — are skipped).
    """

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        *,
        api_key: str | None = None,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: float | None = None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.api_key = api_key
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout or DEFAULT_READ_TIMEOUT

        # API keys MUST ride TLS or TrueNAS auto-revokes them. The WS
        # JSON-RPC endpoint lives on the HTTPS listener; map the plain
        # port 80 to 443 so an operator who copied ":80" from the
        # browser address bar still lands on the TLS port.
        tls_port = 443 if port in (80, 0) else port
        self._uri = f"wss://{host}:{tls_port}{WS_PATH}"

        self._ws: Any = None
        self._id = 0
        self._lock = asyncio.Lock()
        self._breaker = CircuitBreaker(
            failure_threshold=BREAKER_FAILURE_THRESHOLD,
            reset_timeout=BREAKER_RESET_TIMEOUT_SEC,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            # Appliances ship self-signed certs; the MagicDNS / IP host
            # also won't match the cert CN. Match the REST client's
            # verify_ssl=False default for lab + self-host installs.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def connect(self) -> None:
        """Open the WebSocket and authenticate.

        Raises
        ------
        AdapterConnectionError
            The endpoint is unreachable / not the new API (e.g. a
            pre-25.04 box where ``/api/current`` 404s). The adapter
            uses this to fall back to the REST transport.
        AdapterAuthenticationError
            The endpoint IS the new API but the credential was
            rejected — do NOT fall back, surface the auth failure.
        """
        try:
            self._ws = await websockets.connect(
                self._uri,
                ssl=self._ssl_context(),
                max_size=MAX_RESPONSE_BYTES,
                open_timeout=DEFAULT_CONNECT_TIMEOUT,
                ping_interval=None,  # we drive traffic; no idle pings needed
            )
        except TimeoutError as exc:
            # A handshake TIMEOUT means the host is unreachable — surface it as a
            # timeout (504) so the adapter does NOT fall back to a doomed REST
            # connect against the same dead host (its ``except AdapterConnectionError``
            # fallback deliberately does not catch this). A connection-REFUSED
            # (legacy box without the WS endpoint) still raises
            # AdapterConnectionError below and correctly falls back to REST.
            raise AdapterTimeoutError(
                f"TrueNAS WS at {self.host} timed out during handshake",
            ) from exc
        except (WebSocketException, OSError, ssl.SSLError) as exc:
            # Includes InvalidStatus (404 on /api/current for old boxes),
            # refused connections, and TLS errors. Caller may fall back.
            raise AdapterConnectionError(
                f"Cannot open TrueNAS WS at {self.host}: {exc}",
            ) from exc

        try:
            await self._authenticate()
        except Exception:
            await self.disconnect()
            raise

    async def disconnect(self) -> None:
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None

    async def __aenter__(self) -> TrueNASWSClient:
        await self.connect()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _authenticate(self) -> None:
        """Authenticate via ``auth.login_ex``.

        Prefers API-key auth (``API_KEY_PLAIN``); falls back to
        password auth (``PASSWORD_PLAIN``) when no key is configured.
        """
        if self.api_key:
            login = {
                "mechanism": "API_KEY_PLAIN",
                "username": self.username,
                "api_key": self.api_key,
            }
        else:
            login = {
                "mechanism": "PASSWORD_PLAIN",
                "username": self.username,
                "password": self.password,
            }

        result = await self._call("auth.login_ex", [login])
        response_type = (result or {}).get("response_type")
        if response_type == "SUCCESS":
            return

        # Map the documented non-success outcomes to a clear auth error.
        hint = {
            "AUTH_ERR": "credentials rejected (bad key, or the key's owner account is login-disabled — note root is disabled by default on 25.x)",
            "EXPIRED": "the account credential is expired — reset the user's password in the TrueNAS UI",
            "OTP_REQUIRED": "two-factor auth is enabled for this account; API-key auth without OTP is not supported",
            "REDIRECT": "the server requested an auth redirect (unsupported)",
        }.get(str(response_type), f"login_ex returned {response_type!r}")
        raise AdapterAuthenticationError(
            f"TrueNAS rejected credentials at {self.host}: {hint}",
        )

    # ------------------------------------------------------------------
    # Low-level JSON-RPC call
    # ------------------------------------------------------------------

    async def _call(self, method: str, params: list[Any]) -> Any:
        """Issue one JSON-RPC request and return its ``result``.

        Serialized behind a lock (single socket). Reads until the
        response whose ``id`` matches the request — interleaved server
        event notifications (no matching id) are discarded. The circuit
        breaker records transport success/failure.
        """
        if self._ws is None:
            raise AdapterConnectionError("TrueNAS WS client is not connected")
        if not self._breaker.allow_request():
            raise AdapterConnectionError(
                f"TrueNAS WS at {self.host}: circuit breaker open — refusing call",
            )

        async with self._lock:
            self._id += 1
            req_id = self._id
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
            )
            try:
                await self._ws.send(payload)
                # Read until our response arrives (skip event pushes).
                while True:
                    raw = await asyncio.wait_for(self._ws.recv(), self.timeout)
                    msg = json.loads(raw)
                    if msg.get("id") != req_id:
                        continue  # unsolicited notification / other id
                    break
            except TimeoutError as exc:
                self._breaker.record_failure()
                raise AdapterTimeoutError(
                    f"TrueNAS WS {method} timed out",
                ) from exc
            except (WebSocketException, OSError) as exc:
                self._breaker.record_failure()
                raise AdapterConnectionError(
                    f"TrueNAS WS {method} failed: {exc}",
                ) from exc
            except (json.JSONDecodeError, ValueError) as exc:
                self._breaker.record_failure()
                raise TrueNASAPIError(
                    f"TrueNAS WS {method} returned non-JSON: {exc}",
                ) from exc

        self._breaker.record_success()

        if "error" in msg and msg["error"]:
            err = msg["error"] or {}
            data = err.get("data") or {}
            errname = data.get("errname")
            if errname == _ERRNAME_NOT_AUTHENTICATED:
                raise AdapterAuthenticationError(
                    f"TrueNAS WS {method}: not authenticated",
                )
            raise TrueNASAPIError(
                f"TrueNAS WS {method} error: {err.get('message') or errname or err}",
                status_code=int(err.get("code") or 0),
                body=str(data)[:512],
            )
        return msg.get("result")

    # ------------------------------------------------------------------
    # Public read API — mirrors TrueNASClient
    # ------------------------------------------------------------------

    async def get_system_info(self) -> dict[str, Any]:
        data = await self._call(WS_METHOD_SYSTEM_INFO, [])
        if not isinstance(data, dict):
            raise TrueNASAPIError("TrueNAS system.info returned non-object")
        return data

    async def list_pools(self) -> list[dict[str, Any]]:
        data = await self._call(WS_METHOD_POOLS, [])
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS pool.query returned non-list")
        return data

    async def list_datasets(self) -> list[dict[str, Any]]:
        """List datasets, flattened.

        ``pool.dataset.query`` returns a nested tree (each dataset
        carries a ``children`` list). The REST surface was top-level
        only; flattening here surfaces child datasets too, which the
        normalized :class:`Dataset` parser handles one node at a time.
        """
        data = await self._call(WS_METHOD_DATASETS, [])
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS pool.dataset.query returned non-list")
        return _flatten_datasets(data)

    async def list_snapshots(self) -> list[dict[str, Any]]:
        """List snapshots via ``pool.snapshot.query``.

        Falls back to the older ``zfs.snapshot.query`` method name if a
        given build doesn't expose the newer one.
        """
        try:
            data = await self._call(WS_METHOD_SNAPSHOTS, [])
        except TrueNASAPIError as exc:
            if getattr(exc, "status_code", 0) == _JSONRPC_METHOD_NOT_FOUND:
                data = await self._call(WS_METHOD_SNAPSHOTS_LEGACY, [])
            else:
                raise
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS snapshot query returned non-list")
        return data

    async def list_disks(self) -> list[dict[str, Any]]:
        data = await self._call(WS_METHOD_DISKS, [])
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS disk.query returned non-list")
        return data

    async def list_alerts(self) -> list[dict[str, Any]]:
        """Active middleware alerts (``alert.list``) — disk faults, pool
        degradation, temperature thresholds, etc."""
        data = await self._call(WS_METHOD_ALERTS, [])
        return data if isinstance(data, list) else []

    async def disk_temperatures(self) -> dict[str, float]:
        """Per-disk temperatures in °C (``disk.temperatures`` with an empty
        name list = all disks). Returns ``{devname: tempC}``."""
        data = await self._call(WS_METHOD_DISK_TEMPS, [[]])
        return data if isinstance(data, dict) else {}

    async def list_services(self) -> list[dict[str, Any]]:
        """System services (``service.query``) — SMB/NFS/iSCSI/SSH state."""
        data = await self._call(WS_METHOD_SERVICES, [])
        return data if isinstance(data, list) else []

    async def data_protection_counts(self) -> dict[str, int]:
        """Configured data-protection task counts (snapshot / replication /
        cloud-sync). A zero count is a real coverage gap worth surfacing."""
        out: dict[str, int] = {}
        for key, method in (
            ("snapshot_tasks", WS_METHOD_SNAPSHOT_TASKS),
            ("replication", WS_METHOD_REPLICATION),
            ("cloudsync", WS_METHOD_CLOUDSYNC),
        ):
            try:
                r = await self._call(method, [])
                out[key] = len(r) if isinstance(r, list) else 0
            except (TrueNASAPIError, AdapterConnectionError, AdapterTimeoutError):
                out[key] = 0
        return out

    # ------------------------------------------------------------------
    # Write surface (jobs) — used only by the staged-apply path
    # ------------------------------------------------------------------

    async def get_job_status(self, job_id: int) -> dict[str, Any]:
        """Return one middleware job row (``core.get_jobs`` filtered by id)."""
        rows = await self._call(WS_METHOD_CORE_GET_JOBS, [[["id", "=", job_id]]])
        if not isinstance(rows, list) or not rows:
            raise TrueNASAPIError(f"TrueNAS job {job_id} not found")
        first = rows[0]
        if not isinstance(first, dict):
            raise TrueNASAPIError(f"TrueNAS job {job_id} returned non-object")
        return first

    async def job_wait(
        self, job_id: int, *, timeout: float = JOB_POLL_TIMEOUT_SEC
    ) -> dict[str, Any]:
        """Poll ``core.get_jobs`` until the job leaves RUNNING/WAITING.

        Returns the final job row. Raises :class:`AdapterTimeoutError` if it
        does not settle within ``timeout`` (a stuck upload surfaces as a clear
        timeout rather than a hang).
        """
        deadline = time.monotonic() + timeout
        while True:
            st = await self.get_job_status(job_id)
            state = str(st.get("state") or "").upper()
            if state in ("SUCCESS", "FAILED", "ABORTED"):
                return st
            if time.monotonic() > deadline:
                raise AdapterTimeoutError(
                    f"TrueNAS job {job_id} did not finish within {timeout}s (state={state})"
                )
            await asyncio.sleep(JOB_POLL_INTERVAL_SEC)

    async def upload_blob(self, *, dest_path: str, blob: bytes, mode: int | None = None) -> int:
        """Upload ``blob`` to ``dest_path`` via the ``/_upload`` job channel.

        SCALE 25.04+/26.0 file upload is two-channel: the WS JSON-RPC socket
        cannot stream binary, so the bytes ride a multipart HTTPS POST to
        ``/_upload`` (on the same TLS listener as the WS endpoint). The ``data``
        part carries the ``filesystem.put`` job spec; the POST creates+runs the
        job and returns its id, which the caller then waits on via
        :meth:`job_wait`. Returns the integer job id.
        """
        import httpx

        # Defense-in-depth: a credential carrying CR/LF/NUL would inject a
        # second header line into the Authorization value. The key is
        # operator-supplied, not from an event payload, but we refuse it at the
        # sink rather than rely on the HTTP client to reject it.
        if self.api_key and any(c in self.api_key for c in ("\r", "\n", "\x00")):
            raise AdapterAuthenticationError("TrueNAS API key contains illegal control characters")

        tls_port = 443 if self.port in (80, 0) else self.port
        base = f"https://{self.host}:{tls_port}"
        # Omit ``mode`` entirely when unset (idiomatic JSON-RPC: absent, not
        # ``null``) so filesystem.put applies the default permissions.
        opts: dict[str, Any] = {"append": False}
        if mode is not None:
            opts["mode"] = mode
        data = {
            "data": json.dumps({"method": WS_METHOD_FILESYSTEM_PUT, "params": [dest_path, opts]})
        }
        files = {"file": ("blob", blob, "application/octet-stream")}
        # API keys ride TLS only (same revoke rule as the WS channel); auth the
        # upload with the key as a Bearer token. verify follows verify_ssl.
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            # The POST streams the whole blob — use the dedicated upload timeout,
            # NOT the (short) WS read timeout, so a slow multi-MB upload isn't
            # cut off mid-stream (which would orphan a half-created job).
            async with httpx.AsyncClient(
                base_url=base, verify=self.verify_ssl, timeout=UPLOAD_POST_TIMEOUT_SEC
            ) as client:
                resp = await client.post(UPLOAD_PATH, data=data, files=files, headers=headers)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise TrueNASAPIError(
                f"TrueNAS /_upload rejected the request: {exc.response.status_code} "
                f"{exc.response.text[:256]}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.HTTPError as exc:
            raise AdapterConnectionError(f"TrueNAS /_upload failed: {exc}") from exc

        # The endpoint returns the job id — tolerate {"job_id": N} or a bare int.
        try:
            body = resp.json()
        except ValueError:
            body = resp.text.strip()
        job_id = body.get("job_id") if isinstance(body, dict) else body
        try:
            return int(job_id)
        except (TypeError, ValueError) as exc:
            raise TrueNASAPIError(f"TrueNAS /_upload did not return a job id: {body!r}") from exc


def _flatten_datasets(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Depth-first flatten of the dataset tree, deduped by ``id``.

    ``pool.dataset.query`` is inconsistent across builds: some return a
    pure tree (roots only, children nested), while 26.0 returns every
    dataset at top-level *and also* nests it under its parent's
    ``children`` — so a naive recursive flatten double-counts. We
    recurse to cover the tree shape, then dedupe by the unique dataset
    ``id`` (the full ZFS path) to cover the flat-with-redundant-children
    shape. ``children`` is stripped from each row (the parser ignores
    unknown keys, but carrying nested trees per row is wasteful).
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _walk(items: list[dict[str, Any]]) -> None:
        for node in items:
            if not isinstance(node, dict):
                continue
            children = node.get("children") or []
            key = str(node.get("id") or node.get("name") or "")
            if key and key not in seen:
                seen.add(key)
                out.append({k: v for k, v in node.items() if k != "children"})
            if isinstance(children, list) and children:
                _walk(children)

    _walk(nodes)
    return out
