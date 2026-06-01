# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - device reach (transport selection)
============================================

A single place that answers "make this HTTP request to a device" and chooses the
transport by site connectivity:

- **direct** (the default): the controller can route to the device — call it via
  the overlay-aware client (:func:`app.core.http_client.build_async_client`), which
  already handles the userspace SOCKS5 overlay.
- **agent-proxy**: appliance / agent-only sites where the controller has *no* route
  to the device (a camera/PBX that can't join the overlay), but an agent on that
  LAN can — proxy the request through it via
  :meth:`AgentRegistryService.proxy_http_via_site`.

Both transports return the same normalized ``{status_code, headers, body, via}``.
This is the P4 integration seam: adapters call this instead of building their own
client when a site may be agent-only. See docs.freesdn.org.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import httpx

from app.core.http_client import build_async_client


class DeviceUnreachableError(Exception):
    """The device could not be reached over the selected transport."""


# Response headers that describe the original wire encoding/framing and would
# conflict with the re-encoded body we hand back to httpx.
_STRIP_RESPONSE_HEADERS = {
    "content-length",
    "transfer-encoding",
    "content-encoding",
    "connection",
}


class AgentHTTPTransport(httpx.AsyncBaseTransport):
    """An httpx transport that routes EVERY request through a site's agent.

    Instead of connecting to the device directly, each request is sent to the
    agent on the device's LAN (``AgentRegistryService.proxy_http_via_site``) and
    the agent's response is rebuilt into an ``httpx.Response``. Construct an
    adapter's client with this transport and all of its calls reach the device via
    the agent — no per-call rewriting. Used for appliance/agent-only sites the
    controller can't route to (docs.freesdn.org).

        client = build_async_client(transport=AgentHTTPTransport(registry, site_id))
    """

    def __init__(
        self,
        registry: Any,
        site_id: UUID,
        *,
        verify_ssl: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self._registry = registry
        self._site_id = site_id
        self._verify_ssl = verify_ssl
        self._timeout = timeout

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raw = bytes(request.content) if request.content else b""
        body = raw.decode("utf-8", errors="replace") if raw else None
        result = await self._registry.proxy_http_via_site(
            self._site_id,
            url=str(request.url),
            method=request.method,
            headers=dict(request.headers),
            body=body,
            verify_ssl=self._verify_ssl,
            timeout=self._timeout,
        )
        if not (
            result
            and getattr(result, "success", False)
            and isinstance(getattr(result, "result", None), dict)
        ):
            detail = getattr(result, "error", None) or "agent unreachable"
            raise httpx.ConnectError(f"agent proxy failed for {request.url}: {detail}")
        payload = result.result
        headers = [
            (k, v)
            for k, v in (payload.get("headers") or {}).items()
            if k.lower() not in _STRIP_RESPONSE_HEADERS
        ]
        return httpx.Response(
            status_code=int(payload.get("status_code") or 502),
            headers=headers,
            content=(payload.get("body") or "").encode("utf-8"),
            request=request,
        )


async def reach_device_http(
    site_id: UUID,
    url: str,
    *,
    registry: Any = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_ssl: bool = False,
    timeout: float = 15.0,
    prefer_agent: bool = False,
) -> dict[str, Any]:
    """Reach a device's HTTP endpoint, choosing transport by site connectivity.

    When ``prefer_agent`` is set AND ``registry`` reports an agent connected for
    ``site_id``, the request is proxied through that agent (appliance / agent-only
    sites). Otherwise it is sent directly via the overlay-aware client. Returns a
    normalized ``{status_code, headers, body, via}`` for both transports. Raises
    :class:`DeviceUnreachableError` if the chosen transport fails.

    The agent ``registry`` (an ``AgentRegistryService``) is INJECTED by the caller
    — kept out of this service to avoid a service→endpoint import and to keep this
    helper pure/testable.
    """
    if prefer_agent and registry is not None:
        if registry.get_connection_for_site(site_id) is not None:
            result = await registry.proxy_http_via_site(
                site_id,
                url=url,
                method=method,
                headers=headers,
                body=body,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )
            if result and result.success and isinstance(result.result, dict):
                r = result.result
                return {
                    "status_code": r.get("status_code"),
                    "headers": r.get("headers", {}),
                    "body": r.get("body", ""),
                    "via": "agent",
                }
            detail = (
                getattr(result, "error", None) or (result.result if result else None) or "no result"
            )
            raise DeviceUnreachableError(f"agent proxy failed for {url}: {detail}")

    # Direct transport (overlay-aware).
    auth = (username, password or "") if username is not None else None
    async with build_async_client(verify=verify_ssl, timeout=timeout) as client:
        resp = await client.request(
            method,
            url,
            headers=headers or {},
            content=body,
            auth=auth,
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
            "via": "direct",
        }


# ── Construction-layer policy ────────────────────────────────────────────────
# Where adapter clients are built per site, this decides whether to route through
# the agent. The policy is explicit + per-site (no auto-fallback latency): a site
# opts in via `settings.reach_mode == "agent"` (a JSONB flag — no migration).


def site_prefers_agent(site: Any) -> bool:
    """True when a site is configured for agent-only reach (appliance/NAT'd LAN
    the controller can't route to). Read from ``Site.settings['reach_mode']``."""
    site_settings = getattr(site, "settings", None) or {}
    return str(site_settings.get("reach_mode", "")).strip().lower() == "agent"


def agent_transport_for_site(
    registry: Any,
    site: Any,
    *,
    verify_ssl: bool = False,
    timeout: float = 15.0,
) -> AgentHTTPTransport | None:
    """Return an :class:`AgentHTTPTransport` for ``site`` IFF it prefers agent reach
    AND an agent is currently connected for it; otherwise ``None`` (direct reach).

    This is the construction-layer hook: where an adapter client is built, call
    this and pass the result as the client's ``transport``. ``None`` means "build
    a normal (overlay-aware) client". Falls back to direct (returns ``None``) if
    the site wants the agent but none is connected — surfaced as a normal direct
    attempt rather than a hard failure.
    """
    if registry is None or not site_prefers_agent(site):
        return None
    site_id = getattr(site, "id", None)
    if site_id is None or registry.get_connection_for_site(site_id) is None:
        return None
    return AgentHTTPTransport(registry, site_id, verify_ssl=verify_ssl, timeout=timeout)
