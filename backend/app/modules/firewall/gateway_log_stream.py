# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reauthorize a gateway log stream before polling and before releasing data."""

import asyncio
import copy
import hashlib
import json
from collections import OrderedDict
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import dependencies
from app.core.dependencies import CurrentUser
from app.db import session as sessions
from app.modules.firewall.gateway_service import GatewayNotFoundError, GatewayService
from app.modules.firewall.models import GatewayConnection


class GatewayLogStream:
    """The original credential and resource are a ceiling, never a lasting grant.

    Separate, bounded database sessions reload current credentials, roles, grants
    and resource parents. No database transaction remains open between polls.
    A revoked credential, changed target or unavailable authority store ends the
    stream. Data already delivered cannot be withdrawn; this is not a durable log
    cursor or an exactly-once subscription.
    """

    def __init__(self, request: Request, user: CurrentUser, gateway_id: UUID) -> None:
        self.request = request
        self.gateway_id = gateway_id
        self.actor_id = user.id
        org_id = user.organization_id
        if org_id is None:
            raise HTTPException(404, "Gateway not found")
        self.org_id = org_id
        self.credential = self._credential(user)
        self.initial_sites = frozenset(user.accessible_site_ids) if user.is_site_limited else None
        self.binding: tuple[Any, ...] | None = None

    @staticmethod
    def _credential(user: CurrentUser) -> tuple[Any, ...]:
        claims = user.token_claims
        if claims.get("auth_method") == "api_key":
            return ("api_key", claims.get("key_id"))
        return ("jwt", claims.get("jti"), claims.get("tv", 0))

    @staticmethod
    def _binding(gateway: GatewayConnection) -> tuple[Any, ...]:
        # Observation timestamps and sync health can change during a normal poll.
        # A target/credential/site change requires reconnecting the subscription.
        return (
            gateway.org_id,
            gateway.site_id,
            gateway.vendor,
            gateway.host,
            gateway.port,
            gateway.verify_ssl,
            copy.deepcopy(gateway.credentials),
            copy.deepcopy(gateway.settings),
        )

    async def _authorize(self, db: AsyncSession) -> GatewayService:
        user = await dependencies.get_current_user_optional(
            self.request,
            token=await dependencies.oauth2_scheme(self.request),
            api_key=await dependencies.api_key_header(self.request),
            session=db,
        )
        if (
            user is None
            or user.id != self.actor_id
            or user.organization_id != self.org_id
            or self._credential(user) != self.credential
        ):
            raise dependencies.AuthenticationError()
        await dependencies.require_permissions("firewall.view")(user)
        sites = user.accessible_site_ids if user.is_site_limited else None
        if self.initial_sites is not None:
            # Removing the final grant must not widen an existing subscription
            # through the legacy zero-grant/unrestricted account policy.
            sites = set(self.initial_sites.intersection(user.accessible_site_ids))
        service = GatewayService(db=db, accessible_site_ids=sites)
        gateway = await service.get_gateway(self.gateway_id, self.org_id)
        if not user.has_site_permission("firewall.view", gateway.site_id):
            raise GatewayNotFoundError(self.gateway_id)
        binding = self._binding(gateway)
        if self.binding is None:
            self.binding = binding
        elif binding != self.binding:
            raise GatewayNotFoundError(self.gateway_id)
        return service

    async def start(self) -> None:
        # Check before sending the HTTP 200/SSE headers; inaccessible resources
        # get the same opaque response as the non-streaming gateway endpoint.
        async with sessions.security_session_factory() as db:
            await self._authorize(db)

    async def poll(self, limit: int) -> list[dict[str, Any] | str]:
        async with sessions.security_session_factory() as db:
            service = await self._authorize(db)
            result = await service.get_live_firewall_log(self.gateway_id, self.org_id, limit=limit)
        # A revocation or reassignment committed during the device round-trip
        # must suppress that response, including an empty/keepalive response.
        async with sessions.security_session_factory() as db:
            await self._authorize(db)
        logs = result.get("logs") if isinstance(result, dict) else None
        if isinstance(logs, dict):
            logs = logs.get("logs", logs.get("rows"))
        if not isinstance(logs, list) or any(not isinstance(row, (dict, str)) for row in logs):
            raise ValueError("Invalid gateway log response")
        return logs[:limit]

    async def events(self, limit: int, interval: float) -> AsyncIterator[str]:
        seen: OrderedDict[str, None] = OrderedDict()
        try:
            while not await self.request.is_disconnected():
                try:
                    logs = await self.poll(limit)
                except (HTTPException, GatewayNotFoundError):
                    yield 'event: close\ndata: {"error":"Stream authorization ended"}\n\n'
                    return
                except Exception:
                    # Do not leak vendor/auth/storage exception text or keep
                    # polling with stale authority after an unavailable check.
                    yield 'event: close\ndata: {"error":"Log stream unavailable"}\n\n'
                    return
                if await self.request.is_disconnected():
                    return
                fresh = []
                for entry in logs:
                    digest = hashlib.sha256(
                        json.dumps(entry, sort_keys=True, default=str).encode()
                    ).hexdigest()
                    if digest not in seen:
                        seen[digest] = None
                        fresh.append(entry)
                        if len(seen) > 1000:
                            seen.popitem(last=False)
                if fresh:
                    yield f"data: {json.dumps(fresh, default=str)}\n\n"
                else:
                    yield ": keepalive\n\n"
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            return
