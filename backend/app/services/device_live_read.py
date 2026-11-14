# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - interactive reads of a device wait their turn, then serve "as of"
==========================================================================

A page that reads a device live (the gateway detail page opens about twenty
panels, each its own adapter session) used to send every request at once,
whatever a scheduled sync or another user was doing to the box. Now each read:

1. takes the device's slot in SHARED mode (``app/core/device_slot.py``): up to
   ``DEVICE_UI_READ_CONCURRENCY`` UI reads at once, never alongside a
   background poller, waiting up to ``DEVICE_UI_READ_WAIT_SECONDS`` (2 s);
2. if it got the slot: reads live, remembers the answer, and returns it with
   ``as_of`` = now and ``cached: false``;
3. if not: returns the last answer read from the device with its ``as_of``,
   ``cached: true`` and ``cache_reason: "device_busy"``;
4. with nothing remembered yet: keeps waiting, up to
   ``DEVICE_UI_READ_MAX_WAIT_SECONDS`` in all, then answers 503 with
   ``Retry-After`` instead of piling a request onto the busy device.

Responses only GAIN fields (``as_of``, ``cached``, ``cache_reason``); nothing
is renamed or removed. A non-dict answer is passed through unchanged.

The remembered copy is the answer after ``redact_secrets`` (pre-shared keys,
private keys and passwords never land in Valkey), kept for
``DEVICE_UI_READ_CACHE_SECONDS``, under a key that names the device row and the
read. Callers authorize the device BEFORE calling ``live_or_cached``; the cache
is only ever served to a caller who may read that device live.

Every other page (controllers, switches, access points, Omada, UniFi, MikroTik,
Proxmox, TrueNAS, cameras and NVRs, phones and PBXs) reads devices through a
handful of shared helpers that build the device's client. Those helpers call
``take_device_turn(slot_key)`` just before they contact the device, and
``DeviceReadTurnMiddleware`` turns that into the same rules for the whole GET
request: the turn is held until the endpoint has produced its response, the
response is remembered (redacted, at most 1 MB, 200 JSON only), and a busy
device is answered with the last response for that same URL and caller scope.
Besides the three body fields (added to a JSON object response that does not
already use those names), every such response carries ``X-FreeSDN-As-Of``,
``X-FreeSDN-Cached`` and, when cached, ``X-FreeSDN-Cache-Reason``, so list
and typed responses state their age too.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from fastapi import HTTPException

from app.core.device_slot import API_TTL_SECONDS, SHARED, SlotLease, device_slots

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

_CACHE_PREFIX = "freesdn:liveread:"
#: Answers larger than this are not remembered (a firewall log, a huge rule set).
_MAX_CACHED_BYTES = 1_000_000

#: Response headers stating when the answer was read from the device.
AS_OF_HEADER = "X-FreeSDN-As-Of"
CACHED_HEADER = "X-FreeSDN-Cached"
CACHE_REASON_HEADER = "X-FreeSDN-Cache-Reason"
FRESHNESS_HEADERS = (AS_OF_HEADER, CACHED_HEADER, CACHE_REASON_HEADER)
_STAMP_FIELDS = ("as_of", "cached", "cache_reason")


#: ``error.type`` of the 503 a busy device with nothing remembered answers, so
#: the UI recognises it without matching the sentence.
DEVICE_BUSY_ERROR_TYPE = "device_busy"
RETRY_AFTER_SECONDS = 5


def busy_message(reason: str) -> str:
    return f"{reason}. Nothing was sent to it; try again in a few seconds."


def busy_envelope(message: str, request_id: str | None) -> dict[str, Any]:
    """The standard error envelope (app/core/middleware.py) for a busy device."""
    return {
        "error": {
            "code": 503,
            "type": DEVICE_BUSY_ERROR_TYPE,
            "message": message,
            "request_id": request_id,
        }
    }


class DeviceBusyError(HTTPException):
    """503: the device stayed busy and there is no earlier answer to show.

    Rendered by the app's exception handler as the standard error envelope
    with ``type: "device_busy"`` and ``Retry-After``.
    """

    error_type = DEVICE_BUSY_ERROR_TYPE

    def __init__(self, reason: str) -> None:
        super().__init__(
            status_code=503,
            detail=busy_message(reason),
            headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
        )


def cache_key(scope: str, ident: Any, read: str, *params: Any) -> str:
    """``freesdn:liveread:<scope>:<id>:<read>[:<hash of the parameters>]``."""
    key = f"{_CACHE_PREFIX}{scope}:{ident}:{read}"
    if params:
        digest = hashlib.sha256(repr(params).encode()).hexdigest()[:16]
        key += f":{digest}"
    return key


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def stamp(data: Any, as_of: str, *, cached: bool, reason: str | None = None) -> Any:
    """Add the "as of" fields to a dict answer; anything else passes through."""
    if not isinstance(data, dict):
        return data
    out = dict(data)
    out["as_of"] = as_of
    out["cached"] = cached
    out["cache_reason"] = reason
    return out


def _settings() -> Any:
    from app.core.config import settings

    return settings


def _redis() -> Any:
    from app.core.celery_app import _get_solo_redis

    return _get_solo_redis()


def _store_sync(key: str, data: dict[str, Any], as_of: str) -> None:
    from fastapi.encoders import jsonable_encoder

    from app.core.redaction import redact_secrets

    body = json.dumps({"as_of": as_of, "data": redact_secrets(jsonable_encoder(data))}, default=str)
    if len(body) > _MAX_CACHED_BYTES:
        return
    _redis().set(key, body, ex=int(_settings().DEVICE_UI_READ_CACHE_SECONDS))


def _load_sync(key: str) -> dict[str, Any] | None:
    raw = _redis().get(key)
    if not raw:
        return None
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("data"), dict):
        return None
    return data


async def _store(key: str, data: Any, as_of: str) -> None:
    if not isinstance(data, dict):
        return
    try:
        await asyncio.to_thread(_store_sync, key, data, as_of)
    except Exception:  # noqa: BLE001 - a lost cache entry only costs a later live read
        logger.debug("live-read cache store failed for %s", key, exc_info=True)


async def _load(key: str) -> dict[str, Any] | None:
    try:
        return await asyncio.to_thread(_load_sync, key)
    except Exception:  # noqa: BLE001
        logger.debug("live-read cache load failed for %s", key, exc_info=True)
        return None


class _ServeRemembered(BaseException):
    """Raised inside a read that found its device busy, caught by its wrapper.

    A BaseException on purpose: the reads catch ``Exception`` to turn device
    failures into 502s, and a busy device is not a failure.
    """

    def __init__(self, data: dict[str, Any], as_of: str) -> None:
        super().__init__("device busy; serving the last answer")
        self.data, self.as_of = data, as_of


class _StillBusy(BaseException):
    """The device stayed busy for the whole wait and nothing is remembered."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Turn:
    """One interactive read's turn at its device."""

    holder: str
    slot_key: str | None = None
    cache_key: str | None = None
    lease: SlotLease | None = None
    #: ``take_turn`` ran for this read (a read opening two sessions takes one turn).
    taken: bool = False


#: The interactive reads in progress in this request (asyncio task), outermost
#: first, so a read inside a read of the same device does not wait for itself.
_active: contextvars.ContextVar[tuple[_Turn, ...]] = contextvars.ContextVar(
    "freesdn_ui_device_turns", default=()
)


async def take_turn(slot_key: str, cache_key: str) -> None:
    """Called where the read is about to contact the device (before connect).

    Outside an interactive read (a background task running the same service
    code) this does nothing. Otherwise it waits for the device's shared slot,
    and when the device stays busy either hands the remembered answer back to
    the read's wrapper or, with nothing remembered, waits on and finally
    reports the device busy (see the module docstring).
    """
    turns = _active.get()
    if not turns or turns[-1].taken:
        return
    turn = turns[-1]
    turn.taken, turn.slot_key, turn.cache_key = True, slot_key, cache_key
    if any(t.slot_key == slot_key and t.lease is not None for t in turns[:-1]):
        return  # an outer read of this device already holds the turn
    request = _request_read.get()
    if request is not None and slot_key in request.leases:
        return  # this request already holds the device's turn
    conf = _settings()
    wait = float(conf.DEVICE_UI_READ_WAIT_SECONDS)
    lease = await device_slots.acquire(
        slot_key, turn.holder, mode=SHARED, wait=wait, ttl=API_TTL_SECONDS
    )
    if lease is None:
        remembered = await _load(cache_key)
        if remembered is not None:
            raise _ServeRemembered(remembered["data"], str(remembered.get("as_of")))
        rest = max(0.0, float(conf.DEVICE_UI_READ_MAX_WAIT_SECONDS) - wait)
        lease = await device_slots.acquire(
            slot_key, turn.holder, mode=SHARED, wait=rest, ttl=API_TTL_SECONDS
        )
        if lease is None:
            raise _StillBusy(await device_slots.abusy_reason(slot_key))
    turn.lease = lease


async def run_read(holder: str, read: Callable[[], Awaitable[Any]]) -> Any:
    """Run one interactive read; the read calls ``take_turn`` before its I/O."""
    turn = _Turn(holder)
    token = _active.set((*_active.get(), turn))
    try:
        try:
            data = await read()
        except _ServeRemembered as hit:
            _observe(hit.as_of, cached=True, reason="device_busy")
            return stamp(hit.data, hit.as_of, cached=True, reason="device_busy")
        except _StillBusy as busy:
            raise DeviceBusyError(busy.reason) from None
    finally:
        _active.reset(token)
        if turn.lease is not None:
            await device_slots.arelease(turn.lease)
    if not turn.taken:
        # The read never reached the device (it answered from its own short
        # cache, or failed before connecting): there is no read time to state.
        return data
    as_of = _now_iso()
    if turn.cache_key is not None:
        await _store(turn.cache_key, data, as_of)
    _observe(as_of, cached=False)
    return stamp(data, as_of, cached=False)


async def live_or_cached(
    *,
    slot_key: str,
    cache_key: str,
    fetch: Callable[[], Awaitable[Any]],
    holder: str,
) -> Any:
    """``run_read`` for a fetch that does not call ``take_turn`` itself."""

    async def _read() -> Any:
        await take_turn(slot_key, cache_key)
        return await fetch()

    return await run_read(holder, _read)


# ═══════════════════════════════════════════════════════════════════════════
# Request-level turns: every other live read of a device
# ═══════════════════════════════════════════════════════════════════════════


class _ServeRememberedResponse(BaseException):
    """A device stayed busy; the middleware answers with the last response.

    A BaseException for the same reason as ``_ServeRemembered``: endpoint and
    service code turns ``Exception`` into 502s or "offline" bodies, and a busy
    device is neither.
    """

    def __init__(self, body: Any, as_of: str) -> None:
        super().__init__("device busy; serving the last response")
        self.body, self.as_of = body, as_of


@dataclass
class _RequestRead:
    """One GET request's turns at the devices it reads."""

    path: str
    query: str
    #: Device slots this request holds, by slot key.
    leases: dict[str, SlotLease] = field(default_factory=dict)
    #: ``take_device_turn`` ran (the response is a live read of a device).
    taken: bool = False
    #: A helper asked for this request's answer never to be served later.
    cacheable: bool = True
    #: The endpoint has produced its response; nothing waits any more.
    finished: bool = False
    #: (as_of, cached, reason) of every read answered in this request.
    observations: list[tuple[str, bool, str | None]] = field(default_factory=list)
    _cache_key: str | None = None

    def holder(self) -> str:
        return f"UI read ({self.path[:120]})"

    def cache_key(self) -> str:
        """The URL plus the caller's scope: a remembered answer is only served
        to a caller with the same organization, role and site grants."""
        if self._cache_key is None:
            from app.core.site_access import current_user_var

            user = current_user_var.get()
            principal: tuple[Any, ...] = ()
            if user is not None:
                grants = None
                if getattr(user, "is_site_limited", False):
                    grants = sorted(str(s) for s in (user.accessible_site_ids or ()))
                principal = (
                    str(getattr(user, "organization_id", None)),
                    str(getattr(user, "role", None)),
                    bool(getattr(user, "_scoped", False)),
                    grants,
                )
            query = sorted(parse_qsl(self.query, keep_blank_values=True))
            raw = json.dumps([self.path, query, principal], default=str)
            digest = hashlib.sha256(raw.encode()).hexdigest()[:32]
            self._cache_key = f"{_CACHE_PREFIX}http:{digest}"
        return self._cache_key


_request_read: contextvars.ContextVar[_RequestRead | None] = contextvars.ContextVar(
    "freesdn_ui_request_read", default=None
)


def _observe(as_of: str, *, cached: bool, reason: str | None = None) -> None:
    request = _request_read.get()
    if request is not None:
        request.observations.append((as_of, cached, reason))


def uncacheable_read() -> None:
    """The current request's answer must never be served again later (a
    one-time ticket, a token). It still takes its turn at the device."""
    request = _request_read.get()
    if request is not None:
        request.cacheable = False


async def take_device_turn(slot_key: str) -> None:
    """Called by a shared helper just before it contacts a device.

    Outside a GET request handled by ``DeviceReadTurnMiddleware`` (a Celery
    task, a write, a test calling the service directly) this does nothing.
    Inside one it waits up to ``DEVICE_UI_READ_WAIT_SECONDS`` for the device's
    shared slot; if the device stays busy the request is answered with the last
    response remembered for it, or, with none, after up to
    ``DEVICE_UI_READ_MAX_WAIT_SECONDS`` in all, with 503 and ``Retry-After``.
    A request reading several devices takes a turn at each.
    """
    request = _request_read.get()
    if request is None or request.finished or slot_key in request.leases:
        return
    if any(t.slot_key == slot_key and t.lease is not None for t in _active.get()):
        return  # a gateway live read in this request already holds it
    # The key names the caller's scope, read here where the request's user is set.
    key = request.cache_key()
    conf = _settings()
    wait = float(conf.DEVICE_UI_READ_WAIT_SECONDS)
    holder = request.holder()
    lease = await device_slots.acquire(
        slot_key, holder, mode=SHARED, wait=wait, ttl=API_TTL_SECONDS
    )
    if lease is None:
        if request.cacheable:
            remembered = await _load_response(key)
            if remembered is not None:
                raise _ServeRememberedResponse(remembered["body"], str(remembered["as_of"]))
        rest = max(0.0, float(conf.DEVICE_UI_READ_MAX_WAIT_SECONDS) - wait)
        lease = await device_slots.acquire(
            slot_key, holder, mode=SHARED, wait=rest, ttl=API_TTL_SECONDS
        )
        if lease is None:
            raise _StillBusy(await device_slots.abusy_reason(slot_key))
    if request.finished or slot_key in request.leases:
        # The response went out while this turn was being waited for (a
        # background step of the request), or a concurrent read in this request
        # took the device meanwhile: one lease per device, none past the response.
        await device_slots.arelease(lease)
        return
    request.leases[slot_key] = lease
    request.taken = True


def _store_response_sync(key: str, body: Any, as_of: str) -> None:
    from app.core.redaction import redact_secrets

    raw = json.dumps({"as_of": as_of, "body": redact_secrets(body)}, default=str)
    if len(raw) > _MAX_CACHED_BYTES:
        return
    _redis().set(key, raw, ex=int(_settings().DEVICE_UI_READ_CACHE_SECONDS))


def _load_response_sync(key: str) -> dict[str, Any] | None:
    raw = _redis().get(key)
    if not raw:
        return None
    data = json.loads(raw)
    if not isinstance(data, dict) or "body" not in data or not data.get("as_of"):
        return None
    return data


async def _store_response(key: str, body: Any, as_of: str) -> None:
    try:
        await asyncio.to_thread(_store_response_sync, key, body, as_of)
    except Exception:  # noqa: BLE001 - a lost entry only costs a later live read
        logger.debug("live-read response store failed for %s", key, exc_info=True)


async def _load_response(key: str) -> dict[str, Any] | None:
    try:
        return await asyncio.to_thread(_load_response_sync, key)
    except Exception:  # noqa: BLE001
        logger.debug("live-read response load failed for %s", key, exc_info=True)
        return None


async def _release_all(request: _RequestRead) -> None:
    leases, request.leases = list(request.leases.values()), {}
    for lease in leases:
        await device_slots.arelease(lease)


def _stamp_body(body: Any, as_of: str, *, cached: bool, reason: str | None) -> Any:
    """Add the three fields to a JSON object that does not already use them."""
    if isinstance(body, dict) and not any(k in body for k in _STAMP_FIELDS):
        return stamp(body, as_of, cached=cached, reason=reason)
    return body


def _freshness_headers(
    observations: list[tuple[str, bool, str | None]],
) -> list[tuple[bytes, bytes]]:
    """The oldest "as of" of the request's reads; cached if any one was."""
    if not observations:
        return []
    as_of = min(o[0] for o in observations)
    cached = any(o[1] for o in observations)
    out = [
        (AS_OF_HEADER.lower().encode(), as_of.encode("latin-1", "replace")),
        (CACHED_HEADER.lower().encode(), b"true" if cached else b"false"),
    ]
    reason = next((o[2] for o in observations if o[2]), None)
    if reason:
        out.append((CACHE_REASON_HEADER.lower().encode(), reason.encode("latin-1", "replace")))
    return out


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _request_id(scope: Scope) -> str | None:
    """The request ID RequestIDMiddleware gave this request, for the envelope."""
    state = scope.get("state")
    value = state.get("request_id") if isinstance(state, dict) else None
    if value is None:
        from app.core.logging import request_id_var

        value = request_id_var.get()
    return str(value) if value else None


def _json_body(body: Any) -> bytes:
    return json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


class DeviceReadTurnMiddleware:
    """Gives every GET request the turn rules of ``take_device_turn``.

    Install it innermost (before every other middleware is added), so the
    busy-device signal raised inside an endpoint reaches it directly.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "GET":
            await self.app(scope, receive, send)
            return
        query = scope.get("query_string", b"")
        request = _RequestRead(
            path=str(scope.get("path", "")),
            query=query.decode("latin-1") if isinstance(query, bytes) else str(query),
        )
        token = _request_read.set(request)
        held_start: Message | None = None
        chunks: list[bytes] = []

        async def send_wrapper(message: Message) -> None:
            nonlocal held_start
            if message["type"] == "http.response.start":
                request.finished = True
                await _release_all(request)
                headers = list(message.get("headers", []))
                content_type = _header(headers, b"content-type") or b""
                if (
                    request.taken
                    and message.get("status") == 200
                    and content_type.startswith(b"application/json")
                    and _header(headers, b"content-encoding") is None
                ):
                    held_start = message  # rewritten once the body is complete
                    return
                if request.taken and message.get("status") == 200:
                    request.observations.append((_now_iso(), False, None))
                await send(
                    {**message, "headers": headers + _freshness_headers(request.observations)}
                )
                return
            if message["type"] == "http.response.body" and held_start is not None:
                chunks.append(message.get("body", b""))
                if message.get("more_body", False):
                    return
                start, held_start = held_start, None
                await self._send_live(request, start, b"".join(chunks), send)
                return
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except _ServeRememberedResponse as hit:
            request.finished = True
            await _release_all(request)
            request.observations.append((hit.as_of, True, "device_busy"))
            body = _stamp_body(hit.body, hit.as_of, cached=True, reason="device_busy")
            await self._send_json(send, 200, body, request, [])
        except _StillBusy as busy:
            request.finished = True
            await _release_all(request)
            await self._send_json(
                send,
                503,
                busy_envelope(busy_message(busy.reason), _request_id(scope)),
                None,
                [(b"retry-after", str(RETRY_AFTER_SECONDS).encode())],
            )
        finally:
            request.finished = True
            await _release_all(request)
            _request_read.reset(token)

    @staticmethod
    async def _send_live(request: _RequestRead, start: Message, raw: bytes, send: Send) -> None:
        as_of = _now_iso()
        # A gateway read inside this request may have answered from its cache:
        # then this response is not a fresh read and is not remembered as one.
        fresh = not any(o[1] for o in request.observations)
        request.observations.append((as_of, False, None))
        headers = [(k, v) for k, v in start.get("headers", []) if k.lower() != b"content-length"]
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            pass
        else:
            if request.cacheable and fresh:
                await _store_response(request.cache_key(), body, as_of)
            stamped = _stamp_body(body, as_of, cached=False, reason=None)
            if stamped is not body:
                raw = _json_body(stamped)
        headers.append((b"content-length", str(len(raw)).encode()))
        await send({**start, "headers": headers + _freshness_headers(request.observations)})
        await send({"type": "http.response.body", "body": raw, "more_body": False})

    @staticmethod
    async def _send_json(
        send: Send,
        status: int,
        body: Any,
        request: _RequestRead | None,
        extra: list[tuple[bytes, bytes]],
    ) -> None:
        raw = _json_body(body)
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode()),
            *extra,
        ]
        if request is not None:
            headers += _freshness_headers(request.observations)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": raw, "more_body": False})
