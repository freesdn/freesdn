# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Keep snapshot admission owned until the outer application send completes.

Only explicitly adopted download responses arm a deadline. This does not cap
other requests, proxy buffers or arbitrary storage SDK allocations. It neither
starts another receive consumer nor interprets middleware-generated disconnects
as observations of the external client.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import uuid4

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.middleware import apply_request_response_headers

SCOPE_KEY = "freesdn.owned_download_lifetime"


class DownloadLifetime:
    """A single request owns one adopted response, without taking another slot."""

    def __init__(self, deadline: anyio.CancelScope):
        self.deadline = deadline
        self.cleanup: Callable[[], Awaitable[None]] | None = None
        self.closed = False

    def adopt(self, seconds: float, cleanup: Callable[[], Awaitable[None]]) -> None:
        """Transfer cleanup ownership synchronously before cancellable allocation."""
        if self.closed or self.cleanup is not None:
            raise RuntimeError("A download lifetime cannot be adopted twice")
        self.cleanup = cleanup
        self.deadline.deadline = anyio.current_time() + seconds

    async def close(self) -> None:
        """The response callback must drain its cleanup despite cancellation."""
        if self.closed:
            raise RuntimeError("A download lifetime cannot be closed twice")
        self.closed = True
        if self.cleanup is not None:
            await self.cleanup()


class DownloadLifetimeMiddleware:
    """Place outside every body-forwarding application middleware layer."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_started = anyio.current_time()
        started = False
        failure: BaseException | None = None
        lifetime: DownloadLifetime | None = None

        async def observe_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                # A send can fail after transmitting headers. Never synthesize
                # a second status when the first send has already been entered.
                started = True
            await send(message)

        try:
            # No deadline is imposed on ordinary API, SSE or upload requests.
            with anyio.fail_after(None) as deadline:
                lifetime = DownloadLifetime(deadline)
                scope[SCOPE_KEY] = lifetime
                await self.app(scope, receive, observe_send)
                if lifetime.cleanup is not None and anyio.current_time() >= deadline.deadline:
                    raise TimeoutError("Backup download exceeded its deadline")
        except BaseException as error:
            failure = error
        finally:
            # Do not leave a completed lease in the caller's reusable scope.
            scope.pop(SCOPE_KEY, None)
            if lifetime is not None:
                try:
                    await lifetime.close()
                except BaseException as cleanup_error:
                    # A later cancellation must remain cancellation. Preserve
                    # an earlier request error when cleanup has an ordinary
                    # failure; the response callback logs only the error class.
                    if failure is None or not isinstance(cleanup_error, Exception):
                        failure = cleanup_error

        # Mandatory cleanup is shielded; acknowledge an enclosing AnyIO scope
        # after ownership has ended, before returning success or another error.
        await anyio.lowlevel.checkpoint_if_cancelled()
        if (
            isinstance(failure, TimeoutError)
            and lifetime is not None
            and lifetime.cleanup is not None
        ):
            if not started:
                request = Request(scope)
                # The inner request-ID middleware validated/stored this before
                # response adoption. Standalone response users have no ID yet.
                request_id = getattr(request.state, "request_id", None) or str(uuid4())
                response = JSONResponse(
                    {
                        "error": {
                            "code": 504,
                            "message": "Backup download preparation exceeded its deadline.",
                            "request_id": request_id,
                        }
                    },
                    status_code=504,
                )
                apply_request_response_headers(request, response, request_id)
                response.headers["X-Response-Time"] = (
                    f"{(anyio.current_time() - request_started) * 1000:.2f}ms"
                )
                # Reuse completed admission metadata. Never authenticate,
                # consume quota or retry a cancelled operation here.
                response.headers.update(scope.get("freesdn.rate_limit_headers", {}))
                await response(scope, receive, send)
                return
            raise TimeoutError("Backup download exceeded its deadline") from None
        if failure is not None:
            raise failure
