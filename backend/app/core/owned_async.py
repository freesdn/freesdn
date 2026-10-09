# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Keep admitted operations owned until their established completion path ends.

This handles normal request cancellation, not process loss, global event-loop
shutdown, stuck kernel I/O, admission capacity or an operation deadline. Callers
must separately bound resources and provide recovery for interrupted processes.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from functools import wraps
from typing import Any, cast

import anyio

logger = logging.getLogger(__name__)


def complete_before_cancellation[**P, R](
    function: Callable[P, Coroutine[Any, Any, R]],
) -> Callable[P, Coroutine[Any, Any, R]]:
    """Drain admitted work before propagating cancellation to its owner.

    AnyIO shields cancellation scopes; asyncio.shield protects the separately owned
    task from direct Task.cancel(). Repeated direct cancellation is remembered but
    does not detach the operation or let its database session close underneath it.
    The function's own return/exception/commit behavior is otherwise unchanged.
    """

    @wraps(function)
    async def owned(*args: P.args, **kwargs: P.kwargs) -> R:
        # Honor cancellation already pending before allocating a coroutine/task.
        await anyio.lowlevel.checkpoint()
        cancelled = None
        with anyio.CancelScope(shield=True):

            async def capture_outcome() -> tuple[R | None, Exception | None]:
                # A cancelled shield may log the child's later exception. Keep
                # ordinary failures in the owned result until this owner decides
                # whether to rethrow them or emit only a safe diagnostic.
                try:
                    return await function(*args, **kwargs), None
                except Exception as error:
                    return None, error

            operation = asyncio.create_task(capture_outcome())
            while not operation.done():
                try:
                    await asyncio.shield(operation)
                except asyncio.CancelledError as cancellation:
                    if operation.cancelled():
                        raise
                    cancelled = cancellation
            result, error = operation.result()
        # Work and its resource cleanup have drained before leaving the shield.
        # A scope cancellation can have remained pending throughout that drain;
        # it must win over either a normal result or a captured ordinary error.
        try:
            await anyio.lowlevel.checkpoint()
        except asyncio.CancelledError as pending:
            cancelled = cancelled or pending
        if cancelled is not None:
            if error is not None:
                logger.warning("Cancelled owned operation ended with %s", type(error).__name__)
            raise cancelled from None
        if error is not None:
            raise error
        return cast(R, result)

    return owned
