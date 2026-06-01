# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cross-cutting "approved staged-apply window" signal for adapter clients.

``AdapterStagingService.apply_change`` opens this window around the actual live
controller write — *after* its own ``ADAPTER_READ_ONLY`` + ``force`` gate. Adapter
clients that refuse writes while read-only mode is engaged (currently the Omada
client, whose client layer historically had no such gate) consult
``in_apply_window()`` so that a sanctioned staged apply is permitted even while
read-only mode is on, whereas any *direct* (un-staged) write attempt outside the
window is refused.

The window is task-local (``contextvars``), so a staged apply running in one task
never relaxes the gate for a concurrent direct-endpoint call in another task.
"""

from __future__ import annotations

import contextlib
import contextvars

_apply_window: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "adapter_apply_window", default=False
)


def in_apply_window() -> bool:
    """True when the current task is executing an approved staged apply."""
    return _apply_window.get()


@contextlib.contextmanager
def apply_window():
    """Mark the current task as inside an approved staged apply.

    Synchronous context manager: it only sets/resets a contextvar, so it wraps an
    ``await`` correctly (the value propagates across awaits within the same task).
    """
    token = _apply_window.set(True)
    try:
        yield
    finally:
        _apply_window.reset(token)
