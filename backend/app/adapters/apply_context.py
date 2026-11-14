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
from collections.abc import Iterator

_apply_window: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "adapter_apply_window", default=False
)


def in_apply_window() -> bool:
    """True when the current task is executing an approved staged apply."""
    return _apply_window.get()


# Appended to a read-only refusal when the caller sent force=true, so the
# operator learns why their explicit opt-in did not get through.
FORCE_DOES_NOT_LIFT_READ_ONLY = " force=true alone does not lift read-only mode."


def read_only_refuses_write(read_only: bool) -> bool:
    """The one read-only rule every adapter write gate applies.

    While ``ADAPTER_READ_ONLY`` is on, a device write is refused unless it runs
    inside an approved staged apply (:func:`apply_window`). ``force=True`` does
    NOT lift the lock. It is the explicit-intent flag for read-write mode, and
    several callers send it unconditionally (the camera API, the hypervisor
    power/clone/migrate buttons, the distribution engine's MikroTik
    entrypoints), so letting it open the lock made monitor-only mode
    meaningless: a "read-only" install still rebooted cameras and stopped VMs.

    ``AdapterStagingService.apply_change`` refuses outright while read-only is
    on and only then opens the window, so in practice the window matters only
    when the runtime toggle flips mid-apply. Non-mutating POSTs (OPNsense
    search/get, MikroTik and pfSense ping/traceroute/DNS) are classified as
    reads by each client and never reach this rule.
    """
    return read_only and not in_apply_window()


@contextlib.contextmanager
def apply_window() -> Iterator[None]:
    """Mark the current task as inside an approved staged apply.

    Synchronous context manager: it only sets/resets a contextvar, so it wraps an
    ``await`` correctly (the value propagates across awaits within the same task).
    """
    token = _apply_window.set(True)
    try:
        yield
    finally:
        _apply_window.reset(token)
