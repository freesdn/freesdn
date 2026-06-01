# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pre-flight safety gate for UniFi staged writes.

Mirrors ``adapter_omada_preflight`` / ``adapter_opnsense_preflight``: classifies a
staged UniFi change's destructiveness and BLOCKS a CATASTROPHIC operation unless
the staged payload carries ``confirmed=true``. UniFi features carry a ``unifi.``
prefix, so the gate keys on that prefix and is a no-op for any other vendor — safe
to sit unconditionally on the shared apply chokepoint
(``AdapterStagingService.apply_change``).

Before this, UniFi was the only adapter in ``_CATASTROPHIC_EVENT_PREFIXES`` without
a central ``enforce_*`` gate: the clients applier carried its own forget gate, but
the devices applier (``unifi.devices.restart`` / ``unifi.devices.disable``) applied
with ``force=True`` and NO confirmation check — an asymmetry vs OPNsense / Omada /
pfSense / MikroTik. This closes it for every ``unifi.*`` feature in one place.

Owner rule: irreversible/disruptive device + client ops (device restart/disable,
client forget) + ALL deletes require explicit confirmation.
"""

from __future__ import annotations

from fastapi import HTTPException

#: UniFi features that are CATASTROPHIC regardless of their staging ``operation``.
#: This is the SINGLE source of truth for UniFi catastrophic-op confirmation — the
#: clients service used to carry its own in-place forget gate but it was retired in
#: favour of this central one (which also honours apply-time ``confirmed``). Kept in
#: sync with ``_CATASTROPHIC_EVENT_PREFIXES`` (unifi.devices.restart / .disable).
_CATASTROPHIC_FEATURES: frozenset[str] = frozenset(
    {
        "unifi.devices.restart",  # reboots the device — drops every client on it
        "unifi.devices.disable",  # takes the AP/switch offline until re-enabled
        "unifi.devices.upgrade",  # flashes firmware + reboots — disruptive, not cleanly revertible
        "unifi.clients.forget",  # forgets a client — irreversible (re-auth + history loss)
    }
)


def _requires_confirmation(feature: str, operation: str) -> bool:
    """A UniFi op is catastrophic (needs ``confirmed=true``) if it is an
    irreversible/disruptive feature OR any delete (owner rule: ALL deletes gated)."""
    if feature in _CATASTROPHIC_FEATURES:
        return True
    return (operation or "").lower() == "delete"


def enforce_unifi_preflight(
    feature: str | None,
    operation: str | None,
    payload: dict | None,
) -> None:
    """Central runtime gate for UniFi staged changes (no device read).

    No-op for any non-UniFi feature (keyed on the ``unifi.`` prefix) so it can sit
    unconditionally on the shared apply chokepoint. For a UniFi change it blocks a
    CATASTROPHIC op (device restart/disable, client forget, or ANY delete) unless
    the staged payload carries ``confirmed=true`` — matching how OPNsense / Omada /
    pfSense / MikroTik are gated.
    """
    if not (feature or "").startswith("unifi."):
        return
    from app.services.adapter_preflight_common import payload_confirmed

    if _requires_confirmation(feature or "", operation or "") and not payload_confirmed(payload):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{feature} ({operation}) is a catastrophic / irreversible UniFi "
                "operation; re-stage the change with confirmed=true to proceed"
            ),
        )
