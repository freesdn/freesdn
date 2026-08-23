# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The plugin capability vocabulary. Single source of truth.

A plugin declares capabilities in ``plugin.yaml``; the operator sees them in the
install consent dialog; the SDK enforces them at each call site. Those three
things have to agree, and before this module they did not:

  * ``PluginPermission.code`` was an unvalidated free string. A manifest could
    declare ``firewall.admin`` or ``superuser`` and it rendered in the consent
    dialog as a real permission while meaning nothing at all. Consent that does
    not correspond to an enforced capability is worse than no consent, because
    it reads as a security boundary and is not one.
  * The reverse also bit: a typo like ``device.read`` (singular) is not a
    capability, so the plugin installed cleanly and then failed at runtime with
    "requires undeclared permission" the first time it read a device.
  * The mapping used for the confused-deputy guard lived separately in
    sdk.py and had drifted. ``alerts.write`` mapped to ``alert:write``, a core
    permission that DOES NOT EXIST anywhere in FreeSDN. A site_admin holds
    ``alert:create`` and ``alert:update`` and is exactly the role that drives a
    plugin route, and the guard refused them.

So the vocabulary is defined once, here, and both the manifest validator and
the SDK read it.

The rule, restated: a plugin may never exercise a capability the CALLER driving
the request could not exercise directly. ``core_permissions`` is the set that
satisfies a capability and the caller must hold ANY ONE of them -- a set rather
than a single string because FreeSDN's own vocabulary splits by verb
(``alert:create`` / ``alert:update``) where the plugin surface is one write
capability. With no caller bound (a scheduled task, an event handler, an
HMAC-authenticated public route) the plugin runs on its own declared authority,
which is the design.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    """One thing a plugin may be granted."""

    code: str
    #: Shown to the operator in the install consent dialog. Written for someone
    #: deciding whether to trust this plugin, not for the author.
    summary: str
    #: The caller must hold ANY ONE of these core permissions. Empty means the
    #: capability is not caller-gated (none today; kept explicit rather than
    #: implied by omission).
    core_permissions: frozenset[str]


def _cap(code: str, summary: str, *core: str) -> Capability:
    return Capability(code=code, summary=summary, core_permissions=frozenset(core))


CAPABILITIES: dict[str, Capability] = {
    c.code: c
    for c in (
        _cap(
            "devices.read",
            "Read the device inventory: names, addresses, status and ports.",
            "device:read",
        ),
        _cap(
            "devices.register",
            "Create new device records in the inventory.",
            "device:write",
        ),
        _cap(
            "devices.stage",
            "Propose configuration changes to devices. Staged only: a change "
            "still requires an operator to apply it, and never reaches a device "
            "on the plugin's own authority.",
            "device:write",
            "device:update",
            "config:push",
        ),
        _cap(
            "sites.read",
            "Read the sites in this organization, subject to the caller's own site grants.",
            "site:read",
        ),
        _cap(
            "alerts.read",
            "Read existing alerts.",
            "alert:read",
        ),
        _cap(
            "metrics.read",
            "Read time-series metrics for this organization's devices and sites: "
            "device status history, interface counters, and anything else the "
            "platform records.",
            "analytics:read",
        ),
        _cap(
            "alerts.write",
            "Raise and resolve alerts.",
            # NOT "alert:write" -- that permission does not exist. These two are
            # what FreeSDN's own roles actually carry.
            "alert:create",
            "alert:update",
        ),
    )
}


#: Capabilities that let a plugin change something, as opposed to observe it.
#: The install consent dialog leads with these; a read-only plugin is a
#: materially smaller decision than one that can propose a device write.
MUTATING_CAPABILITIES: frozenset[str] = frozenset(
    {"devices.register", "devices.stage", "alerts.write"}
)


def is_known(code: str) -> bool:
    return code in CAPABILITIES


def known_codes() -> list[str]:
    """Sorted, for error messages and docs."""
    return sorted(CAPABILITIES)


def core_permissions_for(code: str) -> frozenset[str]:
    """Core permissions that satisfy a capability. Unknown code -> empty set.

    Returning empty for an unknown code is safe here ONLY because the manifest
    validator rejects unknown codes before anything is installed, and because
    the SDK checks "did the plugin declare this" first. If that ordering ever
    changes, this should raise instead.
    """
    capability = CAPABILITIES.get(code)
    return capability.core_permissions if capability else frozenset()
