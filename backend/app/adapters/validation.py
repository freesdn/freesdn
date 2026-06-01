# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Vendor-agnostic adapter input validation
====================================================

Shared regex validators used by every adapter (Omada, MikroTik,
UniFi, OPNsense, …) to defend against path-traversal injection in
the dozens of vendor-API URL paths that take strings as path
segments. Every adapter's HTTP client interpolates these without
URL-encoding, so validating at the FreeSDN edge is the only defense.

Design rules (apply to every adapter):

* Validation lives HERE, not in vendor-specific modules. Future
  adapters import these helpers; if a new shape is needed (e.g.
  MikroTik uses ``*name=foo`` URL segments), add it here.
* Every helper raises ``HTTPException(400, ...)`` with a clear
  ``label`` so the operator sees which field is malformed.
* Patterns are deliberately conservative — better to reject a
  legitimate-but-unusual ID than to admit a path-traversal payload.

Usage::

    from app.adapters.validation import validate_mac, validate_id

    @router.get("/.../switches/{mac}/...")
    async def get_switch(mac: str, ...):
        mac = validate_mac(mac)
        ...
"""

from __future__ import annotations

import re

from fastapi import HTTPException

# MAC address: aa:bb:cc:dd:ee:ff or AA-BB-CC-DD-EE-FF. No bare hex
# digits, no embedded slashes / dots / control chars.
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$")

# Generic vendor-issued opaque ID: alphanumerics + ``_``, ``.``,
# ``-``, ``*``, ``:``, 1–64 chars. Covers backup IDs, portal IDs,
# WLAN IDs, SSID IDs, target IDs, schedule IDs, etc. Slashes / spaces
# / null bytes / dot-dot all excluded.
# Vendor-agnostic opaque-ID shape:
# * Omada / OPNsense / pfSense use alphanumeric + `_.-` (UUID-like).
# * RouterOS uses `*N` where N is hex — e.g. `*1`, `*80000003`. The
#   leading `*` used to be rejected, which would have broken
#   EVERY update/delete-by-id call against MikroTik (the
#   ``target_id`` validator rejected the row id before it reached
#   the apply dispatch).
# * UniFi addresses devices / clients by MAC (``00:11:22:aa:bb:cc``)
#   as the row identifier. Colon used to be rejected too, which
#   would have broken every
#   ``unifi.clients.block`` / ``forget`` / ``device.restart`` stage
#   that uses target_id=mac.
# Asterisk + colon are safe here — all SQL is parameterised and URLs
# are constructed from typed templates; the ID never gets shell-
# quoted. The ``..`` reject in :func:`validate_id` still applies.
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_.\-*:]{1,64}$")


def validate_mac(mac: str) -> str:
    """Reject anything that isn't a canonically-shaped MAC address.

    Returns the input unchanged on success so the validator can be
    used in an assignment chain: ``mac = validate_mac(mac)``.
    """
    if not _MAC_RE.match(mac or ""):
        raise HTTPException(400, detail="invalid mac address format")
    return mac


def validate_id(value: str, *, label: str = "id") -> str:
    """Reject anything that isn't a vendor-shaped opaque ID.

    ``label`` is echoed in the error so the operator knows which
    field rejected (``backup_id``, ``portal_id``, etc.).

    Defence-in-depth ``..`` reject — the regex above permits the dot
    character (legitimate in many opaque IDs like
    ``backup-2024-05-14.18-30-00``), so ``"a..b"`` and bare ``".."``
    technically match. Every downstream URL-builder in this codebase
    rejects ``..`` in path segments (see ``MikroTikClient._validate_path``,
    ``OpnsenseClient.request``, etc.), but a future adapter that
    interpolates an ID without that chokepoint would inherit a
    path-traversal hole. Rejecting ``..`` here closes the door at the
    earliest validator.
    """
    if not _OPAQUE_ID_RE.match(value or ""):
        raise HTTPException(400, detail=f"invalid {label} format")
    if ".." in value:
        raise HTTPException(400, detail=f"invalid {label} format")
    return value


# Proxmox UPID format:
#   UPID:<node>:<pid_hex>:<pstart_hex>:<starttime_hex>:<dtype>:<id>:<user@realm>:
# Charset is alphanumerics + ``_.-:@``, length ~85 chars on the
# canonical shape. The generic ``validate_id`` regex rejects ``@``
# and caps at 64 chars, which would refuse every real UPID — so the
# proxmox cluster service needs its own validator. Slashes / nulls /
# spaces / ``..`` traversal still excluded. The Proxmox cluster
# apply-path tests caught the gap.
_PROXMOX_UPID_RE = re.compile(r"^[A-Za-z0-9_.\-:@]{1,128}$")


def validate_upid(value: str | None, *, label: str = "upid") -> str:
    """Validate a Proxmox UPID (task id) before it interpolates into
    a Proxmox REST URL. Wider charset + longer cap than the generic
    :func:`validate_id` because real UPIDs contain ``@`` and run to
    ~85 chars. Still rejects ``..`` traversal and the usual
    path-walk attempts.
    """
    if not value or not _PROXMOX_UPID_RE.match(value):
        raise HTTPException(400, detail=f"invalid {label} format")
    if ".." in value:
        raise HTTPException(400, detail=f"invalid {label} format")
    return value


# ── Backwards-compat aliases ─────────────────────────────────────
# These names were used before the helpers moved out of
# ``app/services/gateway_base.py``. Keep them so importers don't
# break. Prefer the canonical names above for new code.

validate_omada_id = validate_id
"""Deprecated alias for :func:`validate_id`. Pre-2026-05 callers."""
