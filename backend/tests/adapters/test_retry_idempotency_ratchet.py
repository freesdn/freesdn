# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: no adapter transport may automatically replay a mutation.

A retry loop that does not consider the request method will re-send a mutation
the device may already have applied. The staging dual gate and the read-only gate
both decide *whether* a write may begin; neither can make a request safe to
replay once it is on the wire.

Concrete harm this prevents, from the review:

  * Grandstream -- a phone drops the connection AS IT BEGINS REBOOTING;
    ``ServerDisconnectedError`` is an ``aiohttp.ClientError``, so the transport
    caught it and retransmitted the REBOOT before ``reboot()`` could read the
    drop as acknowledgement.
  * OPNsense -- writes config.xml BEFORE answering, so a POST addRule that
    completed but exceeded the read timeout was re-sent, and OPNsense does not
    dedupe filter rules. The second rule's UUID is unknown to FreeSDN, so it can
    never be updated or deleted.
  * Omada -- reboot, voucher batches, and controller backup RESTORE inherited a
    default-on retry budget.
  * Hikvision -- a ReadTimeout on a PUT was replayed.

The pattern every transport now follows is the one ``proxmox/client.py`` already
had: replay ``GET``/``HEAD`` (or a connect-phase failure, which never left us),
transmit a mutation exactly once and surface its failure. The staging layer's
``outcome_is_unknown()`` then records that as ``reconciliation_required`` rather
than a false ``failed``.

A SOURCE ratchet cannot prove behaviour, and this one already certified a
guard-shaped no-op: the first Hikvision "guard" wrapped only a log and a sleep,
so the loop advanced and re-sent the mutation anyway, while this file reported it
as guarded. The behavioural counterpart is
``tests/adapters/test_adapter_retry_transmissions.py``, which counts actual
transport calls. Keep both: this one catches a guard being deleted, that one
catches a guard that does not guard.

Note the ``else 2`` in the Omada and Grandstream bounds: those transports also
use the loop to replay after a DEFINITIVE rejection (a 401/403 or an
expired-session errorCode), which is safe for a mutation because a rejected
request was not applied. Collapsing them to 1 broke session recovery for every
write. The transport handlers do the idempotency gating.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ADAPTERS_DIR = Path(__file__).resolve().parents[2] / "app" / "adapters"

#: Transport modules that carry a retry loop, and the token proving the loop is
#: bounded by something method- or phase-aware. Each entry was verified by
#: reading the file; the token is the specific mechanism that adapter uses,
#: because the vendors differ (OPNsense has read-only POST endpoints, Hikvision
#: distinguishes connect-phase from read-phase failures).
#: The value is the EXACT expression that bounds the retry loop. Pinning the
#: bound rather than merely the presence of a constant matters: an earlier
#: version of this ratchet looked for the constant's NAME anywhere in the file,
#: and a mutation that removed the guard from the loop while leaving the name in
#: a comparison sailed straight past it.
GUARDED_TRANSPORTS: dict[str, str] = {
    "proxmox/client.py": "attempts = _MAX_TRANSIENT_RETRIES if is_idempotent else 1",
    "omada/client.py": "max_attempts = self.config.max_retries if (retry and is_idempotent) else 2",
    "grandstream/client.py": "max_attempts = PHONE_MAX_RETRIES if is_idempotent else 2",
    "hikvision/adapter.py": "if not _replay_safe:",
    "opnsense/client.py": "max_attempts = 1 if is_write else self.max_retries",
    "freepbx/rest_client.py": "attempts = REST_MAX_RETRIES if idempotent else 1",
}

#: Files with a loop that is NOT a device-request retry. Exempt by name with the
#: reason, rather than loosening the scan.
NOT_A_REQUEST_RETRY: dict[str, str] = {
    "onvif/discovery.py": (
        "WS-Discovery multicast probe: a discovery datagram is idempotent by "
        "construction and reaches no device state."
    ),
    "mikrotik/adapter.py": (
        "RouterOS command retry is already gated on a per-command safety flag "
        "rather than an HTTP method."
    ),
}

RETRY_LOOP = re.compile(r"for attempt in range\(|while attempt\b")


def _transport_files_with_retry_loops() -> list[Path]:
    out: list[Path] = []
    for path in sorted(ADAPTERS_DIR.rglob("*.py")):
        try:
            src = path.read_text(encoding="utf-8")
        except OSError:  # pragma: no cover
            continue
        if RETRY_LOOP.search(src):
            out.append(path)
    return out


def _rel(path: Path) -> str:
    return path.relative_to(ADAPTERS_DIR).as_posix()


def test_adapter_scan_is_not_empty() -> None:
    """Guard the guard: an empty scan must not read as a pass."""
    assert ADAPTERS_DIR.is_dir(), f"adapters dir not found: {ADAPTERS_DIR}"
    found = _transport_files_with_retry_loops()
    assert len(found) >= 5, f"retry-loop scan looks truncated: {[_rel(p) for p in found]}"


def test_no_transport_retry_loop_is_unaccounted_for() -> None:
    """Every retry loop is either guarded or explicitly exempt with a reason.

    A NEW adapter with an unguarded retry loop fails here, naming the file.
    """
    unaccounted: list[str] = []
    for path in _transport_files_with_retry_loops():
        rel = _rel(path)
        if rel in GUARDED_TRANSPORTS or rel in NOT_A_REQUEST_RETRY:
            continue
        unaccounted.append(rel)

    assert not unaccounted, (
        "Adapter transport(s) with a retry loop that is neither guarded nor "
        "documented as exempt. An unguarded loop will replay a mutation the "
        "device may already have applied -- bound it by method (see "
        "proxmox/client.py) and add it to GUARDED_TRANSPORTS:\n  "
        + "\n  ".join(unaccounted)
    )


@pytest.mark.parametrize("rel,token", sorted(GUARDED_TRANSPORTS.items()))
def test_guarded_transport_still_has_its_guard(rel: str, token: str) -> None:
    """The guard must not be removed or refactored away silently."""
    path = ADAPTERS_DIR / rel
    assert path.exists(), f"{rel} is pinned as guarded but no longer exists"
    src = path.read_text(encoding="utf-8")
    assert token in src, (
        f"{rel} lost its retry-idempotency guard; expected the loop bound "
        f"{token!r}. Without it an ambiguous transport failure replays a "
        "mutation the device may already have applied."
    )


def test_exemptions_still_exist_and_are_explained() -> None:
    """A stale exemption could silently re-admit an unguarded loop."""
    for rel, reason in NOT_A_REQUEST_RETRY.items():
        assert (ADAPTERS_DIR / rel).exists(), f"{rel} is exempt but no longer exists"
        assert len(reason) > 40, f"{rel}: exemption needs a real reason"
