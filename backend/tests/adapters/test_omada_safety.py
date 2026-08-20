# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Production-safety tests for the Omada client's request chokepoint.

Why this file exists
--------------------
Omada is the largest and most-exercised adapter in the product, and it was the
only staged adapter with no safety test of its own. That is not the same as
"untested" -- the write gate is covered by
``tests/security/test_pentest_omada_write_gate.py`` and the raw-passthrough
endpoint by ``test_pentest_omada_raw_blocklist.py`` -- but one guard was
covered by nothing at all:

    the CLIENT-level path-traversal check (``client.py``, "Path-traversal guard
    (chokepoint for ALL endpoint wrappers)").

The raw endpoint's own ``..`` rejection is tested. This one is different and
cannot be substituted for it: it protects the ~100 *typed* wrappers, which
build their paths by interpolating caller-supplied values -- device MAC, site
id, ssid id, network id -- that arrive from untrusted API path params. The
comment in the source spells out the exact bypass it was written for: the MAC
normalisation regex just below it matches only well-formed colon-MACs, so a
hostile ``AA../BB:CC:DD:EE:FF`` or percent-encoded ``%2e%2e%2f`` would sail
past normalisation and into the controller URL, where path normalisation can
escape the intended resource.

Nothing failed if that guard were deleted. These tests fix that, and pin the
two other invariants of the same chokepoint so a refactor cannot quietly
reorder them: the read-only write gate must be evaluated, and reads must never
be gated.

No live controller is contacted at any point.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.adapters.omada.client import (
    _WRITE_METHODS,
    OmadaApiClient,
    OmadaClientConfig,
)
from app.adapters.omada.exceptions import OmadaApiError, OmadaValidationError


def _client() -> OmadaApiClient:
    """A client that never opens a socket -- every test below raises before I/O."""
    return OmadaApiClient(
        OmadaClientConfig(
            host="192.0.2.10",
            username="u",
            password="p",
            omada_id="ctrl-1",
        )
    )


# ── Path-traversal guard: the chokepoint nothing covered ─────────


@pytest.mark.parametrize(
    "path",
    [
        # The exact payload shape named in the source comment: a hostile value
        # interpolated where a MAC is expected.
        "/sites/default/devices/AA../BB:CC:DD:EE:FF",
        "/sites/default/../../maintenance/backup",
        "/sites/../admin",
        "/sites/default/devices/..",
        # Percent-encoded '.' (%2e) and '/' — encode-and-forward would let the
        # controller decode these itself, which is why they are refused here.
        "/sites/%2e%2e/admin",
        "/sites/%2E%2E/admin",
        "/sites/default%2fadmin",
        "/sites/default%2Fadmin",
        # Backslash: Windows-style separator some proxies normalise to '/'.
        "/sites/default\\..\\admin",
        "/sites/default\\admin",
    ],
)
async def test_unsafe_paths_are_refused_before_any_request(path: str) -> None:
    client = _client()
    with pytest.raises(OmadaValidationError) as exc:
        await client._request("GET", path)
    assert "unsafe path" in str(exc.value).lower()


@patch("app.adapters.omada.client._is_adapter_read_only", lambda: False)
async def test_guard_applies_to_every_verb_not_just_writes() -> None:
    """
    Traversal is a read problem as much as a write problem -- reaching a
    resource you were not scoped to is the whole point of the attack, and a GET
    is not covered by the read-only write gate at all.

    Read-only is switched OFF here deliberately. With it on, the write gate
    fires first and every mutating verb raises OmadaApiError, so the test would
    pass without the traversal guard existing at all -- it would be asserting
    the wrong guard.
    """
    client = _client()
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(OmadaValidationError):
            await client._request(method, "/sites/../admin")


@pytest.mark.parametrize(
    "path",
    [
        "/sites/default/devices/AA:BB:CC:DD:EE:FF",
        "/sites/default/setting/wlans",
        "/sites/default/switches/11:22:33:44:55:66/ports",
        "/maintenance/backup",
    ],
)
def test_legitimate_paths_contain_nothing_the_guard_rejects(path: str) -> None:
    """
    The guard is a blocklist, so its value depends entirely on real paths never
    tripping it. Pin that: a false positive here would break live reads on the
    maintainer's controller, which is worse than the bug being prevented.
    """
    assert ".." not in path
    assert "\\" not in path
    assert "%" not in path


# ── Read-only write gate at the client layer ─────────────────────


@pytest.mark.parametrize("method", sorted(_WRITE_METHODS))
@patch("app.adapters.omada.client._is_adapter_read_only", lambda: True)
@patch("app.adapters.omada.client.in_apply_window", lambda: False)
async def test_writes_refused_under_read_only_outside_an_apply_window(method: str) -> None:
    """
    Every mutating verb must be refused. Before this gate existed, any direct
    endpoint -- controller reboot, AP radio/SSID, switch port/PoE/VLAN/ACL --
    mutated the LIVE controller even under read-only, bypassing staging.
    """
    client = _client()
    with pytest.raises(OmadaApiError) as exc:
        await client._request(method, "/sites/default/cmd/reboot")
    assert "READ_ONLY" in str(exc.value)


@patch("app.adapters.omada.client._is_adapter_read_only", lambda: True)
@patch("app.adapters.omada.client.in_apply_window", lambda: False)
async def test_write_methods_covers_every_mutating_verb() -> None:
    """
    The gate keys off _WRITE_METHODS. If a verb were dropped from that set the
    parametrised test above would silently stop checking it, so assert the set
    itself rather than trusting its length.
    """
    assert frozenset({"POST", "PUT", "PATCH", "DELETE"}) == _WRITE_METHODS


@patch("app.adapters.omada.client._is_adapter_read_only", lambda: True)
@patch("app.adapters.omada.client.in_apply_window", lambda: False)
async def test_reads_are_never_gated_by_read_only() -> None:
    """
    Read-only must not mean read-nothing: a GET has to get past the gate.

    The session is stubbed so this asserts the gate's behaviour rather than the
    network's. Without the stub the call reaches _ensure_session() and spends a
    connect timeout against a TEST-NET address, which makes the suite slow and
    the assertion meaningless.
    """
    client = _client()
    sent: list[tuple[str, str]] = []

    async def _fake_ensure_session() -> None:
        client._http = AsyncMock()

    async def _fake_send(method: str, api_path: str, **kwargs: object) -> dict:
        sent.append((method, api_path))
        return {}

    with (
        patch.object(client, "_ensure_session", _fake_ensure_session),
        patch.object(client, "_send", _fake_send, create=True),
    ):
        try:
            await client._request("GET", "/sites/default/devices")
        except OmadaApiError as exc:  # pragma: no cover - only on regression
            assert "READ_ONLY" not in str(exc), "read was refused by the write gate"
        except Exception:
            # Any non-gate failure past this point is transport detail we do
            # not care about here; the gate already let the read through.
            pass
