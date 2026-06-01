# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Self-tests + worked example for the recorded-fixture (cassette) harness.

These run in CI in REPLAY mode (no hardware). They demonstrate the pattern every
adapter cassette test follows: wrap the adapter call in ``use_cassette(...)``, and
assert that the adapter parses/normalizes the REAL captured payload correctly.

To capture a real cassette from your lab, see tests/fixtures_harness/README.md.
"""

from __future__ import annotations

import httpx
import pytest

from tests.fixtures_harness import use_cassette


async def test_replay_serves_the_recorded_real_payload() -> None:
    """REPLAY: the cassette serves the exact payload captured from a real Omada controller.

    This is the template: in a real adapter test you'd build the adapter's client here
    instead of a bare httpx.AsyncClient, call e.g. ``await client.list_sites()``, and
    assert the NORMALIZED result. The point is that the bytes under test came from real
    hardware, so a vendor field rename breaks this test instead of passing silently.
    """
    with use_cassette("omada/sites_list"):
        async with httpx.AsyncClient(base_url="https://omada.lab.example") as client:
            resp = await client.get("/api/v2/sites", params={"currentPage": 1, "currentPageSize": 100})

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["errorCode"] == 0
    sites = payload["result"]["data"]
    assert len(sites) == 1
    assert sites[0]["name"] == "HQ"
    assert sites[0]["id"] == "5f3e9a7c2b1d4e0099aa1234"


async def test_uncovered_call_fails_loudly() -> None:
    """A call the cassette does not cover must raise, not silently pass.

    This is the mechanism that catches "the adapter started making a new request"
    (e.g. after a refactor or a vendor API change) without a fresh recording.
    """
    with use_cassette("omada/sites_list"):
        async with httpx.AsyncClient(base_url="https://omada.lab.example") as client:
            with pytest.raises(AssertionError, match="no recorded interaction"):
                await client.get("/api/v2/this-endpoint-was-never-recorded")


async def test_missing_cassette_load_raises_with_record_instructions() -> None:
    """The low-level loader raises with the record workflow. ``use_cassette``
    translates this into a pytest SKIP on replay (see the harness), so adapter
    cassette tests skip cleanly in public CI / on machines with no lab recording
    instead of failing."""
    from tests.fixtures_harness import Cassette

    with pytest.raises(FileNotFoundError, match="Record it against real hardware"):
        Cassette("omada/does_not_exist_yet").load()


def test_missing_cassette_skips_on_replay() -> None:
    """End-to-end: replaying an absent cassette SKIPS (never fails) — the behavior
    public CI relies on when the off-repo recordings folder isn't present."""
    import pytest as _pytest

    with _pytest.raises(_pytest.skip.Exception):
        with use_cassette("omada/does_not_exist_yet"):
            pass
