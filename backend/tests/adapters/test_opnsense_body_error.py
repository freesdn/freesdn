# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
OPNsense: an HTTP 200 carrying ``result: failed`` is a refusal, not a success.

Background
----------
OPNsense answers a rejected write with HTTP **200** and declares the refusal in
the body::

    {"result": "failed", "validations": {"rule.destination_net": "..."}}

``_request`` inspected only the status code, so that body was returned to the
caller as a normal result. The staged-apply path reads the return value, sees no
exception, and records the change as applied -- so a rule the firewall refused
was written to the audit log as a success and the operator had no way to tell.
Transport-level failures (4xx/5xx, timeouts) always raised correctly; this was
the one gap, and it is the failure mode that matters on a live firewall because
validation rejections are the *common* case when a payload is slightly wrong.

The pfSense sibling has always done this check (``pfsense/client.py``, keyed on
``status == "error"``); this brings OPNsense to parity.

Deliberately narrow
-------------------
Only the exact string ``"failed"`` is treated as a refusal. Any other body shape
passes through untouched -- these tests pin that too, because the risk of a
broad check is breaking reads against the maintainer's live production firewall,
which is a far worse outcome than the bug being fixed.

No live controller is contacted anywhere in this file.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.adapters.opnsense.client import OPNsenseAPIError, OPNsenseClient


def _client() -> OPNsenseClient:
    return OPNsenseClient(
        host="192.0.2.1",
        api_key="k",
        api_secret="s",
        port=443,
        verify_ssl=False,
    )


def _responds(client: OPNsenseClient, payload: object, *, status: int = 200) -> None:
    """Wire the client's httpx session to return one canned 200 response."""
    resp = MagicMock(status_code=status, text="non-empty")
    resp.json.return_value = payload
    client._client = AsyncMock()
    client._client.is_closed = False
    client._client.request = AsyncMock(return_value=resp)


# ── The regression ───────────────────────────────────────────────


async def test_result_failed_raises_instead_of_returning_success() -> None:
    """The bug: a 200 + result=failed was returned as if the write landed."""
    client = _client()
    _responds(client, {"result": "failed", "validations": {"rule.destination_net": "bad"}})

    with pytest.raises(OPNsenseAPIError) as exc:
        await client._request("POST", "/api/firewall/filter/addRule", force=True)

    assert "result=failed" in str(exc.value)


async def test_validation_detail_is_surfaced_to_the_operator() -> None:
    """
    The validations dict is the only thing that says *why* the firewall said no.
    Dropping it leaves an operator with a bare failure and no next step.
    """
    client = _client()
    _responds(client, {"result": "failed", "validations": {"rule.destination_net": "not an IP"}})

    with pytest.raises(OPNsenseAPIError) as exc:
        await client._request("POST", "/api/firewall/filter/addRule", force=True)

    assert "destination_net" in str(exc.value)


async def test_message_field_is_used_when_there_are_no_validations() -> None:
    client = _client()
    _responds(client, {"result": "failed", "message": "interface is not assigned"})

    with pytest.raises(OPNsenseAPIError) as exc:
        await client._request("POST", "/api/firewall/filter/addRule", force=True)

    assert "interface is not assigned" in str(exc.value)


async def test_case_and_whitespace_variants_still_count_as_refusal() -> None:
    """OPNsense modules are not uniform about casing; a refusal is a refusal."""
    for variant in ("FAILED", "Failed", " failed "):
        client = _client()
        _responds(client, {"result": variant})
        with pytest.raises(OPNsenseAPIError):
            await client._request("POST", "/api/firewall/filter/addRule", force=True)


# ── The happy paths this must not disturb ────────────────────────


async def test_result_saved_is_untouched() -> None:
    """``saved`` is OPNsense's success token for a write. Must pass straight through."""
    client = _client()
    _responds(client, {"result": "saved", "uuid": "abc-123"})

    out = await client._request("POST", "/api/firewall/filter/addRule", force=True)
    assert out == {"result": "saved", "uuid": "abc-123"}


async def test_a_read_payload_with_no_result_key_is_untouched() -> None:
    """The overwhelming majority of traffic: reads. These must be unaffected."""
    client = _client()
    payload = {"rows": [{"uuid": "a"}, {"uuid": "b"}], "total": 2}
    _responds(client, payload)

    assert await client._request("GET", "/api/firewall/filter/searchRule") == payload


async def test_list_bodies_are_untouched() -> None:
    """Several endpoints return a bare list; ``.get`` on one would be a TypeError."""
    client = _client()
    _responds(client, [{"uuid": "a"}])

    assert await client._request("GET", "/api/diagnostics/interface/getInterfaceNames") == [
        {"uuid": "a"}
    ]


async def test_unknown_result_values_are_not_treated_as_failure() -> None:
    """
    Fail ONLY on the documented refusal token. An unrecognised value must not
    turn a working call into an exception against a live firewall.
    """
    client = _client()
    for value in ("ok", "saved", "deleted", "", "unknown-token"):
        _responds(client, {"result": value})
        assert await client._request("GET", "/api/firewall/filter/get") == {"result": value}


async def test_non_dict_result_field_does_not_crash() -> None:
    """A ``result`` that is a dict/list (some endpoints do this) must pass through."""
    client = _client()
    payload = {"result": {"status": "running"}}
    _responds(client, payload)

    assert await client._request("GET", "/api/core/service/status") == payload
