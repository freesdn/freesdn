"""Actual OPNsense client with synthetic HTTP transport and documented read routes."""

import asyncio
import copy
import json

import httpx
import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.adapters.opnsense.adapter import OPNsenseAdapter

SECRET = "owned-private-trust-acme-payload"
READS = {
    "ca": ("get_certificate_authorities", "/api/trust/ca/search", "certificate_authorities"),
    "crl": ("get_certificate_revocation_lists", "/api/trust/crl/search", "crls"),
    "certificate": (
        "get_acme_certificates",
        "/api/acmeclient/certificates/search",
        "acme_certificates",
    ),
    "account": ("get_acme_accounts", "/api/acmeclient/accounts/search", "acme_accounts"),
    "validation": (
        "get_acme_validations",
        "/api/acmeclient/validations/search",
        "acme_validations",
    ),
    "action": ("get_acme_actions", "/api/acmeclient/actions/search", "acme_actions"),
}
ROW = {
    "uuid": "owned-uuid",
    "name": "Owned",
    "descr": "Owned CA",
    "refid": "owned-ref",
    "crl_descr": "Owned CRL",
    "enabled": "1",
    "statusCode": "200",
    "altNames": "owned.example.test",
    "private_key": SECRET,
    "api_key": SECRET,
    "certPrivateKey": SECRET,
    "description": "Owned description",
}


def envelope(rows):
    return {"rows": rows, "total": len(rows), "rowCount": len(rows), "current": 1}


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.55", username="owned", password="owned", verify_ssl=True
    )
    adapter._api.max_retries = 1
    state = {"body": envelope([ROW]), "status": 200, "error": None, "requests": []}

    async def response(request):
        state["requests"].append(
            (
                request.method,
                request.url.path,
                json.loads(request.content) if request.content else dict(request.url.params),
            )
        )
        if state["error"]:
            raise state["error"]
        return httpx.Response(state["status"], json=state["body"])

    adapter._api._client = httpx.AsyncClient(
        base_url=adapter._api.base_url, transport=httpx.MockTransport(response)
    )
    try:
        yield adapter, state
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("kind", READS)
@pytest.mark.parametrize("empty", [True, False])
async def test_complete_inventory_uses_real_search_and_keeps_only_public_fields(wire, kind, empty):
    adapter, state = wire
    method, path, key = READS[kind]
    row = copy.deepcopy(ROW)
    if kind == "crl":
        del row["uuid"]  # CRL search is keyed by its CA refid, not a model UUID.
    state["body"] = envelope([] if empty else [row])
    result = await getattr(adapter, method)()
    assert result.success is True and result.data["count"] == (0 if empty else 1)
    assert SECRET not in str(result.data)
    assert len(result.data[key]) == result.data["count"]
    verb = "GET" if kind == "crl" else "POST"
    params = {"current": "1", "rowCount": "-1"} if kind == "crl" else {"current": 1, "rowCount": -1}
    assert state["requests"] == [(verb, path, params)]
    if kind == "certificate" and not empty:
        assert result.data[key][0]["alt_names"] == "owned.example.test"


@pytest.mark.parametrize("kind", READS)
@pytest.mark.parametrize(
    "bad", ["missing", "row-null", "partial", "bool-count", "duplicate", "nested-name"]
)
async def test_invalid_or_truncated_inventory_is_unavailable(wire, kind, bad, caplog):
    adapter, state = wire
    row = copy.deepcopy(ROW)
    body = envelope([row])
    if bad == "missing":
        body = {}
    elif bad == "row-null":
        body = envelope([None])
    elif bad == "partial":
        body["total"] = 2
    elif bad == "bool-count":
        body["rowCount"] = True
    elif bad == "duplicate":
        body = envelope([row, row])
    else:
        row["descr" if kind in {"ca", "crl"} else "name"] = {"private": SECRET}
    state["body"] = body
    result = await getattr(adapter, READS[kind][0])()
    assert result.success is False and result.data is None
    assert (
        SECRET not in str(result) and SECRET not in caplog.text and "Traceback" not in caplog.text
    )


@pytest.mark.parametrize("kind", [*READS, "settings"])
@pytest.mark.parametrize("failure", [403, 503, "timeout", "cancelled"])
async def test_transport_refusal_is_safe_and_cancellation_propagates(wire, kind, failure, caplog):
    adapter, state = wire
    state["body"] = {"message": SECRET}
    method = "get_acme_settings" if kind == "settings" else READS[kind][0]
    if isinstance(failure, int):
        state["status"] = failure
    else:
        state["error"] = (
            asyncio.CancelledError() if failure == "cancelled" else httpx.ReadTimeout(SECRET)
        )
    if failure == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await getattr(adapter, method)()
    else:
        result = await getattr(adapter, method)()
        assert result.success is False and result.data is None
        assert (
            SECRET not in str(result)
            and SECRET not in caplog.text
            and "Traceback" not in caplog.text
        )


async def test_crl_rows_without_a_configured_list_do_not_inflate_count(wire):
    adapter, state = wire
    state["body"] = envelope(
        [
            {"refid": "one", "descr": "CA without CRL"},
            {"refid": "two", "descr": "CA with CRL", "crl_descr": ""},
        ]
    )
    result = await adapter.get_certificate_revocation_lists()
    assert result.success is True and result.data["count"] == 1
    assert result.data["crls"][0]["caref"] == "two"


@pytest.mark.parametrize("selected", ["1", 1])
async def test_settings_read_nested_settings_and_selected_options(wire, selected):
    adapter, state = wire
    state["body"] = {
        "acmeclient": {
            "settings": {
                "enabled": "1",
                "autoRenewal": "1",
                "environment": {
                    "prod": {"selected": selected, "value": "Production"},
                    "stg": {"selected": 0, "value": "Staging"},
                },
                "TLSchallengePort": "43581",
                "private": SECRET,
            },
            "accounts": {"secret": SECRET},
        }
    }
    result = await adapter.get_acme_settings()
    assert result.success is True
    settings = result.data["acme_settings"]
    assert settings["enabled"] is True and settings["auto_renewal"] is True
    assert settings["environment"] == "prod" and settings["tls_challenge_port"] == "43581"
    assert SECRET not in str(result.data)


@pytest.mark.parametrize(
    "body",
    [
        {},
        [],
        None,
        {"acmeclient": {}},
        {"acmeclient": {"settings": {}}},
        {"acmeclient": {"settings": {"enabled": "false", "autoRenewal": "1"}}},
    ],
)
async def test_missing_or_malformed_settings_do_not_claim_disabled(wire, body):
    adapter, state = wire
    state["body"] = body
    result = await adapter.get_acme_settings()
    assert result.success is False and result.data is None


@pytest.mark.parametrize("group", ["trust", "acme"])
@pytest.mark.parametrize("failure", ["failure", "exception", "missing", "partial", "cancelled"])
async def test_aggregate_requires_every_component(wire, monkeypatch, group, failure):
    adapter, _state = wire
    parts = (
        [
            ("get_certificate_authorities", "certificate_authorities"),
            ("get_certificates", "certificates"),
            ("get_certificate_revocation_lists", "crls"),
        ]
        if group == "trust"
        else [
            ("get_acme_settings", "acme_settings"),
            ("get_acme_certificates", "acme_certificates"),
            ("get_acme_accounts", "acme_accounts"),
            ("get_acme_validations", "acme_validations"),
            ("get_acme_actions", "acme_actions"),
        ]
    )
    for name, key in parts:

        async def read(key=key):
            return AdapterResult.ok(
                {key: {"enabled": False, "auto_renewal": True}}
                if key == "acme_settings"
                else {key: [], "count": 0}
            )

        monkeypatch.setattr(adapter, name, read)

    async def failed():
        if failure == "exception":
            raise RuntimeError(SECRET)
        if failure == "cancelled":
            raise asyncio.CancelledError()
        return {
            "failure": AdapterResult.fail(SECRET),
            "missing": AdapterResult.ok({}),
            "partial": AdapterResult.ok({parts[-1][1]: [], "count": 1}),
        }[failure]

    monkeypatch.setattr(adapter, parts[-1][0], failed)
    if failure == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await getattr(adapter, f"get_{group}_overview")()
    else:
        result = await getattr(adapter, f"get_{group}_overview")()
        assert result.success is False and result.data is None and SECRET not in str(result)


@pytest.mark.parametrize(
    "group,index", [("trust", i) for i in range(3)] + [("acme", i) for i in range(5)]
)
async def test_cancelled_component_is_not_hidden_by_another_failure(
    wire, monkeypatch, group, index
):
    adapter, _state = wire
    names = (
        ["get_certificate_authorities", "get_certificates", "get_certificate_revocation_lists"]
        if group == "trust"
        else [
            "get_acme_settings",
            "get_acme_certificates",
            "get_acme_accounts",
            "get_acme_validations",
            "get_acme_actions",
        ]
    )
    for i, name in enumerate(names):

        async def read(i=i):
            if i == index:
                raise asyncio.CancelledError()
            return AdapterResult.fail(SECRET)

        monkeypatch.setattr(adapter, name, read)
    with pytest.raises(asyncio.CancelledError):
        await getattr(adapter, f"get_{group}_overview")()


@pytest.mark.parametrize("selected", ["1", 1])
async def test_all_settings_option_fields_are_normalized(wire, selected):
    adapter, state = wire
    state["body"] = {
        "acmeclient": {
            "settings": {
                "enabled": "1",
                "autoRenewal": "1",
                "environment": {"prod": {"selected": selected, "value": "Production"}},
                "logLevel": {
                    "normal": {"selected": selected, "value": "Normal"},
                    "debug": {"selected": 0, "value": "Debug"},
                },
            }
        }
    }
    result = await adapter.get_acme_settings()
    assert result.success is True
    assert result.data["acme_settings"]["environment"] == "prod"
    assert result.data["acme_settings"]["log_level"] == "normal"


@pytest.mark.parametrize(
    "field,bad",
    [
        ("environment", "ambiguous"),
        ("logLevel", "ambiguous"),
        ("logLevel", "missing"),
        ("logLevel", "nested"),
    ],
)
async def test_invalid_settings_options_are_unavailable(wire, field, bad):
    adapter, state = wire
    settings = {"enabled": "1", "autoRenewal": "1", "environment": "prod", "logLevel": "normal"}
    settings[field] = {
        "ambiguous": {"one": {"selected": 1}, "two": {"selected": 1}},
        "missing": {"one": {"selected": 0}},
        "nested": [SECRET],
    }[bad]
    state["body"] = {"acmeclient": {"settings": settings}}
    result = await adapter.get_acme_settings()
    assert result.success is False and result.data is None and SECRET not in str(result)
