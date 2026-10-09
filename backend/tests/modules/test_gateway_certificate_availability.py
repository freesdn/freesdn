"""Certificate reads through real ASGI/PostgreSQL; identity/device I/O are doubles."""

import asyncio
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from app.adapters.base import AdapterResult
from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.modules.firewall.gateway_service import adapter_registry
from tests.modules import test_gateway_backup_trigger_honesty as helpers

trigger = helpers.trigger
snapshot = helpers.snapshot
SECRET = "owned-private-certificate-inventory-error"


@pytest_asyncio.fixture
async def certificate_inventory(trigger, monkeypatch):
    f = trigger
    f.permissions.append("firewall.view")
    f.certificate_result = AdapterResult.ok({"certificates": []})
    original = adapter_registry.create_adapter

    def create(**kwargs):
        adapter = original(**kwargs)

        async def certificates():
            f.calls.append("certificate-list")
            if isinstance(f.certificate_result, BaseException):
                raise f.certificate_result
            return f.certificate_result

        # Only the concrete adapter method is provided. A made-up legacy name
        # must not silently use a BaseAdapter unsupported-operation stub.
        adapter.get_certificates = certificates
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    yield f


async def request(f, route="expiry", *, gateway_id=None, query=""):
    return await f.client.get(
        f"/firewall/gateways/{gateway_id or f.gateway.id}/certificates/{route}{query}"
    )


def unavailable(kind):
    return {
        "failed": AdapterResult.fail(SECRET),
        "exception": RuntimeError(SECRET),
        "none": None,
        "envelope": {"success": True, "data": {"certificates": []}},
        "truthy-success": AdapterResult(success="yes", data={"certificates": []}),
        "empty": AdapterResult.ok({}),
        "no-data": AdapterResult.ok(),
        "not-list": AdapterResult.ok({"certificates": SECRET}),
        "bad-row": AdapterResult.ok({"certificates": [None]}),
        "mixed-row": AdapterResult.ok({"certificates": [{"cn": "owned"}, SECRET]}),
        "incomplete": AdapterResult.ok({"certificates": [], "count": 1}),
        "bool-count": AdapterResult.ok({"certificates": [], "count": False}),
    }[kind]


@pytest.mark.parametrize("route", ["expiry", "certs"])
@pytest.mark.parametrize(
    "kind",
    [
        "failed",
        "exception",
        "none",
        "envelope",
        "truthy-success",
        "empty",
        "no-data",
        "not-list",
        "bad-row",
        "mixed-row",
        "incomplete",
        "bool-count",
    ],
)
async def test_unavailable_inventory_cannot_report_empty_or_healthy(
    certificate_inventory, route, kind, caplog
):
    f = certificate_inventory
    f.certificate_result = unavailable(kind)
    before = await snapshot(f)
    response = await request(f, route)
    assert response.status_code == 502
    assert "needs_attention" not in response.text
    assert SECRET not in response.text and SECRET not in caplog.text
    assert f.calls == ["construct", "connect", "certificate-list", "disconnect"]
    assert await snapshot(f) == before


@pytest.mark.parametrize("route", ["expiry", "certs"])
@pytest.mark.parametrize("kind", ["NOT_SUPPORTED", "NOT_IMPLEMENTED"])
async def test_unsupported_inventory_is_explicit(certificate_inventory, route, kind):
    f = certificate_inventory
    f.certificate_result = AdapterResult.fail(SECRET, error_code=kind)
    response = await request(f, route)
    assert response.status_code == 501
    assert "needs_attention" not in response.text and SECRET not in response.text


@pytest.mark.parametrize(
    "expiry",
    [
        None,
        "",
        "not-a-date",
        True,
        False,
        1e100,
        "NaN",
        "Infinity",
        {"secret": SECRET},
        [SECRET],
        "99999999999999999",
        "2026-02-30T00:00:00Z",
    ],
)
async def test_unknown_expiry_requires_attention(certificate_inventory, expiry):
    f = certificate_inventory
    f.certificate_result = AdapterResult.ok(
        {"certificates": [{"cn": "owned.example.test", "not_after": expiry, "prv": SECRET}]}
    )
    response = await request(f)
    assert response.status_code == 200
    body = response.json()
    assert body["needs_attention"] is True and body["unknown_count"] == 1
    assert body["valid_count"] == 0 and body["total_certificates"] == 1
    assert body["unknown"] == [
        {
            "name": "owned.example.test",
            "common_name": "owned.example.test",
            "status": "unknown",
            "expires": None,
            "days_remaining": None,
        }
    ]
    assert SECRET not in response.text


@pytest.mark.parametrize(
    "kind",
    ["iso", "fraction", "offset", "legacy", "openssl", "unix-number", "unix-string", "epoch-zero"],
)
async def test_supported_dates_and_opnsense_names(certificate_inventory, kind):
    f = certificate_inventory
    date = datetime.now(UTC).replace(microsecond=0) + timedelta(days=5)
    value = {
        "iso": date.isoformat(),
        "fraction": date.isoformat().replace("+00:00", ".123Z"),
        "offset": date.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat(),
        "legacy": date.strftime("%Y-%m-%d %H:%M:%S"),
        "openssl": date.strftime("%b %d %H:%M:%S %Y GMT"),
        "unix-number": int(date.timestamp()),
        "unix-string": str(int(date.timestamp())),
        "epoch-zero": 0,
    }[kind]
    f.certificate_result = AdapterResult.ok(
        {
            "certificates": [
                {"dn_commonname": "opnsense.example.test", "valid_to": value, "prv": SECRET}
            ]
        }
    )
    response = await request(f)
    assert response.status_code == 200
    body = response.json()
    assert body["needs_attention"] and body["unknown_count"] == 0
    rows = body["expired"] if kind == "epoch-zero" else body["expiring_soon"]
    assert len(rows) == 1 and rows[0]["common_name"] == "opnsense.example.test"
    assert rows[0]["name"] == "opnsense.example.test" and SECRET not in response.text
    assert (
        rows[0]["days_remaining"] < 0
        if kind == "epoch-zero"
        else 3 <= rows[0]["days_remaining"] <= 5
    )


@pytest.mark.parametrize("route", ["expiry", "certs"])
@pytest.mark.parametrize("kind", ["empty", "valid", "expired"])
async def test_confirmed_inventory_controls(certificate_inventory, route, kind):
    f = certificate_inventory
    rows = (
        []
        if kind == "empty"
        else [
            {
                "cn": "owned.example.test",
                "not_after": (datetime.now(UTC) + timedelta(days=60 if kind == "valid" else -60))
                .replace(microsecond=0)
                .isoformat(),
            }
        ]
    )
    f.certificate_result = AdapterResult.ok({"certificates": rows, "count": len(rows)})
    response = await request(f, route)
    assert response.status_code == 200
    body = response.json()
    if route == "certs":
        assert body["certificates"] == rows and body["count"] == len(rows)
    else:
        assert body["total_certificates"] == len(rows)
        assert body["needs_attention"] is (kind == "expired")
        assert body["valid_count"] == (1 if kind == "valid" else 0)
    assert f.calls == ["construct", "connect", "certificate-list", "disconnect"]


@pytest.mark.parametrize("route", ["expiry", "certs"])
@pytest.mark.parametrize("kind", ["anonymous", "permission", "site", "organization", "missing"])
async def test_admission_never_contacts_device(certificate_inventory, route, kind):
    f = certificate_inventory
    gateway_id = None
    if kind == "anonymous":
        f.anonymous = True
    elif kind == "permission":
        f.permissions = []
        f.scoped = True
    elif kind == "site":
        f.user.role = "viewer"
        f.scoped = True
        f.site_ids = {f.sites[1].id}
    elif kind == "organization":
        f.user.organization_id = uuid4()
    else:
        gateway_id = uuid4()
    before = await snapshot(f)
    response = await request(f, route, gateway_id=gateway_id)
    assert response.status_code == (
        401 if kind == "anonymous" else 403 if kind == "permission" else 404
    )
    assert not f.calls and await snapshot(f) == before


@pytest.mark.parametrize("route", ["expiry", "certs"])
@pytest.mark.parametrize("stage", ["construct", "connect"])
async def test_connection_failure_is_safe(certificate_inventory, route, stage, caplog):
    f = certificate_inventory
    f.failure = stage
    response = await request(f, route)
    assert response.status_code == 502
    assert SECRET not in response.text and helpers.SECRET not in response.text
    assert "Traceback" not in caplog.text
    assert f.calls == (
        ["construct"] if stage == "construct" else ["construct", "connect", "disconnect"]
    )


@pytest.mark.parametrize("threshold", [0, 366, "no"])
async def test_invalid_threshold_does_not_call_adapter(certificate_inventory, threshold):
    f = certificate_inventory
    response = await request(f, query=f"?days_threshold={threshold}")
    assert response.status_code == 422 and not f.calls


async def test_real_adapter_method_is_used_and_unsupported_stub_is_not(
    certificate_inventory, monkeypatch
):
    f = certificate_inventory
    adapter = OPNsenseAdapter(host="192.0.2.55", username="owned", password="owned")

    async def connect():
        f.calls.append("connect")
        return True

    async def disconnect():
        f.calls.append("disconnect")

    async def post(path, body):
        f.calls.append((path, body))
        return {
            "rows": [
                {"uuid": str(uuid4()), "dn_commonname": "adapter.example.test", "valid_to": "1"}
            ],
            "total": 1,
            "rowCount": 1,
            "current": 1,
        }

    monkeypatch.setattr(adapter, "connect", connect)
    monkeypatch.setattr(adapter, "disconnect", disconnect)
    monkeypatch.setattr(adapter._api, "post", post)
    monkeypatch.setattr(adapter_registry, "create_adapter", lambda **_kwargs: adapter)
    response = await request(f)
    assert response.status_code == 200
    assert response.json()["expired"][0]["common_name"] == "adapter.example.test"
    assert f.calls == [
        "connect",
        ("/api/trust/cert/search", {"current": 1, "rowCount": -1}),
        "disconnect",
    ]


async def test_cancellation_propagates_and_disconnects(certificate_inventory):
    f = certificate_inventory
    f.certificate_result = asyncio.CancelledError("owned-cancellation")
    with pytest.raises(asyncio.CancelledError):
        await request(f)
    assert f.calls[-1] == "disconnect"
