"""API/DB policy regressions with an explicitly controlled outgoing HTTP client.

HTTPX's real URL parser and the real target validators run. This test double is
not TLS or IPv6 socket qualification; independent owned-listener probes provide
that evidence separately. No real target receives a stored customer secret.
"""

import ipaddress
import os
import ssl
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from httpx import URL, ASGITransport, AsyncClient

from tests.api.test_credential_default_scope import credential_rows
from tests.api.test_credential_http_outcomes import make_outcome_fixture, outcome_cases


def ipv6_cases():
    cases = []
    for kind in ["ula-bare", "ula-bracket", "mapped-bare", "mapped-bracket", "ipv4-control"]:
        for status in [200, 401, 503]:
            for fallback in [False, True]:
                cases.append(
                    {
                        "label": f"{kind}-{status}-{fallback}",
                        "kind": kind,
                        "target_status": status,
                        "fallback": fallback,
                    }
                )
    for case in outcome_cases():
        if case["status"] != 200:
            cases.append({**case, "label": "denied-" + case["label"], "kind": "ula-bare"})
    for label, target in [
        ("mapped-loopback", "::ffff:127.0.0.1"),
        ("bracket-mapped-loopback", "[::ffff:127.0.0.1]"),
        ("mapped-metadata", "::ffff:169.254.169.254"),
        ("bracket-mapped-metadata", "[::ffff:169.254.169.254]"),
        ("mapped-public", "::ffff:8.8.8.8"),
        ("bracket-mapped-public", "[::ffff:8.8.8.8]"),
        ("native-metadata", "fd00:ec2::254"),
        ("native-public", "2606:4700:4700::1111"),
        ("invalid-bracket-name", "[owned.invalid]"),
        ("invalid-bracket-v4", "[10.251.9.1]"),
    ]:
        cases.append({"label": label, "target": target, "status": 400, "kind": "ula-bare"})
    assert len(cases) == 50
    return cases


def ipv6_addresses():
    v4 = os.environ.get("QUALIFICATION_TARGET_IP", "10.251.9.1")
    v6 = os.environ.get("QUALIFICATION_TARGET_IPV6", "fd42:19:20::1")
    assert ipaddress.ip_address(v4).version == 4
    assert ipaddress.ip_address(v6).version == 6
    for value in [v4, v6]:
        ip = ipaddress.ip_address(value)
        assert ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)
    return v4, str(ipaddress.IPv6Address(v6))


async def make_ipv6_fixture(db, case, port=9443):
    v4, v6 = ipv6_addresses()
    targets = {
        "ula-bare": v6,
        "ula-bracket": f"[{v6}]",
        "mapped-bare": f"::ffff:{v4}",
        "mapped-bracket": f"[::ffff:{v4}]",
        "ipv4-control": v4,
    }
    f = await make_outcome_fixture(db, {"status": 200, **case})
    f.ipv6_case = case
    f.expected_pin = v6 if case["kind"].startswith("ula-") else v4
    f.payload.update(
        target_ip=case.get("target", targets[case["kind"]]),
        port=port,
        verify_ssl=case.get("control") != "tls-optout",
    )
    f.outgoing = []
    return f


def ipv6_outgoing_client(f):
    class URLInspectingClient:
        def __init__(self, *, verify, timeout, trust_env):
            assert isinstance(verify, ssl.SSLContext)
            assert verify.verify_mode == ssl.CERT_REQUIRED and verify.check_hostname
            assert timeout == 10 and trust_env is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        @asynccontextmanager
        async def stream(self, method, url, *, auth, follow_redirects, **kwargs):
            assert method == "GET"
            assert auth == ("owned-http-user", "owned-credential-default-secret")
            assert follow_redirects is False
            parsed = URL(url)  # Actual HTTPX parsing, including IPv6 URL syntax.
            assert parsed.host == f.expected_pin
            assert parsed.port == f.payload["port"]
            assert parsed.path == "/" and not parsed.query
            assert not kwargs, "Literal targets need no hostname override"
            f.outgoing.append(
                {
                    "tls": parsed.scheme == "https",
                    "pinned_target_matched": True,
                    "synthetic_auth_received": True,
                    "status": f.ipv6_case.get("target_status", 200),
                }
            )
            yield SimpleNamespace(status_code=f.ipv6_case.get("target_status", 200))

    return URLInspectingClient


async def inspect_ipv6_response(f, response, *, before=False):
    case = f.ipv6_case
    denied = case.get("status", 200) != 200
    expected_status = case.get("status", 200)
    if before and not denied and case["kind"] in {"ula-bracket", "mapped-bare", "mapped-bracket"}:
        expected_status = 400
    assert response.status_code == expected_status, response.text
    actual = await credential_rows(f.db, f.ids)
    for key, row in actual.items():
        omit = (
            {"last_used", "last_test_result", "updated_at"}
            if expected_status == 200 and key == f.target_id
            else set()
        )
        assert {k: v for k, v in row.items() if k not in omit} == {
            k: v for k, v in f.before[key].items() if k not in omit
        }
    if expected_status != 200:
        assert not f.outgoing
        return {
            "status": expected_status,
            "outgoing": [],
            "existing_credential_rows_checked": len(actual),
        }
    received = (not before or case["kind"] == "ipv4-control") and case.get("control") != "untrusted"
    result_status = case.get("target_status", 200)
    expected_success = received and 200 <= result_status < 300
    body = response.json()
    assert body["success"] is expected_success
    assert actual[f.target_id]["last_test_result"] == (
        "reachable" if expected_success else "failed"
    )
    assert len(f.outgoing) == int(received)
    if received:
        assert body["device_info"] is not None
        assert body["device_info"]["status_code"] == result_status
        assert body["device_info"]["authentication_verified"] is False
        assert f.outgoing[0] == {
            "tls": True,
            "pinned_target_matched": True,
            "synthetic_auth_received": True,
            "status": result_status,
        }
    assert "owned-credential-default-secret" not in response.text
    return {
        "status": expected_status,
        "success": body["success"],
        "outgoing": f.outgoing,
        "existing_credential_rows_checked": len(actual),
    }


@pytest.mark.parametrize("case", ipv6_cases(), ids=lambda c: c["label"])
async def test_credential_ipv6_literal_policy_and_url_parsing(db_session, monkeypatch, case):
    import httpx

    f = await make_ipv6_fixture(db_session, case)
    monkeypatch.setattr(httpx, "AsyncClient", ipv6_outgoing_client(f))
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
        trust_env=False,
    ) as client:
        response = await client.post(f.path, json=f.payload)
    await inspect_ipv6_response(f, response)
