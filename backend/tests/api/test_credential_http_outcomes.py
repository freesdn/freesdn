"""A generic HTTP response is connectivity evidence, not credential validation.

Real PostgreSQL and incoming API routes; outgoing HTTP is a controlled double.
Independent TLS qualification is required separately before shipping.
"""

import ssl
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.core import Credential
from tests.api.test_credential_default_scope import credential_rows
from tests.api.test_credential_site_write_caps import make_cap_fixture


def outcome_cases():
    cases = []
    for status in [200, 204, 206, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503]:
        for fallback in [False, True]:
            cases.append(
                {
                    "label": f"http-{status}-fallback-{fallback}",
                    "target_status": status,
                    "fallback": fallback,
                    "status": 200,
                }
            )
    for label, extra, status in [
        ("read-only-site", {"level": "read"}, 403),
        ("unknown-site-level", {"level": "invalid"}, 403),
        ("missing-write", {"permissions": ["settings:read"]}, 403),
        ("invisible-site", {"site": "b"}, 404),
        ("foreign-tenant", {"site": "foreign"}, 404),
        ("scoped-super-foreign", {"site": "foreign", "role": "super_admin", "scoped": True}, 404),
        ("metadata", {"target": "169.254.169.254"}, 400),
        ("loopback", {"target": "127.0.0.1"}, 400),
        ("loopback-ipv6", {"target": "[::1]"}, 400),
        ("public-target", {"target": "8.8.8.8"}, 400),
    ]:
        cases.append({"label": label, **extra, "status": status})
    return cases


async def make_outcome_fixture(db, case):
    f = await make_cap_fixture(db, {"action": "test", **case})
    credential = await db.get(Credential, UUID(f.target_id))
    credential.username = "owned-http-user"
    await db.commit()
    f.before = await credential_rows(db, f.ids)
    f.outcome_case = case
    f.payload = {
        "target_ip": case.get("target", "10.251.9.1"),
        "allow_plaintext_http": case.get("fallback", False),
    }
    f.outgoing = []
    return f


def outgoing_client(f):
    class ControlledClient:
        def __init__(self, *, verify, timeout, trust_env):
            assert isinstance(verify, ssl.SSLContext)
            assert verify.verify_mode == ssl.CERT_REQUIRED and verify.check_hostname
            assert trust_env is False
            self.verify, self.timeout = True, timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        @asynccontextmanager
        async def stream(self, method, url, *, auth, follow_redirects):
            assert method == "GET"
            assert auth == ("owned-http-user", "owned-credential-default-secret")
            assert follow_redirects is False and self.verify is True and self.timeout == 10
            f.outgoing.append(
                {
                    "scheme": url.split(":", 1)[0],
                    "verified_tls": self.verify,
                    "redirects": follow_redirects,
                    "expected_synthetic_auth": True,
                }
            )
            yield SimpleNamespace(status_code=f.outcome_case["target_status"])

    return ControlledClient


async def inspect_outcome_response(f, response, *, before=False):
    case = f.outcome_case
    assert response.status_code == case["status"], response.text
    actual = await credential_rows(f.db, f.ids)
    for key, row in actual.items():
        changed = (
            {"last_used", "last_test_result", "updated_at"}
            if case["status"] == 200 and key == f.target_id
            else set()
        )
        assert {k: v for k, v in row.items() if k not in changed} == {
            k: v for k, v in f.before[key].items() if k not in changed
        }, "Unrelated credential state changed"
    if case["status"] != 200:
        assert not f.outgoing
        return {
            "status": response.status_code,
            "outgoing_requests": 0,
            "existing_credential_rows_checked": len(actual),
            "outcome_honored": True,
        }
    status = case["target_status"]
    expected_success = status < 500 if before else 200 <= status < 300
    body = response.json()
    assert body["success"] is expected_success
    record = actual[f.target_id]
    assert record["last_used"] is not None
    assert record["last_test_result"] == (
        ("success" if before else "reachable") if expected_success else "failed"
    )
    expected_requests = 2 if before and status >= 500 and case["fallback"] else 1
    assert len(f.outgoing) == expected_requests
    assert f.outgoing[0]["scheme"] == "https"
    if expected_requests == 2:
        assert f.outgoing[1]["scheme"] == "http"
    if not before:
        assert body["device_info"]["status_code"] == status
        assert body["device_info"]["authentication_verified"] is False
        assert body["device_info"]["check_kind"] == "http_connectivity"
        assert "authentication was not verified" in body["message"]
        assert str(status) in body["message"]
    for secret in ["owned-credential-default-secret", f.before[f.target_id]["encrypted_password"]]:
        assert secret not in response.text
    return {
        "status": response.status_code,
        "target_status": status,
        "outgoing_requests": len(f.outgoing),
        "existing_credential_rows_checked": len(actual),
        "success": body["success"],
        "stored_result": record["last_test_result"],
        "outcome_honored": not before,
    }


@pytest.mark.parametrize("case", outcome_cases(), ids=lambda c: c["label"])
async def test_generic_http_outcome_is_not_credential_validation(db_session, monkeypatch, case):
    f = await make_outcome_fixture(db_session, case)
    monkeypatch.setattr("httpx.AsyncClient", outgoing_client(f))
    async with AsyncClient(
        transport=ASGITransport(app=f.app, raise_app_exceptions=False),
        base_url="http://owned-fixture",
    ) as client:
        response = await client.post(f.path, json=f.payload)
    await inspect_outcome_response(f, response)
