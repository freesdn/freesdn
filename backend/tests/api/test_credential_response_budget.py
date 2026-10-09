"""A status-only credential check must not consume bodies or run indefinitely.

Real PostgreSQL and TCP HTTP/TLS peers, with synthetic authentication only.
Owned peers offer finite, small payloads; no customer address is contacted.
"""

import asyncio
import base64
import gzip
import socket
import socketserver
import ssl
import threading
import time

import pytest
from httpx import ASGITransport, AsyncClient

from tests.api.test_credential_default_scope import credential_rows
from tests.api.test_credential_http_outcomes import make_outcome_fixture, outcome_cases
from tests.api.test_credential_proxy_isolation import (
    ENV_KEYS,
    owned_bind_address,
    proxy_certificates,
)


def budget_cases():
    cases = []
    for status in [200, 401, 503]:
        for mode in ["large", "chunked", "gzip", "invalid-gzip"]:
            cases.append({"label": f"{status}-{mode}", "target_status": status, "mode": mode})
        cases.append({"label": f"{status}-empty-control", "target_status": status, "mode": "empty"})
    cases.append(
        {"label": "503-no-plaintext-retry", "target_status": 503, "mode": "empty", "fallback": True}
    )
    for fallback in [False, True]:
        cases.append(
            {
                "label": f"slow-headers-{fallback}",
                "target_status": 200,
                "mode": "slow-headers",
                "fallback": fallback,
            }
        )
    cases.append(
        {
            "label": "one-budget-across-fallback",
            "target_status": 200,
            "mode": "timeout-fallback",
            "fallback": True,
        }
    )
    for case in outcome_cases():
        if case["status"] != 200:
            cases.append({**case, "label": "denied-" + case["label"], "mode": "large"})
    assert len(cases) == 29
    return cases


class BudgetPeer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, context, case):
        super().__init__((host, 0), BudgetHandler)
        self.context, self.case = context, case
        self.requests = []
        self.errors = []
        self.closed_before_body = None
        self.body_observed = threading.Event()
        self.stop = threading.Event()
        self.worker = threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.worker.start()

    def close(self):
        self.stop.set()
        self.shutdown()
        self.server_close()
        self.worker.join(5)
        assert not self.worker.is_alive()
        assert not self.errors


class BudgetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw = connection = self.request
        raw.settimeout(20)
        try:
            first = raw.recv(1, socket.MSG_PEEK)
            if not first:
                return
            tls = first == b"\x16"
            if tls:
                try:
                    connection = self.server.context.wrap_socket(raw, server_side=True)
                except ssl.SSLError:
                    return
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(4096)
                assert chunk
                data += chunk
                assert len(data) <= 16384
            lines = data.split(b"\r\n")
            assert lines[0] == b"GET / HTTP/1.1"
            expected = b"Basic " + base64.b64encode(
                b"owned-http-user:owned-credential-default-secret"
            )
            headers = {
                line.split(b":", 1)[0].lower(): line.split(b":", 1)[1].strip()
                for line in lines[1:]
                if b":" in line
            }
            assert headers.get(b"authorization") == expected, "Expected synthetic credential"
            self.server.requests.append({"tls": tls, "synthetic_auth_received": True})
            mode = self.server.case["mode"]
            status = self.server.case.get("target_status", 200)
            if mode == "timeout-fallback" and tls:
                # The old per-read timeout expires and grants HTTP a new budget.
                self.server.stop.wait(11)
                return
            if mode == "slow-headers":
                connection.sendall(b"HTTP/1.1 200 Owned\r\nX-Owned: ")
                for _ in range(24):
                    if self.server.stop.wait(0.5):
                        return
                    connection.sendall(b"x")
                connection.sendall(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if mode in {"empty", "timeout-fallback"}:
                connection.sendall(
                    f"HTTP/1.1 {status} Owned\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
                )
                return
            payload = b"x" * (256 * 1024)
            extra = b""
            if mode == "gzip":
                payload = gzip.compress(b"x" * (4 * 1024 * 1024))
                extra = b"Content-Encoding: gzip\r\n"
            elif mode == "invalid-gzip":
                payload = b"owned-invalid-gzip"
                extra = b"Content-Encoding: gzip\r\n"
            length = (
                b"Transfer-Encoding: chunked\r\n"
                if mode == "chunked"
                else f"Content-Length: {len(payload)}\r\n".encode()
            )
            connection.sendall(
                f"HTTP/1.1 {status} Owned\r\n".encode()
                + length
                + extra
                + b"Connection: close\r\n\r\n"
            )
            # A status-only client closes here. The legacy body reader keeps the
            # socket open waiting for data, which is a deterministic observation
            # separate from elapsed-time or process-memory guesses.
            connection.settimeout(0.4)
            try:
                closed = connection.recv(1) == b""
            except TimeoutError:
                closed = False
            self.server.closed_before_body = closed
            self.server.body_observed.set()
            if closed:
                return
            if mode == "chunked":
                connection.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n")
            else:
                connection.sendall(payload)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
            # Closing an unread response or enforcing the transport deadline
            # deliberately closes this owned peer while it is sending.
            return
        except Exception as error:
            self.server.errors.append(type(error).__name__)
        finally:
            if connection is not raw:
                connection.close()


async def make_budget_fixture(db, case, folder, setenv, delenv):
    for key in ENV_KEYS:
        delenv(key, raising=False)
    host = owned_bind_address()
    context = proxy_certificates(folder, host)
    setenv("SSL_CERT_FILE", str(folder / "ca.pem"))
    peer = BudgetPeer(host, context, case)
    try:
        f = await make_outcome_fixture(db, {"target_status": 200, "status": 200, **case})
        f.budget_case, f.peer = case, peer
        f.payload.update(
            target_ip=case.get("target", host),
            port=peer.server_address[1],
            allow_plaintext_http=case.get("fallback", False),
        )
        return f
    except BaseException:
        peer.close()
        raise


async def inspect_budget_response(f, response, elapsed, *, before=False):
    case = f.budget_case
    expected_status = case.get("status", 200)
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
        assert not f.peer.requests
        return {
            "status": expected_status,
            "requests": 0,
            "existing_credential_rows_checked": len(actual),
        }
    mode = case["mode"]
    timed = mode in {"slow-headers", "timeout-fallback"}
    target_status = case.get("target_status", 200)
    expected_success = (before if timed else 200 <= target_status < 300) and not (
        before and mode == "invalid-gzip"
    )
    body = response.json()
    assert body["success"] is expected_success
    assert actual[f.target_id]["last_test_result"] == (
        "reachable" if expected_success else "failed"
    )
    assert len(f.peer.requests) == (2 if before and mode == "timeout-fallback" else 1)
    if timed:
        if before:
            assert elapsed >= (11.5 if mode == "slow-headers" else 9.5)
        else:
            assert elapsed < 11.5, "Outgoing transport exceeded its shared elapsed budget"
            assert not any(not row["tls"] for row in f.peer.requests)
    else:
        if mode != "empty":
            assert await asyncio.to_thread(f.peer.body_observed.wait, 2)
            assert f.peer.closed_before_body is (not before), (
                "A status-only check consumed the response body"
            )
        if not (before and mode == "invalid-gzip"):
            assert body["device_info"]["status_code"] == target_status
            assert body["device_info"]["authentication_verified"] is False
    assert "owned-credential-default-secret" not in response.text
    return {
        "status": expected_status,
        "success": body["success"],
        "requests": len(f.peer.requests),
        "closed_before_body": f.peer.closed_before_body,
        "elapsed_seconds": round(elapsed, 3),
        "existing_credential_rows_checked": len(actual),
    }


@pytest.mark.parametrize("case", budget_cases(), ids=lambda c: c["label"])
async def test_credential_status_check_does_not_read_bodies_or_extend_deadline(
    db_session, monkeypatch, tmp_path, case
):
    f = await make_budget_fixture(
        db_session, case, tmp_path, monkeypatch.setenv, monkeypatch.delenv
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=f.app, raise_app_exceptions=False),
            base_url="http://owned-fixture",
            trust_env=False,
        ) as client:
            start = time.monotonic()
            response = await client.post(f.path, json=f.payload)
            elapsed = time.monotonic() - start
        await inspect_budget_response(f, response, elapsed)
    finally:
        f.peer.close()
