"""Actual HTTP acceptance through the isolated Caddy edge; no ASGI overrides."""

from __future__ import annotations

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import asyncio
import hashlib
import json
import secrets
import socket
import ssl
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

import httpx

STATE = Path("/tmp/install-probe-state.json")


@contextmanager
def database_probe_loop():
    """Keep pooled connections on one loop across the HTTP backup checks."""
    from app.db.session import dispose_api_engines

    with asyncio.Runner() as runner:
        try:
            yield runner
        finally:
            # Dispose on the owning loop, including when an HTTP assertion fails.
            runner.run(dispose_api_engines())


async def database_content(state, seed):
    from app.core.crypto import decrypt_credential, encrypt_credential
    from app.db.session import async_session_factory, logdb_session_factory
    from app.models.core import Credential, CredentialType
    from sqlalchemy import select, text

    async with async_session_factory() as session:
        if seed:
            cipher = encrypt_credential("synthetic-offline-vault-value")
            session.add(
                Credential(
                    organization_id=UUID(state["organization"]),
                    name="Offline qualification",
                    credential_type=CredentialType.USERNAME_PASSWORD,
                    encrypted_password=cipher,
                )
            )
            await session.commit()
            state["vault_sha256"] = hashlib.sha256(cipher.encode()).hexdigest()
        credential = (
            await session.execute(
                select(Credential).where(Credential.name == "Offline qualification")
            )
        ).scalar_one()
        assert (
            decrypt_credential(credential.encrypted_password)
            == "synthetic-offline-vault-value"
        )
        assert (
            hashlib.sha256(credential.encrypted_password.encode()).hexdigest()
            == state["vault_sha256"]
        )
    async with logdb_session_factory() as session:
        if seed:
            await session.execute(
                text("""
                INSERT INTO events.event_records
                (id,event_type,category,priority,payload,metadata,source,organization_id,timestamp)
                SELECT gen_random_uuid(),'release.acceptance','system','normal',
                    jsonb_build_object('index',n,'message','é-אבג'), '{}',
                    'qualification', CAST(:org AS uuid), now()-n*INTERVAL '1 second'
                FROM generate_series(1,1024) n
            """),
                {"org": state["organization"]},
            )
            await session.commit()
        result = (
            await session.execute(
                text("""
            SELECT count(*), md5(string_agg(payload::text,'|' ORDER BY payload->>'index'))
            FROM events.event_records WHERE source='qualification' AND event_type='release.acceptance'
        """)
            )
        ).one()
        assert result[0] == 1024
        if seed:
            state["logdb_fingerprint"] = result[1]
        assert state["logdb_fingerprint"] == result[1]
        if "soak_events" in state:
            count = (
                await session.execute(
                    text("""
                SELECT count(*) FROM events.event_records
                WHERE source='capacity-qualification' AND organization_id=CAST(:org AS uuid)
            """),
                    {"org": state["organization"]},
                )
            ).scalar_one()
            assert count == state["soak_events"]


def main():
    mode = sys.argv[1]
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    checks = []
    # Route the certificate's localhost name to the isolated edge while keeping
    # real SNI/hostname validation and a trust store containing its own test CA.
    resolve = socket.getaddrinfo

    def edge_address(host, *args, **kwargs):
        return resolve(
            "edge" if host in ("localhost", b"localhost") else host, *args, **kwargs
        )

    socket.getaddrinfo = edge_address
    context = ssl.create_default_context(cafile="/tmp/qualification-ca.crt")
    with database_probe_loop() as database_runner, httpx.Client(
        base_url="https://localhost", verify=context, timeout=45, trust_env=False
    ) as client:

        def request(method, path, code=200, **kwargs):
            response = client.request(method, path, **kwargs)
            assert response.status_code == code, (
                f"{method} {path}: expected {code}, got {response.status_code}"
            )
            return response

        liveness = request("GET", "/healthz")
        assert liveness.text.strip() == "healthy"
        assert liveness.headers["content-type"].startswith("text/plain")
        # Direct navigation and refresh must serve the SPA, including health
        # tabs. A 200 alone previously accepted the edge's plain-text probe.
        for route in ("/", "/health", "/health/devices", "/health/wan"):
            html = request("GET", route)
            assert html.headers["content-type"].startswith("text/html"), route
            assert 'id="root"' in html.text, route
            assert "default-src 'self'" in html.headers["content-security-policy"]
        checks.append("edge liveness and health dashboard deep links stay separate")
        request("GET", "/api/v1/health/ready")
        if mode == "seed":
            state["password"] = "Aa1!" + secrets.token_urlsafe(28)
            response = request(
                "POST",
                "/api/v1/setup/admin",
                json={
                    "email": "qualification@example.com",
                    "username": "qualification-admin",
                    "password": state["password"],
                    "first_name": "Release",
                    "last_name": "Qualification",
                    "organization_name": "Synthetic release acceptance",
                    "organization_slug": "synthetic-acceptance",
                },
            )
            assert response.json()["success"]
            state["user"] = response.json()["user_id"]
            state["organization"] = response.json()["organization_id"]
            state["bootstrap_site"] = response.json()["default_site_id"]
            assert state["organization"]
        request(
            "POST",
            "/api/v1/setup/admin",
            code=403,
            json={
                "email": "second@example.com",
                "username": "second-admin",
                "password": state["password"],
            },
        )
        request("GET", "/api/v1/auth/me", code=401)
        checks.extend(
            [
                "edge SPA/security headers",
                "database readiness",
                "bootstrap closed to anonymous users",
            ]
        )
        if mode == "recovered":
            request(
                "GET",
                "/api/v1/auth/me",
                code=401,
                headers={"Authorization": "Bearer " + state["access"]},
            )
            request(
                "POST",
                "/api/v1/auth/refresh",
                code=401,
                json={"refresh_token": state["refresh"]},
            )
            checks.append(
                "old access and refresh tokens denied after signing-key cutover"
            )
        response = request(
            "POST",
            "/api/v1/auth/login",
            json={"login": "qualification-admin", "password": state["password"]},
        )
        from app.core.cookies import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE

        access = response.cookies[ACCESS_COOKIE]
        refresh = response.cookies[REFRESH_COOKIE]
        assert all(
            "HttpOnly" in value and "Secure" in value
            for value in response.headers.get_list("set-cookie")
            if value.startswith((ACCESS_COOKIE + "=", REFRESH_COOKIE + "="))
        )
        headers = {
            "Origin": "https://localhost",
            "X-CSRF-Token": response.cookies[CSRF_COOKIE],
        }
        # Requests deliberately use the Secure cookie jar, not Bearer auth.
        request(
            "POST",
            "/api/v1/sla/reports/generate",
            code=403,
            headers={"Origin": "https://localhost", "X-CSRF-Token": "wrong"},
            json={
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-01-02T00:00:00Z",
                "format": "csv",
            },
        )
        assert (
            request("GET", "/api/v1/auth/me", headers=headers).json()["id"]
            == state["user"]
        )
        for path in (
            "/api/v1/dashboard/stats",
            "/api/v1/sites",
            "/api/v1/sla/reports",
            "/api/v1/sla/report-schedules",
        ):
            request("GET", path, headers=headers)
        checks.append(
            "verified HTTPS, real cookie session, CSRF refusal and authenticated dashboard/sites/report routes"
        )
        if mode == "seed":
            state["reports"] = []
            for fmt in ("csv", "pdf"):
                report = request(
                    "POST",
                    "/api/v1/sla/reports/generate",
                    code=201,
                    headers=headers,
                    json={
                        "period_start": "2026-01-01T00:00:00Z",
                        "period_end": "2026-01-02T00:00:00Z",
                        "format": fmt,
                        "title": "Synthetic acceptance " + fmt,
                    },
                ).json()
                assert report["file_path"] and report["file_size"] > 0
                body = request(
                    "GET",
                    "/api/v1/sla/reports/" + report["id"] + "/download",
                    headers=headers,
                ).content
                if fmt == "pdf":
                    assert body.startswith(b"%PDF-")
                else:
                    assert b"," in body
                state["reports"].append(
                    {
                        "id": report["id"],
                        "format": fmt,
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "bytes": len(body),
                    }
                )
            state["access"], state["refresh"] = access, refresh
        else:
            for report in state["reports"]:
                # Keep archive verification below the normal per-route limiter,
                # including after a 30-minute soak creates 180 report files.
                time.sleep(0.75)
                body = request(
                    "GET",
                    "/api/v1/sla/reports/" + report["id"] + "/download",
                    headers=headers,
                ).content
                assert hashlib.sha256(body).hexdigest() == report["sha256"]
        checks.append("PDF and CSV archive content")
        database_runner.run(database_content(state, mode == "seed"))
        checks.append("1,024 Timescale event payloads and original vault ciphertext")
        credential_response = request("GET", "/api/v1/credentials/", headers=headers)
        credential_rows = credential_response.json()
        owned_credentials = [
            row for row in credential_rows if row["name"] == "Offline qualification"
        ]
        assert len(owned_credentials) == 1
        assert owned_credentials[0]["credential_type"] == "username_password"
        assert "synthetic-offline-vault-value" not in credential_response.text
        assert not {
            "password", "encrypted_password", "api_key", "token", "snmp_community",
            "ssh_private_key", "certificate",
        }.intersection(owned_credentials[0])
        checks.append("stored credential remains API-readable without exposing secrets")
        # Real worker control via its configured broker, plus all five queues.
        from app.core.celery_app import celery_app

        replies = celery_app.control.inspect(timeout=10).active_queues()
        assert replies and len(replies) == 1
        queues = {q["name"] for group in replies.values() for q in group}
        assert queues == {"default", "discovery", "sync", "priority", "metrics"}
        checks.append("live Celery worker responds and consumes all five Lite queues")
        tasks = [
            celery_app.send_task(
                "app.tasks.maintenance.cleanup_token_revocations", queue=queue
            )
            for queue in sorted(queues)
        ]
        for task in tasks:
            result = task.get(timeout=45)
            assert result["success"] is True and result["deleted"] == 0
        checks.append(
            "real harmless maintenance task completes on each of the five queues"
        )
        if mode == "seed":
            from scheduled_backup_probe import run_scheduled_backup_acceptance

            state["scheduled_backup"] = run_scheduled_backup_acceptance(request, state, headers)
            database_runner.run(database_content(state, False))
            checks.append(
                "packaged scheduled backups, retention, disable, dry-run and real config restore; vault unchanged"
            )
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)
    print(
        "INSTALL_RESULT="
        + json.dumps(
            {
                "passed": True,
                "mode": mode,
                "checks": checks,
                "archive_bytes": {r["format"]: r["bytes"] for r in state["reports"]},
                "scheduled_backup": state.get("scheduled_backup"),
                "scheduled_backup_exercised_in_this_mode": mode == "seed",
            }
        )
    )


if __name__ == "__main__":
    main()
