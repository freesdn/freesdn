# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real DB claims, X.509 material, provider HTTP contracts and TLS peer evidence."""

import asyncio
import ipaddress
import json
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from app.adapters.proxmox.client import ProxmoxClient, ProxmoxClientConfig
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.middleware import setup_exception_handlers
from app.core.site_access import current_user_var
from app.models.core import Controller, User
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import CertificateOperationRequest, CertificateReviewRequest
from app.services import hypervisor_certificates as certs
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_redaction import redact_secrets
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows
from tests.services.test_hypervisor_power import submit as submit_guest

UPID = "UPID:pve1:00001234:00ABCDEF:00000000:acmerenew::root@pam!audit:"


def material(
    *,
    days=30,
    future=False,
    ca=False,
    san=True,
    client_only=False,
    private=None,
    issuer=None,
    ipsan=False,
):
    key = private or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pve1.example.invalid")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.cert.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("pve1.example.invalid"),
                    *([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if ipsan else []),
                ]
            ),
            critical=False,
        )
    if client_only:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    cert = builder.sign(issuer.private if issuer else key, hashes.SHA256())
    return SimpleNamespace(
        cert=cert,
        private=key,
        pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        der=cert.public_bytes(serialization.Encoding.DER),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )


def row(name, cert):
    return {"filename": name, "pem": cert.pem, "fingerprint": cert.fingerprint}


@pytest.fixture
async def system(power, monkeypatch):
    c = power
    c.old, c.new, c.fallback, c.ca = material(), material(), material(), material(ca=True)
    c.state = SimpleNamespace(
        inventory=[
            row("pve-root-ca.pem", c.ca),
            row("pve-ssl.pem", c.fallback),
            row("pveproxy-ssl.pem", c.old),
        ],
        peer=c.old.der,
        status=[{"type": "node", "name": "pve1", "online": 1, "local": 1}],
        config={"acme": "account=default,domains=pve1.example.invalid"},
        writes=[],
        mode="accepted",
        unavailable=None,
        upid=UPID,
        task_status="stopped",
        exitstatus="OK",
        info_calls=0,
        race=False,
        entered=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def dispatch(request):
        state = c.state
        c.calls.append((request.method, request.url.path))
        if request.method != "GET":
            state.writes.append(request)
            state.entered.set()
            if state.mode == "wait":
                await state.release.wait()
            if state.mode == "timeout":
                raise httpx.ReadTimeout("private diagnostic", request=request)
            if state.mode == "reject":
                return httpx.Response(403, json={"errors": {"key": c.new.key}})
            if state.mode == "bad_ack":
                return httpx.Response(200, json={"data": {"key": c.new.key}})
            if state.mode != "unchanged":
                state.inventory = [
                    r for r in state.inventory if r["filename"] != "pveproxy-ssl.pem"
                ]
                if request.method != "DELETE":
                    state.inventory.append(row("pveproxy-ssl.pem", c.new))
                state.peer = c.fallback.der if request.method == "DELETE" else c.new.der
            if state.mode in {"stored", "missing_peer"}:
                state.peer = c.old.der if state.mode == "stored" else None
            ack = (
                state.upid
                if request.method == "PUT"
                else None
                if request.method == "DELETE"
                else {"fingerprint": c.new.fingerprint, "key": c.new.key}
            )
            return httpx.Response(200, json={"data": ack})
        if request.url.path == state.unavailable:
            return httpx.Response(403, json={"errors": {"reason": "private diagnostic"}})
        if request.url.path.endswith("/certificates/info"):
            state.info_calls += 1
            if state.race and state.info_calls == 3:
                state.peer = c.new.der
            stream = SimpleNamespace(
                get_extra_info=lambda _: SimpleNamespace(getpeercert=lambda **_: state.peer)
            )
            return httpx.Response(
                200, json={"data": state.inventory}, extensions={"network_stream": stream}
            )
        if "/tasks/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "upid": state.upid,
                        "node": "pve1",
                        "status": state.task_status,
                        "exitstatus": state.exitstatus,
                    }
                },
            )
        values = {
            "/cluster/status": state.status,
            "/nodes/pve1/config": state.config,
            "/cluster/resources": [{"vmid": 101, "status": "running"}],
        }
        assert request.url.path in values, request.url.path
        return httpx.Response(200, json={"data": values[request.url.path]})

    async def builder(_):
        return connected(dispatch)[0]

    monkeypatch.setattr(certs, "build_proxmox_adapter", builder)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    yield c


def options(c, action="upload", **extra):
    return CertificateReviewRequest(
        action=action,
        **(
            {"certificates": c.new.pem, "key": c.new.key, "overwrite": True}
            if action == "upload"
            else {}
        ),
        **extra,
    )


async def reviewed(c, action="upload", **extra):
    body = options(c, action, **extra)
    async with c.sessions() as db:
        review = await certs.HypervisorCertificateService(db, c.user).review(
            c.controller, "pve1", body
        )
    assert "PRIVATE KEY" not in json.dumps(review)
    return CertificateOperationRequest(
        **body.model_dump(),
        expected_digest=review["expected_digest"],
        request_id=c.request,
        force=True,
        confirmed=True,
    )


async def submit(c, body):
    async with c.sessions() as db:
        return await certs.HypervisorCertificateService(db, c.user).submit(
            c.controller, "pve1", body.action, body
        )


@pytest.mark.parametrize("action", certs.ACTIONS)
async def test_claim_replay_and_independent_completion(system, action):
    c = system
    body = await reviewed(c, action)
    receipt = await submit(c, body)
    assert receipt.status == "applied" and receipt.provider_task.status == "pending"
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1 and len(await rows(c)) == 1
    saved = (await rows(c))[0]
    assert (
        "PRIVATE KEY"
        not in json.dumps(saved.payload)
        + json.dumps(saved.applied_response)
        + receipt.model_dump_json()
    )
    assert c.new.key not in json.dumps(redact_secrets(saved.payload))
    if action == "upload":
        assert certs._key(saved, saved.payload) == c.new.key
        assert redact_secrets(saved.payload)["private_key"] != saved.payload["private_key"]
        wire = parse_qs(c.state.writes[0].content.decode())
        assert wire["key"] == [c.new.key] and wire["force"] == ["1"]
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] == "succeeded"
    assert saved.provider_task["detail"] == (
        "certificate_fallback_endpoint_verified"
        if action == "delete"
        else "certificate_endpoint_verified"
    )
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", certs.ACTIONS)
@pytest.mark.parametrize(
    "mode,expected",
    [
        ("timeout", "reconciliation_required"),
        ("reject", "failed"),
        ("bad_ack", "reconciliation_required"),
    ],
)
async def test_ambiguous_writes_are_not_replayed(system, action, mode, expected):
    c = system
    body = await reviewed(c, action)
    c.state.mode = mode
    result = await submit(c, body)
    assert result.status == expected
    assert (await submit(c, body)).change_id == result.change_id
    assert len(c.state.writes) == 1
    assert "PRIVATE KEY" not in str((await rows(c))[0].failure_reason)


@pytest.mark.parametrize("action", certs.ACTIONS)
@pytest.mark.parametrize("mode", ["unchanged", "missing_peer", "stored"])
async def test_stored_or_missing_state_is_never_false_success(system, action, mode):
    c = system
    body = await reviewed(c, action)
    c.state.mode = mode
    await submit(c, body)
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] in {"unknown", "pending"}
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("mode", ["stale", "race", "acme_config"])
async def test_changed_review_blocks_before_write(system, mode):
    c = system
    body = await reviewed(c, "renew" if mode == "acme_config" else "upload")
    if mode == "race":
        c.state.race = True
        assert (await submit(c, body)).status == "failed"
    else:
        if mode == "stale":
            c.state.peer = c.new.der
        else:
            c.state.config["acme"] = "account=different,domains=pve1.example.invalid"
        with pytest.raises(HTTPException) as e:
            await submit(c, body)
        assert e.value.status_code == 409
    assert not c.state.writes


@pytest.mark.parametrize(
    "mode",
    [
        "empty",
        "malformed",
        "duplicate",
        "fingerprint",
        "missing_fallback",
        "missing_custom",
        "offline",
        "missing_local",
    ],
)
async def test_incomplete_review_fails_closed(system, mode):
    c = system
    if mode == "empty":
        c.state.inventory = []
    if mode == "malformed":
        c.state.inventory = {}
    if mode == "duplicate":
        c.state.inventory.append(c.state.inventory[0])
    if mode == "fingerprint":
        c.state.inventory[-1]["fingerprint"] = "00"
    if mode == "missing_fallback":
        c.state.inventory.pop(1)
    if mode == "missing_custom":
        c.state.inventory.pop()
    if mode == "offline":
        c.state.status[0]["online"] = 0
    if mode == "missing_local":
        c.state.status[0].pop("local")
    with pytest.raises(HTTPException):
        await reviewed(c, "delete")
    assert not c.state.writes and not await rows(c)


@pytest.mark.parametrize(
    "mode",
    [
        "mismatch",
        "expired",
        "future",
        "ca",
        "no_san",
        "client_only",
        "weak_rsa",
        "pem_garbage",
        "key_garbage",
        "duplicate",
        "bad_issuer",
    ],
)
def test_invalid_key_pair_and_chain_are_rejected(mode):
    item = material(
        days=-1 if mode == "expired" else 30,
        future=mode == "future",
        ca=mode == "ca",
        san=mode != "no_san",
        client_only=mode == "client_only",
        private=rsa.generate_private_key(public_exponent=65537, key_size=1024)
        if mode == "weak_rsa"
        else None,
    )
    pem, key = item.pem, item.key
    if mode == "mismatch":
        key = material().key
    if mode == "pem_garbage":
        pem += key
    if mode == "key_garbage":
        key += "unparsed trailing data"
    if mode == "duplicate":
        pem += pem
    if mode == "bad_issuer":
        pem += material(ca=True).pem
    with pytest.raises(HTTPException) as e:
        certs.candidate(pem, key)
    assert e.value.status_code == 400 and key not in str(e.value)


def test_valid_supplied_chain_has_review_fingerprints():
    ca = material(ca=True)
    leaf = material(issuer=ca)
    pem, key, metadata = certs.candidate(leaf.pem + ca.pem, leaf.key)
    assert metadata["chain_fingerprints"] == [leaf.fingerprint, ca.fingerprint]
    assert pem == leaf.pem + ca.pem and key == leaf.key


@pytest.mark.parametrize(
    "field,value",
    [
        ("force", "true"),
        ("confirmed", 1),
        ("restart", "false"),
        ("overwrite", 1),
        ("acme_force", "yes"),
        ("extra", True),
    ],
)
def test_request_options_are_strict(field, value):
    body = {"action": "delete", "request_id": uuid4(), "expected_digest": "a" * 64, field: value}
    with pytest.raises(ValidationError):
        CertificateOperationRequest(**body)


@pytest.mark.parametrize("field", ["restart", "expected_digest", "key"])
async def test_reused_id_with_different_payload_conflicts(system, field):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    proposed = body.model_dump()
    proposed[field] = (
        True if field == "restart" else "b" * 64 if field == "expected_digest" else material().key
    )
    with pytest.raises(HTTPException):
        await submit(c, CertificateOperationRequest(**proposed))
    assert len(c.state.writes) == 1


async def test_encrypted_key_cannot_be_transplanted_or_staged_plaintext(system):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    saved = (await rows(c))[0]
    saved.id = uuid4()
    with pytest.raises(HTTPException):
        certs.validated_plan(saved)
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await AdapterStagingService(db).stage_change(
                organization_id=c.org,
                controller_id=c.controller,
                site_id=c.site,
                feature="proxmox.node.certificate_upload",
                operation="create",
                target_id="pve1",
                actor_id=c.user.id,
                payload={"certificates": c.new.pem, "key": c.new.key},
            )
    assert len(await rows(c)) == 1


async def test_concurrent_duplicate_only_dispatches_once(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    second = await submit(c, body)
    assert second.status == "applying"
    c.state.release.set()
    assert (await first).status == "applied" and len(c.state.writes) == 1


async def test_cancelled_request_retains_claim(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    task = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await submit(c, body)).status == "applying" and len(c.state.writes) == 1


async def test_certificate_blocks_guest_write_until_explicit_resolution(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "missing_peer"
    await submit(c, body)
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    # No restart requested: automatic observation expiry makes manual resolution available.
    async with c.sessions() as db:
        change = await db.get(AdapterPendingChange, saved.id)
        change.applied_at = datetime.now(UTC) - timedelta(days=8)
        change.provider_task_next_poll_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
    await tracking.poll_due_tasks()
    with pytest.raises(HTTPException) as e:
        await submit_guest(c, request_id=uuid4())
    assert e.value.status_code == 409
    saved = next(r for r in await rows(c) if r.id == saved.id)
    assert saved.provider_task["status"] == "unknown"
    async with c.sessions() as db:
        change = await AdapterStagingService(db).discard(
            saved.id, organization_id=c.org, force=True, actor_id=c.user.id
        )
        assert change.status == "discarded"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize(
    "upid",
    [
        UPID.replace("pve1", "pve2"),
        UPID.replace("acmerenew", "qmstart"),
        UPID.replace("acmerenew::", "acmerenew:101:"),
        "not-a-task",
    ],
)
async def test_renewal_rejects_mismatched_task_ack(system, upid):
    c = system
    body = await reviewed(c, "renew")
    c.state.upid = upid
    assert (await submit(c, body)).status == "reconciliation_required"


@pytest.mark.parametrize(
    "mode", ["read_error", "wrong_node", "old_cert", "wrong_san", "task_failure", "warnings"]
)
async def test_renewal_task_ok_is_insufficient(system, mode):
    c = system
    body = await reviewed(c, "renew")
    await submit(c, body)
    if mode == "read_error":
        c.state.unavailable = "/nodes/pve1/certificates/info"
    if mode == "wrong_node":
        c.state.status[0]["name"] = "pve2"
    if mode == "old_cert":
        c.state.inventory[-1] = row("pveproxy-ssl.pem", c.old)
    if mode == "wrong_san":
        c.state.config["acme"] = "domains=changed.example.invalid"
    if mode == "task_failure":
        c.state.exitstatus = "ERROR: failed"
    if mode == "warnings":
        c.state.exitstatus = "WARNINGS: 1"
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] == ("warnings" if mode == "warnings" else "unknown")


@pytest.mark.parametrize(
    "guard",
    ["accepted", "foreign_org", "site_grant", "scoped", "role", "read_only", "force", "confirm"],
)
async def test_http_authorization_and_no_secret_response(system, monkeypatch, guard):
    c = system
    body = await reviewed(c)
    c.calls.clear()
    user = (
        c.user
        if guard in {"accepted", "read_only", "force", "confirm"}
        else CurrentUser(
            User(
                id=c.user.id,
                organization_id=uuid4() if guard == "foreign_org" else c.org,
                role="viewer" if guard == "role" else "site_admin",
            ),
            ["*"],
            scoped=guard == "scoped",
            accessible_site_ids={uuid4()} if guard == "site_grant" else set(),
        )
    )
    if guard == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))

    async def auth():
        token = current_user_var.set(user)
        try:
            yield user
        finally:
            current_user_var.reset(token)

    async def session():
        async with c.sessions() as db:
            yield db

    app = FastAPI()
    setup_exception_handlers(app)
    app.include_router(api.router, prefix="/hypervisor")
    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    payload = body.model_dump(mode="json")
    payload["key"] = c.new.key
    if guard == "force":
        payload["force"] = False
    if guard == "confirm":
        payload["confirmed"] = False
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        url = f"/hypervisor/controllers/{c.controller}/nodes/pve1/certificates/custom"
        response = await client.post(url, json=payload)
        assert c.new.key not in response.text and "PRIVATE KEY" not in response.text
        if guard == "accepted":
            assert response.status_code == 202
            assert (await client.post(url, json={"key": c.new.key})).status_code == 422
        else:
            assert response.status_code in {403, 404, 409} and not c.calls


async def test_inactive_controller_cannot_observe_or_submit(system):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    async with c.sessions() as db:
        controller = await db.scalar(select(Controller).where(Controller.id == c.controller))
        controller.is_active = False
        await db.commit()
    c.calls.clear()
    await tracking.poll_due_tasks()
    assert not c.calls and (await rows(c))[0].provider_task["status"] == "unknown"
    with pytest.raises(HTTPException):
        await submit(c, body)


async def test_real_tls_peer_fingerprint_and_trust_failure(tmp_path):
    material_ = material(ipsan=True)
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    certfile.write_text(material_.pem)
    keyfile.write_text(material_.key)
    keyfile.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    clients = []

    async def serve(reader, writer):
        clients.append(writer)
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"data":[]}'
            )
            await writer.drain()
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    trust = ssl.create_default_context(cafile=str(certfile))
    # This isolated test trusts its fixture certificate and uses its DNS SAN.
    client = ProxmoxClient(ProxmoxClientConfig(host="127.0.0.1", port=port))
    client._authenticated = True
    try:
        client._http = httpx.AsyncClient(
            base_url=f"https://127.0.0.1:{port}", verify=trust, trust_env=False
        )
        data, fingerprint = await client.get_with_peer("/nodes/pve1/certificates/info")
        assert data == [] and fingerprint == material_.fingerprint
        await client._http.aclose()
        client._http = httpx.AsyncClient(
            base_url=f"https://127.0.0.1:{port}", verify=True, trust_env=False
        )
        with pytest.raises(Exception, match="Connection failed"):
            await client.get_with_peer("/nodes/pve1/certificates/info")
    finally:
        await client._http.aclose()
        server.close()
        await server.wait_closed()
        for writer in clients:
            writer.close()


@pytest.mark.parametrize("action", ["delete", "renew"])
async def test_literal_certificate_http_routes_require_reviewed_json(system, action):
    c = system
    body = await reviewed(c, action)

    async def auth():
        return c.user

    async def session():
        async with c.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        url = f"/hypervisor/controllers/{c.controller}/nodes/pve1/certificates/" + (
            "custom" if action == "delete" else "acme/renew"
        )
        method = "DELETE" if action == "delete" else "POST"
        assert (await client.request(method, url, params={"confirmed": True})).status_code == 422
        response = await client.request(method, url, json=body.model_dump(mode="json"))
        assert response.status_code == 202 and response.json()["action"] == action
    assert len(c.state.writes) == 1


async def test_guest_operation_blocks_certificate_dispatch(system):
    c = system
    await submit_guest(c, request_id=uuid4())
    body = await reviewed(c)
    with pytest.raises(HTTPException) as e:
        await submit(c, body)
    assert e.value.status_code == 409 and not c.state.writes


@pytest.mark.parametrize("failure", ["restart", "acme_force", "certificate", "key", "extra"])
def test_cross_action_options_rejected(failure):
    kwargs = {"action": "renew" if failure == "restart" else "delete"}
    kwargs[{"certificate": "certificates", "extra": "password"}.get(failure, failure)] = (
        "sensitive" if failure in {"certificate", "key", "extra"} else True
    )
    with pytest.raises(ValidationError):
        CertificateReviewRequest(**kwargs)


@pytest.mark.parametrize("kind", ["missing", "duplicate", "bad_domain", "wrong_type"])
async def test_invalid_acme_configuration_never_dispatches(system, kind):
    c = system
    c.state.config = {
        "missing": {},
        "duplicate": {
            "acme": "domains=pve1.example.invalid",
            "acmedomain0": "pve1.example.invalid",
        },
        "bad_domain": {"acme": "domains=invalid/path"},
        "wrong_type": {"acme": []},
    }[kind]
    with pytest.raises(HTTPException):
        await reviewed(c, "renew")
    assert not c.state.writes


async def test_native_options_remain_separate_from_apply_force(system):
    c = system
    body = await reviewed(c, "renew", acme_force=True)
    await submit(c, body)
    assert parse_qs(c.state.writes[0].content.decode()) == {"force": ["1"]}


async def test_restart_is_explicit_and_never_added_implicitly(system):
    c = system
    body = await reviewed(c, "delete", restart=True)
    await submit(c, body)
    assert dict(c.state.writes[0].url.params) == {"restart": "1"}


async def test_readback_exception_after_ok_task_cannot_leave_success(system, monkeypatch):
    c = system
    body = await reviewed(c, "renew")
    await submit(c, body)

    async def broken(*args):
        raise ValueError("fixture readback unavailable")

    monkeypatch.setattr(certs, "readback", broken)
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"


@pytest.mark.parametrize("action", certs.ACTIONS)
async def test_certificate_expiring_before_observation_stays_unknown(system, monkeypatch, action):
    c = system
    body = await reviewed(c, action)
    await submit(c, body)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(days=31)

    monkeypatch.setattr(certs, "datetime", Later)
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"
