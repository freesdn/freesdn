# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Reviewed TLS changes. Stored leaf and configured endpoint are separate evidence.

No automatic rollback, trust downgrade, key export or native retry. Proxmox has
no atomic digest precondition here. External operators remain outside our lock.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi import HTTPException
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.core.crypto import decrypt_credential, encrypt_credential
from app.core.dependencies import CurrentUser
from app.core.site_access import assert_site_access_for_request
from app.models.core import Controller, Site
from app.modules.hypervisor.schemas import (
    CertificateOperationRequest,
    CertificateOperationResponse,
    CertificateReviewRequest,
)
from app.schemas.gateway_vpn import ProviderTaskResponse
from app.services.adapter_preflight_common import payload_confirmed
from app.services.adapter_proxmox_vm import build_proxmox_adapter, close_proxmox_adapter
from app.services.hypervisor_operations import _REQUEST_NAMESPACE, HypervisorOperationService

ACTIONS = {
    "upload": ("proxmox.node.certificate_upload", "create"),
    "delete": ("proxmox.node.certificate_delete", "delete"),
    "renew": ("proxmox.node.acme_renew", "create"),
}
FEATURES = {f for f, _ in ACTIONS.values()}
_CONTROL = {"request_id", "expected_digest", "force", "confirmed", "key"}
_CUSTOM = "pveproxy-ssl.pem"
_FALLBACK = "pve-ssl.pem"
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----")


def _node(node: str) -> None:
    if (
        not isinstance(node, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node)
        or ".." in node
    ):
        raise HTTPException(400, detail="Invalid certificate node")


def _chain(pem: str) -> list[x509.Certificate]:
    if not isinstance(pem, str) or not 0 < len(pem) <= 65536:
        raise ValueError("certificate size")
    blocks = _PEM.findall(pem)
    if not 1 <= len(blocks) <= 8 or _PEM.sub("", pem).strip():
        raise ValueError("certificate PEM")
    return [x509.load_pem_x509_certificate(b.encode("ascii")) for b in blocks]


def _metadata(cert: x509.Certificate) -> dict[str, Any]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n.value).lower() for n in san if isinstance(n, (x509.DNSName, x509.IPAddress))]
    except x509.ExtensionNotFound:
        names = []
    return {
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "notbefore": int(cert.not_valid_before_utc.timestamp()),
        "notafter": int(cert.not_valid_after_utc.timestamp()),
        "san": sorted(set(names)),
    }


def _valid_server(cert: x509.Certificate, *, now: bool) -> None:
    if now and not cert.not_valid_before_utc <= datetime.now(UTC) < cert.not_valid_after_utc:
        raise ValueError("validity")
    if not _metadata(cert)["san"]:
        raise ValueError("SAN required")
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("CA leaf")
    except x509.ExtensionNotFound:
        pass
    try:
        if (
            ExtendedKeyUsageOID.SERVER_AUTH
            not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ):
            raise ValueError("server usage")
    except x509.ExtensionNotFound:
        pass
    try:
        if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            raise ValueError("signature usage")
    except x509.ExtensionNotFound:
        pass


def candidate(pem: str, key: str, *, now: bool = True) -> tuple[str, str, dict[str, Any]]:
    """Validate pair and supplied chain, not OS trust, hostname or revocation."""
    try:
        chain = _chain(pem)
        if (
            not isinstance(key, str)
            or not 0 < len(key) <= 32768
            or len(re.findall(r"-----BEGIN ", key)) != 1
        ):
            raise ValueError("key PEM")
        if not re.fullmatch(
            r"\s*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s+[A-Za-z0-9+/=\s]+-----END \1-----\s*",
            key,
        ):
            raise ValueError("key PEM envelope")
        private = serialization.load_pem_private_key(key.encode("ascii"), password=None)
        if not (
            (isinstance(private, rsa.RSAPrivateKey) and private.key_size >= 2048)
            or (isinstance(private, ec.EllipticCurvePrivateKey) and private.key_size >= 256)
        ):
            raise ValueError("unsupported or weak key")

        def public(k: Any) -> bytes:
            return bytes(
                k.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        if not hmac.compare_digest(public(private.public_key()), public(chain[0].public_key())):
            raise ValueError("key mismatch")
        _valid_server(chain[0], now=now)
        for cert in chain:
            algorithm = cert.signature_hash_algorithm
            if algorithm is not None and algorithm.digest_size < 32:
                raise ValueError("weak signature")
            if any(
                e.critical and isinstance(e.value, x509.UnrecognizedExtension)
                for e in cert.extensions
            ):
                raise ValueError("unknown critical extension")
        if len({c.fingerprint(hashes.SHA256()) for c in chain}) != len(chain):
            raise ValueError("duplicate chain certificate")
        for child, issuer in zip(chain, chain[1:], strict=False):
            child.verify_directly_issued_by(issuer)
            if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("issuer not CA")
            if (
                now
                and not issuer.not_valid_before_utc
                <= datetime.now(UTC)
                < issuer.not_valid_after_utc
            ):
                raise ValueError("issuer validity")
            try:
                if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                    raise ValueError("issuer usage")
            except x509.ExtensionNotFound:
                pass
        certs = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
        private_pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        return (
            certs,
            private_pem,
            {
                **_metadata(chain[0]),
                "chain_length": len(chain),
                "chain_fingerprints": [c.fingerprint(hashes.SHA256()).hex() for c in chain],
            },
        )
    except (
        ValueError,
        TypeError,
        UnicodeError,
        InvalidSignature,
        UnsupportedAlgorithm,
        x509.ExtensionNotFound,
    ):
        raise HTTPException(
            400,
            detail="Invalid certificate/key pair or supplied chain; require a valid RSA/EC server certificate with SANs and matching unencrypted key",
        ) from None


def _inventory(raw: Any) -> dict[str, dict[str, Any]]:
    try:
        if not isinstance(raw, list) or not raw or len(raw) > 3:
            raise ValueError("inventory")
        result = {}
        for row in raw:
            name = row["filename"]
            if name not in {_CUSTOM, _FALLBACK, "pve-root-ca.pem"} or name in result:
                raise ValueError("identity")
            chain = _chain(row["pem"])
            if len(chain) != 1:
                raise ValueError("leaf inventory")
            summary = _metadata(chain[0])
            if row["fingerprint"].replace(":", "").lower() != summary["fingerprint"]:
                raise ValueError("fingerprint mismatch")
            result[name] = summary
        if _FALLBACK not in result or "pve-root-ca.pem" not in result:
            raise ValueError("incomplete inventory")
        return result
    except (ValueError, TypeError, KeyError, AttributeError, UnsupportedAlgorithm):
        raise HTTPException(
            502, detail="Certificate inventory is incomplete or malformed"
        ) from None


def _acme(raw: Any) -> tuple[dict[str, str], list[str]]:
    try:
        if not isinstance(raw, dict):
            raise ValueError("config")
        fields = {
            k: v for k, v in raw.items() if k == "acme" or re.fullmatch(r"acmedomain[0-5]", k)
        }
        domains = []
        for name, value in fields.items():
            if not isinstance(value, str) or not 0 < len(value) <= 4096:
                raise ValueError("config field")
            properties = {}
            for part in value.split(","):
                key, val = part.split("=", 1) if "=" in part else ("domain", part)
                if key in properties:
                    raise ValueError("duplicate property")
                properties[key] = val
            if name == "acme":
                if not set(properties) <= {"account", "domains"}:
                    raise ValueError("acme properties")
                domains.extend(
                    properties.get("domains", "").split(";") if properties.get("domains") else []
                )
            else:
                if not set(properties) <= {"domain", "plugin", "alias"}:
                    raise ValueError("domain properties")
                domains.append(properties["domain"])
        domains = [d.lower() for d in domains]
        if (
            not domains
            or len(set(domains)) != len(domains)
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,252}", d) for d in domains)
        ):
            raise ValueError("domains")
        return fields, sorted(domains)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, detail="ACME domain configuration could not be reviewed") from None


async def review_state(
    adapter: Any, node: str, options: dict[str, Any], key: str = "", *, now: bool = True
) -> dict[str, Any]:
    _node(node)
    body = CertificateReviewRequest(**options, key=SecretStr(key))
    proposed = None
    if body.action == "upload":
        _, _, proposed = candidate(body.certificates, key, now=now)
    result = await adapter.get_certificate_operation_state(node, acme=body.action == "renew")
    if not result.success or not isinstance(result.data, dict):
        raise HTTPException(502, detail="Certificate review unavailable; no write was sent")
    raw = result.data
    inventory = _inventory(raw.get("certificates"))
    status = raw.get("status")
    if not isinstance(status, list) or not any(
        isinstance(n, dict)
        and n.get("type") == "node"
        and n.get("name") == node
        and n.get("online") == 1
        for n in status
    ):
        raise HTTPException(409, detail="Certificate target node is not demonstrably online")
    local = [
        n.get("name")
        for n in status
        if isinstance(n, dict) and n.get("type") == "node" and n.get("local") == 1
    ]
    if len(local) != 1 or not isinstance(local[0], str):
        raise HTTPException(502, detail="Configured endpoint node could not be identified")
    custom = inventory.get(_CUSTOM)
    if body.action in {"delete", "renew"} and custom is None:
        raise HTTPException(
            409, detail="A readable custom certificate is required; inspect the node manually"
        )
    if body.action == "upload" and custom is not None and not body.overwrite:
        raise HTTPException(
            409, detail="A custom certificate exists; explicitly review replacement"
        )
    config, domains = _acme(raw.get("config")) if body.action == "renew" else ({}, [])
    if body.action == "delete" and now:
        fallback = next(row for row in raw["certificates"] if row["filename"] == _FALLBACK)
        try:
            _valid_server(_chain(fallback["pem"])[0], now=True)
        except ValueError:
            raise HTTPException(
                409, detail="Fallback certificate is not currently usable"
            ) from None
    snapshot = {
        "node": node,
        "action": body.action,
        "inventory": inventory,
        "candidate": proposed,
        "overwrite": body.overwrite,
        "restart": body.restart,
        "acme_force": body.acme_force,
        "acme_configuration": config,
        "expected_domains": domains,
        "endpoint_node": local[0],
        "endpoint_fingerprint": raw.get("peer"),
    }
    digest = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {"expected_digest": digest, "snapshot": snapshot}


def is_reviewed_certificate(change: Any) -> bool:
    version = (change.payload or {}).get("certificate_version")
    return change.feature in FEATURES and type(version) is int and version == 1


def _key(change: Any, plan: dict[str, Any]) -> str:
    token = plan["private_key"]
    if not isinstance(token, str) or len(token) > 65536:
        raise ValueError("key envelope")
    if not token:
        return ""
    value = json.loads(decrypt_credential(token))
    if (
        not isinstance(value, dict)
        or set(value) != {"change_id", "key"}
        or value["change_id"] != str(change.id)
        or not isinstance(value["key"], str)
        or len(value["key"]) > 32768
    ):
        raise ValueError("key binding")
    return str(value["key"])


def same_payload(change: Any, proposed: dict[str, Any]) -> bool:
    old = change.payload or {}
    if {k: v for k, v in old.items() if k != "private_key"} != {
        k: v for k, v in proposed.items() if k != "private_key"
    }:
        return False
    try:
        return hmac.compare_digest(_key(change, old).encode(), _key(change, proposed).encode())
    except (ValueError, TypeError, KeyError):
        return False


def validated_plan(change: Any) -> dict[str, Any]:
    raw = {k: v for k, v in (change.payload or {}).items() if k != "confirmed"}
    try:
        if not is_reviewed_certificate(change) or set(raw) != {
            "certificate_version",
            "node",
            "expected_digest",
            "options",
            "private_key",
            "baseline",
        }:
            raise ValueError("contract")
        _node(raw["node"])
        if not isinstance(raw["options"], dict) or _CONTROL.intersection(raw["options"]):
            raise ValueError("options")
        body = CertificateOperationRequest(
            request_id=UUID(int=0),
            expected_digest=raw["expected_digest"],
            key=SecretStr(_key(change, raw)),
            **raw["options"],
        )
        if (
            (change.feature, change.operation) != ACTIONS[body.action]
            or change.target_id != raw["node"]
            or body.model_dump(exclude=_CONTROL) != raw["options"]
        ):
            raise ValueError("identity")
        baseline = raw["baseline"]
        if (
            not isinstance(baseline, dict)
            or set(baseline) != {"custom", "fallback", "domains"}
            or not re.fullmatch(r"[a-f0-9]{64}", baseline["fallback"])
            or (
                baseline["custom"] is not None
                and not re.fullmatch(r"[a-f0-9]{64}", baseline["custom"])
            )
            or not isinstance(baseline["domains"], list)
            or any(not isinstance(d, str) for d in baseline["domains"])
        ):
            raise ValueError("baseline")
        if body.action == "upload":
            candidate(body.certificates, body.key.get_secret_value(), now=False)
        return raw
    except (ValueError, TypeError, KeyError, AttributeError, HTTPException):
        raise HTTPException(
            400,
            detail="A bound reviewed certificate plan is required; legacy plaintext intents are refused",
        ) from None


def _baseline(review: dict[str, Any]) -> dict[str, Any]:
    snapshot = review["snapshot"]
    inventory = snapshot["inventory"]
    return {
        "custom": inventory.get(_CUSTOM, {}).get("fingerprint"),
        "fallback": inventory[_FALLBACK]["fingerprint"],
        "domains": snapshot["expected_domains"],
    }


def matches_task(upid: Any, node: str) -> bool:
    from app.services.proxmox_task_tracking import task_node

    return (
        isinstance(upid, str)
        and task_node(upid) == node
        and upid.split(":")[5:7] == ["acmerenew", ""]
    )


async def apply_certificate(domain: Any, change: Any) -> AdapterResult:
    plan = validated_plan(change)
    if not payload_confirmed(change.payload):
        raise HTTPException(409, detail="Certificate changes require explicit confirmation")
    target = (
        await domain.db.execute(
            select(Controller, Site)
            .join(Site, Site.id == Controller.site_id)
            .where(
                Controller.id == change.controller_id,
                Controller.controller_type.in_(("proxmox", "pve")),
                Controller.deleted_at.is_(None),
                Controller.is_active.is_(True),
                Controller.sync_enabled.is_(True),
                Site.organization_id == change.organization_id,
                Site.id == change.site_id,
                Site.deleted_at.is_(None),
                Site.is_active.is_(True),
            )
            .with_for_update(read=True, of=(Controller, Site))
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if target is None:
        raise HTTPException(404, detail="Active Proxmox controller not found")
    assert_site_access_for_request(target.Site.id, detail="site not found")
    adapter = None
    try:
        adapter = await build_proxmox_adapter(target.Controller)
        options, node, key = plan["options"], plan["node"], _key(change, plan)
        current = await review_state(adapter, node, options, key)
        if (
            current["expected_digest"] != plan["expected_digest"]
            or _baseline(current) != plan["baseline"]
        ):
            raise HTTPException(409, detail="Certificate state changed since review; review again")
        action = options["action"]
        if action == "upload":
            result = await adapter.upload_custom_certificate(
                node,
                options["certificates"],
                key,
                overwrite=options["overwrite"],
                restart=options["restart"],
                force=True,
            )
        elif action == "delete":
            result = await adapter.delete_custom_certificate(
                node, restart=options["restart"], force=True
            )
        else:
            result = await adapter.renew_node_acme_certificate(
                node, acme_force=options["acme_force"], force=True
            )
        if not result.success:
            return AdapterResult.fail("Provider rejected certificate operation")
        if action == "renew":
            upid = result.data.get("upid") if isinstance(result.data, dict) else None
            if matches_task(upid, node):
                return AdapterResult.ok({"upid": upid})
        elif action == "delete" and result.data is None:
            return AdapterResult.ok({"certificate_operation": action})
        elif action == "upload" and isinstance(result.data, dict):
            expected = current["snapshot"]["candidate"]["fingerprint"]
            fingerprint = result.data.get("fingerprint")
            if isinstance(fingerprint, str) and fingerprint.replace(":", "").lower() == expected:
                # Never persist the provider's raw response, which may echo keys.
                return AdapterResult.ok({"certificate_operation": action})
        raise AdapterOutcomeUnknownError(
            "Certificate acknowledgement is not verifiable", adapter_id="proxmox"
        )
    finally:
        if adapter is not None:
            await close_proxmox_adapter(adapter)


async def readback(adapter: Any, change: Any, upid: str | None) -> dict[str, str]:
    plan = validated_plan(change)
    action = plan["options"]["action"]
    unknown = {"status": "unknown", "detail": "certificate_not_verified"}
    if action == "renew" and not matches_task(upid, plan["node"]):
        return {"status": "unknown", "detail": "task_identity_mismatch"}
    result = await adapter.get_certificate_operation_state(plan["node"], acme=action == "renew")
    if not result.success or not isinstance(result.data, dict):
        return unknown
    raw = result.data
    inventory = _inventory(raw.get("certificates"))
    actual = inventory.get(_CUSTOM)
    expected = plan["baseline"]["fallback"]
    if action == "delete":
        fallback = inventory[_FALLBACK]
        if (
            actual is not None
            or fallback["fingerprint"] != expected
            or not fallback["notbefore"] <= datetime.now(UTC).timestamp() < fallback["notafter"]
        ):
            return unknown
    else:
        if actual is None:
            return unknown
        expected = actual["fingerprint"]
        if action == "upload":
            if expected != _metadata(_chain(plan["options"]["certificates"])[0])["fingerprint"]:
                return unknown
        elif (
            expected == plan["baseline"]["custom"]
            or actual["san"] != plan["baseline"]["domains"]
            or _acme(raw.get("config"))[1] != plan["baseline"]["domains"]
        ):
            return unknown
        if not actual["notbefore"] <= datetime.now(UTC).timestamp() < actual["notafter"]:
            return unknown
    status = raw.get("status")
    local = (
        [
            n.get("name")
            for n in status
            if isinstance(n, dict) and n.get("type") == "node" and n.get("local") == 1
        ]
        if isinstance(status, list)
        else []
    )
    if local != [plan["node"]]:
        return {"status": "unknown", "detail": "certificate_endpoint_requires_manual_verification"}
    if raw.get("peer") != expected:
        return {
            "status": "pending"
            if action != "renew" and not plan["options"]["restart"]
            else "unknown",
            "detail": "certificate_stored_activation_unverified",
        }
    # API omission alone never proves deletion. Require the reviewed fallback
    # at the configured TLS endpoint. This does not prove private-key erasure.
    return {
        "status": "succeeded",
        "detail": "certificate_fallback_endpoint_verified"
        if action == "delete"
        else "certificate_endpoint_verified",
    }


class HypervisorCertificateService:
    def __init__(self, db: AsyncSession, user: CurrentUser) -> None:
        self.ops = HypervisorOperationService(db, user)

    def _authorize(self) -> None:
        if self.ops.user.is_scoped or not self.ops.user.has_min_role("site_admin"):
            raise HTTPException(403, detail="An unscoped site-admin role is required")

    async def review(
        self, controller_id: UUID, node: str, body: CertificateReviewRequest
    ) -> dict[str, Any]:
        self._authorize()
        _node(node)
        ctrl, site = await self.ops._target(controller_id)
        assert_site_access_for_request(site.id, detail="site not found")
        adapter = None
        try:
            adapter = await build_proxmox_adapter(ctrl)
            return await review_state(
                adapter, node, body.model_dump(exclude=_CONTROL), body.key.get_secret_value()
            )
        finally:
            if adapter is not None:
                await close_proxmox_adapter(adapter)

    async def submit(
        self, controller_id: UUID, node: str, action: str, body: CertificateOperationRequest
    ) -> CertificateOperationResponse:
        from app.services.adapter_proxmox_node import GatewayProxmoxNodeService

        self._authorize()
        _node(node)
        if body.action != action:
            raise HTTPException(400, detail="Certificate action does not match endpoint")
        if body.force is not True or self.ops.staging.is_read_only():
            raise HTTPException(
                403, detail="Certificate changes require ADAPTER_READ_ONLY=false and force=true"
            )
        if body.confirmed is not True:
            raise HTTPException(409, detail="Certificate changes require explicit confirmation")
        _, site = await self.ops._target(controller_id)
        change_id = uuid5(
            _REQUEST_NAMESPACE, f"{site.organization_id}:{self.ops.user.id}:{body.request_id}"
        )
        existing = await self.ops._existing(change_id)
        options = body.model_dump(exclude=_CONTROL)
        key = body.key.get_secret_value()
        if action == "upload":
            options["certificates"], key, _ = candidate(
                body.certificates, key, now=existing is None
            )
        if existing is None:
            review = await self.review(controller_id, node, body)
            if review["expected_digest"] != body.expected_digest:
                raise HTTPException(
                    409, detail="Certificate state changed since review; review again"
                )
            baseline = _baseline(review)
        else:
            # Replays must not re-review changed provider state or repeat a write.
            # _record still compares every option, target, digest and decrypted key.
            saved_baseline = (existing.payload or {}).get("baseline")
            if not isinstance(saved_baseline, dict):
                raise HTTPException(409, detail="request_id belongs to a different operation")
            baseline = saved_baseline
        plan = {
            "certificate_version": 1,
            "node": node,
            "expected_digest": body.expected_digest,
            "options": options,
            "baseline": baseline,
            "private_key": encrypt_credential(json.dumps({"change_id": str(change_id), "key": key}))
            if key
            else "",
        }
        feature, operation = ACTIONS[action]
        change = await self.ops._record(
            controller_id, body.request_id, feature, operation, node, plan
        )
        if change.status == "pending":
            domain = GatewayProxmoxNodeService(self.ops.db)
            try:
                change = await self.ops.staging.apply_change(
                    change_id,
                    force=True,
                    confirmed=True,
                    actor_id=self.ops.user.id,
                    applier=self.ops.guard_applier(change, domain.build_applier(change)),
                )
            except HTTPException:
                saved = await self.ops._existing(change_id)
                if saved is None or saved.status == "pending":
                    raise
                change = saved
        return CertificateOperationResponse(
            action=action,
            target=node,
            request_id=body.request_id,
            change_id=change.id,
            status=change.status,
            provider_task=ProviderTaskResponse.model_validate(change.provider_task)
            if change.provider_task
            else None,
            message="Request recorded. Stored certificate and configured TLS endpoint require readback; keep console recovery access available.",
        )
