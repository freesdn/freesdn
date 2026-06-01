# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway-VPN schemas
==============================

Pydantic models for the Omada-side VPN management API. These represent
configuration that runs ON the managed gateway (IPsec / OpenVPN / L2TP
/ PPTP / WireGuard / SSL-VPN / GRE), distinct from the existing
``/api/v1/vpn/*`` surface which manages FreeSDN's own internal VPN
overlay (Tailscale + WireGuard agents).

The schemas keep the actual config payload as a free-form ``dict`` so
new fields the controller adds (Wi-Fi 6E, v6 features, vendor-specific
tweaks) flow through without a schema migration. Validation is done at
the controller side; we trust callers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ──────────────────────────────────────────────────────────────────────
# Generic envelope used by every read-list endpoint
# ──────────────────────────────────────────────────────────────────────


class GatewayVPNListResponse(BaseModel):
    """List response shared by every VPN protocol."""

    controller_id: UUID
    site_id: UUID | None = None
    omada_site_id: str | None = None
    items: list[dict[str, Any]]
    fetched_at: datetime


class GatewayVPNDetailResponse(BaseModel):
    controller_id: UUID
    site_id: UUID | None = None
    omada_site_id: str | None = None
    item: dict[str, Any]
    fetched_at: datetime


# ──────────────────────────────────────────────────────────────────────
# Pending change (staging) responses
# ──────────────────────────────────────────────────────────────────────

ChangeStatus = Literal["pending", "applying", "applied", "discarded", "failed"]
ChangeOperation = Literal["create", "update", "delete"]


class PendingChangeRequest(BaseModel):
    """Body the UI submits when staging a write.

    The endpoint reads the dotted ``feature`` from the URL path
    (e.g. ``vpn.ipsec.policy``), so the request body just needs the
    payload + optional notes.

    Length bounds bound DoS / DB bloat — without them an authenticated
    user could POST 100 MB of JSON and inflate the
    ``adapter_pending_changes`` table indefinitely.

    Top-level ``extra="forbid"`` rejects unexpected keys at the staging
    boundary so a misspelled / hostile field never reaches the
    controller-side applier. Per-feature payload shapes are still
    validated by each service's ``build_applier``.
    """

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(
        default_factory=dict,
        # 256 KB serialised JSON is plenty for any single config op.
        # The pydantic validator on ``dict`` doesn't expose a direct
        # byte cap, but the request-body cap on the ASGI side gives
        # the actual bound; this annotation is documentation.
        #
        # Defaults to ``{}`` so DELETE operations (which carry no
        # payload — only ``target_id``) don't 422 on a missing field.
        # The frontend's
        # ``MikroTikFirewallTab.tsx`` delete dialog sends
        # ``{target_id: "*N"}`` with no payload, and the schema
        # previously rejected with 422 "body.payload required".
        description="Config payload to push when applied (≤ ~256 KB).",
    )
    target_id: str | None = Field(
        default=None,
        max_length=128,
        description=("Entity ID being modified for update / delete. Omit for create."),
    )
    notes: str | None = Field(
        default=None,
        max_length=2000,
        description="Free-text reason / change-management ticket reference.",
    )


class PendingChangeResponse(BaseModel):
    id: UUID
    organization_id: UUID
    # None for appliance-local daemon (overlay.*) writes, which target no
    # controller — see AdapterPendingChange.controller_id (migration 004).
    controller_id: UUID | None
    site_id: UUID | None
    omada_site_id: str | None
    feature: str
    operation: ChangeOperation
    target_id: str | None
    payload: dict[str, Any]
    status: ChangeStatus
    applied_at: datetime | None
    applied_response: dict[str, Any] | None
    failure_reason: str | None
    notes: str | None
    created_at: datetime
    created_by: UUID | None

    @classmethod
    def from_model(cls, change: Any) -> PendingChangeResponse:
        # Redact secrets from the staged ``payload`` and the
        # controller-echoed ``applied_response`` before they round-trip
        # back to API consumers. Without this, anyone with `*:read`
        # could enumerate pending changes and lift PSKs / RADIUS
        # secrets / WireGuard private keys / hotspot user passwords
        # / RouterOS user passwords that another operator submitted.
        # Particularly load-bearing for ``applied_response`` because
        # RouterOS / OPNsense routinely echo the request body back
        # on write endpoints, persisting plaintext secrets in the DB.
        from app.services.adapter_redaction import redact_secrets

        return cls(
            id=change.id,
            organization_id=change.organization_id,
            controller_id=change.controller_id,
            site_id=change.site_id,
            omada_site_id=change.omada_site_id,
            feature=change.feature,
            operation=change.operation,
            target_id=change.target_id,
            payload=redact_secrets(change.payload or {}),
            status=change.status,
            applied_at=change.applied_at,
            applied_response=(
                redact_secrets(change.applied_response)
                if change.applied_response is not None
                else None
            ),
            failure_reason=change.failure_reason,
            notes=change.notes,
            created_at=change.created_at,
            created_by=change.created_by,
        )


class ApplyPendingChangeRequest(BaseModel):
    """Body for ``POST /pending-changes/{id}/apply``.

    Refused unless ``OMADA_READ_ONLY=false`` AND ``force=true``. Both
    must be set so accidentally clicking Apply in production cannot
    write to the live controller.
    """

    model_config = ConfigDict(extra="forbid")

    force: bool = Field(
        default=False,
        description=(
            "Must be True. Combined with OMADA_READ_ONLY=false in the "
            "environment, this is the explicit opt-in to push the "
            "staged change to the live controller."
        ),
    )
    auto_reload: bool = Field(
        default=False,
        description=(
            "FreePBX only: when True, automatically run doreload after a "
            "successful pbx.* apply so the change goes live on Asterisk — but "
            "ONLY if there are zero active calls (otherwise the reload is "
            "skipped and the 'Apply Config' banner stays). Default False keeps "
            "the safe two-step behavior (apply now, operator reloads when "
            "ready)."
        ),
    )
    confirmed: bool = Field(
        default=False,
        description=(
            "Operator's deliberate sign-off for a CATASTROPHIC or destructive "
            "staged op (any delete, plus device restart/disable/upgrade and "
            "client forget). The vendor pre-flights refuse such ops unless the "
            "change carries confirmation; the apply chokepoint merges this flag "
            "into the staged payload as ``confirmed=true`` before the pre-flights "
            "run. Default False keeps non-destructive applies one-click. This is "
            "a second, op-aware gate ON TOP of force=true — force opens the apply "
            "lane, confirmed acknowledges the specific destructive op."
        ),
    )


# ──────────────────────────────────────────────────────────────────────
# Per-protocol convenience hints — used in the UI for form generation
# ──────────────────────────────────────────────────────────────────────


class IPsecPolicyHint(BaseModel):
    """Documentation-only Pydantic model that catalogs the fields the
    UI form should expose. Returned by ``GET /vpn/ipsec/schema`` so the
    frontend doesn't have to hard-code field lists."""

    name: str
    mode: Literal["siteToSite", "clientToSite"]
    ike_version: Literal["v1", "v2"] = "v2"
    local_subnet: str
    remote_subnet: str
    remote_gateway: str
    pre_shared_key: str
    ike_proposal: str | None = None
    ipsec_proposal: str | None = None
    perfect_forward_secrecy: bool = True
    dead_peer_detection: bool = True
    nat_traversal: bool = True


class WireGuardPeerHint(BaseModel):
    name: str
    public_key: str | None = Field(
        default=None,
        description=(
            "Peer's public key. Omit and the controller will generate a keypair for the peer."
        ),
    )
    preshared_key: str | None = None
    allowed_ips: list[str]
    persistent_keepalive: int = 25
    endpoint: str | None = Field(
        default=None,
        description="host:port for site-to-site mode. Omit for road-warrior peers.",
    )


# ──────────────────────────────────────────────────────────────────────
# Status / runtime info responses
# ──────────────────────────────────────────────────────────────────────


class VPNStatusEntry(BaseModel):
    """One active tunnel / connection."""

    name: str | None = None
    peer: str | None = None
    state: str | None = None
    bytes_rx: int | None = None
    bytes_tx: int | None = None
    last_handshake: datetime | None = None
    extra: dict[str, Any] | None = None


class VPNStatusResponse(BaseModel):
    protocol: Literal["ipsec", "openvpn", "l2tp", "pptp", "wireguard", "sslvpn", "gre"]
    controller_id: UUID
    site_id: UUID | None = None
    items: list[dict[str, Any]]
    fetched_at: datetime
