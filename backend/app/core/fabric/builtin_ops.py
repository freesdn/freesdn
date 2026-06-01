# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — built-in core operations.

A small set of always-available, native, side-effect-safe **sink** operations
the Fabric itself provides (provider ``fabric``), so a Connection always has a
target even before any module declares one — e.g. "on <event> → notify". They
are read/non-device operations (no staging), org-scoped via the
:class:`OperationContext`.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from app.core.fabric.execution import OperationContext, OperationResult
from app.core.fabric.operations import EventSpec, Operation, OperationTier

logger = logging.getLogger(__name__)

# The platform-wide staged-change lifecycle stream. EVERY adapter device write
# (firewall/OPNsense, network/Omada, hypervisor/Proxmox, storage/TrueNAS, …)
# flows through AdapterStagingService, which emits these on the bus
# (app/services/adapter_staging.py). They are therefore the universal SOURCE for
# "something happened on a device": ``controller.change.applied`` with
# ``vendor`` discriminating which system. Declaring them here makes every
# vendor's write activity wireable as a Fabric trigger today, with no
# per-adapter work — e.g. "when an OPNsense change is applied → snapshot a
# Proxmox VM" is just a Connection conditioned on ``vendor == 'opnsense'``.
_CHANGE_PAYLOAD = {
    "type": "object",
    "properties": {
        "change_id": {"type": "string"},
        "controller_id": {"type": "string"},
        "feature": {"type": "string"},
        "operation": {"type": "string"},
        "target_id": {"type": ["string", "null"]},
        "vendor": {
            "type": "string",
            "description": "feature prefix: proxmox/opnsense/omada/truenas/…",
        },
        "status": {"type": "string"},
        "site_id": {"type": "string"},
        "applied_at": {"type": "string"},
        "actor_id": {"type": "string"},
    },
}

# The platform-wide device lifecycle stream. Core sync/discovery
# (app/tasks/sync.py, app/tasks/discovery.py) emit these on the bus for EVERY
# managed device across EVERY vendor/type (AP, switch, firewall, NVR, phone,
# hypervisor node, …) — so "a device went offline → snapshot the covering
# camera" or "a device came online → notify" is wireable platform-wide with no
# per-module work. ``data`` carries old_status/new_status/name/reason.
_DEVICE_PAYLOAD = {
    "type": "object",
    "properties": {
        "device_id": {"type": "string"},
        "site_id": {"type": "string"},
        "data": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "old_status": {"type": "string"},
                "new_status": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
    },
}


async def _notify_handler(ctx: OperationContext) -> OperationResult:
    """Dispatch a multi-channel notification (email/slack/in-app/webhook).

    ``params``: ``{channels: {...}, title: str, body: str}`` — ``channels`` is
    the same JSONB channel config the notification helper consumes. Org-scoped.
    """
    if ctx.db is None:
        return OperationResult.fail("notify requires a DB session", "NO_DB")
    channels = ctx.params.get("channels") or {}
    if not isinstance(channels, dict):
        return OperationResult.fail("notify 'channels' must be an object", "BAD_PARAMS")
    title = str(ctx.params.get("title") or "FreeSDN Fabric")[:200]
    body = str(ctx.params.get("body") or "")[:4000]
    try:
        from app.services.notification_helpers import dispatch_notifications

        results = await dispatch_notifications(ctx.db, channels, title, body, ctx.organization_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Fabric notify failed: %s", exc)
        return OperationResult.fail(f"notify dispatch failed: {exc}", "NOTIFY_ERROR")
    return OperationResult.ok(output={"dispatched": len(results) if results else 0})


async def _log_handler(ctx: OperationContext) -> OperationResult:
    """Emit a structured Fabric log line (a no-side-effect audit sink, useful
    for testing wiring and for record-only Connections)."""
    message = str(ctx.params.get("message") or "")[:2000]
    (ctx.logger or logger).info("Fabric log [org=%s]: %s", ctx.organization_id, message)
    return OperationResult.ok(output={"logged": True})


#: Cap on how much of an external response body we carry back into the chain.
_WEBHOOK_RESPONSE_CAP = 16 * 1024


async def _webhook_handler(ctx: OperationContext) -> OperationResult:
    """POST the chain's data to an external URL — the OUTBOUND half of the
    external-orchestration bridge (FreeSDN → n8n/Zapier/Make/Node-RED/…).

    ``params``: ``{url, method?, payload?, headers?}``. ``url`` is required;
    ``payload`` defaults to the source event (``ctx.trigger``) so "forward the
    event" needs no config. The request goes through ``safe_http_request`` —
    the same DNS-pinned, IP-validated SSRF guard the automation webhook action
    uses — so an operator-authored Connection can NEVER reach loopback, the
    cloud-metadata IP, or private ranges. The response status (and a bounded
    body) flow back into ``output`` so a later step can branch on them.
    """
    url = str(ctx.params.get("url") or "").strip()
    if not url:
        return OperationResult.fail("fabric.webhook requires 'url'", "NO_TARGET")
    method = str(ctx.params.get("method") or "POST").upper()
    if method not in ("POST", "PUT", "PATCH", "GET"):
        return OperationResult.fail(f"unsupported method {method!r}", "BAD_PARAMS")
    payload = ctx.params.get("payload")
    if payload is None:
        payload = ctx.trigger or {}
    headers = ctx.params.get("headers")
    headers = headers if isinstance(headers, dict) else None

    from app.core.config import settings
    from app.core.security_utils import safe_http_request

    # Deploy-owner trust list — lets fabric.webhook reach a self-hosted
    # n8n/HA/Node-RED on the LAN/tailnet (still DNS-pinned + TLS-verified).
    allow_hosts = frozenset(
        h.strip() for h in (settings.FABRIC_WEBHOOK_ALLOWED_HOSTS or "").split(",") if h.strip()
    )

    # Build the request body. When a signing secret is configured we serialize
    # the body ourselves and HMAC-sign the EXACT bytes (X-Fabric-Signature), so
    # the receiver can verify the callback genuinely came from FreeSDN. Without
    # a secret we let httpx serialize via ``json=`` (unsigned).
    send_kwargs: dict[str, Any] = {}
    out_headers = dict(headers) if headers else {}
    if method != "GET":
        secret = settings.FABRIC_WEBHOOK_SIGNING_SECRET or ""
        if secret:
            import json as _json
            import time as _time

            from app.core.security_utils import sign_webhook_payload

            raw = _json.dumps(payload, default=str).encode()
            ts = int(_time.time())
            out_headers.setdefault("Content-Type", "application/json")
            # Timestamp-bound signature (X-Fabric-Timestamp) so the receiver can
            # reject a replayed callback outside its skew window.
            out_headers["X-Fabric-Timestamp"] = str(ts)
            out_headers["X-Fabric-Signature"] = sign_webhook_payload(secret, raw, ts)
            send_kwargs["content"] = raw
        else:
            send_kwargs["json"] = payload
    try:
        resp = await safe_http_request(
            method,
            url,
            headers=out_headers or None,
            timeout=30.0,
            verify_tls=True,
            allow_hosts=allow_hosts,
            **send_kwargs,
        )
    except ValueError as exc:
        # SSRF guard / bad URL — refuse, don't leak which internal target.
        return OperationResult.fail(f"webhook refused: {exc}", "SSRF_BLOCKED")
    except Exception as exc:  # noqa: BLE001 — normalize transport errors
        return OperationResult.fail(f"webhook delivery failed: {exc}", "DELIVERY_ERROR")

    status = int(getattr(resp, "status_code", 0))
    body = ""
    with contextlib.suppress(Exception):
        body = (getattr(resp, "text", "") or "")[:_WEBHOOK_RESPONSE_CAP]
    ok = 200 <= status < 300
    out = {"status_code": status, "ok": ok, "response": body}
    return (
        OperationResult.ok(output=out)
        if ok
        else OperationResult.fail(f"webhook returned {status}", "BAD_STATUS")
    )


def builtin_operations() -> list[Operation]:
    """The Fabric's built-in native sink operations."""
    return [
        Operation(
            id="fabric.notify",
            title="Send notification",
            description="Dispatch a multi-channel notification (email/Slack/in-app/webhook).",
            input_schema={
                "type": "object",
                "properties": {
                    "channels": {"type": "object"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["channels"],
            },
            accepts=("application/json",),
            permission=None,  # safe, non-device sink; gated by Connection authorship
            write=False,
            handler=_notify_handler,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        Operation(
            id="fabric.log",
            title="Record a log line",
            description="Write a structured Fabric log entry (record-only sink).",
            input_schema={
                "type": "object",
                "properties": {"message": {"type": "string"}},
            },
            permission=None,
            write=False,
            handler=_log_handler,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        Operation(
            id="fabric.webhook",
            title="Call an external webhook",
            description=(
                "POST the chain's data to an external URL (n8n/Zapier/Make/…). "
                "SSRF-guarded; the response status + body flow back into the chain."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "External webhook URL (https)"},
                    "method": {
                        "type": "string",
                        "enum": ["POST", "PUT", "PATCH", "GET"],
                        "default": "POST",
                    },
                    "payload": {
                        "type": "object",
                        "description": "Body to send (defaults to the trigger event)",
                    },
                    "headers": {"type": "object", "description": "Optional extra request headers"},
                },
                "required": ["url"],
            },
            accepts=("application/json",),
            # permission=None ⇒ gated by Connection authorship (org-admin) AND
            # deliberately EXCLUDED from the AI-tool bridge — the assistant can
            # never auto-POST org data to an arbitrary URL; only a human wires it.
            permission=None,
            write=False,
            handler=_webhook_handler,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
    ]


def builtin_events() -> list[EventSpec]:
    """Platform-wide event SOURCES the Fabric always exposes.

    The staged-change lifecycle stream is the universal device-write trigger:
    any adapter write (any vendor) surfaces here, so an operator can wire
    cross-app reactions to device activity without each adapter declaring its
    own events. The ``vendor`` field discriminates the originating system.
    """
    return [
        EventSpec(
            event_type="controller.change.applied",
            title="Device change applied",
            description="A staged write succeeded against a device (vendor discriminates which).",
            payload_schema=_CHANGE_PAYLOAD,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        EventSpec(
            event_type="controller.change.staged",
            title="Device change staged",
            description="A write landed in the pending-changes queue awaiting operator sign-off.",
            payload_schema=_CHANGE_PAYLOAD,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        EventSpec(
            event_type="controller.change.failed",
            title="Device change failed",
            description="A staged write failed at the device or applier.",
            payload_schema=_CHANGE_PAYLOAD,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        # Platform-wide device lifecycle (core sync/discovery) — every vendor + type.
        EventSpec(
            event_type="device.status.changed",
            title="Device status changed",
            description="A managed device went online/offline (data.old_status → data.new_status).",
            payload_schema=_DEVICE_PAYLOAD,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        EventSpec(
            event_type="device.discovered",
            title="Device discovered",
            description="A new device was discovered/adopted on a controller.",
            payload_schema=_DEVICE_PAYLOAD,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        EventSpec(
            event_type="device.updated",
            title="Device updated",
            description="A managed device's record changed (rename, re-IP, firmware, …).",
            payload_schema=_DEVICE_PAYLOAD,
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
        # Inbound external-orchestration callback — the INBOUND half of the
        # bridge. An external system (n8n/Zapier/…) authenticates with an org
        # API key and POSTs to /fabric/ingest, which emits this event. Route
        # different callbacks via a condition on payload.name.
        EventSpec(
            event_type="ingest.external",
            title="External callback (ingest)",
            description="An external automation platform (n8n/Zapier/…) posted back via POST /fabric/ingest.",
            payload_schema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "operator label to route on (condition target)",
                    },
                    "data": {
                        "type": "object",
                        "description": "the JSON body the external system posted",
                    },
                },
            },
            tier=OperationTier.NATIVE,
            provider_id="fabric",
        ),
    ]
