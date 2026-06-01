# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Module Events
==================================

Event definitions for the VoIP module.

Events are emitted by adapters (FreePBX AMI/ARI, Grandstream) and consumed
by the VoIP service layer, WebSocket broadcast, and Celery tasks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class VoIPEventType(StrEnum):
    """Types of VoIP events."""

    # ── Call events ────────────────────────────────────────────────────
    CALL_STARTED = "voip.call.started"
    CALL_ANSWERED = "voip.call.answered"
    CALL_ENDED = "voip.call.ended"
    CALL_TRANSFERRED = "voip.call.transferred"
    CALL_ON_HOLD = "voip.call.on_hold"
    CALL_RESUMED = "voip.call.resumed"
    CALL_FAILED = "voip.call.failed"

    # ── Extension events ───────────────────────────────────────────────
    EXTENSION_REGISTERED = "voip.extension.registered"
    EXTENSION_UNREGISTERED = "voip.extension.unregistered"
    EXTENSION_STATE_CHANGED = "voip.extension.state_changed"

    # ── Queue events ───────────────────────────────────────────────────
    QUEUE_CALLER_JOINED = "voip.queue.caller_joined"
    QUEUE_CALLER_LEFT = "voip.queue.caller_left"
    QUEUE_CALLER_ABANDONED = "voip.queue.caller_abandoned"
    QUEUE_MEMBER_ADDED = "voip.queue.member_added"
    QUEUE_MEMBER_REMOVED = "voip.queue.member_removed"
    QUEUE_MEMBER_PAUSED = "voip.queue.member_paused"

    # ── Phone events ───────────────────────────────────────────────────
    PHONE_ONLINE = "voip.phone.online"
    PHONE_OFFLINE = "voip.phone.offline"
    PHONE_REBOOTED = "voip.phone.rebooted"
    PHONE_PROVISIONED = "voip.phone.provisioned"
    PHONE_CONFIG_CHANGED = "voip.phone.config_changed"

    # ── PBX events ─────────────────────────────────────────────────────
    PBX_CONNECTED = "voip.pbx.connected"
    PBX_DISCONNECTED = "voip.pbx.disconnected"
    PBX_CONFIG_APPLIED = "voip.pbx.config_applied"
    PBX_RELOAD = "voip.pbx.reload"

    # ── Voicemail events ───────────────────────────────────────────────
    VOICEMAIL_RECEIVED = "voip.voicemail.received"
    VOICEMAIL_LISTENED = "voip.voicemail.listened"

    # ── Conference events ──────────────────────────────────────────────
    CONFERENCE_STARTED = "voip.conference.started"
    CONFERENCE_ENDED = "voip.conference.ended"
    CONFERENCE_PARTICIPANT_JOINED = "voip.conference.participant_joined"
    CONFERENCE_PARTICIPANT_LEFT = "voip.conference.participant_left"


@dataclass
class VoIPEvent:
    """
    A single VoIP event.

    Emitted by adapters and consumed by the event bus / WebSocket layer.
    """

    event_type: VoIPEventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = ""  # Adapter that produced the event (e.g., "freepbx", "grandstream")
    organization_id: str | None = None
    site_id: str | None = None

    # Event-specific payload
    data: dict[str, Any] = field(default_factory=dict)

    # Identifiers
    channel_id: str | None = None
    extension: str | None = None
    mac_address: str | None = None
    queue_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON / WebSocket broadcast.

        WebSocket sanitization (F-H12 fix): AMI/ARI events can carry
        secrets (recording paths leak voicemail PINs in the filename,
        ``Variable: PASSWORD=...`` headers leak SIP creds, etc.). We
        run ``data`` through ``_sanitize_payload`` from the WebSocket
        service so the broadcast strip-list applies uniformly. The
        toplevel identifiers (channel_id, extension, queue_name) are
        public by design and left untouched.
        """
        from app.services.websocket import _sanitize_payload

        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "organization_id": self.organization_id,
            "site_id": self.site_id,
            "data": _sanitize_payload(self.data),
            "channel_id": self.channel_id,
            "extension": self.extension,
            "mac_address": self.mac_address,
            "queue_name": self.queue_name,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Helper constructors for common events
# ═══════════════════════════════════════════════════════════════════════════════


def call_started_event(
    channel_id: str,
    caller: str,
    callee: str,
    direction: str = "internal",
    *,
    source: str = "freepbx",
) -> VoIPEvent:
    return VoIPEvent(
        event_type=VoIPEventType.CALL_STARTED,
        source=source,
        channel_id=channel_id,
        data={
            "caller": caller,
            "callee": callee,
            "direction": direction,
        },
    )


def call_ended_event(
    channel_id: str,
    duration: int,
    disposition: str = "ANSWERED",
    *,
    source: str = "freepbx",
) -> VoIPEvent:
    return VoIPEvent(
        event_type=VoIPEventType.CALL_ENDED,
        source=source,
        channel_id=channel_id,
        data={
            "duration": duration,
            "disposition": disposition,
        },
    )


def extension_state_event(
    extension: str,
    state: str,
    *,
    source: str = "freepbx",
) -> VoIPEvent:
    return VoIPEvent(
        event_type=VoIPEventType.EXTENSION_STATE_CHANGED,
        source=source,
        extension=extension,
        data={"state": state},
    )


def phone_provisioned_event(
    mac_address: str,
    extension: str = "",
    *,
    source: str = "grandstream",
) -> VoIPEvent:
    return VoIPEvent(
        event_type=VoIPEventType.PHONE_PROVISIONED,
        source=source,
        mac_address=mac_address,
        extension=extension,
        data={"mac_address": mac_address, "extension": extension},
    )


def queue_caller_event(
    event_type: VoIPEventType,
    queue_name: str,
    caller_id: str = "",
    position: int = 0,
    wait_time: int = 0,
    *,
    source: str = "freepbx",
) -> VoIPEvent:
    return VoIPEvent(
        event_type=event_type,
        source=source,
        queue_name=queue_name,
        data={
            "caller_id": caller_id,
            "position": position,
            "wait_time": wait_time,
        },
    )


# ── Operator-initiated write events ─
#
# The taxonomy + dataclass above represent ADAPTER-emitted events
# (AMI streaming, ARI websocket, phone status pings) that already
# flow through the WebSocket forwarder. The two helpers below are for
# OPERATOR-initiated writes (originate a call, reboot a phone,
# provision an extension, reload the PBX) which previously emitted
# nothing — they bypass AdapterStagingService AND the streaming-event
# layer because they aren't device-pushed, they're operator-pushed.
#
# Same publish_adapter_event helper the cameras module uses; one call
# per high-leverage write endpoint. Automation rules can match by
# adapter_id ("freepbx" / "grandstream") + action.

from app.core.events import (
    EventCategory as _CoreEventCategory,
)
from app.core.events import (
    EventPriority as _CoreEventPriority,
)
from app.core.events import (
    publish_adapter_event as _publish_adapter_event,
)


async def record_pbx_action(
    action: str,
    *,
    pbx_id: Any,
    adapter_id: str,
    organization_id: Any | None,
    outcome: str = "ok",
    priority: _CoreEventPriority = _CoreEventPriority.NORMAL,
    **extra: Any,
) -> None:
    """Emit ``pbx.<action>.<outcome>`` on the central event bus.

    Use after PBX-level operator writes: originate / hangup /
    transfer / reload / extension CRUD / trunk CRUD. Reload lifts to
    HIGH priority via the priority arg.
    """
    import logging

    try:
        await _publish_adapter_event(
            f"pbx.{action}.{outcome}",
            adapter_id=adapter_id,
            organization_id=(str(organization_id) if organization_id else None),
            category=_CoreEventCategory.DEVICE,
            priority=priority,
            pbx_id=str(pbx_id),
            **extra,
        )
    except Exception:
        logging.getLogger(__name__).debug(
            "pbx event publish skipped for action=%s pbx=%s",
            action,
            pbx_id,
            exc_info=True,
        )


async def record_phone_action(
    action: str,
    *,
    phone_id: Any,
    adapter_id: str,
    organization_id: Any | None,
    outcome: str = "ok",
    priority: _CoreEventPriority = _CoreEventPriority.NORMAL,
    **extra: Any,
) -> None:
    """Emit ``phone.<action>.<outcome>`` on the central event bus.

    Use after phone-level operator writes: provision / reboot /
    decommission / maintenance / firmware push. Reboot lifts to HIGH.
    """
    import logging

    try:
        await _publish_adapter_event(
            f"phone.{action}.{outcome}",
            adapter_id=adapter_id,
            organization_id=(str(organization_id) if organization_id else None),
            category=_CoreEventCategory.DEVICE,
            priority=priority,
            phone_id=str(phone_id),
            **extra,
        )
    except Exception:
        logging.getLogger(__name__).debug(
            "phone event publish skipped for action=%s phone=%s",
            action,
            phone_id,
            exc_info=True,
        )
