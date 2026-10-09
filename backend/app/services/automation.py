# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Automation Service
=================================

Rule-based automation engine for network operations.

Features:
- Event-triggered automation
- Scheduled tasks
- Condition evaluation
- Action chains
- Rate limiting and throttling
"""

import asyncio
import contextlib
import hashlib
import logging
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Union
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================


class TriggerType(StrEnum):
    """Types of automation triggers."""

    EVENT = "event"  # Triggered by system events
    SCHEDULE = "schedule"  # Cron-like schedule
    WEBHOOK = "webhook"  # External webhook
    MANUAL = "manual"  # Manual trigger
    THRESHOLD = "threshold"  # Metric threshold crossed


# Trigger types that have a LIVE driver. EVENT rules fire from the event bus
# (the engine subscribes on rule load); MANUAL rules fire via
# ``POST /automation/rules/{id}/trigger``. SCHEDULE / WEBHOOK / THRESHOLD have
# no driver yet, so they are neither offered to the UI nor accepted at rule
# creation — honest: never expose a trigger that would silently never fire.
IMPLEMENTED_TRIGGER_TYPES: frozenset[TriggerType] = frozenset(
    {TriggerType.EVENT, TriggerType.MANUAL}
)


class ActionType(StrEnum):
    """Types of automation actions."""

    # Device actions
    DEVICE_REBOOT = "device.reboot"
    DEVICE_POE_CYCLE = "device.poe_cycle"
    DEVICE_LOCATE = "device.locate"
    DEVICE_CONFIG = "device.config"

    # Camera actions (close the automation loop — rules can ACT on cameras,
    # not just be triggered by camera.alert.* events). Map 1:1 to Hikvision
    # adapter capabilities that already exist.
    CAMERA_PTZ = "camera.ptz"  # move / goto preset
    CAMERA_SNAPSHOT = "camera.snapshot"  # capture a still (for alert annotation)
    CAMERA_MOTION_DETECTION = "camera.motion_detection"  # enable/disable + sensitivity
    CAMERA_REBOOT = "camera.reboot"  # reboot the camera/NVR

    # Network actions
    NETWORK_BLOCK_CLIENT = "network.block_client"
    NETWORK_UNBLOCK_CLIENT = "network.unblock_client"
    NETWORK_QUARANTINE = "network.quarantine"

    # Alert actions
    ALERT_CREATE = "alert.create"
    ALERT_RESOLVE = "alert.resolve"

    # Notification actions
    NOTIFY_EMAIL = "notify.email"
    NOTIFY_WEBHOOK = "notify.webhook"
    NOTIFY_SLACK = "notify.slack"
    NOTIFY_IN_APP = "notify.in_app"

    # System actions
    SCRIPT_RUN = "script.run"
    API_CALL = "api.call"
    DELAY = "delay"

    # LLM actions (requires LLM governance)
    LLM_CLASSIFY = "llm.classify"
    LLM_EXTRACT = "llm.extract"
    LLM_SUMMARIZE = "llm.summarize"

    # Fabric operation — invoke ANY native catalog Operation (the universal
    # app-interconnect). The op is selected by params["operation_id"]; writes
    # STAGE through the dual-gate (never auto-applied). One additive enum member
    # converges the automation action plane onto the Fabric registry.
    FABRIC_OPERATION = "fabric.operation"


class ConditionOperator(StrEnum):
    """Operators for condition evaluation."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_EQUAL = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"  # Regex
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class RuleStatus(StrEnum):
    """Automation rule status."""

    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    ERROR = "error"


# =============================================================================
# Exceptions
# =============================================================================


class AutomationError(Exception):
    """Base automation error."""

    pass


class RuleEvaluationError(AutomationError):
    """Rule evaluation failed."""

    pass


class ActionExecutionError(AutomationError):
    """Action execution failed."""

    pass


class ThrottleError(AutomationError):
    """Action throttled."""

    pass


# =============================================================================
# Conditions
# =============================================================================


@dataclass
class Condition:
    """
    Condition for rule evaluation.

    Evaluates to true/false based on event data.
    """

    field: str  # Dot notation field path
    operator: ConditionOperator
    value: Any

    def evaluate(self, data: dict[str, Any]) -> bool:
        """Evaluate condition against data."""
        field_value = self._get_field_value(data, self.field)

        # Existence checks
        if self.operator == ConditionOperator.EXISTS:
            return field_value is not None
        if self.operator == ConditionOperator.NOT_EXISTS:
            return field_value is None

        if field_value is None:
            return False

        # Comparison operations
        match self.operator:
            case ConditionOperator.EQUALS:
                return bool(field_value == self.value)
            case ConditionOperator.NOT_EQUALS:
                return bool(field_value != self.value)
            case ConditionOperator.GREATER_THAN:
                return bool(field_value > self.value)
            case ConditionOperator.GREATER_EQUAL:
                return bool(field_value >= self.value)
            case ConditionOperator.LESS_THAN:
                return bool(field_value < self.value)
            case ConditionOperator.LESS_EQUAL:
                return bool(field_value <= self.value)
            case ConditionOperator.CONTAINS:
                return self.value in str(field_value)
            case ConditionOperator.NOT_CONTAINS:
                return self.value not in str(field_value)
            case ConditionOperator.MATCHES:
                # SECURITY: Use safe_regex to prevent ReDoS
                from app.core.security_utils import safe_regex

                try:
                    compiled = safe_regex(self.value, timeout_hint="condition pattern")
                    # Cap the matched input length: stdlib `re` has no execution
                    # timeout, and the safe_regex blocklist can't catch every
                    # catastrophic-backtracking pattern (e.g. (a+)+b). Bounding the
                    # input to 4 KB bounds the worst-case backtracking work so a
                    # crafted pattern can't hang the (synchronous) event loop in
                    # the automation engine.
                    return bool(compiled.match(str(field_value)[:4096]))
                except ValueError:
                    return False
            case ConditionOperator.IN:
                return field_value in self.value
            case ConditionOperator.NOT_IN:
                return field_value not in self.value
            case _:
                return False

    def _get_field_value(self, data: dict[str, Any], path: str) -> Any:
        """Extract value using dot notation path."""
        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Condition":
        return cls(
            field=data["field"],
            operator=ConditionOperator(data["operator"]),
            value=data["value"],
        )


@dataclass
class ConditionGroup:
    """Group of conditions with AND/OR logic."""

    conditions: list[Union[Condition, "ConditionGroup"]]
    logic: str = "and"  # "and" or "or"

    def evaluate(self, data: dict[str, Any]) -> bool:
        """Evaluate all conditions in the group."""
        if not self.conditions:
            return True

        results = [c.evaluate(data) for c in self.conditions]

        if self.logic == "and":
            return all(results)
        return any(results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "logic": self.logic,
            "conditions": [c.to_dict() for c in self.conditions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], _depth: int = 0) -> "ConditionGroup":
        # A-8: Limit recursion depth to prevent stack overflow from deeply-nested
        # user-supplied condition trees (max 10 nesting levels is more than enough).
        _MAX_DEPTH = 10
        if _depth > _MAX_DEPTH:
            raise ValueError(
                f"ConditionGroup nesting exceeds maximum depth ({_MAX_DEPTH}). "
                "Simplify the condition tree."
            )
        conditions: list[Condition | ConditionGroup] = []
        for item in data.get("conditions", []):
            if "logic" in item:
                conditions.append(cls.from_dict(item, _depth=_depth + 1))
            else:
                conditions.append(Condition.from_dict(item))
        return cls(conditions=conditions, logic=data.get("logic", "and"))


# =============================================================================
# Actions
# =============================================================================


@dataclass
class Action:
    """Automation action configuration."""

    action_type: ActionType
    params: dict[str, Any] = field(default_factory=dict)
    delay_seconds: int = 0
    continue_on_error: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "params": self.params,
            "delay_seconds": self.delay_seconds,
            "continue_on_error": self.continue_on_error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        return cls(
            action_type=ActionType(data["action_type"]),
            params=data.get("params", {}),
            delay_seconds=data.get("delay_seconds", 0),
            continue_on_error=data.get("continue_on_error", True),
        )


@dataclass
class ActionResult:
    """Result of an action execution."""

    success: bool
    action_type: ActionType
    execution_time_ms: float = 0
    output: dict[str, Any] | None = None
    error: str | None = None
    # Authority refusals stop the entire chain even when an action permits errors.
    stop_chain: bool = False


# =============================================================================
# Rules
# =============================================================================


@dataclass
class AutomationRule:
    """Automation rule definition."""

    id: UUID
    name: str
    description: str | None
    organization_id: UUID
    trigger_type: TriggerType
    trigger_config: dict[str, Any]
    conditions: ConditionGroup | None
    actions: list[Action]
    status: RuleStatus = RuleStatus.ACTIVE
    priority: int = 0
    cooldown_seconds: int = 60
    max_triggers_per_hour: int = 100
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None
    last_triggered: datetime | None = None
    trigger_count: int = 0
    # The rule AUTHOR. Threaded into action execution as actor_id so a
    # fabric.operation re-checks the author's CURRENT permission at fire time.
    # Without it actor_id is None and every fabric.operation rule fails closed.
    created_by: UUID | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "organization_id": str(self.organization_id),
            "trigger_type": self.trigger_type.value,
            "trigger_config": self.trigger_config,
            "conditions": self.conditions.to_dict() if self.conditions else None,
            "actions": [a.to_dict() for a in self.actions],
            "status": self.status.value,
            "priority": self.priority,
            "cooldown_seconds": self.cooldown_seconds,
            "max_triggers_per_hour": self.max_triggers_per_hour,
        }


@dataclass
class RuleExecution:
    """Record of a rule execution."""

    id: UUID
    rule_id: UUID
    triggered_at: datetime
    trigger_data: dict[str, Any]
    actions_executed: list[ActionResult]
    success: bool
    error: str | None = None
    duration_ms: float = 0


# =============================================================================
# Automation Engine
# =============================================================================

# A-2: Lua script for atomic sliding-window rate limit check.
# Redis executes Lua scripts as a single atomic unit — no other command
# can interleave between ZREMRANGEBYSCORE, ZCARD, and ZADD.  This closes
# the TOCTOU race where two concurrent workers both read count < limit and
# both insert, exceeding max_triggers_per_hour.
#
# Args: KEYS[1]=sorted-set key, ARGV[1]=window_start_ts, ARGV[2]=now_ts,
#       ARGV[3]=max_count, ARGV[4]=expire_seconds, ARGV[5]=unique attempt member
# Returns: 1 if the call is allowed (entry added), 0 if throttled.
_THROTTLE_LUA_SCRIPT = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now_ts = tonumber(ARGV[2])
local max_count = tonumber(ARGV[3])
local expire_secs = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
local count = redis.call('ZCARD', key)
if count < max_count then
    redis.call('ZADD', key, now_ts, ARGV[5])
    redis.call('EXPIRE', key, expire_secs)
    return 1
end
return 0
"""


async def _system_alert_rule_id(db: Any, org_id: Any) -> Any:
    """The system AlertRule that owns automation-generated alerts.

    ``Alert.rule_id`` is NOT NULL because an alert normally belongs to the
    alert rule that raised it. An automation rule is a different thing entirely,
    so there is no natural rule to point at -- and omitting it makes the insert
    fail outright, which is what ``alert.create`` did.

    One system rule per organization, created on first use, mirroring what
    ``PluginSettingsSDK``'s sibling does for plugin-generated alerts.
    """
    from sqlalchemy import select

    from app.models.alert_rules import AlertRule

    rule_name = "__automation_alerts"
    existing = await db.execute(
        select(AlertRule.id).where(
            AlertRule.organization_id == org_id,
            AlertRule.name == rule_name,
            AlertRule.is_system.is_(True),
            # A soft-deleted system rule must not be reused: alerts would hang
            # off a row the rest of the platform treats as gone. Recreating is
            # safe -- the name carries no unique constraint.
            AlertRule.alive(),
        )
    )
    rule_id = existing.scalar_one_or_none()
    if rule_id:
        return rule_id

    rule = AlertRule(
        organization_id=org_id,
        name=rule_name,
        description="System rule owning alerts raised by the automation engine.",
        rule_type="custom",
        status="active",
        severity="warning",
        is_system=True,
        conditions={},
    )
    db.add(rule)
    await db.flush()
    return rule.id


class AutomationEngine:
    """
    Rule-based automation engine.

    Evaluates rules against events and executes actions.
    """

    def __init__(self) -> None:
        self._rules: dict[UUID, AutomationRule] = {}
        self._action_handlers: dict[ActionType, Callable[..., Awaitable[Any]]] = {}
        self._event_subscriptions: dict[str, list[UUID]] = {}
        # rule_id -> name, for event rules that named no pattern
        self._unsubscribed_rules: dict[UUID, str] = {}
        # Latest coordination refusal on this worker. This is not an execution
        # record or durable fleet-wide history, and contains no event payload.
        self._coordination_blocks: dict[UUID, dict[str, str]] = {}
        self._lock = asyncio.Lock()  # protects _rules, _action_handlers, _event_subscriptions
        self._running = False
        self._subscription_id: str | None = None  # event bus subscription handle
        self._redis = None  # A-1: shared pool, created lazily on first use
        # Register built-in action handlers
        self._register_builtin_handlers()

        # Register LLM action handlers
        try:
            from app.services.automation_llm import register_llm_handlers

            register_llm_handlers(self)
        except Exception as e:
            logger.debug("LLM handlers not registered: %s", e)

    @property
    def unsubscribed_rules(self) -> dict[Any, str]:
        """Event rules that name no pattern, so they fire on nothing.

        Surfaced rather than only logged: "my rule does not fire" and "my rule
        fires on everything" are the two failure modes here, and an operator
        cannot tell either from the rule list.
        """
        return dict(self._unsubscribed_rules)

    def coordination_blocks(self, organization_id: UUID | None) -> list[dict[str, str]]:
        """Return only this organization's active rules refused on this worker."""
        if organization_id is None:
            return []
        return [
            {"rule_id": str(rule_id), **details}
            for rule_id, details in self._coordination_blocks.items()
            if (rule := self._rules.get(rule_id)) is not None
            and rule.organization_id == organization_id
            and rule.status == RuleStatus.ACTIVE
        ]

    def _coordination_refused(self, rule: AutomationRule, reason: str) -> None:
        previous = self._coordination_blocks.get(rule.id)
        if previous is None or previous["reason"] != reason:
            self._coordination_blocks[rule.id] = {
                "reason": reason,
                "since": datetime.now(UTC).isoformat(),
            }
            # Do not copy client exception strings, URLs or event data into logs.
            logger.warning("Automation rule %s refused: %s", rule.id, reason)

    def _register_builtin_handlers(self) -> None:
        """Register built-in action handlers for notifications and alerts."""

        async def _handle_notify_email(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.services.notification import NotificationChannel, NotificationService

            async with async_session_factory() as db:
                svc = NotificationService(db)
                result = await svc.send(
                    channel=NotificationChannel.EMAIL,
                    recipient=params.get("to", params.get("recipient", "")),
                    title=params.get("title", params.get("subject", "Automation Notification")),
                    body=params.get("body", params.get("message", "")),
                )
                return {"success": result.success, "error": result.error}

        async def _handle_notify_slack(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.services.notification import NotificationChannel, NotificationService

            async with async_session_factory() as db:
                svc = NotificationService(db)
                result = await svc.send(
                    channel=NotificationChannel.SLACK,
                    recipient=params.get("channel", params.get("recipient", "")),
                    title=params.get("title", "Automation Notification"),
                    body=params.get("body", params.get("message", "")),
                )
                return {"success": result.success, "error": result.error}

        async def _handle_notify_in_app(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.services.notification import NotificationChannel, NotificationService

            async with async_session_factory() as db:
                svc = NotificationService(db)
                result = await svc.send(
                    channel=NotificationChannel.IN_APP,
                    recipient=params.get("user_id", params.get("recipient", "")),
                    title=params.get("title", "Automation Notification"),
                    body=params.get("body", params.get("message", "")),
                )
                return {"success": result.success, "error": result.error}

        async def _handle_notify_webhook(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.services.notification import NotificationChannel, NotificationService

            async with async_session_factory() as db:
                svc = NotificationService(db)
                result = await svc.send(
                    channel=NotificationChannel.WEBHOOK,
                    recipient=params.get("url", params.get("recipient", "")),
                    title=params.get("title", "Automation Notification"),
                    body=params.get("body", params.get("message", "")),
                    data=params.get("data"),
                )
                return {"success": result.success, "error": result.error}

        async def _handle_alert_create(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.models.alert_rules import Alert

            async with async_session_factory() as db:
                context = params.get("__context__", {})
                # SECURITY: ``organization_id`` /
                # ``device_id`` / ``site_id`` MUST come from context
                # (the rule's owning org), NOT from action params. The
                # params come from the rule's ``actions[].params`` blob
                # which any ORG_ADMIN can write — letting params win
                # over context meant a rule in org A could ``alert.
                # create`` into org B with a forged ``organization_id``.
                org_id = context.get("organization_id")
                if not org_id:
                    return {"success": False, "error": "no organization context"}

                # ``Alert.rule_id`` is NOT NULL: an alert belongs to the
                # ALERT rule that raised it, which an AUTOMATION rule is not.
                # This handler omitted it, so every ``alert.create`` action
                # ever written died on the constraint -- the action has never
                # worked. The plugin SDK solved the same problem by attaching a
                # system AlertRule, so do the same rather than invent a second
                # answer.
                rule_id = await _system_alert_rule_id(db, org_id)

                severity = params.get("severity", "warning")
                title = params.get("title", "Automation Alert")

                # ``fingerprint`` is NOT NULL too -- a second constraint this
                # handler never satisfied. Two independent NOT NULL violations
                # is as close to proof as it gets that ``alert.create`` had
                # never once run successfully.
                #
                # It is the alert dedup key, so derive it from what identifies
                # THIS alert rather than filling it with a random value: two
                # firings of the same rule with the same title should collapse
                # onto one alert, which is the behaviour the column exists for.
                fingerprint = hashlib.sha256(
                    f"automation:{rule_id}:{title}:{severity}".encode()
                ).hexdigest()[:64]

                alert = Alert(
                    organization_id=org_id,
                    rule_id=rule_id,
                    fingerprint=fingerprint,
                    severity=severity,
                    title=title,
                    message=params.get("message", "Alert created by automation engine"),
                    device_id=context.get("device_id"),
                    site_id=context.get("site_id"),
                    source="automation",
                )
                db.add(alert)
                await db.commit()
                await db.refresh(alert)
                return {"success": True, "alert_id": str(alert.id)}

        async def _handle_alert_resolve(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.models.alert_rules import Alert
            from app.services.alert_rules import AlertRuleService

            # SECURITY: org-scope the resolve like alert.create / camera actions.
            # organization_id comes from __context__ (the rule's owning org), NEVER
            # from params. Without this an org-A rule could resolve ANY tenant's
            # alert by UUID — get_alert/resolve_alert are NOT org-filtered, while
            # the direct alert API enforces org. This path must match it.
            context = params.get("__context__", {})
            org_id = context.get("organization_id")
            alert_id = params.get("alert_id")
            if not alert_id:
                return {"success": False, "resolved": False, "error": "No alert_id provided"}
            if not org_id:
                return {"success": False, "resolved": False, "error": "no organization context"}
            aid = UUID(alert_id) if isinstance(alert_id, str) else alert_id
            async with async_session_factory() as db:
                alert = await db.get(Alert, aid)
                if alert is None or str(alert.organization_id) != str(org_id):
                    return {
                        "success": False,
                        "resolved": False,
                        "error": "alert not found in this organization",
                    }
                svc = AlertRuleService(db)
                result = await svc.resolve_alert(
                    aid,
                    # Automated resolution has no interactive user. The nullable
                    # FK records this honestly; an invented UUID violates it.
                    user_id=None,
                    note="Auto-resolved by automation engine",
                )
                if result is None:
                    return {
                        "success": False,
                        "resolved": False,
                        "error": "alert already resolved or unavailable",
                    }
                await db.commit()
                return {"success": True, "resolved": True}

        async def _resolve_camera_for_action(
            db: Any, params: dict[str, Any], permission: str, access: str
        ) -> Any:
            """Authorize the current rule author before opening a camera adapter.

            SECURITY: organization_id comes from __context__ (the rule's owning
            org), NEVER from params — same rule as alert.create. A rule can only
            act on cameras in its own org, even if params forge a camera_id.
            """
            from app.core.dependencies import CurrentUser, _get_user_by_id, _load_user_permissions
            from app.modules.cameras.api import _enforce_camera_access
            from app.modules.cameras.models import Camera

            context = params.get("__context__", {})
            org_id = context.get("organization_id")
            camera_id_str = params.get("camera_id")
            if not camera_id_str:
                return None, "camera_id required in action params"
            if not org_id:
                return None, "no organization context"
            actor_id = context.get("actor_id")
            if not actor_id:
                return None, "camera action requires a current rule author"
            try:
                # Resolve in this action's fresh session, including site grants.
                # Never accept identity or authorization supplied in action params.
                author = await _get_user_by_id(db, str(UUID(str(actor_id))))
                if (
                    author is None
                    or not author.is_active
                    or author.deleted_at is not None
                    or str(author.organization_id) != str(org_id)
                ):
                    return None, "camera action requires an active author in this organization"
                grants = author.site_access or []
                principal = CurrentUser(
                    author,
                    await _load_user_permissions(author),
                    accessible_site_ids={grant.site_id for grant in grants},
                    site_access_levels={grant.site_id: grant.access_level for grant in grants},
                )
                if not principal.has_permission(permission):
                    return None, "rule author no longer holds the required camera permission"
                cam = await db.get(
                    Camera, UUID(camera_id_str) if isinstance(camera_id_str, str) else camera_id_str
                )
                if (
                    cam is None
                    or str(cam.organization_id) != str(org_id)
                    or cam.deleted_at is not None
                ):
                    return None, "camera not found in this organization"
                if not principal.has_site_permission(permission, cam.site_id):
                    return None, "rule author lacks the required permission at this camera site"
                # Reuse the same site and per-camera/group grants as interactive
                # camera access. Lookup errors must not widen authority.
                await _enforce_camera_access(db, principal, cam.id, access)
                return cam, None
            except Exception:
                # DB/client errors can contain connection details. Refuse before
                # adapter creation without copying them into execution history.
                return None, "camera authorization denied or unavailable"

        async def _handle_camera_ptz(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.modules.cameras.api import _API_WRITE_FORCE, _get_adapter_for_camera

            async with async_session_factory() as db:
                cam, err = await _resolve_camera_for_action(db, params, "cameras.ptz", "ptz")
                if err:
                    return {"success": False, "error": err}
                adapter, channel = await _get_adapter_for_camera(cam, db)
                try:
                    action = params.get("ptz_action", params.get("action", "stop"))
                    preset = params.get("preset")
                    if action == "preset" and preset is not None:
                        result = await adapter.goto_preset(
                            device_id=str(cam.id),
                            preset=int(preset),
                            channel=channel,
                            force=_API_WRITE_FORCE,
                        )
                    else:
                        result = await adapter.ptz_control(
                            device_id=str(cam.id),
                            action=action,
                            speed=int(params.get("speed", 50)),
                            channel=channel,
                            force=_API_WRITE_FORCE,
                        )
                    ok = getattr(result, "success", True)
                    return {"success": bool(ok), "camera_id": str(cam.id), "action": action}
                finally:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

        async def _handle_camera_snapshot(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.modules.cameras.api import _get_adapter_for_camera

            async with async_session_factory() as db:
                cam, err = await _resolve_camera_for_action(db, params, "cameras.view", "live")
                if err:
                    return {"success": False, "error": err}
                adapter, channel = await _get_adapter_for_camera(cam, db)
                try:
                    img = await adapter.get_snapshot(device_id=str(cam.id), channel=channel)
                    n = len(img) if img else 0
                    return {"success": n > 0, "camera_id": str(cam.id), "bytes": n}
                finally:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

        async def _handle_camera_motion_detection(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.modules.cameras.api import _API_WRITE_FORCE, _get_adapter_for_camera

            async with async_session_factory() as db:
                cam, err = await _resolve_camera_for_action(
                    db, params, "cameras.manage", "configure"
                )
                if err:
                    return {"success": False, "error": err}
                adapter, channel = await _get_adapter_for_camera(cam, db)
                try:
                    cfg = {"enabled": bool(params.get("enabled", True))}
                    if params.get("sensitivity_level") is not None:
                        cfg["sensitivity_level"] = int(params["sensitivity_level"])
                    result = await adapter.set_motion_detection(
                        config=cfg,
                        channel=channel,
                        force=_API_WRITE_FORCE,
                    )
                    return {"success": getattr(result, "success", True), "camera_id": str(cam.id)}
                finally:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

        async def _handle_camera_reboot(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.modules.cameras.api import _API_WRITE_FORCE, _get_adapter_for_camera

            async with async_session_factory() as db:
                cam, err = await _resolve_camera_for_action(
                    db, params, "cameras.manage", "configure"
                )
                if err:
                    return {"success": False, "error": err}
                adapter, _channel = await _get_adapter_for_camera(cam, db)
                try:
                    result = await adapter.reboot_device(
                        device_id=str(cam.id),
                        force=_API_WRITE_FORCE,
                    )
                    return {"success": getattr(result, "success", True), "camera_id": str(cam.id)}
                finally:
                    with contextlib.suppress(Exception):
                        await adapter.disconnect()

        async def _handle_fabric_operation(params: dict[str, Any]) -> dict[str, Any]:
            """Invoke a native Fabric catalog Operation from an automation rule.

            The op is selected by ``operation_id``; ``operation_params`` becomes
            the OperationContext params. Org/actor come from the rule's
            ``__context__`` (NEVER from params — same audit invariant as
            ``_handle_alert_create``). Writes route through the executor's
            staging path (returns ``staged_change_id``, never auto-applied).
            Plugin ops are refused here — they reach automation via their own
            PluginAutomationBridge, not this native bridge.
            """
            from uuid import UUID

            from app.core.fabric.execution import OperationContext
            from app.core.fabric.executor import operation_executor
            from app.core.fabric.operations import OperationTier
            from app.core.fabric.registry import fabric_registry
            from app.core.fabric.runtime import fabric_permission_checker
            from app.db import async_session_factory

            context = params.get("__context__", {})
            org_raw = context.get("organization_id")
            if not org_raw:
                return {"success": False, "error": "no organization context"}
            operation_id = params.get("operation_id")
            if not operation_id:
                return {"success": False, "error": "operation_id is required"}
            op = fabric_registry.get_operation(str(operation_id))
            if op is None:
                return {"success": False, "error": f"unknown operation: {operation_id}"}
            # NATIVE ONLY, and this is not an oversight. A plugin operation is
            # a CATALOGUE PROJECTION: the registry advertises it so rules and
            # the assistant can see it exists, and it is executed by the
            # plugin's own per-(plugin, organization) runtime -- its REST routes
            # and event handlers -- never by the shared registry.
            #
            # The reason is tenancy. A plugin has ONE runtime instance PER
            # ORGANIZATION, but the Fabric registry is process-wide and holds
            # one Operation per id. A handler captured at registration time
            # belongs to whichever organization started the plugin first, so
            # invoking it from a rule in a DIFFERENT organization would run one
            # tenant's plugin instance against another tenant's context.
            #
            # I removed this gate once, believing it was incomplete wiring, and
            # immediately produced exactly that: a rule in org A ran a handler
            # bound to org B's runtime. The gate is the fix, not the problem.
            # Reaching a plugin from a rule needs a per-org handler lookup that
            # does not exist yet; until it does, use the plugin's own event
            # subscription (plugin -> rule works fine) or its REST route.
            if op.tier is not OperationTier.NATIVE:
                return {"success": False, "error": "operation is not native"}

            actor_raw = context.get("actor_id")
            # re-check the rule AUTHOR's CURRENT permission at fire
            # time — parity with Fabric Connections (which gate via the Negotiator's
            # fabric_permission_checker). A rule authored by an admin who was later
            # demoted, suspended, or moved out of the org must NOT keep executing
            # fabric ops under the stored actor_id. Fail closed (missing/inactive/
            # cross-org author or lost permission → deny).
            if op.permission and not await fabric_permission_checker(
                UUID(str(actor_raw)) if actor_raw else None,
                op.permission,
                UUID(str(org_raw)),
            ):
                return {
                    "success": False,
                    "error": "rule author no longer holds the required permission for this operation",
                }
            async with async_session_factory() as db:
                # The rule AUTHOR's site
                # grant, resolved from the stored actor_id -- an automation rule
                # runs on a schedule or an event, so there is no live principal
                # to take it from. This block already re-checks the author's
                # PERMISSION above; without the grant a site-limited author's
                # rule could still reach every site in the org.
                from app.core.site_access import resolve_actor_site_grants

                rule_actor = UUID(str(actor_raw)) if actor_raw else None
                ctx = OperationContext(
                    organization_id=UUID(str(org_raw)),
                    params=dict(params.get("operation_params") or {}),
                    actor_id=rule_actor,
                    db=db,
                    trigger=context.get("trigger_data", {}) or {},
                    logger=logging.getLogger("fabric.automation"),
                    accessible_site_ids=await resolve_actor_site_grants(db, rule_actor),
                )
                result = await operation_executor.execute(op, ctx)
                return result.to_dict()

        self.register_action_handler(ActionType.NOTIFY_EMAIL, _handle_notify_email)
        self.register_action_handler(ActionType.FABRIC_OPERATION, _handle_fabric_operation)
        self.register_action_handler(ActionType.NOTIFY_SLACK, _handle_notify_slack)
        self.register_action_handler(ActionType.NOTIFY_IN_APP, _handle_notify_in_app)
        self.register_action_handler(ActionType.NOTIFY_WEBHOOK, _handle_notify_webhook)
        self.register_action_handler(ActionType.ALERT_CREATE, _handle_alert_create)
        self.register_action_handler(ActionType.ALERT_RESOLVE, _handle_alert_resolve)
        self.register_action_handler(ActionType.CAMERA_PTZ, _handle_camera_ptz)
        self.register_action_handler(ActionType.CAMERA_SNAPSHOT, _handle_camera_snapshot)
        self.register_action_handler(
            ActionType.CAMERA_MOTION_DETECTION, _handle_camera_motion_detection
        )
        self.register_action_handler(ActionType.CAMERA_REBOOT, _handle_camera_reboot)

    def _get_redis(self) -> Any:
        """
        Return a shared Redis connection pool.

        A-1: Creating a new pool per call (aioredis.from_url inside every
        process_event × rule iteration) is extremely wasteful.  We create the
        pool once and reuse it for the lifetime of the engine.
        """
        if self._redis is None:
            from app.core.redis_client import get_async_redis

            self._redis = get_async_redis(decode_responses=True)
        return self._redis

    # =========================================================================
    # Rule Management
    # =========================================================================

    def _remove_rule_subscriptions(self, rule_id: UUID) -> None:
        """Remove every old index entry while the caller holds ``_lock``."""
        for pattern, rule_ids in list(self._event_subscriptions.items()):
            remaining = [rid for rid in rule_ids if rid != rule_id]
            if remaining:
                self._event_subscriptions[pattern] = remaining
            else:
                del self._event_subscriptions[pattern]
        self._unsubscribed_rules.pop(rule_id, None)

    async def register_rule(self, rule: AutomationRule) -> None:
        """Register an automation rule."""
        async with self._lock:
            # Reads hydrate existing rules too. Replacement must not accumulate
            # duplicate entries or leave the previous event pattern active.
            self._remove_rule_subscriptions(rule.id)
            self._rules[rule.id] = rule

            # Subscribe to events if event-triggered
            if rule.trigger_type == TriggerType.EVENT:
                event_pattern = str(rule.trigger_config.get("event_pattern") or "").strip()
                if not event_pattern:
                    # A rule that says "event" and names no event USED TO default
                    # to "*", so it fired on every event in the organisation.
                    # That is not a lenient default, it is the loudest possible
                    # behaviour: an operator writing "notify me when a device
                    # goes offline" got notifications for every controller sync,
                    # every discovery run, every alert -- and, once the collector
                    # began publishing, every warning-level syslog line from
                    # every device, with a 60-second cooldown as the only brake.
                    #
                    # The UI has no field for the pattern and posts an empty
                    # trigger_config, so EVERY event rule created through the web
                    # interface was in this state.
                    #
                    # Refused rather than silently narrowed: the rule stays in the
                    # database, does not fire, and says so. "*" is still a valid
                    # pattern -- it just has to be asked for.
                    logger.error(
                        "Automation rule %s (%s) is event-triggered but names no "
                        "event_pattern; it will NOT fire. Set trigger_config."
                        "event_pattern (use '*' if you really mean every event).",
                        rule.name,
                        rule.id,
                    )
                    self._unsubscribed_rules[rule.id] = rule.name
                else:
                    if event_pattern not in self._event_subscriptions:
                        self._event_subscriptions[event_pattern] = []
                    self._event_subscriptions[event_pattern].append(rule.id)

        logger.info("Registered automation rule: %s (%s)", rule.name, rule.id)

    async def unregister_rule(self, rule_id: UUID) -> bool:
        """Unregister an automation rule."""
        async with self._lock:
            if rule_id not in self._rules:
                return False

            rule = self._rules.pop(rule_id)
            # Remove all occurrences, including duplicates retained by an older
            # worker, so recreating the rule cannot revive an obsolete pattern.
            self._remove_rule_subscriptions(rule_id)
            self._coordination_blocks.pop(rule_id, None)

        logger.info("Unregistered automation rule: %s", rule.name)
        return True

    def get_rule(self, rule_id: UUID) -> AutomationRule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_rules(
        self,
        organization_id: UUID | None = None,
        status: RuleStatus | None = None,
    ) -> list[AutomationRule]:
        """Get rules with optional filters."""
        rules = list(self._rules.values())

        if organization_id:
            rules = [r for r in rules if r.organization_id == organization_id]
        if status:
            rules = [r for r in rules if r.status == status]

        return sorted(rules, key=lambda r: r.priority, reverse=True)

    async def update_rule_status(self, rule_id: UUID, status: RuleStatus) -> bool:
        """Update rule status."""
        async with self._lock:
            if rule_id not in self._rules:
                return False

            self._rules[rule_id].status = status
            self._rules[rule_id].updated_at = datetime.now(UTC)
            if status != RuleStatus.ACTIVE:
                self._coordination_blocks.pop(rule_id, None)
        return True

    # =========================================================================
    # Action Handlers
    # =========================================================================

    def register_action_handler(
        self,
        action_type: ActionType,
        handler: Callable[..., Awaitable[Any]],
    ) -> None:
        """Register an action handler (safe to call sync during init).

        The key must be a real ``ActionType``. A plain string looks like it
        works -- the dict accepts it and ``implemented_action_types()`` happily
        returns it -- but no rule can ever name it (``Action.from_dict`` coerces
        through the enum), and the rule-create endpoint formats this set with
        ``t.value``, so one str key turns its 422 into a 500. The plugin bridge
        used to do exactly that; refuse it here so the next caller finds out
        immediately instead of via a broken error path.
        """
        if not isinstance(action_type, ActionType):
            raise TypeError(
                f"action_type must be an ActionType, got {type(action_type).__name__}: "
                f"{action_type!r}. Plugin actions are not registered here -- they are "
                "projected into the Fabric catalogue instead."
            )
        self._action_handlers[action_type] = handler
        logger.debug("Registered action handler: %s", action_type)

    def implemented_action_types(self) -> set[ActionType]:
        """The action types that actually have a registered handler.

        Single source of truth for what the UI may offer and what rule
        creation accepts — derived from the live registry so it can never
        drift from the set of actions the engine can really execute.
        """
        return set(self._action_handlers)

    async def _authorize_action(self) -> bool:
        """Standalone evaluators have no persistent definition to revalidate."""
        return True

    async def _execute_action(
        self,
        action: Action,
        context: dict[str, Any],
    ) -> ActionResult:
        """Execute a single action."""
        start_time = datetime.now(UTC)

        handler = self._action_handlers.get(action.action_type)
        if not handler:
            return ActionResult(
                success=False,
                action_type=action.action_type,
                error=f"No handler for action type: {action.action_type}",
            )

        try:
            # Apply delay — A-10: cap to prevent indefinite blocking of the event loop
            _MAX_ACTION_DELAY = 300  # 5 minutes max pre-action delay
            if action.delay_seconds > 0:
                delay = min(action.delay_seconds, _MAX_ACTION_DELAY)
                await asyncio.sleep(delay)

            # Revalidate AFTER delay: revocation during a wait must prevent effects.
            if not await self._authorize_action():
                return ActionResult(
                    success=False,
                    action_type=action.action_type,
                    execution_time_ms=(datetime.now(UTC) - start_time).total_seconds() * 1000,
                    error="Automation definition changed or unavailable; action refused",
                    stop_chain=True,
                )

            # Merge context into params
            params = {**action.params, "__context__": context}

            # Execute handler
            output = await handler(params)

            duration = (datetime.now(UTC) - start_time).total_seconds() * 1000

            # A handler signals failure two ways: by RAISING, or by RETURNING
            # ``{"success": False, "error": ...}``. Only the first was honoured,
            # so every graceful failure was recorded as a successful action:
            #
            #   camera.ptz            the camera refused the move
            #   camera.snapshot       the capture failed
            #   camera.motion_detection / camera.reboot   likewise
            #   fabric.operation      unknown op, no org context, non-native op,
            #                         or the rule author having lost the
            #                         permission the op requires
            #
            # All eight of those paths return a failure dict, and the rule
            # history showed green for every one. An operator reading that
            # history has no way to know the action did nothing -- which is
            # strictly worse than a visible error, because it removes the
            # signal that something needs looking at.
            succeeded = True
            error: str | None = None
            if isinstance(output, dict) and output.get("success") is False:
                succeeded = False
                error = str(output.get("error") or "action reported failure")
                logger.warning(
                    "Automation action %s reported failure: %s", action.action_type, error
                )

            return ActionResult(
                success=succeeded,
                action_type=action.action_type,
                execution_time_ms=duration,
                output=output,
                error=error,
            )
        except Exception as e:
            logger.error("Action execution failed: %s - %s", action.action_type, e)
            duration = (datetime.now(UTC) - start_time).total_seconds() * 1000
            return ActionResult(
                success=False,
                action_type=action.action_type,
                execution_time_ms=duration,
                error=str(e),
            )

    # =========================================================================
    # Rule Evaluation
    # =========================================================================

    async def process_event(
        self,
        event_type: str,
        event_data: dict[str, Any],
        event_id: str | None = None,
        event_org_id: str | None = None,
    ) -> list[RuleExecution]:
        """
        Process an event and trigger matching rules.

        Args:
            event_type: Event type string
            event_data: Event payload
            event_id: Shared event ID for duplicate suppression while the Redis
                      claim remains present (300 seconds). This is not durable
                      exactly-once delivery or recovery after Redis state loss.

        Returns:
            List of rule executions
        """
        executions = []

        # Find matching rules
        matching_rules = await self._event_rules(event_type, event_org_id)

        # SECURITY (cross-tenant isolation): a rule fires ONLY on events from its
        # OWN organization. Events carry organization_id on the Event object; a
        # system event with no org fires NO org-scoped rule (fail-closed).
        # Without this, an Org-B rule would trigger on an Org-A event (matched by
        # event_type alone) and leak Org-A's payload via its notify/log/webhook
        # actions — the camera.status / ai.budget cross-tenant class.
        matching_rules = [
            r
            for r in matching_rules
            if event_org_id is not None and str(r.organization_id) == str(event_org_id)
        ]

        for rule in matching_rules:
            if rule.status != RuleStatus.ACTIVE:
                continue

            # Only a positively acknowledged shared claim authorizes an event
            # action. A timeout can follow a successful write: never delete the
            # uncertain claim or fall back to a worker-local decision. Native
            # camera actions are not all protected by the Fabric staging gate.
            if event_id:
                try:
                    r = self._get_redis()
                    idempotency_key = f"automation:exec:{rule.id}:{event_id}"
                    acquired = await r.set(idempotency_key, "1", nx=True, ex=300)
                    if acquired is False or acquired is None:
                        self._coordination_blocks.pop(rule.id, None)
                        logger.debug(
                            f"Idempotency skip: rule={rule.id} already processing event={event_id}"
                        )
                        continue
                    if acquired is not True:
                        self._coordination_refused(rule, "invalid event claim response")
                        continue
                except Exception:
                    self._coordination_refused(rule, "event claim unavailable or uncertain")
                    continue

            # Check throttling (Redis-backed, survives restarts)
            if not await self._check_throttle(rule):
                logger.debug("Rule %s throttled", rule.id)
                continue

            # Evaluate conditions
            if rule.conditions and not rule.conditions.evaluate(event_data):
                logger.debug("Rule %s conditions not met", rule.id)
                continue

            # Execute rule
            execution = await self._execute_rule(rule, event_data)
            executions.append(execution)

            # Update in-memory rule stats (DB stats updated by trigger_count column)
            rule.last_triggered = datetime.now(UTC)
            rule.trigger_count += 1

        return executions

    async def _event_rules(
        self, event_type: str, organization_id: str | None
    ) -> list[AutomationRule]:
        """Standalone evaluator selection; production overrides with committed reads."""
        return self._find_matching_rules(event_type)

    def _find_matching_rules(self, event_type: str) -> list[AutomationRule]:
        """Find rules that match an event type."""
        matching = []

        for pattern, rule_ids in self._event_subscriptions.items():
            if self._matches_pattern(event_type, pattern):
                for rule_id in rule_ids:
                    if rule := self._rules.get(rule_id):
                        matching.append(rule)

        # Sort by priority
        return sorted(matching, key=lambda r: r.priority, reverse=True)

    def _matches_pattern(self, event_type: str, pattern: str) -> bool:
        """Check if event type matches pattern (supports wildcards)."""
        if pattern == "*":
            return True

        # SECURITY: Use safe_regex for user-supplied patterns
        from app.core.security_utils import safe_regex

        regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
        try:
            compiled = safe_regex(f"^{regex_pattern}$", timeout_hint="event pattern")
            return bool(compiled.match(event_type))
        except ValueError:
            return False

    async def _check_throttle(self, rule: AutomationRule) -> bool:
        """
        Check if rule execution should be throttled.

        A-3 fix: cooldown is now Redis-backed so it is shared across all
        workers and survives restarts.  Previously, each worker maintained its
        own in-memory last_triggered; a restart reset the timer, allowing
        immediate re-execution. Now a Redis key with TTL = cooldown_seconds
        acts as the distributed lock.  Rate limiting also uses Redis.
        Unavailable or uncertain coordination refuses execution. A reserved
        claim/cooldown is not undone after a later failure; there is no automatic
        replay or exactly-once guarantee across state loss, eviction or restore.
        """
        now = datetime.now(UTC)

        # A-3: Cooldown — SET NX with TTL equal to cooldown_seconds.
        # Key present = still in cooldown (another worker already ran within window).
        if rule.cooldown_seconds > 0:
            try:
                r = self._get_redis()
                cooldown_key = f"automation:cooldown:{rule.id}"
                # Returns True if key was set (not in cooldown), False if already exists
                can_run = await r.set(cooldown_key, "1", nx=True, ex=rule.cooldown_seconds)
                if can_run is False or can_run is None:
                    self._coordination_blocks.pop(rule.id, None)
                    return False
                if can_run is not True:
                    self._coordination_refused(rule, "invalid cooldown response")
                    return False
            except Exception:
                self._coordination_refused(rule, "cooldown unavailable or uncertain")
                return False

        # A-2: Atomic sliding-window rate limit via Lua script.
        # The Lua script atomically removes stale entries, checks the count,
        # and only records this attempt if under the limit — eliminating the
        # TOCTOU race present in the old pipeline approach.
        try:
            r = self._get_redis()
            key = f"automation:throttle:{rule.id}"
            window_start = (now - timedelta(hours=1)).timestamp()
            now_ts = now.timestamp()

            result = await r.eval(
                _THROTTLE_LUA_SCRIPT,
                1,  # number of KEYS
                key,  # KEYS[1]
                window_start,  # ARGV[1]
                now_ts,  # ARGV[2]
                rule.max_triggers_per_hour,  # ARGV[3]
                3700,  # ARGV[4] — expire after 1h + buffer
                uuid4().hex,  # ARGV[5] — same-timestamp attempts must remain distinct
            )
            if type(result) is not int or result not in (0, 1):
                self._coordination_refused(rule, "invalid rate limit response")
                return False
            self._coordination_blocks.pop(rule.id, None)
            return result == 1
        except Exception:
            self._coordination_refused(rule, "rate limit unavailable or uncertain")
            return False

    async def _execute_rule(
        self,
        rule: AutomationRule,
        trigger_data: dict[str, Any],
    ) -> RuleExecution:
        """Execute a rule's action chain."""
        execution_id = uuid4()
        start_time = datetime.now(UTC)
        action_results: list[ActionResult] = []

        logger.info("Executing rule: %s (%s)", rule.name, rule.id)

        context = {
            "rule_id": str(rule.id),
            "execution_id": str(execution_id),
            "trigger_data": trigger_data,
            "organization_id": str(rule.organization_id),
            # Author identity for staged-write attribution (e.g. a fabric.operation
            # action that stages a device change is audited to the rule's author).
            "actor_id": str(rule.created_by) if getattr(rule, "created_by", None) else None,
        }

        overall_success = True
        error_message = None

        for action in rule.actions:
            result = await self._execute_action(action, context)
            action_results.append(result)

            if not result.success:
                overall_success = False
                if result.stop_chain or not action.continue_on_error:
                    error_message = f"Action {action.action_type} failed: {result.error}"
                    break

        duration = (datetime.now(UTC) - start_time).total_seconds() * 1000

        execution = RuleExecution(
            id=execution_id,
            rule_id=rule.id,
            triggered_at=start_time,
            trigger_data=trigger_data,
            actions_executed=action_results,
            success=overall_success,
            error=error_message,
            duration_ms=duration,
        )

        logger.info(
            f"Rule execution complete: {rule.name} - "
            f"success={overall_success}, duration={duration:.1f}ms"
        )

        # Persist execution record to database
        # Use a fresh session so this commit is independent of any parent transaction.
        # We deliberately do NOT let persistence failure abort the execution result.
        try:
            from app.db.session import AsyncSessionLocal
            from app.models.automation import AutomationExecutionRecord

            async with AsyncSessionLocal() as _session:
                record = AutomationExecutionRecord(
                    id=execution_id,
                    rule_id=rule.id,
                    organization_id=rule.organization_id,
                    triggered_at=start_time,
                    trigger_data=trigger_data,
                    actions_executed=[
                        {
                            "action_type": (
                                ar.action_type.value
                                if hasattr(ar.action_type, "value")
                                else str(ar.action_type)
                            ),
                            "success": ar.success,
                            "error": ar.error,
                            "execution_time_ms": ar.execution_time_ms,
                            "output": ar.output,
                        }
                        for ar in action_results
                    ],
                    success=overall_success,
                    error=error_message,
                    duration_ms=duration,
                )
                _session.add(record)
                # Also persist ``trigger_count`` + ``last_triggered``
                # on the rule. Previously these were only incremented
                # on the in-memory ``AutomationRule`` dataclass — every
                # worker had its own copy, counts diverged per process
                # and silently reset on every restart. The summary
                # endpoint always showed 0 triggers regardless of
                # actual activity.
                from sqlalchemy import update as _sa_update

                from app.models.automation import AutomationRuleRecord

                await _session.execute(
                    _sa_update(AutomationRuleRecord)
                    .where(AutomationRuleRecord.id == rule.id)
                    .values(
                        trigger_count=AutomationRuleRecord.trigger_count + 1,
                        last_triggered=start_time,
                    )
                )
                await _session.commit()
        except Exception:
            # DB driver errors can embed SQL parameters, including action payloads.
            logger.error("Failed to persist automation execution for rule %s", rule.id)

        return execution

    # =========================================================================
    # Manual Triggers
    # =========================================================================

    async def trigger_rule(
        self,
        rule_id: UUID,
        data: dict[str, Any] | None = None,
        *,
        organization_id: UUID | None = None,
    ) -> RuleExecution | None:
        """Manually trigger a rule in a standalone evaluator."""
        rule = self._rules.get(rule_id)
        if not rule or (organization_id is not None and rule.organization_id != organization_id):
            return None

        return await self._execute_rule(rule, data or {})

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def start(self) -> None:
        """Start the automation engine."""
        if self._running:
            return

        self._running = True

        # Subscribe to event bus with correct Event-object handler signature.
        # The event bus calls handlers as: await handler(event: Event)
        # Pass event.id for idempotency protection across workers.
        from app.core.events import event_bus

        async def handle_event(event: Any) -> None:
            if not self._running:
                return
            try:
                await self.process_event(
                    event.event_type,
                    event.payload,
                    event_id=event.id,
                    event_org_id=getattr(event, "organization_id", None),
                )
            except Exception as exc:
                logger.error(
                    "Automation engine error processing event %s: %s", event.event_type, exc
                )

        self._subscription_id = event_bus.subscribe("*", handle_event)
        logger.info("Automation engine started")

    async def stop(self) -> None:
        """Stop the automation engine."""
        self._running = False
        if self._subscription_id:
            try:
                from app.core.events import event_bus

                event_bus.unsubscribe(self._subscription_id)
            except Exception:
                logger.warning(
                    "Failed to unsubscribe from event bus (sub=%s)",
                    self._subscription_id,
                    exc_info=True,
                )
            self._subscription_id = None
        logger.info("Automation engine stopped")


# =============================================================================
# Default Action Handlers
# =============================================================================


async def handle_device_reboot(params: dict[str, Any]) -> dict[str, Any]:
    """Handle device reboot action."""
    device_id = params.get("device_id")
    if not device_id:
        raise ActionExecutionError("device_id required")

    from app.db.session import AsyncSessionLocal
    from app.services.device_control import DeviceControlService

    async with AsyncSessionLocal() as db:
        svc = DeviceControlService(db)
        await svc.reboot_device(UUID(device_id))
        await db.commit()

    return {"device_id": device_id, "status": "reboot_initiated"}


async def handle_notify_webhook(params: dict[str, Any]) -> dict[str, Any]:
    """Handle webhook notification action."""
    from app.core.security_utils import safe_http_request

    url = params.get("url")
    payload = params.get("payload", {})

    if not url:
        raise ActionExecutionError("url required")

    # DNS-rebinding-safe request (hostname pinned to validated IP)
    try:
        response = await safe_http_request("POST", url, json=payload, timeout=30.0)
    except ValueError as ssrf_err:
        raise ActionExecutionError(f"SSRF blocked: {ssrf_err}") from ssrf_err
    response.raise_for_status()

    return {"status_code": response.status_code}


async def handle_delay(params: dict[str, Any]) -> dict[str, Any]:
    """Handle delay action."""
    seconds = params.get("seconds", 0)
    # SECURITY: Cap delay to prevent indefinite sleep
    MAX_DELAY_SECONDS = 3600  # 1 hour
    if seconds > MAX_DELAY_SECONDS:
        seconds = MAX_DELAY_SECONDS
    if seconds < 0:
        seconds = 0
    await asyncio.sleep(seconds)
    return {"delayed_seconds": seconds}


# =============================================================================
# Service Class
# =============================================================================


class AutomationService:
    """
    Automation service for managing rules.

    Wraps the automation engine with database persistence.
    """

    def __init__(self, db: Any, engine: AutomationEngine | None = None) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession

        self.db: AsyncSession = db
        self.engine = engine or _PersistentAutomationEngine()

    @staticmethod
    def _rule_from_record(rec: Any) -> AutomationRule:
        """Convert a persisted ``AutomationRuleRecord`` into an engine ``AutomationRule``.

        THE SINGLE conversion. There used to be two hand-written copies -- one in
        ``get_rule`` and one in ``_load_rules_from_db`` -- and they drifted: the
        hydration copy omitted ``created_by``. Startup calls ``_load_rules_from_db``
        (main.py), so after every restart every rule was resurrected with no author,
        ``_execute_rule`` put ``actor_id=None`` in the action context, and
        ``_handle_fabric_operation`` re-checked the author permission with
        ``fabric_permission_checker(None, ...)`` -- which fails closed. Every
        permission-bearing fabric.operation rule silently reported "rule author no
        longer holds the required permission" and did nothing, until an admin
        happened to open the rule in the UI (``get_rule`` warms the engine with the
        good copy, incidentally repairing that one object). Keep this the only
        record -> rule conversion; ``tests/services/test_automation_hydration.py``
        pins the two entry points to identical output.
        """
        return AutomationRule(
            id=rec.id,
            name=rec.name,
            description=rec.description,
            organization_id=rec.organization_id,
            trigger_type=TriggerType(rec.trigger_type),
            trigger_config=rec.trigger_config or {},
            conditions=ConditionGroup.from_dict(rec.conditions) if rec.conditions else None,
            actions=[Action.from_dict(a) for a in (rec.actions or [])],
            status=RuleStatus(rec.status),
            priority=rec.priority,
            cooldown_seconds=rec.cooldown_seconds,
            max_triggers_per_hour=rec.max_triggers_per_hour,
            created_at=rec.created_at,
            updated_at=rec.updated_at,
            last_triggered=rec.last_triggered,
            trigger_count=rec.trigger_count,
            # The rule AUTHOR. Dropping this here is what broke fabric rules on
            # restart -- see the docstring. Any new field belongs here too.
            created_by=rec.created_by,
        )

    async def _load_rules_from_db(self, organization_id: UUID | None = None) -> None:
        """Load rules from database into the in-memory engine."""
        from sqlalchemy import and_, select

        from app.models.automation import AutomationRuleRecord

        conditions = []
        if organization_id:
            conditions.append(AutomationRuleRecord.organization_id == organization_id)
        conditions.append(AutomationRuleRecord.status == RuleStatus.ACTIVE.value)

        result = await self.db.execute(select(AutomationRuleRecord).where(and_(*conditions)))
        records = result.scalars().all()

        for rec in records:
            if rec.id not in self.engine._rules:
                await self.engine.register_rule(self._rule_from_record(rec))

    async def create_rule(
        self,
        name: str,
        organization_id: UUID,
        trigger_type: TriggerType,
        trigger_config: dict[str, Any],
        actions: list[dict[str, Any]],
        conditions: dict[str, Any] | None = None,
        description: str | None = None,
        priority: int = 0,
        cooldown_seconds: int = 60,
        max_triggers_per_hour: int = 100,
        created_by: UUID | None = None,
    ) -> AutomationRule:
        """Create a new automation rule."""
        from app.models.automation import AutomationRuleRecord

        rule = AutomationRule(
            id=uuid4(),
            name=name,
            description=description,
            organization_id=organization_id,
            trigger_type=trigger_type,
            trigger_config=trigger_config,
            conditions=ConditionGroup.from_dict(conditions) if conditions else None,
            actions=[Action.from_dict(a) for a in actions],
            priority=priority,
            cooldown_seconds=cooldown_seconds,
            max_triggers_per_hour=max_triggers_per_hour,
            created_by=created_by,
        )

        # Persist to database
        record = AutomationRuleRecord(
            id=rule.id,
            organization_id=organization_id,
            name=name,
            description=description,
            trigger_type=trigger_type.value,
            trigger_config=trigger_config,
            conditions=conditions,
            actions=actions,
            status=RuleStatus.ACTIVE.value,
            priority=priority,
            cooldown_seconds=cooldown_seconds,
            max_triggers_per_hour=max_triggers_per_hour,
            created_by=created_by,
        )
        self.db.add(record)
        await self.db.flush()

        # Register with engine
        await self.engine.register_rule(rule)

        return rule

    async def get_rule(self, rule_id: UUID) -> AutomationRule | None:
        """Get a rule by ID. Falls back to database if not in memory."""
        rule = self.engine.get_rule(rule_id)
        if rule:
            return rule

        # Try loading from database
        from sqlalchemy import select

        from app.models.automation import AutomationRuleRecord

        result = await self.db.execute(
            select(AutomationRuleRecord).where(AutomationRuleRecord.id == rule_id)
        )
        rec = result.scalar_one_or_none()
        if not rec:
            return None

        rule = self._rule_from_record(rec)
        await self.engine.register_rule(rule)
        return rule

    async def get_rules(
        self,
        organization_id: UUID | None = None,
        status: RuleStatus | None = None,
    ) -> list[AutomationRule]:
        """Get rules with filters. Loads from database."""
        await self._load_rules_from_db(organization_id)
        return self.engine.get_rules(organization_id, status)

    async def update_rule(
        self,
        rule_id: UUID,
        organization_id: UUID | None = None,
        **updates: Any,
    ) -> AutomationRule | None:
        """Validate an isolated replacement before changing persistent/live state.

        The database lookup remains organization-scoped. A lookup/validation/
        flush failure cannot mutate the currently cached action chain. The caller
        still owns commit; cross-worker invalidation and post-flush rollback are
        separate lifecycle concerns.
        """
        from copy import deepcopy
        from dataclasses import fields
        from types import SimpleNamespace

        from sqlalchemy import select

        from app.models.automation import AutomationRuleRecord

        result = await self.db.execute(
            select(AutomationRuleRecord).where(
                AutomationRuleRecord.id == rule_id,
                *(
                    [AutomationRuleRecord.organization_id == organization_id]
                    if organization_id is not None
                    else []
                ),
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None
        # Keep defense in depth when a caller supplies a custom session adapter.
        if organization_id is not None and record.organization_id != organization_id:
            return None

        writable = {
            "name",
            "description",
            "trigger_type",
            "trigger_config",
            "conditions",
            "actions",
            "status",
            "priority",
            "cooldown_seconds",
            "max_triggers_per_hour",
        }
        if updates.keys() - writable:
            raise ValueError("Unsupported automation rule update field")
        normalized = deepcopy(updates)
        for key, value in normalized.items():
            if key == "conditions" and isinstance(value, ConditionGroup):
                normalized[key] = value.to_dict()
            elif key == "actions" and isinstance(value, list):
                normalized[key] = [a.to_dict() if isinstance(a, Action) else a for a in value]
            elif (
                key == "trigger_type"
                and isinstance(value, TriggerType)
                or key == "status"
                and isinstance(value, RuleStatus)
            ):
                normalized[key] = value.value
        updated_at = datetime.now(UTC)
        snapshot = {
            item.name: deepcopy(getattr(record, item.name)) for item in fields(AutomationRule)
        }
        snapshot.update(normalized, updated_at=updated_at)
        replacement = self._rule_from_record(SimpleNamespace(**snapshot))

        for key, value in normalized.items():
            setattr(record, key, value)
        record.updated_at = updated_at
        await self.db.flush()
        await self.engine.register_rule(replacement)
        return replacement

    async def delete_rule(self, rule_id: UUID, organization_id: UUID | None = None) -> bool:
        """Delete a rule. organization_id must match rule owner (A-5: IDOR fix)."""
        from sqlalchemy import delete as sa_delete

        from app.models.automation import AutomationRuleRecord

        # A-5: scope DELETE to org so admins of other orgs cannot delete foreign rules
        where_clauses = [AutomationRuleRecord.id == rule_id]
        if organization_id is not None:
            where_clauses.append(AutomationRuleRecord.organization_id == organization_id)

        result = await self.db.execute(
            sa_delete(AutomationRuleRecord).where(*where_clauses).returning(AutomationRuleRecord.id)
        )
        deleted = result.fetchone() is not None
        await self.db.flush()

        if deleted:
            await self.engine.unregister_rule(rule_id)
        return deleted

    async def enable_rule(self, rule_id: UUID, organization_id: UUID | None = None) -> bool:
        """Enable a rule. A-6: now persisted to DB and org-scoped."""
        from sqlalchemy import select

        from app.models.automation import AutomationRuleRecord

        # A-6: verify ownership and persist — in-memory-only was silently not persisted
        result = await self.db.execute(
            select(AutomationRuleRecord).where(
                AutomationRuleRecord.id == rule_id,
                *(
                    [AutomationRuleRecord.organization_id == organization_id]
                    if organization_id
                    else []
                ),
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            return False
        record.status = RuleStatus.ACTIVE.value
        record.updated_at = datetime.now(UTC)
        await self.db.flush()
        # Warm the engine cache (no-op if already present) so the in-memory status
        # update succeeds even when this worker hasn't loaded the rule yet — otherwise
        # update_rule_status returns False for an uncached rule and the toggle 404s.
        await self.get_rule(rule_id)
        return await self.engine.update_rule_status(rule_id, RuleStatus.ACTIVE)

    async def disable_rule(self, rule_id: UUID, organization_id: UUID | None = None) -> bool:
        """Disable a rule. A-6: now persisted to DB and org-scoped."""
        from sqlalchemy import select

        from app.models.automation import AutomationRuleRecord

        result = await self.db.execute(
            select(AutomationRuleRecord).where(
                AutomationRuleRecord.id == rule_id,
                *(
                    [AutomationRuleRecord.organization_id == organization_id]
                    if organization_id
                    else []
                ),
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            return False
        record.status = RuleStatus.DISABLED.value
        record.updated_at = datetime.now(UTC)
        await self.db.flush()
        # Warm the engine cache (no-op if already present) so the in-memory status
        # update succeeds even when this worker hasn't loaded the rule yet — otherwise
        # update_rule_status returns False for an uncached rule and the toggle 404s.
        await self.get_rule(rule_id)
        return await self.engine.update_rule_status(rule_id, RuleStatus.DISABLED)

    async def trigger_rule(
        self,
        rule_id: UUID,
        data: dict[str, Any] | None = None,
        organization_id: UUID | None = None,
    ) -> RuleExecution | None:
        """Resolve current request scope, then revalidate committed execution state."""
        from sqlalchemy import select

        from app.models.automation import AutomationRuleRecord

        statement = select(AutomationRuleRecord).where(AutomationRuleRecord.id == rule_id)
        if organization_id is not None:
            statement = statement.where(AutomationRuleRecord.organization_id == organization_id)
        record = (await self.db.execute(statement)).scalar_one_or_none()
        if record is None:
            return None
        # Keep explicit standalone engines useful without treating their cache as
        # an ownership check. Production engines independently read committed data.
        await self.engine.register_rule(deepcopy(self._rule_from_record(record)))
        return await self.engine.trigger_rule(rule_id, data, organization_id=organization_id)


class _PersistentAutomationEngine(AutomationEngine):
    """Production selection reads committed definitions, never cached authority.

    The base engine remains a standalone evaluator. Both production construction
    sites use this implementation; database failure never selects cached rules.
    """

    def __init__(self) -> None:
        super().__init__()
        self._execution_authority: ContextVar[AutomationRule | None] = ContextVar(
            "automation_execution_authority", default=None
        )

    @staticmethod
    def _definition(rule: AutomationRule) -> dict[str, Any]:
        return {**rule.to_dict(), "created_by": str(rule.created_by) if rule.created_by else None}

    async def _execute_rule(
        self, rule: AutomationRule, trigger_data: dict[str, Any]
    ) -> RuleExecution:
        # ContextVars isolate concurrent and nested chains. Copying also prevents
        # a request's cache edits from mutating this execution's authority.
        token = self._execution_authority.set(deepcopy(rule))
        try:
            return await super()._execute_rule(rule, trigger_data)
        finally:
            self._execution_authority.reset(token)

    async def _authorize_action(self) -> bool:
        selected = self._execution_authority.get()
        if selected is None:
            return False
        current = await self._persisted_rules(
            organization_id=selected.organization_id, rule_id=selected.id
        )
        return len(current) == 1 and self._definition(current[0]) == self._definition(selected)

    async def _persisted_rules(
        self,
        *,
        organization_id: UUID | str | None,
        rule_id: UUID | None = None,
        event_only: bool = False,
    ) -> list[AutomationRule]:
        from sqlalchemy import select

        from app.db.session import AsyncSessionLocal
        from app.models.automation import AutomationRuleRecord
        from app.models.core import Organization

        if organization_id is None and rule_id is None:
            return []
        if organization_id is not None:
            try:
                organization_id = UUID(str(organization_id))
            except (TypeError, ValueError):
                return []
        statement = (
            select(AutomationRuleRecord)
            .join(Organization, Organization.id == AutomationRuleRecord.organization_id)
            .where(Organization.is_active.is_(True), Organization.deleted_at.is_(None))
        )
        if organization_id is not None:
            statement = statement.where(AutomationRuleRecord.organization_id == organization_id)
        if rule_id is not None:
            statement = statement.where(AutomationRuleRecord.id == rule_id)
        if event_only:
            statement = statement.where(
                AutomationRuleRecord.status == RuleStatus.ACTIVE.value,
                AutomationRuleRecord.trigger_type == TriggerType.EVENT.value,
            )
        try:
            async with AsyncSessionLocal() as db:
                records = (await db.execute(statement)).scalars().all()
                snapshots = []
                for record in records:
                    try:
                        if (
                            not isinstance(record.trigger_config, dict)
                            or not isinstance(record.actions, list)
                            or (
                                record.conditions is not None
                                and not isinstance(record.conditions, dict)
                            )
                        ):
                            raise ValueError("Invalid definition shape")
                        rule = AutomationService._rule_from_record(record)
                        if (
                            type(rule.priority) is not int
                            or type(rule.cooldown_seconds) is not int
                            or rule.cooldown_seconds < 0
                            or type(rule.max_triggers_per_hour) is not int
                            or rule.max_triggers_per_hour < 1
                            or any(
                                not isinstance(action.params, dict)
                                or type(action.delay_seconds) is not int
                                or action.delay_seconds < 0
                                or type(action.continue_on_error) is not bool
                                for action in rule.actions
                            )
                        ):
                            raise ValueError("Invalid definition fields")
                        snapshots.append(deepcopy(rule))
                    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
                        logger.warning("Ignored an invalid persisted automation definition")
        except Exception:
            logger.warning("Committed automation definitions unavailable; execution refused")
            return []
        return sorted(snapshots, key=lambda rule: (-rule.priority, str(rule.id)))

    async def _event_rules(
        self, event_type: str, organization_id: str | None
    ) -> list[AutomationRule]:
        rules = await self._persisted_rules(organization_id=organization_id, event_only=True)
        matching = []
        for rule in rules:
            pattern = str(rule.trigger_config.get("event_pattern") or "").strip()
            if pattern and self._matches_pattern(event_type, pattern):
                # Diagnostics may remember a copy, but edits to that copy must
                # never change an execution's isolated committed snapshot.
                await self.register_rule(deepcopy(rule))
                matching.append(rule)
        return matching

    async def trigger_rule(
        self,
        rule_id: UUID,
        data: dict[str, Any] | None = None,
        *,
        organization_id: UUID | None = None,
    ) -> RuleExecution | None:
        rules = await self._persisted_rules(organization_id=organization_id, rule_id=rule_id)
        if len(rules) != 1:
            return None
        # Explicit manual execution retains the existing disabled/paused-rule
        # behavior. Event selection requires ACTIVE; neither path trusts cache.
        return await self._execute_rule(rules[0], data or {})


# Production event-bus and API engine: persistence is mandatory here.
automation_engine = _PersistentAutomationEngine()
