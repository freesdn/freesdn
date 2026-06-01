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
import logging
from collections.abc import Awaitable, Callable
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
#       ARGV[3]=max_count, ARGV[4]=expire_seconds
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
    redis.call('ZADD', key, now_ts, tostring(now_ts))
    redis.call('EXPIRE', key, expire_secs)
    return 1
end
return 0
"""


class AutomationEngine:
    """
    Rule-based automation engine.

    Evaluates rules against events and executes actions.
    """

    def __init__(self) -> None:
        self._rules: dict[UUID, AutomationRule] = {}
        self._action_handlers: dict[ActionType, Callable[..., Awaitable[Any]]] = {}
        self._event_subscriptions: dict[str, list[UUID]] = {}
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
                alert = Alert(
                    organization_id=org_id,
                    severity=params.get("severity", "warning"),
                    title=params.get("title", "Automation Alert"),
                    message=params.get("message", "Alert created by automation engine"),
                    device_id=context.get("device_id"),
                    site_id=context.get("site_id"),
                    source="automation",
                )
                db.add(alert)
                await db.commit()
                await db.refresh(alert)
                return {"alert_id": str(alert.id)}

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
                return {"resolved": False, "error": "No alert_id provided"}
            if not org_id:
                return {"resolved": False, "error": "no organization context"}
            aid = UUID(alert_id) if isinstance(alert_id, str) else alert_id
            async with async_session_factory() as db:
                alert = await db.get(Alert, aid)
                if alert is None or str(alert.organization_id) != str(org_id):
                    return {"resolved": False, "error": "alert not found in this organization"}
                svc = AlertRuleService(db)
                result = await svc.resolve_alert(
                    aid,
                    user_id=UUID("00000000-0000-0000-0000-000000000000"),  # system
                    note="Auto-resolved by automation engine",
                )
                await db.commit()
                return {"resolved": result is not None}

        async def _resolve_camera_for_action(db: Any, params: dict[str, Any]) -> Any:
            """Shared: load + org-scope the camera named in action params.

            SECURITY: organization_id comes from __context__ (the rule's owning
            org), NEVER from params — same rule as alert.create. A rule can only
            act on cameras in its own org, even if params forge a camera_id.
            """
            from app.modules.cameras.models import Camera

            context = params.get("__context__", {})
            org_id = context.get("organization_id")
            camera_id_str = params.get("camera_id")
            if not camera_id_str:
                return None, "camera_id required in action params"
            if not org_id:
                return None, "no organization context"
            cam = await db.get(
                Camera, UUID(camera_id_str) if isinstance(camera_id_str, str) else camera_id_str
            )
            if cam is None or str(cam.organization_id) != str(org_id) or cam.deleted_at is not None:
                return None, "camera not found in this organization"
            return cam, None

        async def _handle_camera_ptz(params: dict[str, Any]) -> dict[str, Any]:
            from app.db import async_session_factory
            from app.modules.cameras.api import _API_WRITE_FORCE, _get_adapter_for_camera

            async with async_session_factory() as db:
                cam, err = await _resolve_camera_for_action(db, params)
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
                cam, err = await _resolve_camera_for_action(db, params)
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
                cam, err = await _resolve_camera_for_action(db, params)
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
                cam, err = await _resolve_camera_for_action(db, params)
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
                ctx = OperationContext(
                    organization_id=UUID(str(org_raw)),
                    params=dict(params.get("operation_params") or {}),
                    actor_id=UUID(str(actor_raw)) if actor_raw else None,
                    db=db,
                    trigger=context.get("trigger_data", {}) or {},
                    logger=logging.getLogger("fabric.automation"),
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

    async def register_rule(self, rule: AutomationRule) -> None:
        """Register an automation rule."""
        async with self._lock:
            self._rules[rule.id] = rule

            # Subscribe to events if event-triggered
            if rule.trigger_type == TriggerType.EVENT:
                event_pattern = rule.trigger_config.get("event_pattern", "*")
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

            # Remove event subscriptions
            for _pattern, rule_ids in self._event_subscriptions.items():
                if rule_id in rule_ids:
                    rule_ids.remove(rule_id)

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
        return True

    # =========================================================================
    # Action Handlers
    # =========================================================================

    def register_action_handler(
        self,
        action_type: ActionType,
        handler: Callable[..., Awaitable[Any]],
    ) -> None:
        """Register an action handler (safe to call sync during init)."""
        self._action_handlers[action_type] = handler
        logger.debug("Registered action handler: %s", action_type)

    def implemented_action_types(self) -> set[ActionType]:
        """The action types that actually have a registered handler.

        Single source of truth for what the UI may offer and what rule
        creation accepts — derived from the live registry so it can never
        drift from the set of actions the engine can really execute.
        """
        return set(self._action_handlers)

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

            # Merge context into params
            params = {**action.params, "__context__": context}

            # Execute handler
            output = await handler(params)

            duration = (datetime.now(UTC) - start_time).total_seconds() * 1000

            return ActionResult(
                success=True,
                action_type=action.action_type,
                execution_time_ms=duration,
                output=output,
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
            event_id: Unique event ID used for idempotency (prevents double-execution
                      across multiple workers if the same event is delivered twice)

        Returns:
            List of rule executions
        """
        executions = []

        # Find matching rules
        matching_rules = self._find_matching_rules(event_type)

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

            # Idempotency: use Redis SET NX for at-most-once execution per
            # (rule, event) pair across all workers (300s TTL covers any
            # reasonable processing window). NOTE: best-effort, not a hard
            # guarantee — if Redis is unreachable we PROCEED (fail-open, see the
            # except below) rather than silently drop the automation. For a
            # security/network platform, an occasional duplicate notify/webhook
            # during a Redis outage is safer than silently not firing a rule;
            # device writes are separately de-duplicated by the staging
            # pipeline's atomic claim, so a double-apply cannot occur there.
            if event_id:
                try:
                    r = self._get_redis()
                    idempotency_key = f"automation:exec:{rule.id}:{event_id}"
                    acquired = await r.set(idempotency_key, "1", nx=True, ex=300)
                    if not acquired:
                        logger.debug(
                            f"Idempotency skip: rule={rule.id} already processing event={event_id}"
                        )
                        continue
                except Exception as e:
                    logger.warning("Idempotency check failed (proceeding): %s", e)

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
        Falls back to in-memory on Redis error (fail open).
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
                if not can_run:
                    return False
            except Exception as e:
                logger.warning("Redis cooldown check failed (falling back to in-memory): %s", e)
                # Fallback: use in-memory last_triggered if Redis is unavailable
                if rule.last_triggered:
                    cooldown_until = rule.last_triggered + timedelta(seconds=rule.cooldown_seconds)
                    if now < cooldown_until:
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
            )
            return bool(result)
        except Exception as e:
            logger.warning("Redis throttle check failed (allowing execution): %s", e)
            return True  # Fail open — prefer false-positive executions over silent drops

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
                if not action.continue_on_error:
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
        except Exception as _persist_err:
            logger.error(f"Failed to persist execution record for rule {rule.id}: {_persist_err}")

        return execution

    # =========================================================================
    # Manual Triggers
    # =========================================================================

    async def trigger_rule(
        self,
        rule_id: UUID,
        data: dict[str, Any] | None = None,
    ) -> RuleExecution | None:
        """Manually trigger a rule."""
        rule = self._rules.get(rule_id)
        if not rule:
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
        self.engine = engine or AutomationEngine()

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
                rule = AutomationRule(
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
                )
                await self.engine.register_rule(rule)

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

        rule = AutomationRule(
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
            created_by=rec.created_by,
        )
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
        """Update a rule. organization_id must match rule owner (A-4: IDOR fix)."""
        from sqlalchemy import select

        from app.models.automation import AutomationRuleRecord

        # DB-fallback lookup: rules are not always in the per-process engine cache
        # (after restart, or under multiple workers each has its own cache). get_rule
        # loads from DB and warms the engine so the subsequent mutation works.
        rule = await self.get_rule(rule_id)
        if not rule:
            return None

        # A-4: verify the rule belongs to the caller's org before mutating
        # (get_rule does not filter by org, so the org check is enforced here)
        if organization_id is not None and rule.organization_id != organization_id:
            return None  # silently 404 — do not expose existence to wrong org

        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)

        rule.updated_at = datetime.now(UTC)

        # Persist to database (scoped by org for defence-in-depth)
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
        if record:
            for key, value in updates.items():
                if hasattr(record, key):
                    if key == "conditions" and isinstance(value, ConditionGroup):
                        record.conditions = value.to_dict()
                    elif (
                        key == "actions"
                        and isinstance(value, list)
                        and value
                        and isinstance(value[0], Action)
                    ):
                        record.actions = [a.to_dict() for a in value]
                    elif key == "trigger_type" and isinstance(value, TriggerType):
                        record.trigger_type = value.value
                    elif key == "status" and isinstance(value, RuleStatus):
                        record.status = value.value
                    else:
                        setattr(record, key, value)
            record.updated_at = datetime.now(UTC)
            await self.db.flush()

        return rule

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
        """Manually trigger a rule. A-7: verify org ownership before triggering."""
        # DB-fallback lookup so "Run Now" works for rules not in this worker's cache
        # (after restart / under multiple workers). get_rule warms the engine, so the
        # subsequent engine.trigger_rule cache lookup succeeds.
        rule = await self.get_rule(rule_id)
        if not rule:
            return None
        # A-7: an admin from another org must not be able to trigger foreign rules
        # (get_rule does not filter by org, so the org check is enforced here)
        if organization_id is not None and rule.organization_id != organization_id:
            return None
        return await self.engine.trigger_rule(rule_id, data)


# Global engine instance
automation_engine = AutomationEngine()
