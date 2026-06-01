# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Adapter operation decorators
========================================

Three decorators that turn the adapter contract (read paths run live;
writes stage; operator actions emit events) into structural enforcement
rather than PR-review discipline.

The adapter contract requires every adapter method to do four things
consistently:

1. Emit a Prometheus metric with vendor + outcome labels.
2. Publish an event on the bus when the operation completes (so
   automation rules, WebSocket clients, and plugins see it).
3. Validate inputs at the gate (mac/id format).
4. Route writes through staging when ``ADAPTER_READ_ONLY`` is True.

Today these requirements are met by ~15 lines of boilerplate inside
each service method. The decorators below collapse that to a single
decorator line so a new adapter author cannot ship without the
machinery.

----
Three decorators for three write semantics:

@adapter_read(feature)
    For READ paths (list extensions, get device status, fetch CDR).
    Emits a latency metric on success, an error metric on failure.
    Does NOT publish events to the bus — reads are silent by design.

@direct_action(feature, target_field=None, priority="normal")
    For OPERATOR-INITIATED ACTIONS that bypass staging by design
    (PTZ move, originate call, reboot device, snapshot capture).
    Calls the wrapped method live, then publishes
    ``<feature>.<outcome>`` to the event bus and increments the
    counter. Outcome is ``ok`` on return, ``failed`` on exception.
    Exceptions propagate after the event fires.

@staged_write(feature, operation, payload_keys=None)
    For STATEFUL CONFIG WRITES that should go through the stage→apply
    gate (VLAN create, firewall rule, motion-detection zones).
    When ``ADAPTER_READ_ONLY`` is True, the decorated method returns
    an :class:`AdapterPendingChange` row instead of calling through
    to the live device. When ``ADAPTER_READ_ONLY`` is False AND
    ``force=True`` is passed, calls through and applies live. This
    requires the service class to have a ``self.staging``
    :class:`AdapterStagingService` attribute (every
    :class:`GatewayServiceBase` subclass has this).

----
Usage:

    class PBXService(GatewayServiceBase):

        @adapter_read("pbx.extensions.list")
        async def list_extensions(self, pbx_id: UUID) -> list[Extension]:
            adapter = await self._get_adapter(pbx_id)
            return await adapter.list_extensions()

        @direct_action("pbx.originate_call", target_field="pbx_id",
                       priority="normal")
        async def originate_call(
            self, *, pbx_id: UUID, organization_id: UUID,
            from_ext: str, to_number: str,
        ) -> dict:
            adapter = await self._get_adapter(pbx_id)
            return await adapter.originate_call(from_ext, to_number)

        @staged_write("vlan.create", operation="create",
                       payload_keys=("vlan_id", "name", "subnet"))
        async def create_vlan(
            self, *, organization_id: UUID, controller_id: UUID,
            vlan_id: int, name: str, subnet: str,
        ) -> AdapterPendingChange:
            # No body needed — decorator handles staging.
            pass
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec, TypeVar
from uuid import UUID

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")


# ════════════════════════════════════════════════════════════════════
# Internal helpers
# ════════════════════════════════════════════════════════════════════


def _resolve_arg(kwargs: dict[str, Any], names: tuple[str, ...]) -> Any | None:
    """Return the first kwarg present from a list of acceptable names.

    Service methods use different param names for the same concept
    (``organization_id`` vs ``org_id``; ``camera_id`` vs ``device_id``).
    The decorator accepts any of them so it doesn't force a rename
    of every existing signature.
    """
    for name in names:
        if name in kwargs and kwargs[name] is not None:
            return kwargs[name]
    return None


def _to_str_id(value: Any) -> str | None:
    """Coerce a UUID/int/str into a string for event payloads.

    Returns ``None`` when ``value`` is None so callers can filter out
    missing fields. Otherwise stringifies — UUIDs become their canonical
    form, ints become decimal strings.
    """
    if value is None:
        return None
    return str(value)


# ════════════════════════════════════════════════════════════════════
# @adapter_read
# ════════════════════════════════════════════════════════════════════


def adapter_read(
    feature: str,
    *,
    vendor: str | None = None,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorate a READ method to emit latency + error metrics.

    Reads are NOT staged and do NOT publish events — they're silent by
    design (a list call shouldn't broadcast on the event bus). The only
    observability they need is metrics so operators can see latency
    histograms and error rates.

    ``feature`` follows the same dotted convention as staged_write and
    direct_action: ``"<vendor>.<resource>.<action>"`` (e.g.
    ``"freepbx.extensions.list"``).

    ``vendor`` is extracted from ``feature`` if not specified.
    """
    derived_vendor = vendor or (feature.split(".", 1)[0] if "." in feature else "unknown")

    def deco(
        func: Callable[P, Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            start = time.monotonic()
            try:
                result = await func(*args, **kwargs)
            except Exception:
                _emit_read_error(derived_vendor, feature)
                raise
            else:
                _emit_read_latency(derived_vendor, feature, time.monotonic() - start)
                return result

        wrapper.__adapter_decorator__ = "adapter_read"  # type: ignore[attr-defined]
        wrapper.__adapter_feature__ = feature  # type: ignore[attr-defined]
        return wrapper

    return deco


def _emit_read_latency(vendor: str, feature: str, seconds: float) -> None:
    """Bump the read-latency histogram. Best-effort, never raises."""
    try:
        from app.core.metrics import adapter_request_duration

        adapter_request_duration.labels(adapter=vendor, method=feature).observe(seconds)
    except Exception:
        logger.debug(
            "metric emit skipped for read %s",
            feature,
            exc_info=True,
        )


def _emit_read_error(vendor: str, feature: str) -> None:
    """Bump the read-error counter. Best-effort, never raises."""
    try:
        from app.core.metrics import adapter_errors_total

        adapter_errors_total.labels(adapter=vendor, error_type=f"read:{feature}").inc()
    except Exception:
        logger.debug(
            "metric emit skipped for read error %s",
            feature,
            exc_info=True,
        )


# ════════════════════════════════════════════════════════════════════
# @direct_action
# ════════════════════════════════════════════════════════════════════

# Method-arg name aliases the decorator will look for to populate
# common event fields. The decorator walks the kwargs in this order
# and picks the first non-None match. Callers that want different
# names can pass ``target_field=...`` to override the target lookup.
_TARGET_FIELD_ALIASES: tuple[str, ...] = (
    "camera_id",
    "nvr_id",
    "pbx_id",
    "phone_id",
    "controller_id",
    "device_id",
    "target_id",
)
_ORG_FIELD_ALIASES: tuple[str, ...] = (
    "organization_id",
    "org_id",
)
_SITE_FIELD_ALIASES: tuple[str, ...] = ("site_id",)
_ACTOR_FIELD_ALIASES: tuple[str, ...] = (
    "actor_id",
    "user_id",
)


def direct_action(
    feature: str,
    *,
    target_field: str | None = None,
    priority: str = "normal",
    vendor: str | None = None,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorate an ACTION method (PTZ, originate, reboot) to emit events.

    Calls the wrapped method live. On return, publishes
    ``<feature>.ok`` on the event bus. On exception, publishes
    ``<feature>.failed`` and re-raises. The event payload carries
    ``adapter_id`` (= ``feature``'s vendor prefix), ``target_id``,
    ``organization_id``, ``site_id``, and ``actor_id`` extracted from
    the method's kwargs by name.

    ``target_field`` lets the caller override the target-id lookup;
    by default the decorator scans ``camera_id``/``nvr_id``/``pbx_id``/
    ``phone_id``/``controller_id``/``device_id``/``target_id`` in that
    order and uses the first one set.

    ``priority`` is ``"normal"`` by default. Use ``"high"`` for
    operator-visible writes (PTZ, reboot, originate) and ``"critical"``
    for catastrophic actions (factory reset, firmware install).

    The decorated method's return value (or exception) is preserved
    untouched — the decorator is purely additive observability.
    """
    derived_vendor = vendor or (feature.split(".", 1)[0] if "." in feature else "unknown")

    def deco(
        func: Callable[P, Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                result = await func(*args, **kwargs)
            except Exception as exc:
                await _publish_action_event(
                    feature=feature,
                    outcome="failed",
                    vendor=derived_vendor,
                    priority=priority,
                    kwargs=dict(kwargs),
                    target_field=target_field,
                    error=type(exc).__name__,
                )
                raise
            await _publish_action_event(
                feature=feature,
                outcome="ok",
                vendor=derived_vendor,
                priority=priority,
                kwargs=dict(kwargs),
                target_field=target_field,
                error=None,
            )
            return result

        wrapper.__adapter_decorator__ = "direct_action"  # type: ignore[attr-defined]
        wrapper.__adapter_feature__ = feature  # type: ignore[attr-defined]
        return wrapper

    return deco


async def _publish_action_event(
    *,
    feature: str,
    outcome: str,
    vendor: str,
    priority: str,
    kwargs: dict[str, Any],
    target_field: str | None,
    error: str | None,
) -> None:
    """Publish ``<feature>.<outcome>`` to the event bus.

    Delegates to :func:`app.core.events.publish_adapter_event` so this
    decorator emits events through the same code path the existing
    ``record_camera_action`` / ``record_pbx_action`` helpers use.
    The helper is best-effort and never raises — a broken event bus
    MUST NEVER fail the operator action that already happened on the
    live device.
    """
    try:
        from app.core.events import EventCategory, EventPriority, publish_adapter_event

        try:
            ep = EventPriority(priority)
        except ValueError:
            ep = EventPriority.NORMAL

        # Resolve identifiers from method kwargs.
        target_names = (target_field,) if target_field else _TARGET_FIELD_ALIASES
        target_id = _to_str_id(_resolve_arg(kwargs, target_names))
        organization_id = _to_str_id(_resolve_arg(kwargs, _ORG_FIELD_ALIASES))
        site_id = _to_str_id(_resolve_arg(kwargs, _SITE_FIELD_ALIASES))
        actor_id = _to_str_id(_resolve_arg(kwargs, _ACTOR_FIELD_ALIASES))

        extra: dict[str, Any] = {"feature": feature, "outcome": outcome}
        if target_id is not None:
            extra["target_id"] = target_id
        if site_id is not None:
            extra["site_id"] = site_id
        if actor_id is not None:
            extra["actor_id"] = actor_id
        if error is not None:
            extra["error"] = error

        await publish_adapter_event(
            f"{feature}.{outcome}",
            adapter_id=vendor,
            organization_id=organization_id,
            priority=ep,
            category=EventCategory.DEVICE,
            **extra,
        )
    except Exception:
        logger.debug(
            "event publish skipped for action %s.%s",
            feature,
            outcome,
            exc_info=True,
        )


# ════════════════════════════════════════════════════════════════════
# @staged_write
# ════════════════════════════════════════════════════════════════════


def staged_write(
    feature: str,
    *,
    operation: str = "create",
    payload_keys: tuple[str, ...] | None = None,
    target_field: str | None = None,
) -> Callable[[Callable[P, Awaitable[Any]]], Callable[P, Awaitable[Any]]]:
    """Decorate a CONFIG-WRITE method to route through staging.

    The decorated method should be on a service class that has a
    ``self.staging`` attribute (an :class:`AdapterStagingService`
    instance — provided by :class:`GatewayServiceBase`).

    When called, the decorator:

    1. Extracts ``organization_id``, ``controller_id``, and other
       identifiers from kwargs.
    2. Builds the staging payload from kwargs (either every keyword
       arg, or only the ones listed in ``payload_keys``).
    3. Calls ``self.staging.stage_change(...)`` and returns the
       resulting :class:`AdapterPendingChange` row.

    The wrapped method's BODY is never executed — the decorator owns
    the staging path entirely. Adapter authors write a stub body
    (``pass``) so the signature is documentation-only.

    The downstream apply path (when an operator hits "Apply") is
    handled by the dispatcher in :mod:`app.services.adapter_staging`,
    which routes to the right ``build_applier(...)`` by feature
    prefix. The applier lives on the same service class as the
    decorated stage method.

    Note: this decorator REPLACES the manual stage-method boilerplate
    (~15 lines per method). Adapters migrated to v2 should consolidate
    their stage methods to use this decorator.
    """

    def deco(
        func: Callable[P, Awaitable[Any]],
    ) -> Callable[P, Awaitable[Any]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            if not args:
                raise TypeError(
                    f"{func.__name__} decorated with @staged_write must be "
                    "an instance method (self is required)"
                )
            self = args[0]
            staging = getattr(self, "staging", None)
            if staging is None:
                raise RuntimeError(
                    f"{type(self).__name__} has no 'self.staging' "
                    "attribute; @staged_write requires the service to "
                    "extend GatewayServiceBase or provide an "
                    "AdapterStagingService at self.staging"
                )

            # Extract canonical identifiers from kwargs.
            organization_id = _resolve_arg(kwargs, _ORG_FIELD_ALIASES)
            controller_id = _resolve_arg(kwargs, ("controller_id",))
            site_id = _resolve_arg(kwargs, _SITE_FIELD_ALIASES)
            actor_id = _resolve_arg(kwargs, _ACTOR_FIELD_ALIASES)
            target_names = (target_field,) if target_field else _TARGET_FIELD_ALIASES
            target_id = _resolve_arg(kwargs, target_names)

            if organization_id is None:
                raise TypeError(
                    f"{func.__name__} (@staged_write) requires "
                    "'organization_id' or 'org_id' in kwargs"
                )
            if controller_id is None:
                raise TypeError(
                    f"{func.__name__} (@staged_write) requires 'controller_id' in kwargs"
                )

            # Build the payload from the listed keys, or everything
            # except canonical identifiers + plumbing args.
            _PLUMBING = {
                "organization_id",
                "org_id",
                "controller_id",
                "site_id",
                "actor_id",
                "user_id",
                "notes",
                "force",
            }
            if payload_keys is not None:
                payload = {
                    k: kwargs[k] for k in payload_keys if k in kwargs and kwargs[k] is not None
                }
            else:
                payload = {k: v for k, v in kwargs.items() if k not in _PLUMBING and v is not None}

            if not isinstance(organization_id, UUID):
                try:
                    organization_id = UUID(str(organization_id))
                except Exception as exc:
                    raise TypeError(
                        f"{func.__name__}: organization_id must be a UUID, "
                        f"got {type(organization_id).__name__}"
                    ) from exc
            if not isinstance(controller_id, UUID):
                try:
                    controller_id = UUID(str(controller_id))
                except Exception as exc:
                    raise TypeError(
                        f"{func.__name__}: controller_id must be a UUID, "
                        f"got {type(controller_id).__name__}"
                    ) from exc

            site_uuid: UUID | None = None
            if site_id is not None:
                try:
                    site_uuid = site_id if isinstance(site_id, UUID) else UUID(str(site_id))
                except Exception:
                    site_uuid = None

            actor_uuid: UUID | None = None
            if actor_id is not None:
                try:
                    actor_uuid = actor_id if isinstance(actor_id, UUID) else UUID(str(actor_id))
                except Exception:
                    actor_uuid = None

            return await staging.stage_change(
                organization_id=organization_id,
                controller_id=controller_id,
                feature=feature,
                operation=operation,
                payload=payload,
                site_id=site_uuid,
                target_id=str(target_id) if target_id is not None else None,
                actor_id=actor_uuid,
                notes=kwargs.get("notes") if isinstance(kwargs.get("notes"), str) else None,
            )

        wrapper.__adapter_decorator__ = "staged_write"  # type: ignore[attr-defined]
        wrapper.__adapter_feature__ = feature  # type: ignore[attr-defined]
        wrapper.__adapter_operation__ = operation  # type: ignore[attr-defined]
        return wrapper

    return deco


__all__ = [
    "adapter_read",
    "direct_action",
    "staged_write",
]
