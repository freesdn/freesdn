# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device writes made directly from a request
====================================================

Two kinds of device write do not wait in the pending-change queue, and each
leaves a record (``docs/agents/STAGING-MIGRATION.md``, options 2 and 3):

* **Configuration writes** (:func:`write_through_staging`). Staged and applied
  in the same request through ``AdapterStagingService.apply_now``: refused
  while read-only mode is on, refused without ``force``, and recorded in the
  staging ledger with who, what, when and the result. The response is the
  adapter's, unchanged.
* **Operational actions** (:func:`audited_device_action`): reboot, PoE cycle,
  PTZ moves and patrols, call control, service restarts and the like. Staging
  models "intent now, effect after review", which fits an action badly: an
  operator rebooting an access point expects it to reboot. These are not
  staged. Each writes an audit record once the device accepts it: user,
  target, action, parameters (secrets removed) and result. Whether an action
  runs in read-only mode is decided by the adapter's own gate, as before.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.adapter_result import adapter_result_field
from app.core.redaction import redact_secrets

logger = logging.getLogger(__name__)

_RESULT_CAP = 2000

#: Opens the session a ledger row or audit record is written in, given the
#: caller's session. Tests replace it (see tests/conftest.py): a test's data
#: lives in an uncommitted outer transaction that no other connection can see.
LedgerSessionFactory = Callable[[AsyncSession | None], AbstractAsyncContextManager[AsyncSession]]
ledger_session_factory: LedgerSessionFactory | None = None


@contextlib.asynccontextmanager
async def ledger_session(db: AsyncSession | None) -> AsyncIterator[AsyncSession]:
    """A session of its own for the ledger and the audit record.

    The staging chokepoint commits: the ``applying`` row before the device is
    contacted, the result after. On the caller's session those commits would
    also commit whatever the request had changed so far, before the device
    accepted the write, and a refused write would leave that local change in
    place where it used to be rolled back. So the record is written in its own
    transaction, and the request keeps its own. NullPool, so it is safe from
    any event loop (API workers and Celery alike).
    """
    factory = ledger_session_factory
    if factory is not None:
        async with factory(db) as session:
            yield session
        return
    from app.db.session import celery_session_factory

    async with celery_session_factory() as session:
        yield session


async def write_through_staging[T](
    db: AsyncSession,
    *,
    organization_id: UUID,
    controller_id: UUID | None,
    feature: str,
    operation: str,
    payload: dict[str, Any],
    perform: Callable[[], Awaitable[T]],
    force: bool,
    actor_id: UUID | None,
    site_id: UUID | None = None,
    target_id: str | None = None,
    notes: str | None = None,
    return_failed_result: bool = False,
    slot_key: str | None = None,
) -> T:
    """Make a configuration write through the staging chokepoint, in this request.

    ``feature`` is recorded as ``direct.<feature>``; ``operation`` is
    ``create``, ``update`` or ``delete``; ``payload`` describes the write and is
    stored with secrets redacted. ``slot_key`` names the device for a write
    with no controller row (the write waits for that device's turn). See
    ``AdapterStagingService.apply_now``.
    """
    from app.services.adapter_staging import AdapterStagingService

    async with ledger_session(db) as ledger:
        return await AdapterStagingService(ledger).apply_now(
            organization_id=organization_id,
            controller_id=controller_id,
            feature=feature,
            operation=operation,
            payload=payload,
            perform=perform,
            force=force,
            actor_id=actor_id,
            site_id=site_id,
            target_id=target_id,
            notes=notes,
            return_failed_result=return_failed_result,
            slot_key=slot_key,
        )


def request_actor_id() -> UUID | None:
    """The user making the current request, for code that is not handed one."""
    from app.core.site_access import current_user_var

    actor = getattr(current_user_var.get(), "id", None)
    return actor if isinstance(actor, UUID) else None


async def apply_group_through_staging(
    db: AsyncSession,
    members: list[Any],
    *,
    force: bool,
    actor_id: UUID | None,
    notes: str | None = None,
) -> Any:
    """A change to several devices, as one staged change group, in this request.

    See ``AdapterStagingService.apply_group_now``: a row per device under one
    group, every member preflighted before any is applied, and an outcome per
    device. Written in its own transaction, like :func:`write_through_staging`.
    """
    from app.services.adapter_staging import AdapterStagingService

    async with ledger_session(db) as ledger:
        return await AdapterStagingService(ledger).apply_group_now(
            members, force=force, actor_id=actor_id, notes=notes
        )


async def controller_scope(db: AsyncSession, controller_id: UUID) -> tuple[UUID, UUID | None]:
    """(organization, site) a controller belongs to, for its ledger rows.

    Callers have already authorized the controller; this only reads where it
    lives, so a super administrator's write is recorded under the controller's
    own organization rather than the caller's.
    """
    from fastapi import HTTPException
    from sqlalchemy import select

    from app.models.core import Controller, Site

    # freesdn:include-deleted -- the caller has already authorized this
    # controller; this only reads which organization its ledger row belongs to,
    # which is the same whether or not the site was soft-deleted since.
    row = (
        await db.execute(
            select(Site.organization_id, Controller.site_id)
            .join(Site, Controller.site_id == Site.id)
            .where(Controller.id == controller_id)
        )
    ).first()
    if row is None:
        raise HTTPException(404, detail="controller not found")
    return row[0], row[1]


@dataclass(frozen=True)
class WriteScope:
    """Where a device write is recorded: organization, site and controller."""

    organization_id: UUID
    site_id: UUID | None
    controller_id: UUID | None


async def device_scope(db: AsyncSession, device: Any) -> WriteScope:
    """The scope of a ``devices.devices`` row, read from its site."""
    from fastapi import HTTPException
    from sqlalchemy import select

    from app.models.core import Site

    # freesdn:include-deleted -- as in controller_scope: the device is already
    # authorized; only its organization, for the ledger row, is read here.
    site_id = getattr(device, "site_id", None)
    organization_id = None
    if site_id is not None:
        organization_id = (
            await db.execute(select(Site.organization_id).where(Site.id == site_id))
        ).scalar_one_or_none()
    if organization_id is None:
        raise HTTPException(404, detail="device not found")
    return WriteScope(organization_id, site_id, getattr(device, "controller_id", None))


def adapter_implements(adapter: Any, name: str) -> bool:
    """True when the adapter really implements ``name``.

    ``BaseAdapter`` defines most write methods as a placeholder answering
    NOT_SUPPORTED, so ``hasattr`` is always true; compare against it instead.
    """
    from app.adapters.base import BaseAdapter

    method = getattr(type(adapter), name, None)
    return method is not None and method is not getattr(BaseAdapter, name, None)


async def within[T](adapter: Any, call: Callable[[], Awaitable[T]]) -> T:
    """Run ``call`` inside the adapter's connection context."""
    async with adapter:
        return await call()


def _target(device: Any) -> str:
    return str(getattr(device, "mac_address", None) or getattr(device, "id", ""))


async def write_device_config[T](
    db: AsyncSession,
    device: Any,
    *,
    actor_id: UUID | None,
    feature: str,
    operation: str,
    payload: dict[str, Any],
    perform: Callable[[], Awaitable[T]],
    force: bool = True,
    return_failed_result: bool = True,
    slot_key: str | None = None,
) -> T:
    """:func:`write_through_staging` for a write to one device row.

    ``force`` defaults to True for the routes that have never taken a force
    flag: their behaviour does not change, and the write is now refused in
    read-only mode by the chokepoint itself and recorded. A route that has a
    flag passes it. ``return_failed_result`` defaults to True because these
    routes inspect ``result.success`` themselves.
    """
    scope = await device_scope(db, device)
    return await write_through_staging(
        db,
        organization_id=scope.organization_id,
        controller_id=scope.controller_id,
        site_id=scope.site_id,
        feature=feature,
        operation=operation,
        target_id=_target(device),
        payload=payload,
        perform=perform,
        force=force,
        actor_id=actor_id,
        return_failed_result=return_failed_result,
        slot_key=slot_key,
    )


async def device_action[T](
    db: AsyncSession,
    device: Any,
    *,
    actor_id: UUID | None,
    action: str,
    parameters: dict[str, Any] | None,
    perform: Callable[[], Awaitable[T]],
) -> T:
    """:func:`audited_device_action` for an action on one device row."""
    from app.services.adapter_staging import controller_slot_key_for

    scope = await device_scope(db, device)
    return await audited_device_action(
        db,
        action=action,
        target_type="device",
        target_id=getattr(device, "id", None),
        target_name=getattr(device, "name", None) or _target(device),
        organization_id=scope.organization_id,
        site_id=scope.site_id,
        actor_id=actor_id,
        parameters={"mac": getattr(device, "mac_address", None), **(parameters or {})},
        perform=perform,
        slot_key=await controller_slot_key_for(db, scope.controller_id),
    )


async def write_controller_config[T](
    db: AsyncSession,
    controller_id: UUID,
    *,
    actor_id: UUID | None,
    feature: str,
    operation: str,
    payload: dict[str, Any],
    perform: Callable[[], Awaitable[T]],
    target_id: str | None = None,
    force: bool = True,
    return_failed_result: bool = True,
) -> T:
    """:func:`write_through_staging` for a controller-wide write.

    The defaults are those of :func:`write_device_config`, for the same reason.
    """
    organization_id, site_id = await controller_scope(db, controller_id)
    return await write_through_staging(
        db,
        organization_id=organization_id,
        controller_id=controller_id,
        site_id=site_id,
        feature=feature,
        operation=operation,
        target_id=target_id or str(controller_id),
        payload=payload,
        perform=perform,
        force=force,
        actor_id=actor_id,
        return_failed_result=return_failed_result,
    )


async def controller_action[T](
    db: AsyncSession,
    controller_id: UUID,
    *,
    actor_id: UUID | None,
    action: str,
    parameters: dict[str, Any] | None,
    perform: Callable[[], Awaitable[T]],
) -> T:
    """:func:`audited_device_action` for an action addressed to a controller."""
    from app.services.adapter_staging import controller_slot_key_for

    organization_id, site_id = await controller_scope(db, controller_id)
    return await audited_device_action(
        db,
        action=action,
        target_type="controller",
        target_id=controller_id,
        target_name=str(controller_id),
        organization_id=organization_id,
        site_id=site_id,
        actor_id=actor_id,
        parameters=parameters,
        perform=perform,
        slot_key=await controller_slot_key_for(db, controller_id),
    )


def _summarize(result: Any) -> Any:
    """A bounded, JSON-safe, secret-free rendering of an action's result."""
    candidate: Any = result
    if hasattr(result, "model_dump"):
        with contextlib.suppress(Exception):
            candidate = result.model_dump()
    elif hasattr(result, "__dataclass_fields__"):
        from dataclasses import asdict

        with contextlib.suppress(Exception):
            candidate = asdict(result)
    try:
        text = json.dumps(candidate, default=str)
    except (TypeError, ValueError):
        return {"type": type(result).__name__}
    safe = redact_secrets(json.loads(text)) if text.startswith(("{", "[")) else json.loads(text)
    rendered = json.dumps(safe, default=str)
    if len(rendered) > _RESULT_CAP:
        return {"truncated": True, "head": rendered[:_RESULT_CAP]}
    return safe


def _accepted(result: Any) -> bool:
    """False for a result the device reported as refused."""
    if adapter_result_field(result, "success") is False:
        return False
    if isinstance(result, dict) and result.get("success") is False:
        return False
    return True


async def audited_device_action[T](
    db: AsyncSession | None,
    *,
    action: str,
    target_type: str,
    target_id: Any,
    target_name: str | None,
    organization_id: UUID | None,
    actor_id: UUID | None,
    perform: Callable[[], Awaitable[T]],
    parameters: dict[str, Any] | None = None,
    site_id: UUID | None = None,
    slot_key: str | None = None,
) -> T:
    """Run an operational device action and record it once the device accepts it.

    ``perform`` makes the device call and its result is returned unchanged; an
    exception it raises propagates unchanged and nothing is recorded, because
    nothing was accepted. ``parameters`` must describe the action (port,
    channel, destination); secret values in it are removed before storage.
    The record is best-effort: a failed audit write is logged and never turns
    an action the device took into an error.

    ``slot_key`` names the device: the action waits briefly for its turn
    (``app/core/device_slot.acquire_write_turn``), like a configuration write,
    and a device that stays busy refuses it with 503 before anything is sent.
    """
    from app.core.device_slot import acquire_write_turn

    turn = await acquire_write_turn(slot_key, f"an action ({action})")
    try:
        result = await perform()
    finally:
        await turn.release()
    if not _accepted(result):
        return result
    try:
        from app.services.audit import AuditService

        async with ledger_session(db) as ledger:
            await _log_action(
                AuditService(ledger),
                ledger,
                action=action,
                target_type=target_type,
                target_id=target_id,
                target_name=target_name,
                organization_id=organization_id,
                site_id=site_id,
                actor_id=actor_id,
                parameters=parameters,
                result=result,
            )
    except Exception:  # noqa: BLE001 - the action already happened on the device
        logger.warning("audit record for device action %s could not be written", action)
    return result


async def _log_action(
    audit: Any,
    ledger: AsyncSession,
    *,
    action: str,
    target_type: str,
    target_id: Any,
    target_name: str | None,
    organization_id: UUID | None,
    site_id: UUID | None,
    actor_id: UUID | None,
    parameters: dict[str, Any] | None,
    result: Any,
) -> None:
    try:
        await audit.log(
            action=f"device_action:{action}",
            resource_type=target_type,
            resource_id=target_id if isinstance(target_id, UUID) else None,
            resource_name=target_name,
            organization_id=organization_id,
            site_id=site_id,
            actor_id=actor_id,
            new_state={
                "action": action,
                "target_id": str(target_id) if target_id is not None else None,
                "parameters": redact_secrets(dict(parameters or {})),
                "result": _summarize(result),
            },
            tags=["device-action"],
        )
        await ledger.commit()
    except Exception:
        with contextlib.suppress(Exception):
            await ledger.rollback()
        raise
