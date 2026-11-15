# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""An in-memory change-group runner for tests whose database is a stub.

``AdapterStagingService.apply_group_now`` writes ledger rows, so it needs a
real session. Tests that drive a multi-device write with a fake database (and
are about something else: call shapes, status honesty, messages) replace
``device_writes.apply_group_through_staging`` with :func:`run_group`, which
follows the same rules without the rows: every member preflighted first, a
refusal anywhere applies nothing, the first failure stops the group, and the
members already applied are compensated. tests/services/test_change_groups.py
covers the real one.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from app.core.adapter_result import adapter_result_field


async def run_group(_db: Any, members: list[Any], **_kwargs: Any) -> Any:
    from app.services.adapter_staging import GroupOutcome, MemberOutcome

    outcome = GroupOutcome(group_id=uuid4())
    refusals: dict[str, str] = {}
    for member in members:
        if member.preflight is not None:
            reason = await member.preflight()
            if reason:
                refusals[member.key] = reason
    if refusals:
        outcome.preflight_refused = True
        outcome.members = [
            MemberOutcome(m.key, None, "not_applied", refusals.get(m.key) or "not applied")
            for m in members
        ]
        return outcome
    applied: list[tuple[Any, Any]] = []
    failed_key = None
    for member in members:
        if failed_key is not None:
            outcome.members.append(
                MemberOutcome(
                    member.key, None, "not_applied", f"not applied: {failed_key} failed first"
                )
            )
            continue
        try:
            result = await member.perform()
        except Exception as exc:  # noqa: BLE001 - mirrors apply_change
            outcome.members.append(MemberOutcome(member.key, None, "failed", type(exc).__name__))
            failed_key = member.key
            continue
        if adapter_result_field(result, "success") is False:
            outcome.members.append(
                MemberOutcome(member.key, None, "failed", adapter_result_field(result, "error"))
            )
            failed_key = member.key
            continue
        outcome.members.append(MemberOutcome(member.key, None, "applied", result=result))
        applied.append((member, result))
    if failed_key is not None:
        for member, result in applied:
            if member.compensate is None:
                continue
            await member.compensate(result)
            for existing in outcome.members:
                if existing.key == member.key:
                    existing.status = "compensated"
                    existing.reason = f"undone because {failed_key} failed"
    return outcome
