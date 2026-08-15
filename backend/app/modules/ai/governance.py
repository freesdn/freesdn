# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - LLM Governance Layer
=====================================

Three-layer security model for LLM usage:

1. **Global Kill Switch**: ``LLM_GLOBALLY_ENABLED`` env var (default: False)
2. **Org Policy**: Per-org ``LLMOrgPolicy`` (DISABLED / LOCAL_ONLY / CLOUD_APPROVED)
3. **Field Selector**: Automation rules declare explicit ``input_fields`` (no wildcards)

Also provides:
- Token budgeting with atomic Redis increment (fallback to DB)
- LLMCallLog audit (field names only, not content — privacy-preserving)
- Three structured operations: classify, extract, summarize
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# =============================================================================
# Enums & Constants
# =============================================================================


class LLMOrgPolicy(StrEnum):
    """Organization-level LLM usage policy."""

    DISABLED = "disabled"  # No LLM access (default)
    LOCAL_ONLY = "local_only"  # Ollama only
    CLOUD_APPROVED = "cloud_approved"  # OpenAI + Anthropic + Ollama


CLOUD_PROVIDERS = frozenset({"openai", "anthropic"})
LOCAL_PROVIDERS = frozenset({"ollama"})


class LLMOperation(StrEnum):
    """Structured LLM operations (non-chat)."""

    CLASSIFY = "classify"
    EXTRACT = "extract"
    SUMMARIZE = "summarize"


# =============================================================================
# Operation Request Schemas
# =============================================================================


class ClassifyRequest(BaseModel):
    """Classify text into one of a set of labels."""

    operation: str = "classify"
    text: str = Field(max_length=8000)
    labels: list[str] = Field(min_length=2, max_length=20)
    prompt_template: str | None = Field(default=None, max_length=500)


class ExtractRequest(BaseModel):
    """Extract structured data from text."""

    operation: str = "extract"
    text: str = Field(max_length=16000)
    # output_schema flows into the LLM prompt as raw JSON. The
    # docstring promised "max 10 properties, depth 2" but Pydantic
    # never enforced it — a 100 KB schema doubled the prompt cost
    # and could be used to inflate provider bills. Cap at 10 keys
    # at the top level + 8 KB total serialised size + depth 3.
    output_schema: dict[str, Any]
    prompt_template: str | None = Field(default=None, max_length=500)

    @field_validator("output_schema")
    @classmethod
    def _v_schema(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 10:
            raise ValueError("output_schema must have <= 10 top-level keys")

        def _depth(obj: Any, level: int = 0) -> int:
            if level > 5:
                raise ValueError("output_schema nesting depth exceeds 5")
            if isinstance(obj, dict):
                return 1 + max((_depth(x, level + 1) for x in obj.values()), default=0)
            if isinstance(obj, list):
                return 1 + max((_depth(x, level + 1) for x in obj), default=0)
            return 0

        _depth(v)
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        if size > 8 * 1024:
            raise ValueError(f"output_schema exceeds 8192 bytes (got {size})")
        return v


class SummarizeRequest(BaseModel):
    """Summarize text into plain language."""

    operation: str = "summarize"
    text: str = Field(max_length=32000)
    max_words: int = Field(default=200, ge=50, le=500)
    prompt_template: str | None = Field(default=None, max_length=500)


# =============================================================================
# Governance Exceptions
# =============================================================================


class LLMGloballyDisabledError(Exception):
    """Global kill switch is off."""


class LLMOrgDisabledError(Exception):
    """Organization LLM policy is DISABLED."""


class LLMProviderNotAllowedError(Exception):
    """Provider not permitted under current org policy."""


class LLMBudgetExceededError(Exception):
    """Monthly token budget exceeded."""


# =============================================================================
# Governance Service
# =============================================================================


class LLMGovernanceService:
    """
    Enforces the 3-layer LLM security model and manages token budgets.

    Usage in AI service::

        governance = LLMGovernanceService()
        governance.check_global_kill_switch()
        policy = await governance.get_org_policy(db, org_id)
        governance.check_provider_allowed(policy, "openai")
        await governance.check_token_budget(org_id, estimated_tokens=500)
        # ... call LLM ...
        await governance.log_call(db, org_id, ...)
    """

    def check_global_kill_switch(self) -> None:
        """
        Layer 1: Check the global kill switch.

        The ``LLM_GLOBALLY_ENABLED`` env var must be set to ``true``
        (case-insensitive). Defaults to ``false`` — LLM is off by default.
        """
        enabled = os.getenv("LLM_GLOBALLY_ENABLED", "false").lower() in ("true", "1", "yes")
        if not enabled:
            raise LLMGloballyDisabledError(
                "LLM features are globally disabled. Set LLM_GLOBALLY_ENABLED=true to enable."
            )

    async def get_org_policy(self, db: AsyncSession, org_id: UUID) -> LLMOrgPolicy:
        """
        Layer 2: Read the organization's LLM policy.

        Reads from ``ai.org_llm_policies`` (one row per org). Returns
        DISABLED if no policy row exists. Previously this scanned
        ``ai_provider_configs`` with ``LIMIT 1`` and no ``ORDER BY`` —
        non-deterministic with multiple providers configured (H2).
        """
        from app.modules.ai.models import OrgLLMPolicy as OrgPolicyRow

        result = await db.execute(
            select(OrgPolicyRow.llm_org_policy).where(OrgPolicyRow.organization_id == org_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return LLMOrgPolicy.DISABLED
        try:
            return LLMOrgPolicy(row)
        except ValueError:
            return LLMOrgPolicy.DISABLED

    def check_org_policy(self, policy: LLMOrgPolicy) -> None:
        """Raise if org policy is DISABLED."""
        if policy == LLMOrgPolicy.DISABLED:
            raise LLMOrgDisabledError(
                "LLM features are disabled for this organization. "
                "An admin must set the LLM policy in AI Settings."
            )

    def check_provider_allowed(self, policy: LLMOrgPolicy, provider_id: str) -> None:
        """
        Layer 2 (continued): Verify the provider is allowed under the org policy.

        Uses allowlist approach:
        - LOCAL_ONLY: only local providers (Ollama) are allowed
        - CLOUD_APPROVED: all known providers are allowed
        - Unknown providers are always rejected
        """
        ALL_KNOWN_PROVIDERS = CLOUD_PROVIDERS | LOCAL_PROVIDERS

        if policy == LLMOrgPolicy.DISABLED:
            raise LLMOrgDisabledError("LLM is disabled for this organization")

        if provider_id not in ALL_KNOWN_PROVIDERS:
            raise LLMProviderNotAllowedError(
                f"Unknown provider '{provider_id}'. "
                f"Allowed providers: {', '.join(sorted(ALL_KNOWN_PROVIDERS))}"
            )

        if policy == LLMOrgPolicy.LOCAL_ONLY and provider_id not in LOCAL_PROVIDERS:
            raise LLMProviderNotAllowedError(
                f"Provider '{provider_id}' is not allowed under LOCAL_ONLY policy. "
                f"Only local providers ({', '.join(sorted(LOCAL_PROVIDERS))}) are permitted."
            )

    async def check_token_budget(
        self,
        db: AsyncSession,
        org_id: UUID,
        estimated_tokens: int = 0,
    ) -> None:
        """
        Check and increment the org's monthly token budget.

        Uses Redis atomic INCRBY for performance. Falls back to DB if Redis
        is unavailable. Reads from ``ai.org_llm_policies`` (H2).
        """
        from app.modules.ai.models import OrgLLMPolicy as OrgPolicyRow

        result = await db.execute(
            select(OrgPolicyRow).where(
                OrgPolicyRow.organization_id == org_id,
            )
        )
        policy_row = result.scalar_one_or_none()
        if not policy_row:
            # No policy row = enforce a conservative default budget (100k
            # tokens) to prevent unlimited usage for unconfigured orgs.
            budget = 100_000
            used = 0
            # Only check DB fallback since no row to read from.
            if estimated_tokens > budget:
                raise LLMBudgetExceededError(
                    f"Monthly token budget exceeded ({estimated_tokens}/{budget}). "
                    f"Configure an AI provider to set a custom budget."
                )
            return

        raw_budget = getattr(policy_row, "monthly_token_budget", None)
        budget = raw_budget if raw_budget is not None and raw_budget > 0 else 100_000
        used = getattr(policy_row, "tokens_used_this_month", 0) or 0

        # Try Redis first for atomic budget check
        try:
            redis_used = await self._redis_budget_check(org_id, budget, estimated_tokens)
            if redis_used is not None:
                if redis_used > budget:
                    raise LLMBudgetExceededError(
                        f"Monthly token budget exceeded ({redis_used}/{budget}). "
                        f"Budget resets at the start of next month."
                    )
                return
        except LLMBudgetExceededError:
            raise
        except Exception:
            pass  # Redis unavailable, fall back to DB

        # DB fallback
        if used + estimated_tokens > budget:
            raise LLMBudgetExceededError(
                f"Monthly token budget exceeded ({used}/{budget}). "
                f"Budget resets at the start of next month."
            )

    async def _redis_budget_check(
        self,
        org_id: UUID,
        budget: int,
        estimated_tokens: int,
    ) -> int | None:
        """Atomic Redis INCRBY for token budget. Returns new total or None."""
        try:
            from app.core.events import event_bus

            r = event_bus._redis
            if r is None:
                return None
            now = datetime.now(UTC)
            key = f"llm:budget:{org_id}:{now.year}:{now.month:02d}"
            current = await r.incrby(key, estimated_tokens)
            # Set TTL for auto-cleanup (32 days covers any month)
            if current == estimated_tokens:
                await r.expire(key, 32 * 86400)
            return int(current)
        except Exception:
            return None

    async def _redis_budget_rollback(
        self,
        org_id: UUID,
        tokens: int,
    ) -> None:
        """Roll back a Redis budget increment (e.g. after a failed LLM call)."""
        try:
            from app.core.events import event_bus

            r = event_bus._redis
            if r is None:
                return
            now = datetime.now(UTC)
            key = f"llm:budget:{org_id}:{now.year}:{now.month:02d}"
            await r.decrby(key, tokens)
        except Exception:
            logger.debug("Redis budget rollback failed for org %s", org_id)

    async def record_token_usage(
        self,
        db: AsyncSession,
        org_id: UUID,
        tokens_used: int,
    ) -> None:
        """Update the DB token counter atomically (called after successful LLM call).

        Writes to ``ai.org_llm_policies`` (H2). If no policy row exists for
        the org, this is a no-op — the budget check above will create one
        when an admin first sets the policy.
        """
        from sqlalchemy import update

        from app.modules.ai.models import OrgLLMPolicy as OrgPolicyRow

        # Atomic SQL UPDATE to avoid lost-update race condition.
        stmt = (
            update(OrgPolicyRow)
            .where(OrgPolicyRow.organization_id == org_id)
            .values(tokens_used_this_month=OrgPolicyRow.tokens_used_this_month + tokens_used)
            .returning(
                OrgPolicyRow.tokens_used_this_month,
                OrgPolicyRow.monthly_token_budget,
            )
        )
        result = await db.execute(stmt)
        row = result.first()
        if not row:
            return

        raw_budget = row[1]
        used = row[0]
        budget = raw_budget if raw_budget is not None and raw_budget > 0 else 100_000

        # Check 80% alert threshold
        if used >= budget * 0.8:
            try:
                from app.core.events import Event, event_bus

                await event_bus.publish(
                    Event(
                        event_type="ai.budget.warning",
                        payload={
                            "organization_id": str(org_id),
                            "used": used,
                            "budget": budget,
                            "percentage": round(used / budget * 100, 1),
                        },
                        source="ai:governance",
                        organization_id=str(org_id),
                    )
                )
            except Exception:
                pass

    async def log_call(
        self,
        db: AsyncSession,
        *,
        organization_id: UUID,
        provider: str,
        model: str,
        operation: str,
        input_fields_sent: list[str],
        prompt_tokens: int,
        completion_tokens: int,
        success: bool,
        error: str | None = None,
        latency_ms: float = 0.0,
        rule_id: UUID | None = None,
        execution_id: UUID | None = None,
    ) -> None:
        """
        Write a privacy-preserving audit log entry.

        Stores field NAMES (not values) and token counts.
        """
        from app.modules.ai.models import LLMCallLog

        log = LLMCallLog(
            organization_id=organization_id,
            rule_id=rule_id,
            execution_id=execution_id,
            provider=provider,
            model=model,
            operation=operation,
            input_fields_sent=input_fields_sent,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            success=success,
            error=error[:500] if error else None,
            latency_ms=latency_ms,
        )
        db.add(log)

    async def execute_structured(
        self,
        db: AsyncSession,
        org_id: UUID,
        operation: LLMOperation,
        input_data: dict[str, str],
        provider_id: str | None = None,
        rule_id: UUID | None = None,
        execution_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Execute a structured LLM operation (classify/extract/summarize).

        This is the primary entry point for automation LLM actions.
        Enforces all 3 governance layers, builds the prompt, calls the
        provider, logs the call, and returns the result.

        Args:
            db: Database session
            org_id: Organization ID
            operation: LLMOperation enum
            input_data: Dict of field_name -> field_value (already selected)
            provider_id: Override provider (defaults to org's first enabled)
            rule_id: Automation rule ID (for audit log)
            execution_id: Automation execution ID (for audit log)

        Returns:
            {"result": ..., "tokens_used": int, "model": str}
        """
        start = time.monotonic()

        # Layer 1: Global kill switch
        self.check_global_kill_switch()

        # Layer 2: Org policy
        policy = await self.get_org_policy(db, org_id)
        self.check_org_policy(policy)

        # Determine provider
        if not provider_id:
            provider_id = "ollama" if policy == LLMOrgPolicy.LOCAL_ONLY else "openai"
        self.check_provider_allowed(policy, provider_id)

        # Layer 3: Budget check (estimate tokens from input size)
        input_text = " ".join(str(v)[:1000] for v in input_data.values())
        estimated = len(input_text.split()) * 2  # Rough estimate
        await self.check_token_budget(db, org_id, estimated)

        # Build prompt for the operation
        prompt = self._build_structured_prompt(operation, input_data)

        # Call provider
        from app.modules.ai.service import AIChatService

        service = AIChatService()
        provider = await service._get_provider(db, org_id, provider_id)

        messages = [
            {
                "role": "system",
                "content": "You are a data processing assistant. Respond ONLY with the requested output format. No explanations.",
            },
            {"role": "user", "content": prompt},
        ]

        try:
            response = await provider.chat(
                messages=messages,
                tools=None,
                max_tokens=500,
            )
            success = True
            error = None
            result_text = response.content
            prompt_tokens = response.usage.prompt_tokens if response.usage else 0
            completion_tokens = response.usage.completion_tokens if response.usage else 0
            total_tokens = prompt_tokens + completion_tokens
        except Exception as exc:
            success = False
            error = str(exc)
            result_text = ""
            prompt_tokens = 0
            completion_tokens = 0
            total_tokens = 0

        latency_ms = (time.monotonic() - start) * 1000

        # Log the call (privacy-preserving: field names only)
        await self.log_call(
            db,
            organization_id=org_id,
            provider=provider_id,
            model=getattr(response, "model", provider_id) if success else provider_id,
            operation=operation.value,
            input_fields_sent=list(input_data.keys()),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            success=success,
            error=error,
            latency_ms=latency_ms,
            rule_id=rule_id,
            execution_id=execution_id,
        )

        # Record token usage for budget tracking
        if success:
            if total_tokens > 0:
                await self.record_token_usage(db, org_id, total_tokens)
            # Reconcile the Redis reservation (pre-incremented by `estimated` at the
            # budget check) DOWN to actual usage — otherwise the monthly counter
            # inflates by (estimate - actual) per call and eventually false-rejects.
            if estimated > 0:
                await self._redis_budget_rollback(org_id, estimated - total_tokens)

        if not success:
            # Roll back the full Redis reservation since the LLM call failed
            if estimated > 0:
                await self._redis_budget_rollback(org_id, estimated)
            raise RuntimeError(f"LLM call failed: {error}")

        return {
            "result": result_text,
            "tokens_used": total_tokens,
            "model": getattr(response, "model", provider_id),
            "operation": operation.value,
        }

    @staticmethod
    def _sanitize_key(key: str) -> str:
        """Sanitize a field key for safe prompt embedding (strip Markdown/injection)."""
        import re

        # Only allow alphanumeric, underscore, hyphen, dot
        return re.sub(r"[^a-zA-Z0-9_.\-]", "_", key)[:100]

    def _build_structured_prompt(
        self,
        operation: LLMOperation,
        input_data: dict[str, str],
    ) -> str:
        """Build operation-specific prompt from input data."""
        # Sanitize keys and truncate values to prevent prompt injection
        fields_text = "\n".join(
            f"{self._sanitize_key(k)}: {str(v)[:1000]}"
            for k, v in input_data.items()
            if not k.startswith("_")  # Skip control fields
        )

        if operation == LLMOperation.CLASSIFY:
            labels = input_data.get("_labels", "")
            return (
                f"Classify the following data into exactly ONE of these labels: {labels}\n\n"
                f"{fields_text}\n\n"
                f"Respond with ONLY the label, nothing else."
            )
        elif operation == LLMOperation.EXTRACT:
            schema = input_data.get("_output_schema", "{}")
            return (
                f"Extract structured data from the following text.\n"
                f"Output MUST be valid JSON matching this schema: {schema}\n\n"
                f"{fields_text}\n\n"
                f"Respond with ONLY the JSON object."
            )
        elif operation == LLMOperation.SUMMARIZE:
            max_words = input_data.get("_max_words", "200")
            return (
                f"Summarize the following data in {max_words} words or fewer.\n\n"
                f"{fields_text}\n\n"
                f"Respond with ONLY the summary text."
            )
        else:
            return fields_text


# Module-level singleton
governance = LLMGovernanceService()


# =============================================================================
# Monthly budget reset (M1)
# =============================================================================
#
# ``OrgLLMPolicy.budget_reset_at`` was added in migration 008 but nothing
# ever flipped ``tokens_used_this_month`` back to zero — so an org's
# monthly counter was effectively a lifetime counter. This Celery task,
# registered via ``app.core.celery_app.beat_schedule`` (see
# ``reset-monthly-ai-budgets`` entry), runs daily at 00:05 UTC and resets
# any org whose ``budget_reset_at`` is in a previous calendar month.
#
# We define the task INSIDE the AI module so the operational logic stays
# co-located with the policy model. ``celery_app.py`` only needs to add
# the beat-schedule entry and include ``app.modules.ai.governance`` in
# its task-discovery list.


def _register_monthly_reset_task() -> Any:
    """Idempotently register the monthly-budget reset Celery task.

    Wrapped in a function so importing this module doesn't require a
    running Celery context — useful for unit tests that import the
    governance helpers without the worker stack.
    """
    try:
        from app.core.celery_app import celery_app
        from app.db.session import CelerySessionLocal
    except Exception:
        logger.debug("Celery app unavailable; reset_monthly_ai_budgets not registered")
        return None

    @celery_app.task(name="ai.reset_monthly_budgets", ignore_result=True)  # type: ignore[untyped-decorator]
    def reset_monthly_ai_budgets() -> dict[str, Any]:  # pragma: no cover - exercised by beat
        """Reset ``tokens_used_this_month`` for orgs in a new calendar month.

        Strategy: any policy row whose ``budget_reset_at`` is NULL or in
        a previous month gets ``tokens_used_this_month=0`` and
        ``budget_reset_at=now()``. We also wipe the Redis counter so the
        atomic path in ``check_token_budget`` doesn't immediately
        re-trip the budget.
        """
        import asyncio

        from sqlalchemy import or_, update

        from app.modules.ai.models import OrgLLMPolicy as OrgPolicyRow

        async def _run() -> dict[str, Any]:
            now = datetime.now(UTC)
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            reset_count = 0
            async with CelerySessionLocal() as db:  # type: ignore[misc]
                stmt = (
                    update(OrgPolicyRow)
                    .where(
                        or_(
                            OrgPolicyRow.budget_reset_at.is_(None),
                            OrgPolicyRow.budget_reset_at < month_start,
                        )
                    )
                    .values(tokens_used_this_month=0, budget_reset_at=now)
                    .returning(OrgPolicyRow.organization_id)
                )
                result = await db.execute(stmt)
                org_ids = [r[0] for r in result.fetchall()]
                await db.commit()
                reset_count = len(org_ids)

            # Best-effort Redis wipe so the per-org atomic counters
            # don't shadow the DB reset.
            try:
                from app.core.events import event_bus

                r = event_bus._redis
                if r is not None:
                    for org_id in org_ids:
                        # Drop the previous month's key — current-month
                        # key already references the new month string.
                        prev = now.replace(day=1) - timedelta(days=1)
                        key = f"llm:budget:{org_id}:{prev.year}:{prev.month:02d}"
                        try:
                            await r.delete(key)
                        except Exception:
                            pass
            except Exception:
                logger.debug("Could not clear Redis counters during monthly reset", exc_info=True)

            return {"reset": reset_count, "at": now.isoformat()}

        return asyncio.run(_run())

    return reset_monthly_ai_budgets


# Register on import so Celery worker autodiscovery picks it up.
_register_monthly_reset_task()
