# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Module Database Models
=========================================

Stores AI conversations, messages, and provider configurations.
Uses PostgreSQL schema "ai" (separate from "core" schema).
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, TimestampMixin, UUIDMixin


class AIConversation(Base, UUIDMixin, AuditMixin):
    """A conversation session with the AI assistant."""

    __tablename__ = "ai_conversations"
    __table_args__ = (
        Index("ix_ai_conv_user", "user_id"),
        Index("ix_ai_conv_org", "organization_id"),
        {"schema": "ai"},
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[UUID | None] = mapped_column(nullable=True)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # openai/anthropic/ollama
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class AIMessage(Base, UUIDMixin):
    """A single message in an AI conversation."""

    __tablename__ = "ai_messages"
    __table_args__ = (
        Index("ix_ai_msg_conv", "conversation_id"),
        {"schema": "ai"},
    )

    conversation_id: Mapped[UUID] = mapped_column(
        ForeignKey("ai.ai_conversations.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # user/assistant/tool
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_calls: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    tool_call_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    token_usage: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AIProviderConfig(Base, UUIDMixin, AuditMixin):
    """LLM provider configuration per organization."""

    __tablename__ = "ai_provider_configs"
    __table_args__ = (
        Index("ix_ai_provider_org_provider", "organization_id", "provider", unique=True),
        {"schema": "ai"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # openai/anthropic/ollama
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    default_model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # LLM Governance — added in migration 008
    llm_org_policy: Mapped[str] = mapped_column(
        String(20), default="disabled", server_default="disabled", nullable=False
    )
    monthly_token_budget: Mapped[int] = mapped_column(
        Integer, default=100_000, server_default="100000", nullable=False
    )
    tokens_used_this_month: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    budget_reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OrgLLMPolicy(Base, UUIDMixin, TimestampMixin):
    """
    Per-organization LLM governance policy and monthly token budget.

    Migrated out of ``AIProviderConfig`` (H2) so the policy is *one row per org*
    rather than non-deterministically read from "some" provider row. Per-provider
    settings (API key, model, base_url) still live on ``AIProviderConfig``.

    NOTE: was declared ``AuditMixin`` (adds ``created_by`` / ``updated_by``)
    but the original ``013_ai_org_llm_policy`` migration (since squashed into
    the ``001_initial`` baseline) only created the timestamp columns. Every
    ``SELECT *`` 500'd with ``UndefinedColumnError:
    column org_llm_policies.created_by does not exist``, breaking
    ``GET /ai/providers`` and ``GET /ai/governance/usage`` on every page
    load. Switched to ``TimestampMixin`` to match what the DB actually has
    — policy rows are created server-side via ``_get_or_create_org_policy``
    (no human author) so created_by/updated_by carry no value here.
    """

    __tablename__ = "org_llm_policies"
    __table_args__ = (
        Index("ix_org_llm_policy_org", "organization_id", unique=True),
        {"schema": "ai"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=False
    )
    llm_org_policy: Mapped[str] = mapped_column(
        String(20), default="disabled", server_default="disabled", nullable=False
    )
    monthly_token_budget: Mapped[int] = mapped_column(
        Integer, default=100_000, server_default="100000", nullable=False
    )
    tokens_used_this_month: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    budget_reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LLMCallLog(Base, UUIDMixin):
    """
    Privacy-preserving audit log for LLM calls.

    Stores field NAMES (not values), token counts, and latency.
    Used for budget tracking, compliance, and debugging.
    """

    __tablename__ = "llm_call_logs"
    __table_args__ = (
        Index("ix_llm_call_logs_org", "organization_id"),
        Index("ix_llm_call_logs_created", "created_at"),
        Index("ix_llm_call_logs_rule", "rule_id"),
        {"schema": "ai"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[UUID | None] = mapped_column(nullable=True)
    execution_id: Mapped[UUID | None] = mapped_column(nullable=True)

    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    operation: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # classify|extract|summarize|chat

    input_fields_sent: Mapped[list[Any]] = mapped_column(JSONB, default=list, nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
