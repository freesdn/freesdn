# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Module API
==============================

Chat, conversation management, and provider configuration endpoints.
"""

import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_active_user, is_unscoped_org_admin
from app.db import get_session
from app.modules.ai.models import AIConversation, AIMessage, AIProviderConfig, OrgLLMPolicy
from app.modules.ai.service import AIChatService, _decrypt, _encrypt

logger = logging.getLogger(__name__)
router = APIRouter()
_service = AIChatService()


# =============================================================================
# Provider base_url allowlist (C2)
# =============================================================================
#
# The previous implementation accepted *any* base_url that survived a
# generic ``validate_target_host(..., allow_private=True)`` check, which
# is intended for on-prem device management — so for OpenAI/Anthropic an
# attacker who reached the admin endpoint could redirect API traffic
# (with the org's stored API key in the header) to an arbitrary host.
#
# We now allowlist explicit hostnames per provider, with an optional
# ``settings.AI_PROVIDER_PROXY_HOSTS`` escape hatch for operators who
# legitimately front the public API with a reverse proxy. Ollama still
# accepts any host (it's a local LLM by design) but we block cloud
# instance-metadata IPs to prevent SSRF into AWS/GCP credentials.

# Cloud-metadata blocking for an Ollama ``base_url`` lives in
# ``_ollama_host_is_metadata`` below. It reuses the SINGLE central set in
# ``app.core.security_utils`` so the list can't drift again — the local copy
# that used to live here had gone stale and was missing Alibaba
# (100.100.100.200) and Oracle (192.0.0.192) IMDS.

#: Per-provider hostname allowlist for ``base_url``. Values are the
#: lowercased ``urlparse(...).hostname`` strings.
PROVIDER_BASE_URL_ALLOWLIST: dict[str, frozenset[str]] = {
    "openai": frozenset({"api.openai.com"}),
    "anthropic": frozenset({"api.anthropic.com"}),
}


def _allowed_proxy_hosts() -> set[str]:
    """Read ``settings.AI_PROVIDER_PROXY_HOSTS`` (CSV) for operator overrides.

    Operators who legitimately reverse-proxy OpenAI/Anthropic (e.g. through
    Cloudflare Workers, an internal LLM gateway) can set this CSV env var
    to extend the allowlist. We deliberately keep the override on settings
    (not the DB) so a compromised admin account cannot widen the SSRF
    surface without filesystem access.
    """
    try:
        from app.core.config import settings

        raw = getattr(settings, "AI_PROVIDER_PROXY_HOSTS", None) or ""
        return {h.strip().lower() for h in raw.split(",") if h.strip()}
    except Exception:
        return set()


def _ollama_host_is_metadata(host: str) -> bool:
    """True if an Ollama ``base_url`` host IS — or RESOLVES to — a cloud
    instance-metadata endpoint (AWS/GCP/Azure/Alibaba/Oracle IMDS).

    ALWAYS blocked, independent of ``AI_OLLAMA_ALLOW_PRIVATE_HOSTS``: an
    operator who legitimately allows a local/LAN Ollama still must never be
    able to pivot the provider into IMDS for cloud-credential theft. Reuses the
    single central metadata set so the list can't drift, and checks resolved
    addresses so a DNS name pointing at a metadata IP can't slip past.
    """
    import ipaddress

    from app.core.security_utils import (
        _METADATA_IPS,
        CLOUD_METADATA_IP_LITERALS,
        _resolve_hostname,
    )

    if host in _METADATA_IPS:  # literal metadata IP or metadata.google.internal
        return True
    try:
        ipaddress.ip_address(host)
        return False  # an IP literal not matched above is not a metadata endpoint
    except ValueError:
        pass
    return any(ip in CLOUD_METADATA_IP_LITERALS for ip in _resolve_hostname(host))


def _ollama_host_is_private(host: str) -> bool:
    """True if an Ollama ``base_url`` host is — or RESOLVES to — a private /
    loopback / reserved address (the SSRF surface we block by default).

    Resolves hostnames so ``localhost``-aliases and DNS names pointing at
    private IPs can't slip past a literal-string check. Fail-closed: a
    malformed or unresolvable host is treated as private (blocked), mirroring
    ``is_private_ip``. An operator who genuinely runs a local/LAN Ollama opts
    out via ``AI_OLLAMA_ALLOW_PRIVATE_HOSTS``.
    """
    import ipaddress

    from app.core.security_utils import _resolve_hostname, is_private_ip

    try:
        ipaddress.ip_address(host)
        return is_private_ip(host)  # IP literal
    except ValueError:
        pass
    ips = _resolve_hostname(host)
    if not ips:
        return True  # unresolvable → can't confirm safe → block
    return any(is_private_ip(ip) for ip in ips)


def _validate_provider_base_url(provider_id: str, base_url: str) -> None:
    """Reject base_url updates that don't satisfy the per-provider policy.

    - ``openai`` / ``anthropic``: hostname MUST be in the static allowlist
      or in ``settings.AI_PROVIDER_PROXY_HOSTS``. Scheme MUST be https.
    - ``ollama``: blocks cloud instance-metadata endpoints AND, by default,
      private/loopback/reserved hosts (SSRF) — an operator running a local
      Ollama opts in via ``AI_OLLAMA_ALLOW_PRIVATE_HOSTS``.
    """
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="Invalid base URL: missing host")

    if provider_id == "ollama":
        # Block instance-metadata even for the "local" provider — a malicious
        # admin could otherwise point Ollama at IMDS. ALWAYS enforced, even when
        # AI_OLLAMA_ALLOW_PRIVATE_HOSTS is set (a local Ollama is fine; IMDS
        # never is), and covers hostnames that RESOLVE to a metadata IP.
        if _ollama_host_is_metadata(host):
            raise HTTPException(
                status_code=400,
                detail=f"base_url '{host}' is a cloud-metadata endpoint and is not allowed",
            )
        # SSRF: Ollama is "local by design", but accepting ANY host let an
        # org_admin point it at internal services (Redis/Postgres/other tenants)
        # as a blind SSRF pivot. Block private/loopback/reserved (incl. via
        # hostname resolution) unless an operator explicitly allows a local/LAN
        # endpoint. This is the inverse of the C2 fix above — the ollama branch
        # had reintroduced exactly the RFC1918 gap C2 removed for cloud providers.
        from app.core.config import settings

        if not getattr(
            settings, "AI_OLLAMA_ALLOW_PRIVATE_HOSTS", False
        ) and _ollama_host_is_private(host):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"base_url '{host}' resolves to a private/loopback address. "
                    "Set AI_OLLAMA_ALLOW_PRIVATE_HOSTS=true to use a local/LAN Ollama endpoint."
                ),
            )
        return

    allowed = PROVIDER_BASE_URL_ALLOWLIST.get(provider_id, frozenset())
    proxy_hosts = _allowed_proxy_hosts()
    if host in allowed or host in proxy_hosts:
        # For cloud providers, only allow HTTPS — never let an admin
        # downgrade traffic carrying the API key onto plain HTTP.
        if (parsed.scheme or "").lower() != "https":
            raise HTTPException(
                status_code=400,
                detail=f"base_url for '{provider_id}' must use https://",
            )
        return

    raise HTTPException(
        status_code=400,
        detail=(
            f"base_url '{host}' is not in the allowlist for provider '{provider_id}'. "
            f"Permitted hosts: {sorted(allowed) or 'n/a'} (extend via "
            f"AI_PROVIDER_PROXY_HOSTS for reverse-proxy deployments)."
        ),
    )


async def _get_or_create_org_policy(session: AsyncSession, organization_id: UUID) -> OrgLLMPolicy:
    """Fetch the single per-org policy row, creating defaults if missing."""
    result = await session.execute(
        select(OrgLLMPolicy).where(OrgLLMPolicy.organization_id == organization_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = OrgLLMPolicy(organization_id=organization_id)
        session.add(row)
        await session.flush()
    return row


# =============================================================================
# Schemas
# =============================================================================


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    conversation_id: UUID | None = None
    # Allowlist providers — was a free-form str that flowed all the
    # way to _get_provider() before the unknown-provider check fired,
    # so a malformed value would 500 instead of cleanly 422'ing.
    provider: str = Field(default="openai", pattern=r"^(openai|anthropic|ollama)$")


class ChatResponse(BaseModel):
    conversation_id: str
    message: str
    tool_calls_executed: list[str]
    provider: str
    model: str


class ConversationSummary(BaseModel):
    id: UUID
    title: str | None
    provider: str
    model: str
    total_tokens: int
    created_at: str
    message_count: int = 0

    class Config:
        from_attributes = True


class ConversationDetail(ConversationSummary):
    messages: list[dict[str, Any]]


class ProviderConfigUpdate(BaseModel):
    # api_key caps mirror the credentials baseline (PEM-shaped keys
    # can be a few KB for service-account JSON).
    api_key: str | None = Field(default=None, max_length=16384)
    base_url: str | None = Field(default=None, max_length=2048)
    default_model: str | None = Field(default=None, max_length=128)
    is_enabled: bool | None = None
    # settings JSONB persisted to AIProviderConfig.settings and
    # re-read on every chat request. Cap to keep DoS-shaped payloads
    # out of the column.
    settings: dict[str, Any] | None = None
    # LLM Governance
    llm_org_policy: str | None = Field(default=None, max_length=32)
    monthly_token_budget: int | None = Field(default=None, ge=0, le=1_000_000_000)

    @field_validator("settings")
    @classmethod
    def _v_settings(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        if len(v) > 64:
            raise ValueError("settings must contain at most 64 keys")
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        if size > 16 * 1024:
            raise ValueError(f"settings exceeds 16384 bytes (got {size})")
        return v


class ProviderConfigResponse(BaseModel):
    provider: str
    is_enabled: bool
    default_model: str | None
    base_url: str | None
    api_key_set: bool  # True if key is configured (never expose actual key)
    settings: dict[str, Any]
    # LLM Governance
    llm_org_policy: str = "disabled"
    monthly_token_budget: int = 100_000
    tokens_used_this_month: int = 0


# =============================================================================
# Chat Endpoints
# =============================================================================


async def _check_ai_rate_limit(user_id: str, max_per_minute: int = 10) -> None:
    """Per-user rate limiting for AI chat (sliding window via Redis).

    H5: fails CLOSED on Redis errors. An attacker who can DoS Redis must
    not be able to bypass the per-user rate limit and run up the LLM bill.
    """
    try:
        from app.core.redis_client import get_async_redis

        client: Any = get_async_redis(decode_responses=True)
        key = f"ai:ratelimit:{user_id}"
        import time

        now = time.time()
        try:
            async with client.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(key, 0, now - 60)  # remove entries older than 1 min
                pipe.zcard(key)
                pipe.zadd(key, {str(now): now})
                pipe.expire(key, 120)
                results = await pipe.execute()
            count = results[1]
            if count >= max_per_minute:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"AI chat rate limit exceeded ({max_per_minute} requests/minute)",
                )
        finally:
            # Close the per-call client on ALL paths (incl. the 429 raise) so a
            # rate-limited/abusive caller cannot leak a Redis connection per hit.
            await client.aclose()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("AI rate limit Redis backend unavailable: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI rate limiter unavailable",
        ) from exc


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ChatResponse:
    """
    Send a message to the AI assistant.

    The AI will use available tools to query network state and return a response.
    """
    if not current_user.has_permission("ai.chat"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Requires ai.chat permission"
        )

    # SECURITY: per-user rate limiting (10 requests/minute)
    await _check_ai_rate_limit(str(current_user.id))

    from app.modules.ai.governance import (
        LLMBudgetExceededError,
        LLMGloballyDisabledError,
        LLMOrgDisabledError,
        LLMProviderNotAllowedError,
    )

    try:
        result = await _service.chat(
            user=current_user,
            db=session,
            message=body.message,
            conversation_id=body.conversation_id,
            provider_id=body.provider,
        )
        return ChatResponse(**result)
    except LLMGloballyDisabledError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI service is currently disabled",
        )
    except (LLMOrgDisabledError, LLMProviderNotAllowedError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI service is not available for this organization",
        )
    except LLMBudgetExceededError:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="AI usage budget exceeded"
        )
    except ValueError as e:
        logger.error("AI chat validation error: %s", e, exc_info=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid chat request")
    except Exception as e:
        logger.error("AI chat error: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI provider error",
        )


# =============================================================================
# Conversation Management
# =============================================================================


@router.get("/conversations", response_model=list[ConversationSummary])
async def list_conversations(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List conversations for the current user."""
    result = await session.execute(
        select(AIConversation)
        .where(AIConversation.user_id == current_user.id)
        .order_by(AIConversation.created_at.desc())
        .limit(100)
    )
    convs = result.scalars().all()
    # Serialize
    out = []
    for c in convs:
        out.append(
            ConversationSummary(
                id=c.id,
                title=c.title,
                provider=c.provider,
                model=c.model,
                total_tokens=c.total_tokens,
                created_at=c.created_at.isoformat(),
            )
        )
    return out


@router.get("/conversations/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(
    conversation_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ConversationDetail:
    """Get a conversation with all its messages."""
    result = await session.execute(
        select(AIConversation).where(
            AIConversation.id == conversation_id,
            AIConversation.user_id == current_user.id,
        )
    )
    conv = result.scalar_one_or_none()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")

    msg_result = await session.execute(
        select(AIMessage)
        .where(AIMessage.conversation_id == conversation_id)
        .order_by(AIMessage.created_at.asc())
    )
    messages = [
        {
            "id": str(m.id),
            "role": m.role,
            "content": m.content,
            "tool_calls": m.tool_calls,
            "tool_call_id": m.tool_call_id,
            "tool_name": m.tool_name,
            "created_at": m.created_at.isoformat(),
        }
        for m in msg_result.scalars().all()
    ]

    return ConversationDetail(
        id=conv.id,
        title=conv.title,
        provider=conv.provider,
        model=conv.model,
        total_tokens=conv.total_tokens,
        created_at=conv.created_at.isoformat(),
        message_count=len(messages),
        messages=messages,
    )


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(
    conversation_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a conversation and all its messages."""
    result = await session.execute(
        select(AIConversation).where(
            AIConversation.id == conversation_id,
            AIConversation.user_id == current_user.id,
        )
    )
    conv = result.scalar_one_or_none()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    await session.delete(conv)
    await session.commit()


# =============================================================================
# Provider Configuration (admin only)
# =============================================================================


@router.get("/providers", response_model=list[ProviderConfigResponse])
async def list_providers(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[ProviderConfigResponse]:
    """List provider configurations for the organization."""
    if not current_user.has_permission("ai.admin") and not is_unscoped_org_admin(current_user):
        # the raw ``is_org_admin`` arm ignored the API-key scope ceiling,
        # letting a scoped key narrowed away from ``ai.admin`` administer providers.
        raise HTTPException(status_code=403, detail="Requires ai.admin permission")

    result = await session.execute(
        select(AIProviderConfig).where(
            AIProviderConfig.organization_id == current_user.organization_id
        )
    )
    configs = {c.provider: c for c in result.scalars().all()}

    # H2: governance state lives on OrgLLMPolicy now, not on the
    # (potentially multiple) provider rows.
    policy_row = None
    if current_user.organization_id:
        policy_result = await session.execute(
            select(OrgLLMPolicy).where(OrgLLMPolicy.organization_id == current_user.organization_id)
        )
        policy_row = policy_result.scalar_one_or_none()

    org_policy = policy_row.llm_org_policy if policy_row else "disabled"
    org_budget = policy_row.monthly_token_budget if policy_row else 100_000
    org_used = policy_row.tokens_used_this_month if policy_row else 0

    out = []
    for provider_id in ("openai", "anthropic", "ollama"):
        cfg = configs.get(provider_id)
        out.append(
            ProviderConfigResponse(
                provider=provider_id,
                is_enabled=cfg.is_enabled if cfg else False,
                default_model=cfg.default_model if cfg else None,
                base_url=cfg.base_url if cfg else None,
                api_key_set=bool(cfg and cfg.api_key_encrypted),
                settings=cfg.settings if cfg else {},
                llm_org_policy=org_policy,
                monthly_token_budget=org_budget,
                tokens_used_this_month=org_used,
            )
        )
    return out


@router.put("/providers/{provider_id}", response_model=ProviderConfigResponse)
async def update_provider(
    provider_id: str,
    body: ProviderConfigUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ProviderConfigResponse:
    """Configure or update an LLM provider."""
    if not current_user.has_permission("ai.admin") and not is_unscoped_org_admin(current_user):
        # the raw ``is_org_admin`` arm ignored the API-key scope ceiling,
        # letting a scoped key narrowed away from ``ai.admin`` administer providers.
        raise HTTPException(status_code=403, detail="Requires ai.admin permission")
    if provider_id not in ("openai", "anthropic", "ollama"):
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider_id}")
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    result = await session.execute(
        select(AIProviderConfig).where(
            AIProviderConfig.organization_id == current_user.organization_id,
            AIProviderConfig.provider == provider_id,
        )
    )
    config = result.scalar_one_or_none()
    if not config:
        config = AIProviderConfig(
            organization_id=current_user.organization_id,
            provider=provider_id,
        )
        session.add(config)

    if body.api_key is not None:
        config.api_key_encrypted = _encrypt(body.api_key) if body.api_key else None
    if body.base_url is not None:
        if body.base_url:
            # C2: per-provider allowlist replaces the generic
            # validate_target_host check (which permitted any RFC1918
            # address — so an admin could redirect OpenAI traffic with
            # the org's API key to an attacker-controlled host).
            _validate_provider_base_url(provider_id, body.base_url)
        config.base_url = body.base_url
    if body.default_model is not None:
        config.default_model = body.default_model
    if body.is_enabled is not None:
        config.is_enabled = body.is_enabled
    if body.settings is not None:
        config.settings = body.settings

    # H2: governance fields (policy + budget) live on OrgLLMPolicy now.
    policy_row: OrgLLMPolicy | None = None
    if body.llm_org_policy is not None or body.monthly_token_budget is not None:
        policy_row = await _get_or_create_org_policy(session, current_user.organization_id)
        if body.llm_org_policy is not None:
            if body.llm_org_policy not in ("disabled", "local_only", "cloud_approved"):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid LLM policy. Must be: disabled, local_only, cloud_approved",
                )
            policy_row.llm_org_policy = body.llm_org_policy
        if body.monthly_token_budget is not None:
            if body.monthly_token_budget < 0:
                raise HTTPException(status_code=400, detail="Token budget must be non-negative")
            policy_row.monthly_token_budget = body.monthly_token_budget

    await session.commit()
    await session.refresh(config)

    # Refresh / fetch policy values for the response.
    if policy_row is None:
        policy_result = await session.execute(
            select(OrgLLMPolicy).where(OrgLLMPolicy.organization_id == current_user.organization_id)
        )
        policy_row = policy_result.scalar_one_or_none()

    return ProviderConfigResponse(
        provider=config.provider,
        is_enabled=config.is_enabled,
        default_model=config.default_model,
        base_url=config.base_url,
        api_key_set=bool(config.api_key_encrypted),
        settings=config.settings,
        llm_org_policy=policy_row.llm_org_policy if policy_row else "disabled",
        monthly_token_budget=policy_row.monthly_token_budget if policy_row else 100_000,
        tokens_used_this_month=policy_row.tokens_used_this_month if policy_row else 0,
    )


@router.post("/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Test connectivity to a configured LLM provider."""
    if not current_user.has_permission("ai.admin") and not is_unscoped_org_admin(current_user):
        # the raw ``is_org_admin`` arm ignored the API-key scope ceiling,
        # letting a scoped key narrowed away from ``ai.admin`` administer providers.
        raise HTTPException(status_code=403, detail="Requires ai.admin permission")
    # Match the ``update_provider`` allowlist — previously a bogus
    # provider id ran the DB query for nothing and returned 200 with
    # "Provider not configured" (indistinguishable from a real
    # unconfigured one).
    if provider_id not in ("openai", "anthropic", "ollama"):
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider_id}")

    result = await session.execute(
        select(AIProviderConfig).where(
            AIProviderConfig.organization_id == current_user.organization_id,
            AIProviderConfig.provider == provider_id,
        )
    )
    config = result.scalar_one_or_none()
    if not config or not config.api_key_encrypted:
        return {"success": False, "error": "Provider not configured"}

    api_key = _decrypt(config.api_key_encrypted)
    try:
        # H1: use `async with` so we never leak the httpx client even on
        # a failed/timed-out test.
        if provider_id == "openai":
            from app.modules.ai.providers.openai import OpenAIProvider

            async with OpenAIProvider(api_key=api_key) as p:
                ok = await p.test_connection()
        elif provider_id == "anthropic":
            from app.modules.ai.providers.anthropic import AnthropicProvider

            async with AnthropicProvider(api_key=api_key) as p:
                ok = await p.test_connection()
        elif provider_id == "ollama":
            from app.modules.ai.providers.ollama import OllamaProvider

            async with OllamaProvider(base_url=config.base_url or "http://localhost:11434") as p:
                ok = await p.test_connection()
        else:
            return {"success": False, "error": "Unknown provider"}
        return {"success": ok}
    except Exception as e:
        logger.error("AI provider connection test failed: %s", e, exc_info=True)
        return {"success": False, "error": f"Connection test failed ({type(e).__name__})"}


@router.get("/tools")
async def list_tools(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """List available AI tools and their descriptions."""
    from app.modules.ai.tools import TOOL_REGISTRY, load_tools

    load_tools()
    tools = [
        {"name": t.name, "description": t.description, "permission": t.permission}
        for t in TOOL_REGISTRY.values()
    ]
    return {"tools": tools, "total": len(tools)}


# =============================================================================
# LLM Governance Endpoints
# =============================================================================


@router.get("/governance/usage")
async def get_governance_usage(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Get current month's LLM token usage and budget."""
    if not current_user.has_permission("ai.admin") and not is_unscoped_org_admin(current_user):
        # the raw ``is_org_admin`` arm ignored the API-key scope ceiling,
        # letting a scoped key narrowed away from ``ai.admin`` administer providers.
        raise HTTPException(status_code=403, detail="Requires ai.admin permission")
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    # H2: read from OrgLLMPolicy (one row per org) instead of an arbitrary
    # provider config row.
    result = await session.execute(
        select(OrgLLMPolicy).where(OrgLLMPolicy.organization_id == current_user.organization_id)
    )
    policy_row = result.scalar_one_or_none()

    budget = getattr(policy_row, "monthly_token_budget", 100_000) if policy_row else 100_000
    used = getattr(policy_row, "tokens_used_this_month", 0) if policy_row else 0
    policy = getattr(policy_row, "llm_org_policy", "disabled") if policy_row else "disabled"

    return {
        "llm_org_policy": policy,
        "monthly_token_budget": budget,
        "tokens_used_this_month": used,
        "percentage_used": round(used / budget * 100, 1) if budget > 0 else 0,
        "budget_remaining": max(0, budget - used),
    }


@router.get("/governance/logs")
async def get_governance_logs(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    # Previously ``page=0`` was silently rewritten to ``page=1`` via
    # ``max(1, page)`` and ``size=10000`` was silently clamped to 100
    # — the response then echoed ``size=10000`` while only returning
    # 100 rows, which confused pagination clients. Enforce at the
    # query layer so callers get a clear 422 instead.
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
) -> dict[str, Any]:
    """List LLM call audit logs (admin only)."""
    if not current_user.has_permission("ai.admin") and not is_unscoped_org_admin(current_user):
        # the raw ``is_org_admin`` arm ignored the API-key scope ceiling,
        # letting a scoped key narrowed away from ``ai.admin`` administer providers.
        raise HTTPException(status_code=403, detail="Requires ai.admin permission")
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="Organization required")

    from sqlalchemy import func

    from app.modules.ai.models import LLMCallLog

    # Total count
    count_result = await session.execute(
        select(func.count())
        .select_from(LLMCallLog)
        .where(LLMCallLog.organization_id == current_user.organization_id)
    )
    total = count_result.scalar() or 0

    # Paginated results
    offset = (max(1, page) - 1) * min(size, 100)
    result = await session.execute(
        select(LLMCallLog)
        .where(LLMCallLog.organization_id == current_user.organization_id)
        .order_by(LLMCallLog.created_at.desc())
        .offset(offset)
        .limit(min(size, 100))
    )
    logs = [
        {
            "id": str(log.id),
            "provider": log.provider,
            "model": log.model,
            "operation": log.operation,
            "input_fields_sent": log.input_fields_sent,
            "prompt_tokens": log.prompt_tokens,
            "completion_tokens": log.completion_tokens,
            "success": log.success,
            "error": log.error,
            "latency_ms": round(log.latency_ms, 1),
            "rule_id": str(log.rule_id) if log.rule_id else None,
            "created_at": log.created_at.isoformat(),
        }
        for log in result.scalars().all()
    ]

    return {"logs": logs, "total": total, "page": page, "size": size}
