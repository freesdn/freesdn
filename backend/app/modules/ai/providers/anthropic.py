# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Anthropic LLM Provider
=======================================

Direct httpx calls to Anthropic Messages API.
No anthropic SDK dependency — pure REST.
"""

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx

from app.modules.ai.providers.base import (
    BaseLLMProvider,
    LLMResponse,
    LLMStreamChunk,
    TokenUsage,
    ToolCall,
)

logger = logging.getLogger(__name__)

ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"
# OFFLINE FALLBACK ONLY -- `fetch_models()` asks the account what this key may
# actually call, which is the only correct answer per operator. Current Claude
# 5 family first, with the 4.x ids retained because keys still address them.
SUPPORTED_MODELS = [
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
    "claude-fable-5-1",
    "claude-opus-4-5",
    "claude-sonnet-4-20250514",
    "claude-haiku-4-5-20251001",
]


class AnthropicProvider(BaseLLMProvider):
    PROVIDER_ID = "anthropic"
    PROVIDER_NAME = "Anthropic"

    def __init__(self, api_key: str, base_url: str = ANTHROPIC_API_BASE):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "Content-Type": "application/json",
            },
            timeout=120.0,
        )

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    def list_models(self) -> list[str]:
        return SUPPORTED_MODELS

    async def fetch_models(self) -> list[str]:
        """Ask the account which models this key may call.

        Same free `GET /v1/models` that `test_connection()` already uses, so
        this costs no tokens. The response is paginated; `limit=1000` covers
        the whole catalogue in one call, and `has_more` is still followed a
        bounded number of times rather than trusted to be false.
        """
        collected: list[str] = []
        after: str | None = None
        try:
            for _ in range(5):  # bounded: never loop on a misbehaving `has_more`
                params: dict[str, str | int] = {"limit": 1000}
                if after:
                    params["after_id"] = after
                r = await self._client.get("/models", params=params)
                r.raise_for_status()
                payload = r.json()
                page = [
                    str(m.get("id"))
                    for m in (payload.get("data") or [])
                    if isinstance(m, dict) and m.get("id")
                ]
                collected.extend(page)
                if not payload.get("has_more") or not page:
                    break
                after = page[-1]
        except Exception:
            logger.warning(
                "Anthropic model listing failed; falling back to the built-in list",
                exc_info=True,
            )
            return self.list_models()

        # Newest first: the ids sort lexicographically in roughly the wrong
        # order, so reverse-sort puts the current generation at the top.
        return sorted(set(collected), reverse=True) or self.list_models()

    async def test_connection(self) -> bool:
        """Verify the key works without billing the operator.

        M3: previously this POSTed to ``/messages`` with ``max_tokens=1``,
        which costs money every time the Settings page opens a test.
        Anthropic now exposes a free ``GET /v1/models`` listing — that's
        the same auth code-path with zero token cost.
        """
        try:
            r = await self._client.get("/models")
            return r.status_code == 200
        except Exception:
            return False

    def _convert_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert OpenAI-style tool defs to Anthropic format."""
        result = []
        for t in tools:
            fn = t.get("function", t)
            result.append(
                {
                    "name": fn["name"],
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        return result

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Separate system message from rest
        system = ""
        user_messages = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                user_messages.append(m)

        payload: dict[str, Any] = {
            "model": model or "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_messages,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = self._convert_tools(tools)

        response = await self._client.post("/messages", json=payload)
        response.raise_for_status()
        data = response.json()

        content_text = ""
        tool_calls = None

        for block in data.get("content", []):
            if block["type"] == "text":
                content_text += block["text"]
            elif block["type"] == "tool_use":
                if tool_calls is None:
                    tool_calls = []
                tool_calls.append(
                    ToolCall(
                        id=block["id"],
                        name=block["name"],
                        arguments=block.get("input", {}),
                    )
                )

        usage_data = data.get("usage", {})
        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
                total_tokens=usage_data.get("input_tokens", 0) + usage_data.get("output_tokens", 0),
            ),
            model=data.get("model", model or ""),
            finish_reason=data.get("stop_reason", "stop"),
        )

    async def stream_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[LLMStreamChunk]:
        system = ""
        user_messages = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                user_messages.append(m)

        payload: dict[str, Any] = {
            "model": model or "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": user_messages,
            "stream": True,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = self._convert_tools(tools)

        async with self._client.stream("POST", "/messages", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                try:
                    data = json.loads(line[6:])
                    event_type = data.get("type", "")
                    if event_type == "content_block_delta":
                        delta = data.get("delta", {})
                        if delta.get("type") == "text_delta":
                            yield LLMStreamChunk(delta=delta.get("text", ""))
                    elif event_type == "message_stop":
                        yield LLMStreamChunk(finish_reason="stop")
                except (json.JSONDecodeError, KeyError):
                    continue
