# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - OpenAI LLM Provider
====================================

Direct httpx calls to OpenAI Chat Completions API.
No openai SDK dependency — pure REST.
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

OPENAI_API_BASE = "https://api.openai.com/v1"
# OFFLINE FALLBACK ONLY -- `fetch_models()` asks the account what it may
# actually call. Entitlements are per-key, so this can never be right for
# every operator. These ids are left as-is rather than refreshed by guesswork:
# a fallback naming models that do not exist, or that the key cannot call, is
# worse than a dated one, and it is only ever reached when the API is
# unreachable.
SUPPORTED_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]

# `GET /models` returns every model on the account, including ones that are
# not chat completions endpoints at all. Offering those in a chat model picker
# produces a confusing list and a runtime error if one is chosen.
_NON_CHAT_MARKERS = (
    "embedding",
    "whisper",
    "tts",
    "dall-e",
    "moderation",
    "audio",
    "image",
    "transcribe",
    "search",
    "similarity",
    "edit",
    "davinci",
    "babbage",
    "curie",
    "ada",
    "codex",
)


class OpenAIProvider(BaseLLMProvider):
    PROVIDER_ID = "openai"
    PROVIDER_NAME = "OpenAI"

    def __init__(self, api_key: str, base_url: str = OPENAI_API_BASE):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
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

        `test_connection()` already hit this endpoint and discarded the body,
        keeping only the status code -- the listing was always available, it
        was just never read.
        """
        try:
            r = await self._client.get("/models")
            r.raise_for_status()
            payload = r.json()
        except Exception:
            logger.warning(
                "OpenAI model listing failed; falling back to the built-in list",
                exc_info=True,
            )
            return self.list_models()

        ids = [
            str(m.get("id"))
            for m in (payload.get("data") or [])
            if isinstance(m, dict) and m.get("id")
        ]
        chat = [i for i in ids if not any(mark in i.lower() for mark in _NON_CHAT_MARKERS)]
        # If the filter removed everything the account is presumably not a
        # standard OpenAI one (a compatible gateway naming models differently),
        # so show what it reported rather than an empty picker.
        return sorted(set(chat or ids)) or self.list_models()

    async def test_connection(self) -> bool:
        try:
            r = await self._client.get("/models")
            return r.status_code == 200
        except Exception:
            return False

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": model or "gpt-4o",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]
        msg = choice["message"]
        usage_data = data.get("usage", {})

        tool_calls = None
        if msg.get("tool_calls"):
            tool_calls = [
                ToolCall(
                    id=tc["id"],
                    name=tc["function"]["name"],
                    arguments=json.loads(tc["function"]["arguments"] or "{}"),
                )
                for tc in msg["tool_calls"]
            ]

        return LLMResponse(
            content=msg.get("content") or "",
            tool_calls=tool_calls,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
            ),
            model=data.get("model", model or ""),
            finish_reason=choice.get("finish_reason", "stop"),
        )

    async def stream_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[LLMStreamChunk]:
        payload: dict[str, Any] = {
            "model": model or "gpt-4o",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with self._client.stream("POST", "/chat/completions", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str == "[DONE]":
                    break
                try:
                    data = json.loads(data_str)
                    choice = data["choices"][0]
                    delta = choice.get("delta", {})
                    yield LLMStreamChunk(
                        delta=delta.get("content") or "",
                        finish_reason=choice.get("finish_reason"),
                    )
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue
