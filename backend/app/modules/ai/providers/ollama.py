# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Ollama LLM Provider
=====================================

Direct httpx calls to Ollama's OpenAI-compatible endpoint.
Default base URL: http://localhost:11434
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

DEFAULT_OLLAMA_URL = "http://localhost:11434"


class OllamaProvider(BaseLLMProvider):
    PROVIDER_ID = "ollama"
    PROVIDER_NAME = "Ollama (Local)"

    def __init__(self, api_key: str = "", base_url: str = DEFAULT_OLLAMA_URL):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Content-Type": "application/json"},
            timeout=300.0,  # Local models can be slow on first load
        )

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    def list_models(self) -> list[str]:
        # Dynamic — populated from /api/tags at runtime
        return ["llama3", "mistral", "codestral", "gemma2", "phi3", "qwen2"]

    async def test_connection(self) -> bool:
        try:
            r = await self._client.get("/api/tags")
            return r.status_code == 200
        except Exception:
            return False

    async def list_available_models(self) -> list[str]:
        """Fetch actually-pulled models from Ollama."""
        try:
            r = await self._client.get("/api/tags")
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return self.list_models()

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Use OpenAI-compatible endpoint
        payload: dict[str, Any] = {
            "model": model or "llama3",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        response = await self._client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]
        msg = choice["message"]
        usage_data = data.get("usage", {})

        tool_calls = None
        if msg.get("tool_calls"):
            tool_calls = [
                ToolCall(
                    id=tc.get("id", f"call_{i}"),
                    name=tc["function"]["name"],
                    arguments=json.loads(tc["function"].get("arguments", "{}") or "{}"),
                )
                for i, tc in enumerate(msg["tool_calls"])
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
            "model": model or "llama3",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with self._client.stream("POST", "/v1/chat/completions", json=payload) as response:
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
