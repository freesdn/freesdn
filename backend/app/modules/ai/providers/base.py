# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - LLM Provider Base
==================================

Abstract base class for LLM providers.
Providers implement chat() and stream_chat() using direct httpx calls
(no provider-specific SDKs — just REST).
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from types import TracebackType
from typing import Any

JSONDict = dict[str, Any]


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""

    id: str
    name: str
    arguments: JSONDict


@dataclass
class TokenUsage:
    """Token usage stats from an LLM API call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class LLMResponse:
    """Completed LLM response."""

    content: str
    tool_calls: list[ToolCall] | None = None
    usage: TokenUsage | None = None
    model: str = ""
    finish_reason: str = "stop"


@dataclass
class LLMStreamChunk:
    """Single streaming chunk."""

    delta: str = ""
    finish_reason: str | None = None
    tool_call_delta: JSONDict | None = None


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    PROVIDER_ID: str
    PROVIDER_NAME: str

    @abstractmethod
    async def chat(
        self,
        messages: list[JSONDict],
        tools: list[JSONDict] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat request and return the full response."""
        ...

    @abstractmethod
    async def stream_chat(
        self,
        messages: list[JSONDict],
        tools: list[JSONDict] | None = None,
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AsyncIterator[LLMStreamChunk]:
        """Send a chat request and yield streaming chunks."""
        ...

    @abstractmethod
    def list_models(self) -> list[str]:
        """Return list of supported model IDs."""
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Verify the provider is reachable with current credentials."""
        ...

    async def close(self) -> None:  # noqa: B027
        """Close any underlying HTTP clients. Override in subclasses."""
        pass

    async def __aenter__(self) -> "BaseLLMProvider":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        await self.close()
        return False
