# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Model lists must come from the provider, using the operator's own key.

Which models a key may call is a property of the account and its tier, so a
list compiled at build time is wrong for somebody by construction: it offers
models the key cannot call and hides ones it can.

Before this, the list existed twice as a hardcoded array -- once per provider
module and again in the settings UI -- and `BaseLLMProvider.list_models()` was
declared `def`, not `async def`, so it could not have made a request even if
something had wanted it to. (Nothing did: the backend copy had no callers at
all, so the array the operator saw was the frontend's.)

`fetch_models()` is the async path that asks the provider. Its contract:

  * parse the provider's own listing endpoint
  * NEVER raise -- an unreachable provider degrades to the built-in list,
    because a settings page that throws leaves an empty model picker
  * stay bounded -- no unbounded pagination loop on a misbehaving server

The fallbacks are deliberately NOT asserted to equal any particular list here;
these pin the fetch behaviour, which is the part that was missing.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.modules.ai.providers.anthropic import SUPPORTED_MODELS as ANTHROPIC_FALLBACK
from app.modules.ai.providers.anthropic import AnthropicProvider
from app.modules.ai.providers.ollama import OllamaProvider
from app.modules.ai.providers.openai import SUPPORTED_MODELS as OPENAI_FALLBACK
from app.modules.ai.providers.openai import OpenAIProvider


def _mount(provider: Any, handler) -> None:
    """Swap the provider's httpx client for one backed by `handler`."""
    provider._client = httpx.AsyncClient(
        base_url="http://provider.test",
        transport=httpx.MockTransport(handler),
    )


# ── OpenAI ─────────────────────────────────────────────────────────────────


async def test_openai_fetch_models_returns_what_the_account_reports():
    """The key's entitled models, not the built-in array."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "object": "list",
                "data": [
                    {"id": "some-future-chat-model", "object": "model"},
                    {"id": "another-chat-model", "object": "model"},
                ],
            },
        )

    p = OpenAIProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    assert seen == ["/models"], "must ask the account, not guess"
    assert models == ["another-chat-model", "some-future-chat-model"]
    # The whole point: a model nobody hardcoded is offered.
    assert "some-future-chat-model" not in OPENAI_FALLBACK


async def test_openai_fetch_models_hides_non_chat_models():
    """`/models` lists embeddings, audio and image models too.

    Offering those in a chat-model picker produces a confusing list and a
    runtime error if one is selected.
    """

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "a-chat-model"},
                    {"id": "text-embedding-3-large"},
                    {"id": "whisper-1"},
                    {"id": "tts-1-hd"},
                    {"id": "dall-e-3"},
                    {"id": "omni-moderation-latest"},
                ]
            },
        )

    p = OpenAIProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    assert models == ["a-chat-model"]


async def test_openai_fetch_models_keeps_everything_for_a_compatible_gateway():
    """An OpenAI-compatible gateway names models however it likes.

    If the chat filter removed everything, the account is not a standard
    OpenAI one -- showing an empty picker would be worse than showing what it
    reported.
    """

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "tts-local-llm"}]})

    p = OpenAIProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    assert models == ["tts-local-llm"]


@pytest.mark.parametrize(
    "handler",
    [
        pytest.param(lambda _r: httpx.Response(401, json={"error": "bad key"}), id="unauthorized"),
        pytest.param(lambda _r: httpx.Response(200, text="<html>not json</html>"), id="non_json"),
        pytest.param(lambda _r: httpx.Response(500, text="boom"), id="server_error"),
    ],
)
async def test_openai_fetch_models_never_raises(handler):
    """An unreachable or hostile provider must not break the settings page."""
    p = OpenAIProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()
    assert models == OPENAI_FALLBACK


async def test_openai_fetch_models_survives_a_connection_error():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    p = OpenAIProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()
    assert models == OPENAI_FALLBACK


# ── Anthropic ──────────────────────────────────────────────────────────────


async def test_anthropic_fetch_models_returns_the_live_catalogue():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"type": "model", "id": "claude-aaa-1"},
                    {"type": "model", "id": "claude-zzz-9"},
                ],
                "has_more": False,
            },
        )

    p = AnthropicProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    # Newest first: these ids sort the wrong way round, so the order is reversed.
    assert models == ["claude-zzz-9", "claude-aaa-1"]


async def test_anthropic_fetch_models_follows_pagination():
    pages = [
        {"data": [{"id": "claude-p1-a"}, {"id": "claude-p1-b"}], "has_more": True},
        {"data": [{"id": "claude-p2-a"}], "has_more": False},
    ]
    calls: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(request.url.params))
        return httpx.Response(200, json=pages[min(len(calls) - 1, len(pages) - 1)])

    p = AnthropicProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    assert set(models) == {"claude-p1-a", "claude-p1-b", "claude-p2-a"}
    assert len(calls) == 2
    # The second page must be requested from where the first ended.
    assert calls[1].get("after_id") == "claude-p1-b"


async def test_anthropic_fetch_models_pagination_is_bounded():
    """A server that always claims `has_more` must not loop forever."""
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            200, json={"data": [{"id": f"claude-{calls['n']}"}], "has_more": True}
        )

    p = AnthropicProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    assert calls["n"] <= 5, "unbounded pagination would hang the settings page"
    assert models


async def test_anthropic_fetch_models_never_raises():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "nope"})

    p = AnthropicProvider(api_key="k")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()
    assert models == ANTHROPIC_FALLBACK


# ── Ollama ─────────────────────────────────────────────────────────────────


async def test_ollama_fetch_models_reports_what_the_host_has_pulled():
    """Ollama's real list is whatever `/api/tags` says is installed.

    `list_models()` used to carry a comment claiming it was "populated from
    /api/tags at runtime" while returning a literal. The dynamic read existed
    as `list_available_models()` and nothing was wired to it.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(
            200, json={"models": [{"name": "qwen3:32b"}, {"name": "my-private-finetune:latest"}]}
        )

    p = OllamaProvider(base_url="http://provider.test")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()

    assert seen == ["/api/tags"]
    assert models == ["qwen3:32b", "my-private-finetune:latest"]
    assert "my-private-finetune:latest" not in p.list_models()


async def test_ollama_fetch_models_falls_back_when_host_is_down():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    p = OllamaProvider(base_url="http://provider.test")
    _mount(p, handler)
    async with p:
        models = await p.fetch_models()
    assert models == p.list_models()
