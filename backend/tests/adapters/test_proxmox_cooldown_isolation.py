# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""One controller's failed connection must not block another authentication route."""

from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from app.adapters.proxmox import client as module


@pytest.fixture
def peer(monkeypatch):
    state = SimpleNamespace(mode="network", attempts=0, clients=[], clock=100.0)

    def respond(request):
        state.attempts += 1
        if state.mode == "network":
            raise httpx.ConnectError("owned unavailable peer", request=request)
        if state.mode == "timeout":
            raise httpx.ConnectTimeout("owned timeout", request=request)
        if state.mode == "reject":
            return httpx.Response(401, json={"data": None})
        if state.mode == "missing-ticket":
            return httpx.Response(200, json={"data": {}})
        return httpx.Response(
            200, json={"data": {"ticket": "owned-ticket", "CSRFPreventionToken": "owned-csrf"}}
        )

    def build(**kwargs):
        client = httpx.AsyncClient(
            **kwargs,
            **({} if "transport" in kwargs else {"transport": httpx.MockTransport(respond)}),
        )
        state.clients.append(client)
        return client

    monkeypatch.setattr(module, "build_async_client", build)
    monkeypatch.setattr(module, "_reachability", module._ReachabilityTracker())
    monkeypatch.setattr(module, "_ticket_cache", module._TicketCache())
    monkeypatch.setattr(module, "_connection_cache", module._ConnectionCache())
    monkeypatch.setattr(module.time, "monotonic", lambda: state.clock)
    state.transport = lambda: httpx.MockTransport(respond)
    return state


def config(**changes):
    return replace(
        module.ProxmoxClientConfig(
            host="192.168.254.254", username="owned", password="owned-password", verify_ssl=True
        ),
        **changes,
    )


async def failure(peer, *, settings=None, transport=None):
    client = module.ProxmoxClient(settings or config(), transport=transport)
    with pytest.raises(module.ProxmoxApiError):
        await client.connect()
    assert client._http is None
    assert not client.is_connected
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["reject", "missing-ticket"])
async def test_authentication_failure_does_not_start_network_cooldown(peer, mode):
    peer.mode = mode
    await failure(peer)
    peer.mode = "success"
    async with module.ProxmoxClient(config()) as client:
        assert client.is_connected
    assert peer.attempts == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "credentials",
    [{"password": ""}, {"token_id": "owned@pam!partial"}, {"token_secret": "owned-partial"}],
)
async def test_incomplete_credentials_do_not_block_corrected_controller(peer, credentials):
    await failure(peer, settings=config(**credentials))
    peer.mode = "success"
    async with module.ProxmoxClient(config()) as client:
        assert client.is_connected
    assert peer.attempts == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"host": "192.168.254.253"},
        {"port": 8007},
        {"use_ssl": False},
        {"verify_ssl": False},
        {"username": "other"},
        {"password": "other-password"},
        {"realm": "other"},
        {"timeout": 15.5},
        {"token_id": "owned@pam!other", "token_secret": "owned-token"},
    ],
)
async def test_network_failure_isolated_to_exact_direct_context(peer, changes):
    await failure(peer)
    peer.mode = "success"
    async with module.ProxmoxClient(config(**changes)) as client:
        assert client.is_connected


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", ["HTTPS_PROXY", "SSL_CERT_FILE", "overlay"])
async def test_routing_or_trust_change_is_not_blocked_by_previous_failure(
    peer, monkeypatch, setting
):
    await failure(peer)
    if setting == "overlay":
        monkeypatch.setattr(
            "app.core.http_client.overlay_socks_proxy", lambda: "socks5://owned.invalid:1080"
        )
    else:
        monkeypatch.setenv(setting, "owned-new-route-or-trust")
    peer.mode = "success"
    async with module.ProxmoxClient(config()) as client:
        assert client.is_connected


@pytest.mark.asyncio
@pytest.mark.parametrize("direction", ["agent-agent", "agent-direct", "direct-agent"])
async def test_custom_transport_failure_does_not_block_another_route(peer, direction):
    first = None if direction == "direct-agent" else peer.transport()
    second = None if direction == "agent-direct" else peer.transport()
    await failure(peer, transport=first)
    peer.mode = "success"
    async with module.ProxmoxClient(config(), transport=second) as client:
        assert client.is_connected
    assert peer.attempts == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["network", "timeout"])
async def test_same_direct_context_keeps_network_cooldown_and_retries_after_expiry(peer, mode):
    peer.mode = mode
    await failure(peer)
    peer.mode = "success"
    with pytest.raises(module.ProxmoxApiError, match="cooldown"):
        await module.ProxmoxClient(config()).connect()
    assert peer.attempts == 1
    peer.clock += 11
    async with module.ProxmoxClient(config()) as client:
        assert client.is_connected
    assert peer.attempts == 2 and all(c.is_closed for c in peer.clients)


@pytest.mark.asyncio
async def test_same_custom_client_keeps_its_own_cooldown(peer):
    client = await failure(peer, transport=peer.transport())
    with pytest.raises(module.ProxmoxApiError, match="cooldown"):
        await client.connect()
    peer.clock += 11
    peer.mode = "success"
    async with client:
        assert client.is_connected
    assert peer.attempts == 2


@pytest.mark.asyncio
async def test_manual_host_reset_allows_direct_retry(peer):
    await failure(peer)
    module.reset_host_reachability(config().host)
    peer.mode = "success"
    async with module.ProxmoxClient(config()) as client:
        assert client.is_connected
    assert peer.attempts == 2


@pytest.mark.asyncio
async def test_success_in_another_context_does_not_clear_original_failure(peer):
    await failure(peer)
    peer.mode = "success"
    async with module.ProxmoxClient(config(port=8007)):
        pass
    with pytest.raises(module.ProxmoxApiError, match="cooldown"):
        await module.ProxmoxClient(config()).connect()
    assert peer.attempts == 2


def test_cooldown_is_effective_at_zero_monotonic_time(peer):
    peer.clock = 0.0
    tracker = module._ReachabilityTracker()
    tracker.mark_unreachable("owned")
    assert not tracker.is_reachable("owned")


def test_expired_failure_is_removed_when_checked(peer):
    tracker = module._ReachabilityTracker()
    tracker.mark_unreachable("owned")
    peer.clock += 11
    assert tracker.is_reachable("owned")
    assert not tracker._failures


def test_reachability_storage_is_bounded(peer):
    tracker = module._ReachabilityTracker()
    for i in range(300):
        tracker.mark_unreachable(f"owned-{i}")
    assert len(tracker._failures) <= 256
    assert not tracker.is_reachable("owned-299")


def test_recording_failure_prunes_expired_entries(peer):
    tracker = module._ReachabilityTracker()
    tracker.mark_unreachable("owned-old")
    peer.clock += 11
    tracker.mark_unreachable("owned-new")
    assert len(tracker._failures) == 1
    assert not tracker.is_reachable("owned-new")
