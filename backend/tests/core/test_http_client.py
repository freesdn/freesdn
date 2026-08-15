# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the overlay-aware HTTP client factory (P3 egress-reach keystone)."""

from app.core import http_client


def _clear_vpn_env(monkeypatch):
    for k in (
        "VPN_MODE",
        "FREESDN_OPENVPN_SIDECAR",
        "FREESDN_WIREGUARD_SIDECAR",
        "FREESDN_VPN_AUTOSTART",
    ):
        monkeypatch.delenv(k, raising=False)


def test_overlay_proxy_none_in_off_and_sidecar_modes(monkeypatch):
    _clear_vpn_env(monkeypatch)
    # default (off) -> no overlay proxy
    assert http_client.overlay_socks_proxy() is None
    # sidecar shares the tunnel netns (transparent routing) -> still no proxy
    monkeypatch.setenv("FREESDN_WIREGUARD_SIDECAR", "true")
    assert http_client.overlay_socks_proxy() is None


def test_overlay_proxy_set_in_userspace_mode(monkeypatch):
    _clear_vpn_env(monkeypatch)
    monkeypatch.setenv("FREESDN_VPN_AUTOSTART", "true")  # -> userspace
    assert http_client.overlay_socks_proxy() == "socks5://127.0.0.1:1055"
    monkeypatch.setenv("FREESDN_OVERLAY_SOCKS5", "socks5://10.0.0.1:9050")
    assert http_client.overlay_socks_proxy() == "socks5://10.0.0.1:9050"


def test_build_async_client_injects_proxy_only_when_userspace(monkeypatch):
    captured = {}

    def fake_client(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(http_client.httpx, "AsyncClient", fake_client)

    # off -> no proxy injected
    _clear_vpn_env(monkeypatch)
    http_client.build_async_client(base_url="http://device")
    assert "proxy" not in captured

    # userspace -> proxy injected
    monkeypatch.setenv("FREESDN_VPN_AUTOSTART", "true")
    http_client.build_async_client(base_url="http://device")
    assert captured.get("proxy") == "socks5://127.0.0.1:1055"

    # an explicit caller proxy is always respected (never overridden)
    http_client.build_async_client(base_url="http://device", proxy="socks5://explicit")
    assert captured["proxy"] == "socks5://explicit"


def test_build_aiohttp_session_no_connector_in_off_mode(monkeypatch):
    import aiohttp

    captured = {}

    def fake_session(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(aiohttp, "ClientSession", fake_session)
    _clear_vpn_env(monkeypatch)
    http_client.build_aiohttp_session(trust_env=False)
    # off mode -> no overlay SOCKS connector injected (pure pass-through)
    assert "connector" not in captured
