# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A gateway's settings JSON reaches the adapter only through a per-vendor allow-list.

``app.modules.gateway.adapter_helpers.build_adapter`` (gateway sync, drift,
VLAN distribution and the passthrough routes) splatted ``gw.settings`` into
``adapter_registry.create_adapter`` whole, and ``GatewayService._build_adapter``
dropped only a block-list. Any key an org admin put in that JSON became an
adapter constructor argument: pfSense pastes ``api_version`` into every request
path, ``timeout`` sets how long a sync holds a worker, and a key that collides
with an explicit argument (``verify_ssl``) raised ``TypeError`` on every sync.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.adapters.registry import adapter_registry
from app.core.crypto import encrypt_dict
from app.modules.firewall.adapter_settings import (
    GATEWAY_ADAPTER_SETTINGS,
    gateway_adapter_settings,
)
from app.modules.gateway.adapter_helpers import build_adapter

VENDORS = sorted(GATEWAY_ADAPTER_SETTINGS)

#: Constructor arguments an org admin must not be able to inject.
INJECTED = {
    "base_url": "https://198.51.100.9",
    "scheme": "http",
    "ssl_context": "none",
    "verify": False,
    "ca_bundle": "/etc/passwd",
    "proxies": {"all://": "http://198.51.100.9:3128"},
    "direct_write_force": True,
    "read_only": False,
    "force": True,
    "token_id": "x",
}


def _gateway(vendor: str, settings: dict) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        vendor=vendor,
        host="192.168.77.77",
        port=8443,
        verify_ssl=True,
        credentials=encrypt_dict({"username": "u", "password": "p"}),
        settings=settings,
    )


@pytest.fixture
def spy(monkeypatch):
    calls: list[dict] = []

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    return calls


@pytest.mark.parametrize("vendor", VENDORS)
def test_build_adapter_forwards_only_the_vendors_options(spy, vendor):
    good = {"use_ssl": True, "timeout": 20, "api_version": "v2", "parent_interface": "igc2"}
    build_adapter(_gateway(vendor, {**good, **INJECTED}))

    (call,) = spy
    extra = {
        k: v
        for k, v in call.items()
        if k not in {"adapter_id", "host", "username", "password", "port", "verify_ssl"}
    }
    assert extra == {k: v for k, v in good.items() if k in GATEWAY_ADAPTER_SETTINGS[vendor]}
    assert call["verify_ssl"] is True and call["port"] == 8443


@pytest.mark.parametrize("vendor", VENDORS)
def test_a_key_that_collides_with_an_explicit_argument_no_longer_breaks_the_build(spy, vendor):
    """``**{"verify_ssl": False}`` next to ``verify_ssl=gw.verify_ssl`` is a TypeError."""
    build_adapter(_gateway(vendor, {"verify_ssl": False, "port": 1, "host": "198.51.100.9"}))
    (call,) = spy
    assert call["verify_ssl"] is True
    assert call["port"] == 8443
    assert call["host"] == "192.168.77.77"


@pytest.mark.parametrize(
    ("vendor", "key", "value"),
    [
        ("pfsense", "api_version", "../../diag_command.php?x="),
        ("pfsense", "api_version", "v3"),
        ("opnsense", "timeout", 86400),
        ("mikrotik", "timeout", 0),
        ("mikrotik", "timeout", True),
        ("pfsense", "use_ssl", "false"),
        ("opnsense", "parent_interface", "igc2; reboot"),
        ("openwrt", "parent_interface", ""),
    ],
)
def test_a_value_outside_its_check_is_dropped(vendor, key, value):
    assert gateway_adapter_settings(vendor, {key: value}) == {}


def test_a_real_pfsense_adapter_keeps_its_own_api_version(caplog):
    """End to end through the real registry: the injected path segment never lands."""
    gw = _gateway("pfsense", {"api_version": "../../evil", "timeout": 15})
    with caplog.at_level("WARNING", logger="app.modules.firewall.adapter_settings"):
        adapter = build_adapter(gw)
    assert adapter._api.api_version == "v2"
    assert "api_version" in caplog.text
    assert "../../evil" not in caplog.text  # the key is logged, never the value


def test_an_unknown_vendor_gets_no_options():
    assert gateway_adapter_settings("someday-vendor", {"timeout": 10}) == {}
