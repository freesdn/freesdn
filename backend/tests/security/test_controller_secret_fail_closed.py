# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Recognized encrypted controller credentials must never fall back to raw values."""

import importlib
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from app.core import crypto

HELPERS = [
    ("app.services.adapter_factory", "_decrypt_secret"),
    ("app.services.radius", "_safe_decrypt"),
    ("app.services.roaming", "_safe_decrypt"),
    ("app.services.vpn_orchestration", "_safe_decrypt"),
    ("app.api.v1.endpoints.unifi_deps", "_decrypt_if_needed"),
    ("app.api.v1.endpoints.poe", "_decrypt_if_needed"),
    ("app.api.v1.endpoints.network", "_decrypt_if_needed"),
    ("app.api.v1.endpoints.access_points", "_decrypt_if_needed"),
    ("app.api.v1.endpoints.switches", "_decrypt_if_needed"),
]
SAFE_ERROR = "Stored controller credential could not be decrypted"


@pytest.mark.parametrize("field", ["password", "client_secret"])
def test_existing_ORM_properties_already_reject_unreadable_values_control(field):
    from app.models.core import Controller

    row = Controller(config={field: invalid_secret("wrong-key")})
    with pytest.raises(ValueError):
        getattr(row, field)


def invalid_secret(mode):
    if mode == "wrong-key":
        return Fernet(Fernet.generate_key()).encrypt(b"owned-private-value").decode()
    if mode == "malformed":
        return "gAAAAA" + "!" * 110
    assert mode == "non-utf8"
    return crypto._get_fernet().encrypt(b"\xff").decode()


@pytest.mark.parametrize("module_name,name", HELPERS)
@pytest.mark.parametrize("mode", ["wrong-key", "malformed", "non-utf8"])
def test_unreadable_encrypted_value_never_returns_raw_credential(module_name, name, mode):
    value = invalid_secret(mode)
    assert crypto.is_encrypted(value)
    helper = getattr(importlib.import_module(module_name), name)
    with pytest.raises(ValueError) as raised:
        helper(value)
    assert str(raised.value) == SAFE_ERROR
    assert value not in str(raised.value)


@pytest.mark.parametrize("module_name,name", HELPERS)
@pytest.mark.parametrize("mode", ["none", "empty", "plaintext", "unicode-plaintext", "encrypted"])
def test_empty_legacy_and_readable_encrypted_values_remain_controls(module_name, name, mode):
    expected = (
        ""
        if mode in ["none", "empty"]
        else "owned-password-\u00e9"
        if mode == "unicode-plaintext"
        else "owned-password"
    )
    value = (
        None
        if mode == "none"
        else crypto.encrypt_credential(expected)
        if mode == "encrypted"
        else expected
    )
    assert getattr(importlib.import_module(module_name), name)(value) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,field",
    [
        (p, f)
        for p in ["factory", "poe", "network", "access_points", "switches"]
        for f in ["password", "client_secret"]
    ]
    + [("unifi_deps", "password"), ("factory", "token_secret")],
)
async def test_adapter_construction_stops_before_using_corrupt_secret(monkeypatch, path, field):
    from app.services import adapter_factory

    value = invalid_secret("wrong-key")
    controller = SimpleNamespace(
        controller_type="proxmox" if field == "token_secret" else "omada",
        host="192.168.254.254",
        port=8006,
        use_ssl=True,
        verify_ssl=True,
        username="owned",
        password="owned-password",
        connection_mode="cloud" if field == "client_secret" else "local",
        client_id="owned-id",
        client_secret="owned-cloud-secret",
        omada_id="owned",
        cloud_region="us",
        config={},
    )
    if field == "token_secret":
        controller.config = {"token_id": "owned@pve!monitor", "token_secret": value}
    else:
        setattr(controller, field, value)
    calls = []

    def build(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace()

    if path == "factory":
        module = adapter_factory
        monkeypatch.setattr(module, "get_adapter", build)
    else:
        module = importlib.import_module("app.api.v1.endpoints." + path)
        monkeypatch.setattr(
            module, "UniFiAdapter" if path == "unifi_deps" else "get_adapter", build
        )
    with pytest.raises(ValueError, match=SAFE_ERROR):
        if path == "factory":
            adapter_factory.build_adapter_for_controller(controller)
        elif path == "unifi_deps":
            module._build_adapter(controller)
        elif path == "network":
            await module._get_adapter_for_controller(controller)
        else:
            await module._get_adapter_for_device(
                SimpleNamespace(controller=controller, device_metadata={})
            )
    assert not calls
