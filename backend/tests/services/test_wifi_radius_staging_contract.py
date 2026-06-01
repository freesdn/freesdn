# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pins the WiFi/RADIUS staged-write -> Omada API-call contract.

Verified live (staged-only) against the dual-gate: a WPA-Enterprise SSID change
stages to a pending row and routes to the Omada ``update_ssid_advanced`` PATCH
without touching the controller. This locks that (feature, operation) -> client
method mapping so a refactor cannot silently send a staged RADIUS change to the
wrong endpoint.
"""

from __future__ import annotations

from app.adapters.omada.client import OmadaApiClient
from app.services.adapter_omada_wifi import _APPLY


def test_wpa_enterprise_ssid_change_maps_to_update_ssid_advanced() -> None:
    assert _APPLY[("wifi.ssid.advanced", "update")] == "update_ssid_advanced"


def test_wlan_group_advanced_maps_correctly() -> None:
    assert _APPLY[("wifi.wlan_group.advanced", "update")] == "update_wlan_group_advanced"


def test_unknown_wifi_feature_is_not_mapped() -> None:
    assert ("wifi.bogus", "update") not in _APPLY


def test_client_exposes_the_mapped_ssid_method() -> None:
    # The method the staged change resolves to must exist on the Omada client.
    assert callable(getattr(OmadaApiClient, "update_ssid_advanced", None))
