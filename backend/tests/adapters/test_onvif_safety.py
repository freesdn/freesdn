# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the ONVIF camera adapter read-only gate.

ONVIF was the only camera adapter that executed operational/config writes
(PTZ move, goto/set/delete preset, image settings, reboot) unconditionally,
ignoring ``ADAPTER_READ_ONLY`` (external pre-public review,
finding F2). This restores parity with the Hikvision adapter: every write
is refused unless the caller passes ``force=True`` AND the operator has
cleared ``ADAPTER_READ_ONLY``. The cameras API/service opt in for
sanctioned operator actions (``_API_WRITE_FORCE`` / ``_with_force``), so
the legitimate paths are unaffected.

No live camera is contacted — the read-only refusal fires before any
connection is attempted.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.adapters.onvif.adapter import (
    AdapterReadOnlyError,
    ONVIFAdapter,
    _enforce_read_only,
    _is_adapter_read_only,
)


def _make_adapter() -> ONVIFAdapter:
    """Build an adapter pointed at a TEST-NET-1 (RFC 5737) host."""
    return ONVIFAdapter(host="192.0.2.1", username="admin", password="x", port=80)


# The full ONVIF write surface — name + a minimal valid arg tuple. Each is
# a live-device mutation that must be gated.
_MUTATORS: list[tuple[str, tuple, dict]] = [
    ("ptz_control", ("", "left"), {"speed": 50, "channel": 1}),
    ("goto_preset", ("", 1), {"channel": 1}),
    ("set_preset", ("", 1, "home"), {"channel": 1}),
    ("delete_preset", ("", 1), {"channel": 1}),
    ("set_image_settings", ({"brightness": 50},), {"channel": 1}),
    ("reboot_device", ("",), {}),
]


# ─────────────────────────────────────────────────────────────────────────────
# Read-only gate
# ─────────────────────────────────────────────────────────────────────────────


class TestReadOnlyGate:
    """Every ONVIF write refuses when ``ADAPTER_READ_ONLY`` is set unless
    the caller passes ``force=True``. The refusal fires on the first line,
    before any ``connect()``, so the test never opens a socket."""

    @pytest.mark.asyncio
    @patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize("name,args,kwargs", _MUTATORS, ids=[m[0] for m in _MUTATORS])
    async def test_write_refused_by_default(self, name: str, args: tuple, kwargs: dict) -> None:
        adapter = _make_adapter()
        method = getattr(adapter, name)
        with pytest.raises(AdapterReadOnlyError):
            await method(*args, **kwargs)

    @pytest.mark.asyncio
    @patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: True)
    async def test_force_true_opts_in(self) -> None:
        """With ``force=True`` the gate is bypassed — proven by reaching the
        next guard (the PTZ-capability check returns a NOT_SUPPORTED fail)
        rather than the read-only refusal. ``_connected`` is pre-set so no
        socket is opened."""
        adapter = _make_adapter()
        adapter._connected = True
        adapter._onvif_caps.has_ptz = False
        result = await adapter.ptz_control("", "left", speed=50, channel=1, force=True)
        # Reached the capability guard → gate did NOT refuse.
        assert result.success is False
        assert result.error_code == "NOT_SUPPORTED"

    @pytest.mark.asyncio
    @patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: False)
    async def test_no_force_needed_when_read_only_off(self) -> None:
        """When the operator clears ADAPTER_READ_ONLY the gate is a no-op
        even without force — the call proceeds to the next guard."""
        adapter = _make_adapter()
        adapter._connected = True
        adapter._onvif_caps.has_ptz = False
        result = await adapter.ptz_control("", "left", speed=50, channel=1)
        assert result.success is False
        assert result.error_code == "NOT_SUPPORTED"


# ─────────────────────────────────────────────────────────────────────────────
# Helper unit behaviour + default
# ─────────────────────────────────────────────────────────────────────────────


class TestEnforceHelper:
    @patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: True)
    def test_enforce_raises_without_force(self) -> None:
        with pytest.raises(AdapterReadOnlyError):
            _enforce_read_only(force=False, action="test")

    @patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: True)
    def test_enforce_passes_with_force(self) -> None:
        # No raise.
        _enforce_read_only(force=True, action="test")

    @patch("app.adapters.onvif.adapter._is_adapter_read_only", lambda: False)
    def test_enforce_passes_when_read_only_off(self) -> None:
        _enforce_read_only(force=False, action="test")

    def test_default_is_read_only(self) -> None:
        # Shipped default is True — no env override in this test process.
        assert _is_adapter_read_only() is True
