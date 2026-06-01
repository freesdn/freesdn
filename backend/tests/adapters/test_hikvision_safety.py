# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Production-safety tests for the Hikvision adapter.

Restores the reference dual-gate contract shared with
Omada / Proxmox / OPNsense / pfSense / MikroTik. The Hikvision
adapter mutates camera config (motion detection, recording
schedules, PTZ presets, two-way audio) and rebooting an NVR
drops every active stream — bad writes hurt.

The HTTP layer is mocked everywhere so **no live Hikvision device
is contacted** by this test module.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.hikvision.adapter import (
    AdapterReadOnlyError,
    HikvisionAdapter,
    _is_adapter_read_only,
    _validate_channel,
    _validate_host_not_ssrf,
)

# ─────────────────────────────────────────────────────────────────────────────
# Construction helper
# ─────────────────────────────────────────────────────────────────────────────


def _make_adapter() -> HikvisionAdapter:
    """Build an adapter pointed at a TEST-NET-1 (RFC 5737) host.

    Using ``192.0.2.1`` keeps the test from accidentally talking to
    a real device on the LAN even if the SSRF guard is bypassed.
    """
    return HikvisionAdapter(
        host="192.0.2.1", username="admin", password="x", port=80,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Channel validation
# ─────────────────────────────────────────────────────────────────────────────


class TestChannelValidation:
    """Critical #4 — every channel-bearing method funnels through
    ``_validate_channel`` so a hostile caller can't smuggle path
    segments via ``channel=`` into an ISAPI URL."""

    @pytest.mark.parametrize("value", [1, 16, 64, 128, 256])
    def test_accepts_in_range(self, value: int) -> None:
        assert _validate_channel(value) == value

    @pytest.mark.parametrize("value", [0, -1, 257, 1000, 99999])
    def test_rejects_out_of_range(self, value: int) -> None:
        with pytest.raises(AdapterError):
            _validate_channel(value)

    @pytest.mark.parametrize("value", ["abc", "../../etc", "1; rm -rf /"])
    def test_rejects_non_int(self, value: str) -> None:
        with pytest.raises(AdapterError):
            _validate_channel(value)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# Host SSRF validation
# ─────────────────────────────────────────────────────────────────────────────


class TestHostSSRFValidator:
    """Critical #3 / #5 — host + callback_url must reject loopback /
    metadata / link-local."""

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "127.0.0.42",
            "169.254.169.254",  # AWS / GCP metadata
            "localhost",
            "0.0.0.0",
            "::1",
        ],
    )
    def test_rejects_blocked_hosts(self, host: str) -> None:
        with pytest.raises(AdapterError):
            _validate_host_not_ssrf(host)

    @pytest.mark.parametrize(
        "host",
        [
            "10.0.0.1",       # RFC1918 — allowed by default
            "192.168.1.150",
            "172.16.10.10",
            "203.0.113.5",    # TEST-NET-3 — public
        ],
    )
    def test_accepts_legitimate_hosts(self, host: str) -> None:
        # No raise.
        assert _validate_host_not_ssrf(host) == host

    def test_rejects_empty(self) -> None:
        with pytest.raises(AdapterError):
            _validate_host_not_ssrf("")


class TestConstructorSSRFGuard:
    """The constructor must refuse to build an adapter pointed at a
    blocked address — discovered the bug late means a poisoned NVR
    row in the DB could send ISAPI requests at cloud metadata."""

    @pytest.mark.parametrize(
        "host", ["127.0.0.1", "169.254.169.254", "localhost"],
    )
    def test_rejects_ssrf_host_in_constructor(self, host: str) -> None:
        with pytest.raises(AdapterError):
            HikvisionAdapter(
                host=host, username="admin", password="x", port=80,
            )

    def test_rejects_ssrf_host_via_full_url(self) -> None:
        # Even when the host is embedded in a full URL, the
        # validator must dig the hostname out and check it.
        with pytest.raises(AdapterError):
            HikvisionAdapter(
                host="http://169.254.169.254:80",
                username="admin",
                password="x",
                port=80,
            )


# ─────────────────────────────────────────────────────────────────────────────
# Dual-gate read-only contract
# ─────────────────────────────────────────────────────────────────────────────


class TestReadOnlyGate:
    """Critical #1 — every write method refuses to execute when
    ``ADAPTER_READ_ONLY`` is set unless the caller passes
    ``force=True``. We patch the helper directly so the test does
    not depend on environment state."""

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_reboot_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.reboot_device("")

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_set_motion_detection_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.set_motion_detection({"enabled": True}, channel=1)

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_ptz_control_refused_by_default(self) -> None:
        """PTZ commands cause physical motion — must be gated."""
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.ptz_control("", "left", speed=50, channel=1)

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_subscribe_events_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.subscribe_events(
                "http://203.0.113.5/cb", event_types=["VMD"],
            )

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_set_recording_schedule_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.set_recording_schedule({"enabled": True}, channel=1)

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_send_audio_data_refused_by_default(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterReadOnlyError):
            await adapter.send_audio_data(channel=1, audio_data=b"\x00")

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: True,
    )
    async def test_force_true_opts_in(self) -> None:
        """When the caller explicitly passes ``force=True`` the gate
        is bypassed — verified by reaching the next guard (in this
        case the connect/channel check) rather than the read-only
        block-error."""
        adapter = _make_adapter()
        # Channel validation runs before the HTTP call so an
        # out-of-range channel surfaces an ``AdapterError`` (not
        # the ``AdapterReadOnlyError`` we'd see if the gate had
        # refused). This is the cleanest signal that ``force=True``
        # was respected.
        with pytest.raises(AdapterError) as exc:
            await adapter.set_motion_detection(
                {"enabled": True}, channel=999, force=True,
            )
        assert not isinstance(exc.value, AdapterReadOnlyError)


# ─────────────────────────────────────────────────────────────────────────────
# subscribe_events callback URL SSRF
# ─────────────────────────────────────────────────────────────────────────────


class TestSubscribeEventsCallbackSSRF:
    """Critical #5 — the callback URL must be validated even when
    the caller has cleared ``ADAPTER_READ_ONLY`` and passed
    ``force=True``."""

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: False,
    )
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/cb",
            "http://169.254.169.254/cb",
            "http://localhost/cb",
        ],
    )
    async def test_rejects_ssrf_callback_url(self, url: str) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.subscribe_events(url, force=True)

    @pytest.mark.asyncio
    @patch(
        "app.adapters.hikvision.adapter._is_adapter_read_only",
        lambda: False,
    )
    async def test_rejects_non_http_scheme(self) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            await adapter.subscribe_events("file:///etc/passwd", force=True)


# ─────────────────────────────────────────────────────────────────────────────
# Circuit breaker
# ─────────────────────────────────────────────────────────────────────────────


class TestCircuitBreaker:
    """High #10 — every adapter ships a labelled CircuitBreaker so
    the shared ``freesdn_adapter_circuit_state`` Prometheus gauge
    has a Hikvision series."""

    def test_breaker_starts_closed_with_labels(self) -> None:
        adapter = _make_adapter()
        assert adapter._breaker.state == "closed"
        assert adapter._breaker.name == "hikvision"
        assert "192.0.2.1" in adapter._breaker.host

    def test_breaker_trips_after_threshold_failures(self) -> None:
        adapter = _make_adapter()
        # The breaker is configured with failure_threshold=5.
        for _ in range(5):
            adapter._breaker.record_failure()
        assert adapter._breaker.state == "open"
        assert adapter._breaker.allow_request() is False

    def test_breaker_resets_on_success(self) -> None:
        adapter = _make_adapter()
        for _ in range(3):
            adapter._breaker.record_failure()
        adapter._breaker.record_success()
        assert adapter._breaker.state == "closed"


# ─────────────────────────────────────────────────────────────────────────────
# rtsp URL split (safe vs internal)
# ─────────────────────────────────────────────────────────────────────────────


class TestRtspUrlSplit:
    """High #12 — ``get_rtsp_url`` previously always returned the
    masked-creds variant which doesn't actually authenticate. The
    new ``get_rtsp_url_internal`` returns a working URL for
    server-side proxying; the public ``get_rtsp_url`` continues to
    return the masked variant for API responses."""

    def test_safe_variant_masks_credentials(self) -> None:
        adapter = _make_adapter()
        url = adapter.get_rtsp_url_safe(channel=1, stream="main")
        assert "***:***" in url
        assert "admin" not in url
        assert ":x@" not in url

    def test_internal_variant_embeds_credentials(self) -> None:
        adapter = _make_adapter()
        url = adapter.get_rtsp_url_internal(channel=1, stream="main")
        # Real creds are present.
        assert "admin" in url
        assert "x@" in url
        assert "***" not in url

    def test_legacy_get_rtsp_url_returns_safe(self) -> None:
        """Existing callers (API response bodies) get the masked
        variant — that's the bug-preserving behaviour."""
        adapter = _make_adapter()
        assert (
            adapter.get_rtsp_url(channel=1, stream="main")
            == adapter.get_rtsp_url_safe(channel=1, stream="main")
        )

    @pytest.mark.parametrize("channel", [0, -1, 257])
    def test_invalid_channel_rejected(self, channel: int) -> None:
        adapter = _make_adapter()
        with pytest.raises(AdapterError):
            adapter.get_rtsp_url_safe(channel=channel)


# ─────────────────────────────────────────────────────────────────────────────
# Read-only flag default
# ─────────────────────────────────────────────────────────────────────────────


class TestReadOnlyFlagDefaults:
    """Default-safe: when the helper cannot resolve the setting it
    falls back to read-only=True so a misconfigured deployment errs
    on the side of refusing writes."""

    def test_default_is_read_only(self) -> None:
        # The shipped default is True — no env override in this
        # test process.
        assert _is_adapter_read_only() is True


# ─────────────────────────────────────────────────────────────────────────────
# Vendor dispatch in cameras/api.py
# ─────────────────────────────────────────────────────────────────────────────


class TestVendorDispatch:
    """High #8 — ``_get_adapter_for_camera`` must refuse to return a
    HikvisionAdapter for a non-Hikvision camera row. The check lives
    in ``_require_hikvision_camera``."""

    def test_requires_hikvision_device_type(self) -> None:
        from types import SimpleNamespace

        from fastapi import HTTPException

        from app.modules.cameras.api import _require_hikvision_camera

        # ONVIF camera row — must raise.
        cam = SimpleNamespace(device_type="onvif", vendor="Dahua")
        with pytest.raises(HTTPException) as exc:
            _require_hikvision_camera(cam)
        assert exc.value.status_code == 400

    def test_allows_hikvision_by_device_type(self) -> None:
        from types import SimpleNamespace

        from app.modules.cameras.api import _require_hikvision_camera

        cam = SimpleNamespace(device_type="hikvision", vendor="Hikvision")
        # No raise.
        _require_hikvision_camera(cam)

    def test_allows_hikvision_by_vendor_string(self) -> None:
        from types import SimpleNamespace

        from app.modules.cameras.api import _require_hikvision_camera

        # device_type missing but vendor mentions Hikvision.
        cam = SimpleNamespace(device_type=None, vendor="Hikvision DS-7616")
        _require_hikvision_camera(cam)


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot cache public_stats
# ─────────────────────────────────────────────────────────────────────────────


class TestSnapshotCachePublicStats:
    """High #16 — ``get_stream_stats`` no longer reaches into the
    snapshot cache's private ``_viewers`` map."""

    def test_public_stats_shape(self) -> None:
        from app.modules.cameras.api import _SnapshotCache

        cache = _SnapshotCache()
        stats = cache.public_stats()
        assert set(stats.keys()) == {"channels", "viewers"}
        assert stats["channels"] == 0
        assert stats["viewers"] == 0
