# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for ``app.adapters.decorators``.

These are the reference tests for the BaseAdapter v2 decorator
layer. They prove that:

1. ``@adapter_read`` emits latency on success, error counter on failure,
   and never publishes to the event bus.
2. ``@direct_action`` calls through to the wrapped method, publishes
   ``<feature>.ok`` on success and ``<feature>.failed`` on exception,
   and propagates exceptions after the event fires.
3. ``@staged_write`` skips the method body entirely and routes through
   ``self.staging.stage_change`` with the right payload + identifiers.

The contract is structurally enforced: any new adapter PR that doesn't
use these decorators for write methods misses the metric + event + audit
emissions that the platform-citizen audit identified as load-bearing.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

from app.adapters.decorators import (
    adapter_read,
    direct_action,
    staged_write,
)


# ════════════════════════════════════════════════════════════════════
# @adapter_read
# ════════════════════════════════════════════════════════════════════

class TestAdapterRead:
    """``@adapter_read`` should emit metrics but never events."""

    @pytest.mark.asyncio
    async def test_passthrough_returns_wrapped_value(self) -> None:
        @adapter_read("freepbx.extensions.list")
        async def list_ext() -> list[str]:
            return ["1001", "1002"]

        result = await list_ext()
        assert result == ["1001", "1002"]

    @pytest.mark.asyncio
    async def test_emits_latency_on_success(self) -> None:
        @adapter_read("freepbx.extensions.list")
        async def list_ext() -> list[str]:
            return ["1001"]

        with patch(
            "app.core.metrics.adapter_request_duration"
        ) as mock_metric:
            mock_metric.labels.return_value.observe = AsyncMock(
                return_value=None
            )
            mock_metric.labels.return_value.observe.side_effect = (
                lambda _v: None
            )
            await list_ext()

        mock_metric.labels.assert_called_once_with(
            adapter="freepbx", method="freepbx.extensions.list"
        )

    @pytest.mark.asyncio
    async def test_emits_error_on_exception_and_propagates(self) -> None:
        @adapter_read("freepbx.extensions.list")
        async def list_ext_fails() -> list[str]:
            raise RuntimeError("PBX unreachable")

        with patch("app.core.metrics.adapter_errors_total") as mock_metric:
            mock_metric.labels.return_value.inc = lambda: None
            with pytest.raises(RuntimeError, match="PBX unreachable"):
                await list_ext_fails()

        mock_metric.labels.assert_called_once_with(
            adapter="freepbx",
            error_type="read:freepbx.extensions.list",
        )

    @pytest.mark.asyncio
    async def test_does_not_publish_events(self) -> None:
        """Reads are silent — they MUST NOT publish to the event bus.

        If reads published events, every dashboard tab polling every 5s
        would flood the bus with no-op traffic.
        """
        @adapter_read("freepbx.extensions.list")
        async def list_ext() -> list[str]:
            return []

        with patch("app.core.events.publish_adapter_event") as mock_pub:
            await list_ext()

        mock_pub.assert_not_called()

    def test_metadata_attached_for_introspection(self) -> None:
        """Decorator should attach ``__adapter_decorator__`` and
        ``__adapter_feature__`` so contract-enforcement tooling can
        introspect a service class and verify every method is wrapped.
        """
        @adapter_read("freepbx.extensions.list")
        async def list_ext() -> list[str]:
            return []

        assert list_ext.__adapter_decorator__ == "adapter_read"
        assert list_ext.__adapter_feature__ == "freepbx.extensions.list"


# ════════════════════════════════════════════════════════════════════
# @direct_action
# ════════════════════════════════════════════════════════════════════

class TestDirectAction:
    """``@direct_action`` should call through + publish event."""

    @pytest.mark.asyncio
    async def test_returns_wrapped_value(self) -> None:
        @direct_action("camera.ptz_move", target_field="camera_id")
        async def ptz(*, camera_id: str, pan: int, tilt: int) -> dict:
            return {"status": "moving"}

        result = await ptz(camera_id="cam-1", pan=50, tilt=0)
        assert result == {"status": "moving"}

    @pytest.mark.asyncio
    async def test_publishes_ok_event_on_success(self) -> None:
        @direct_action("camera.ptz_move", target_field="camera_id")
        async def ptz(*, camera_id: str, pan: int) -> dict:
            return {"status": "moving"}

        with patch("app.core.events.publish_adapter_event") as mock_pub:
            await ptz(camera_id="cam-1", pan=50)

        assert mock_pub.call_count == 1
        call = mock_pub.call_args
        assert call.args[0] == "camera.ptz_move.ok"
        assert call.kwargs["adapter_id"] == "camera"
        assert call.kwargs["target_id"] == "cam-1"
        assert call.kwargs["outcome"] == "ok"
        assert call.kwargs["feature"] == "camera.ptz_move"

    @pytest.mark.asyncio
    async def test_publishes_failed_event_on_exception(self) -> None:
        @direct_action("camera.ptz_move", target_field="camera_id")
        async def ptz_fails(*, camera_id: str, pan: int) -> dict:
            raise ConnectionError("camera unreachable")

        with patch("app.core.events.publish_adapter_event") as mock_pub:
            with pytest.raises(ConnectionError):
                await ptz_fails(camera_id="cam-1", pan=50)

        call = mock_pub.call_args
        assert call.args[0] == "camera.ptz_move.failed"
        assert call.kwargs["outcome"] == "failed"
        assert call.kwargs["error"] == "ConnectionError"
        assert call.kwargs["target_id"] == "cam-1"

    @pytest.mark.asyncio
    async def test_default_target_field_aliases_resolve(self) -> None:
        """Without ``target_field``, the decorator should auto-resolve
        from the canonical alias list (camera_id / nvr_id / pbx_id /
        phone_id / controller_id / device_id / target_id)."""
        @direct_action("phone.reboot")
        async def reboot(*, phone_id: str, organization_id: UUID) -> None:
            return None

        org = uuid4()
        with patch("app.core.events.publish_adapter_event") as mock_pub:
            await reboot(phone_id="aa:bb:cc:dd:ee:ff", organization_id=org)

        call = mock_pub.call_args
        assert call.kwargs["target_id"] == "aa:bb:cc:dd:ee:ff"
        assert call.kwargs["organization_id"] == str(org)

    @pytest.mark.asyncio
    async def test_priority_passed_through(self) -> None:
        @direct_action(
            "nvr.reboot", target_field="nvr_id", priority="critical"
        )
        async def reboot_nvr(*, nvr_id: str) -> None:
            return None

        with patch("app.core.events.publish_adapter_event") as mock_pub:
            await reboot_nvr(nvr_id="nvr-1")

        # publish_adapter_event signature uses EventPriority enum.
        # Just verify the call was made with a priority arg.
        assert mock_pub.call_count == 1
        from app.core.events import EventPriority
        assert mock_pub.call_args.kwargs["priority"] == EventPriority.CRITICAL

    @pytest.mark.asyncio
    async def test_event_bus_failure_does_not_break_action(self) -> None:
        """If the event bus is down, the operator action must still
        complete. We can't recall a PTZ command because Redis is sad."""
        @direct_action("camera.ptz_move", target_field="camera_id")
        async def ptz(*, camera_id: str) -> dict:
            return {"status": "moved"}

        with patch(
            "app.core.events.publish_adapter_event",
            side_effect=RuntimeError("bus down"),
        ):
            # Must not raise.
            result = await ptz(camera_id="cam-1")

        assert result == {"status": "moved"}

    def test_metadata_attached_for_introspection(self) -> None:
        @direct_action("camera.ptz_move", target_field="camera_id")
        async def ptz(*, camera_id: str) -> dict:
            return {}

        assert ptz.__adapter_decorator__ == "direct_action"
        assert ptz.__adapter_feature__ == "camera.ptz_move"


# ════════════════════════════════════════════════════════════════════
# @staged_write
# ════════════════════════════════════════════════════════════════════

class _FakeStaging:
    """Stand-in for ``AdapterStagingService`` used by the decorator
    tests. Captures the call args so assertions can verify the
    decorator built the right staging payload."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def stage_change(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        # Return a stand-in for AdapterPendingChange — the test asserts
        # the decorator returned this exact value untouched.
        return {"_stub_change": True, **kwargs}


class _FakeService:
    """Service-class stand-in that exposes the same shape
    ``GatewayServiceBase`` provides: ``self.staging`` is an instance of
    something with an ``async stage_change(**kwargs)`` method."""

    def __init__(self) -> None:
        self.staging = _FakeStaging()


class TestStagedWrite:
    """``@staged_write`` should bypass the method body and route through
    ``self.staging.stage_change``."""

    @pytest.mark.asyncio
    async def test_routes_through_staging_with_full_payload(self) -> None:
        class S(_FakeService):
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *,
                organization_id: UUID,
                controller_id: UUID,
                vlan_id: int,
                name: str,
                subnet: str,
            ) -> None:
                # Body should never execute.
                raise AssertionError("decorator should bypass body")

        svc = S()
        org, ctrl = uuid4(), uuid4()
        result = await svc.create_vlan(
            organization_id=org,
            controller_id=ctrl,
            vlan_id=30,
            name="IoT",
            subnet="10.30.0.0/24",
        )

        assert len(svc.staging.calls) == 1
        call = svc.staging.calls[0]
        assert call["organization_id"] == org
        assert call["controller_id"] == ctrl
        assert call["feature"] == "vlan.create"
        assert call["operation"] == "create"
        # Payload contains only the non-plumbing kwargs.
        assert call["payload"] == {
            "vlan_id": 30, "name": "IoT", "subnet": "10.30.0.0/24",
        }
        assert result["_stub_change"] is True

    @pytest.mark.asyncio
    async def test_respects_payload_keys_filter(self) -> None:
        """When ``payload_keys`` is specified, only those keys are
        included in the staged payload — everything else is dropped."""
        class S(_FakeService):
            @staged_write(
                "vlan.create",
                operation="create",
                payload_keys=("vlan_id", "name"),
            )
            async def create_vlan(
                self, *,
                organization_id: UUID,
                controller_id: UUID,
                vlan_id: int,
                name: str,
                subnet: str,
                purpose: str = "general",
            ) -> None:
                pass

        svc = S()
        await svc.create_vlan(
            organization_id=uuid4(),
            controller_id=uuid4(),
            vlan_id=30,
            name="IoT",
            subnet="10.30.0.0/24",
            purpose="iot",
        )

        call = svc.staging.calls[0]
        # subnet + purpose dropped because not in payload_keys.
        assert call["payload"] == {"vlan_id": 30, "name": "IoT"}

    @pytest.mark.asyncio
    async def test_target_id_resolved_from_aliases(self) -> None:
        class S(_FakeService):
            @staged_write("camera.motion.update", operation="update")
            async def update_motion(
                self, *,
                organization_id: UUID,
                controller_id: UUID,
                camera_id: str,
                sensitivity: int,
            ) -> None:
                pass

        svc = S()
        await svc.update_motion(
            organization_id=uuid4(),
            controller_id=uuid4(),
            camera_id="cam-1",
            sensitivity=80,
        )

        call = svc.staging.calls[0]
        assert call["target_id"] == "cam-1"

    @pytest.mark.asyncio
    async def test_missing_organization_id_raises_type_error(self) -> None:
        class S(_FakeService):
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *, controller_id: UUID, vlan_id: int
            ) -> None:
                pass

        svc = S()
        with pytest.raises(TypeError, match="organization_id"):
            await svc.create_vlan(controller_id=uuid4(), vlan_id=30)

    @pytest.mark.asyncio
    async def test_missing_controller_id_raises_type_error(self) -> None:
        class S(_FakeService):
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *, organization_id: UUID, vlan_id: int
            ) -> None:
                pass

        svc = S()
        with pytest.raises(TypeError, match="controller_id"):
            await svc.create_vlan(organization_id=uuid4(), vlan_id=30)

    @pytest.mark.asyncio
    async def test_service_without_staging_raises_runtime_error(self) -> None:
        """The decorator MUST refuse to silently swallow the
        misconfiguration — a service that lacks ``self.staging`` would
        otherwise lose every write to the void."""
        class S:
            # No `staging` attribute at all.
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *, organization_id: UUID, controller_id: UUID,
                vlan_id: int,
            ) -> None:
                pass

        svc = S()
        with pytest.raises(RuntimeError, match="staging"):
            await svc.create_vlan(
                organization_id=uuid4(),
                controller_id=uuid4(),
                vlan_id=30,
            )

    @pytest.mark.asyncio
    async def test_org_id_alias_works(self) -> None:
        """``org_id`` and ``organization_id`` should both work — services
        in the codebase use both names."""
        class S(_FakeService):
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *, org_id: UUID, controller_id: UUID, vlan_id: int,
            ) -> None:
                pass

        svc = S()
        org = uuid4()
        await svc.create_vlan(org_id=org, controller_id=uuid4(), vlan_id=30)
        call = svc.staging.calls[0]
        assert call["organization_id"] == org

    @pytest.mark.asyncio
    async def test_uuid_coercion_from_string(self) -> None:
        """Endpoints often pass UUIDs as strings (FastAPI path params).
        The decorator should accept both."""
        class S(_FakeService):
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *, organization_id: Any, controller_id: Any,
                vlan_id: int,
            ) -> None:
                pass

        svc = S()
        org_uuid = uuid4()
        ctrl_uuid = uuid4()
        await svc.create_vlan(
            organization_id=str(org_uuid),
            controller_id=str(ctrl_uuid),
            vlan_id=30,
        )
        call = svc.staging.calls[0]
        assert call["organization_id"] == org_uuid
        assert call["controller_id"] == ctrl_uuid

    def test_metadata_attached_for_introspection(self) -> None:
        class S(_FakeService):
            @staged_write("vlan.create", operation="create")
            async def create_vlan(
                self, *, organization_id: UUID, controller_id: UUID,
            ) -> None:
                pass

        method = S.create_vlan
        assert method.__adapter_decorator__ == "staged_write"
        assert method.__adapter_feature__ == "vlan.create"
        assert method.__adapter_operation__ == "create"
