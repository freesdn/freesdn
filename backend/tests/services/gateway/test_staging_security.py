# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Security-focused tests for AdapterStagingService.

These verify the production-safety invariants for the staging
service. Every test runs against a mocked AsyncSession
— **no live Omada controller is contacted** at any point.

What we verify:

1. Stage refuses bad ``target_id`` (path-traversal attempts).
2. Stage refuses bad URL-path keys in payload (mac, wlan_id, etc.).
3. Apply enforces the dual-gate (OMADA_READ_ONLY + force=true).
4. Apply atomically claims the row (FOR UPDATE), preventing double-apply.
5. Discard checks org BEFORE mutation (no cross-tenant write).
6. Discard refuses non-pending rows unless force=True.
7. Reads list_pending pushes site_id into SQL, not Python post-filter.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.staging import AdapterPendingChange
from app.services.adapter_staging import AdapterStagingService


def _make_session() -> MagicMock:
    """A MagicMock async session with the bare-minimum surface the
    staging service uses. Async methods are AsyncMock; sync methods
    (like ``add``) are plain MagicMock."""
    session = MagicMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    # stage_change runs a ``SELECT count(*)`` pending-backlog guard whose
    # ``.scalar()`` must be an int (``>= _MAX_PENDING_PER_ORG``). A bare
    # AsyncMock().execute() returns a MagicMock whose .scalar() is non-numeric,
    # so configure an explicit scalar()->0 (empty backlog) result.
    count_result = MagicMock()
    count_result.scalar.return_value = 0
    session.execute = AsyncMock(return_value=count_result)
    session.get = AsyncMock(return_value=None)
    return session


def _make_change(
    *,
    organization_id=None,
    feature: str = "vpn.ipsec.policy",
    operation: str = "create",
    status: str = "pending",
    site_id=None,
) -> AdapterPendingChange:
    """A pending change row (real model, no DB)."""
    return AdapterPendingChange(
        id=uuid4(),
        organization_id=organization_id or uuid4(),
        controller_id=uuid4(),
        site_id=site_id,
        omada_site_id="omada-site-1",
        feature=feature,
        operation=operation,
        target_id=None,
        payload={},
        status=status,
        notes=None,
    )


# ── Stage validation ─────────────────────────────────────────────


class TestStageChangeValidation:
    """``stage_change`` must reject malformed input BEFORE the row
    hits the DB — that way a path-traversal payload never even gets
    persisted, let alone applied."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_target",
        [
            "../../etc/passwd",
            "foo/bar",
            "foo bar",
            "foo\x00",
            "abc%2F..%2Fadmin",
        ],
    )
    async def test_rejects_path_traversal_target_id(self, bad_target: str) -> None:
        svc = AdapterStagingService(_make_session())
        with pytest.raises(HTTPException) as exc:
            await svc.stage_change(
                organization_id=uuid4(),
                controller_id=uuid4(),
                feature="vpn.ipsec.policy",
                operation="update",
                payload={},
                target_id=bad_target,
            )
        assert exc.value.status_code == 400
        assert "target_id" in exc.value.detail

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "key, bad_value",
        [
            ("mac", "NOT_A_MAC"),
            ("mac", "../foo"),
            ("switch_mac", "aa:bb:cc"),  # too short
            ("device_mac", "../etc/passwd"),
            ("wlan_id", "../admin"),
            ("ssid_id", "foo bar"),
            ("portal_id", "x;y"),
            ("backup_id", "abc/../config"),
            ("template_id", "foo\x00"),
        ],
    )
    async def test_rejects_path_traversal_payload_keys(self, key: str, bad_value: str) -> None:
        """Defense-in-depth: payload keys that flow into Omada URL
        paths at apply time get validated at stage time."""
        svc = AdapterStagingService(_make_session())
        with pytest.raises(HTTPException) as exc:
            await svc.stage_change(
                organization_id=uuid4(),
                controller_id=uuid4(),
                feature="wifi.locate_ap",
                operation="create",
                payload={key: bad_value},
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_bad_mac_inside_payload_list(self) -> None:
        """Bulk operations carry lists of MACs in payload[macs] — each
        element must validate, not just the list itself."""
        svc = AdapterStagingService(_make_session())
        with pytest.raises(HTTPException):
            await svc.stage_change(
                organization_id=uuid4(),
                controller_id=uuid4(),
                feature="bulk.device.reboot",
                operation="create",
                # First element is good, second is the smuggle attempt.
                payload={"mac": ["aa:bb:cc:dd:ee:ff", "../etc/passwd"]},
            )

    @pytest.mark.asyncio
    async def test_accepts_clean_payload(self) -> None:
        """Sanity check: a well-formed stage call lands in the DB."""
        session = _make_session()
        svc = AdapterStagingService(session)
        await svc.stage_change(
            organization_id=uuid4(),
            controller_id=uuid4(),
            feature="wifi.locate_ap",
            operation="create",
            payload={"mac": "aa:bb:cc:dd:ee:ff"},
            target_id="ap-1",
        )
        # ``add`` was called (the row was persisted) and commit fired.
        session.add.assert_called_once()
        session.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_unrelated_payload_keys_pass_through(self) -> None:
        """A field named ``mac`` on a feature that doesn't actually
        flow it into a URL path still gets validated (defensive); but
        unrelated keys (``description``, ``enabled``, etc.) pass."""
        session = _make_session()
        svc = AdapterStagingService(session)
        await svc.stage_change(
            organization_id=uuid4(),
            controller_id=uuid4(),
            feature="vpn.ipsec.policy",
            operation="create",
            payload={
                "name": "branch-1",
                "description": "any string../works/here",
                "enabled": True,
                "remoteSubnet": "10.0.0.0/24",
            },
        )
        session.add.assert_called_once()


# ── Apply: dual-gate + atomic claim ──────────────────────────────


class TestApplyChangeDualGate:
    """The dual-gate is the keystone of production safety: an apply
    must be refused unless ``OMADA_READ_ONLY=false`` AND
    ``force=true``."""

    @pytest.mark.asyncio
    async def test_refuses_when_read_only_without_force(self, monkeypatch) -> None:
        # Monkey-patch the read-only check so we don't depend on env.
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: True),
        )
        svc = AdapterStagingService(_make_session())
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(uuid4(), force=False, applier=AsyncMock())
        assert exc.value.status_code == 403
        assert "ADAPTER_READ_ONLY" in exc.value.detail

    @pytest.mark.asyncio
    async def test_refuses_force_only_when_read_only_engaged(self, monkeypatch) -> None:
        """force=true alone MUST NOT bypass the env lock.

        When ADAPTER_READ_ONLY is enabled the apply must be refused
        regardless of the force flag — gate 1 is a hard env lock that
        no API caller can open.
        """
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: True),
        )
        svc = AdapterStagingService(_make_session())
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(uuid4(), force=True, applier=AsyncMock())
        assert exc.value.status_code == 403
        assert "ADAPTER_READ_ONLY" in exc.value.detail

    @pytest.mark.asyncio
    async def test_passes_dual_gate_when_env_open_and_force_true(self, monkeypatch) -> None:
        """When ADAPTER_READ_ONLY=false AND force=true the dual-gate
        passes and control reaches subsequent guards (applier=None → 500
        confirms we advanced past gate 2).
        """
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        svc = AdapterStagingService(_make_session())
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(uuid4(), force=True, applier=None)
        assert exc.value.status_code == 500  # past both gates
        assert "applier" in exc.value.detail

    @pytest.mark.asyncio
    async def test_refuses_with_no_applier(self, monkeypatch) -> None:
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        svc = AdapterStagingService(_make_session())
        # Both gates open (env=false, force=True); missing applier → 500.
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(uuid4(), force=True, applier=None)
        assert exc.value.status_code == 500


class TestApplyChangeAtomicClaim:
    """The atomic claim prevents a double-click from pushing the
    same ``create`` to the live controller twice."""

    @pytest.mark.asyncio
    async def test_404_when_change_missing(self, monkeypatch) -> None:
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        # FOR UPDATE select returns None.
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(uuid4(), force=True, applier=AsyncMock())
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_409_when_change_not_pending(self, monkeypatch) -> None:
        """A row already claimed by another apply (status=applying) or
        previously applied/discarded must 409."""
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        existing = _make_change(status="applying")
        session.execute.return_value = MagicMock(
            scalar_one_or_none=MagicMock(return_value=existing)
        )
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(existing.id, force=True, applier=AsyncMock())
        assert exc.value.status_code == 409
        assert "applying" in exc.value.detail

    @pytest.mark.asyncio
    async def test_status_flips_to_applying_then_applied(self, monkeypatch) -> None:
        """The row should transition pending → applying (committed) →
        applied (committed). Two commits before the applier returns
        means a concurrent reader sees ``applying`` and 409s."""
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        change = _make_change(status="pending")
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

        observed_states: list[str] = []

        async def fake_commit() -> None:
            observed_states.append(change.status)

        session.commit = AsyncMock(side_effect=fake_commit)

        applier = AsyncMock(return_value={"ok": True})
        svc = AdapterStagingService(session)
        result = await svc.apply_change(change.id, force=True, applier=applier)

        # Commit fired twice: once for the claim (applying) and once
        # for the final state (applied).
        assert observed_states == ["applying", "applied"]
        assert result.status == "applied"
        applier.assert_awaited_once_with(change)

    @pytest.mark.asyncio
    async def test_stored_confirmed_cannot_bypass_unconfirmed_catastrophic_apply(
        self, monkeypatch
    ) -> None:
        """A caller who staged ``payload.confirmed=true``
        MUST NOT bypass the catastrophic-op confirmation on an UNCONFIRMED apply.

        apply_change builds the preflight view with ``confirmed=bool(confirmed)`` from
        the APPLY REQUEST — authoritative over any value smuggled into the free-form
        stored payload — so an unconfirmed apply of a delete/forget is refused (409)
        and the applier never runs, even though the stored payload says confirmed=true.
        """
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        # The attacker seeded the reserved flag straight into the free-form payload.
        change = _make_change(feature="unifi.clients.forget", operation="delete", status="pending")
        change.payload = {"mac": "aa:bb:cc:dd:ee:ff", "confirmed": True}
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
        applier = AsyncMock(return_value={"ok": True})
        svc = AdapterStagingService(session)

        # Unconfirmed apply → 409 from the UniFi catastrophic preflight; the stored
        # confirmed=true is overwritten by the (False) apply flag and the applier
        # is NEVER awaited.
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(change.id, force=True, confirmed=False, applier=applier)
        assert exc.value.status_code == 409
        applier.assert_not_awaited()

        # A genuinely confirmed apply proceeds through the very same gate.
        change_ok = _make_change(
            feature="unifi.clients.forget", operation="delete", status="pending"
        )
        change_ok.payload = {"mac": "aa:bb:cc:dd:ee:ff"}
        session.execute.return_value = MagicMock(
            scalar_one_or_none=MagicMock(return_value=change_ok)
        )
        applier_ok = AsyncMock(return_value={"ok": True})
        result = await svc.apply_change(
            change_ok.id, force=True, confirmed=True, applier=applier_ok
        )
        assert result.status == "applied"
        applier_ok.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_preflightless_vendor_delete_blocked_without_confirmation(
        self, monkeypatch
    ) -> None:
        """A vendor with NO registered pre-flight (openwrt / pbx /
        truenas-storage) must still not blind-apply a DELETE on a bare force toggle.
        The universal delete backstop gates it — closing the exact asymmetry the six
        per-vendor pre-flights already cover."""
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        change = _make_change(feature="openwrt.firewall.rule", operation="delete", status="pending")
        change.payload = {}  # no confirmed
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
        applier = AsyncMock(return_value={"ok": True})
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(change.id, force=True, confirmed=False, applier=applier)
        assert exc.value.status_code == 409
        applier.assert_not_awaited()
        assert change.status == "pending"

        # …and it applies once the operator confirms at apply time.
        change_ok = _make_change(
            feature="openwrt.firewall.rule", operation="delete", status="pending"
        )
        change_ok.payload = {}
        session.execute.return_value = MagicMock(
            scalar_one_or_none=MagicMock(return_value=change_ok)
        )
        applier_ok = AsyncMock(return_value={"ok": True})
        result = await svc.apply_change(
            change_ok.id, force=True, confirmed=True, applier=applier_ok
        )
        assert result.status == "applied"
        applier_ok.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_applier_failure_marks_row_failed(self, monkeypatch) -> None:
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        change = _make_change(status="pending")
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

        async def boom(_change) -> None:
            raise RuntimeError("controller said no")

        applier = AsyncMock(side_effect=boom)
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(change.id, force=True, applier=applier)
        assert exc.value.status_code == 502
        # Detail must NOT include the raw repr of the exception (which
        # could leak controller URLs / tokens).
        assert "controller said no" not in exc.value.detail
        assert change.status == "failed"
        # failure_reason is sanitized to the exception class name.
        assert change.failure_reason == "RuntimeError"

    @pytest.mark.asyncio
    async def test_applier_returns_failed_result_marks_row_failed(self, monkeypatch) -> None:
        """An applier that RETURNS a failed AdapterResult (``success=False``)
        — instead of raising — must NOT be recorded as 'applied'. ``apply_change``
        must guard against both raised exceptions and returned failure results, so a
        write the device REFUSED is never marked 'applied', preserving the
        DB<->device consistency invariant for EVERY adapter (Proxmox firewall,
        OPNsense, FreePBX, …)."""
        from types import SimpleNamespace

        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        change = _make_change(status="pending")
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

        # Applier RETURNS (does not raise) a failed result.
        applier = AsyncMock(
            return_value=SimpleNamespace(
                success=False, error="device rejected: rule conflict", message=None
            )
        )
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(change.id, force=True, applier=applier)

        assert exc.value.status_code == 502
        # The adapter's own structured cause is surfaced (a user-facing message,
        # not a raw exception repr) and persisted for the failed-changes drawer.
        assert "rule conflict" in exc.value.detail
        assert change.status == "failed"
        assert change.failure_reason == "device rejected: rule conflict"
        # The key invariant: success bookkeeping never ran.
        assert getattr(change, "applied_at", None) is None

    @pytest.mark.asyncio
    async def test_applier_returns_successful_result_marks_row_applied(self, monkeypatch) -> None:
        """Guard the OTHER side of the chokepoint: a result whose ``success`` is
        True (or absent, like the legacy dict path) must still reach 'applied'.
        ``success is False`` must be the ONLY trip wire — a broader truthiness
        check would regress every adapter returning a success=True result."""
        from types import SimpleNamespace

        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService,
            "is_read_only",
            staticmethod(lambda: False),
        )
        session = _make_session()
        change = _make_change(status="pending")
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))

        applier = AsyncMock(return_value=SimpleNamespace(success=True, message="ok"))
        svc = AdapterStagingService(session)
        result = await svc.apply_change(change.id, force=True, applier=applier)

        assert result.status == "applied"


# ── Discard: tenant scope + status guard ─────────────────────────


class TestDiscardSecurity:
    # Discard now uses ``SELECT ... FOR UPDATE`` to claim the row
    # before flipping status, the
    # same locking pattern apply uses. The tests previously stubbed
    # ``session.get`` ; they now stub ``session.execute`` returning a
    # MagicMock with ``scalar_one_or_none`` chained off, mirroring the
    # ``TestApplyChangeAtomicClaim`` fixtures above.

    @pytest.mark.asyncio
    async def test_404s_on_cross_tenant_change(self) -> None:
        """A user passing another org's UUID must 404 BEFORE any
        state mutation — otherwise they can flip a row they don't
        own and only then receive a 404."""
        session = _make_session()
        other_org = _make_change(status="pending")  # owned by random org
        session.execute.return_value = MagicMock(
            scalar_one_or_none=MagicMock(return_value=other_org)
        )
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.discard(
                other_org.id,
                organization_id=uuid4(),  # different org
            )
        assert exc.value.status_code == 404
        # Critical: no commit ran. The row was not mutated.
        session.commit.assert_not_awaited()
        assert other_org.status == "pending"

    @pytest.mark.asyncio
    async def test_404s_when_change_missing(self) -> None:
        session = _make_session()
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.discard(uuid4(), organization_id=uuid4())
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_refuses_non_pending_without_force(self) -> None:
        session = _make_session()
        org = uuid4()
        change = _make_change(status="applied", organization_id=org)
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
        svc = AdapterStagingService(session)
        with pytest.raises(HTTPException) as exc:
            await svc.discard(change.id, organization_id=org)
        assert exc.value.status_code == 409

    @pytest.mark.asyncio
    async def test_force_allows_discard_from_applying(self) -> None:
        """Operator-recovery flow: a row stuck in 'applying' (worker
        crash) should be discardable with force=True."""
        session = _make_session()
        org = uuid4()
        change = _make_change(status="applying", organization_id=org)
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
        svc = AdapterStagingService(session)
        result = await svc.discard(change.id, organization_id=org, force=True)
        assert result.status == "discarded"

    @pytest.mark.asyncio
    async def test_normal_pending_discard_succeeds(self) -> None:
        session = _make_session()
        org = uuid4()
        change = _make_change(status="pending", organization_id=org)
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
        svc = AdapterStagingService(session)
        result = await svc.discard(change.id, organization_id=org)
        assert result.status == "discarded"
        session.commit.assert_awaited()


# ── OPNsense pre-flight gate at the apply chokepoint ─────────────


class TestOpnsensePreflightAtApply:
    """The OPNsense pre-flight gate is enforced centrally in ``apply_change``
    (the single sanctioned apply path), so a catastrophic op cannot be
    blind-applied even past the dual-gate. Non-OPNsense vendors are untouched."""

    @staticmethod
    def _svc_with(monkeypatch, change):
        from app.services import adapter_staging

        monkeypatch.setattr(
            adapter_staging.AdapterStagingService, "is_read_only", staticmethod(lambda: False)
        )
        session = _make_session()
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=change))
        return AdapterStagingService(session), session

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "feature,operation",
        [
            ("opnsense.firewall.rule", "delete"),  # ANY delete
            ("opnsense.nat.port_forward", "delete"),
            ("opnsense.system.reboot", "create"),  # system op (op=create)
            ("opnsense.system.backup_restore", "create"),
            ("opnsense.system.backup_delete", "create"),  # delete-in-spirit, op=create
        ],
    )
    async def test_blocks_catastrophic_without_confirmation(
        self, monkeypatch, feature, operation
    ) -> None:
        change = _make_change(status="pending", feature=feature, operation=operation)
        change.payload = {}  # no confirmed
        svc, session = self._svc_with(monkeypatch, change)
        applier = AsyncMock(return_value={"ok": True})
        with pytest.raises(HTTPException) as exc:
            await svc.apply_change(change.id, force=True, applier=applier)
        assert exc.value.status_code == 409
        # The device was never touched and the row was NOT flipped to applying.
        applier.assert_not_awaited()
        assert change.status == "pending"

    @pytest.mark.asyncio
    async def test_allows_catastrophic_with_confirmation(self, monkeypatch) -> None:
        """Confirmation is an APPLY-TIME decision: passing ``confirmed=True`` to
        apply_change (what the Pending-Changes drawer does) clears the gate. A
        ``confirmed`` merely staged into the payload does NOT — that path is the
        bypass covered by test_stored_confirmed_cannot_bypass_* above."""
        change = _make_change(
            status="pending", feature="opnsense.firewall.rule", operation="delete"
        )
        change.payload = {}  # confirmation supplied at apply time, never staged
        svc, session = self._svc_with(monkeypatch, change)
        applier = AsyncMock(return_value={"ok": True})
        result = await svc.apply_change(change.id, force=True, confirmed=True, applier=applier)
        applier.assert_awaited_once_with(change)
        assert result.status == "applied"

    @pytest.mark.asyncio
    async def test_safe_opnsense_create_not_gated(self, monkeypatch) -> None:
        change = _make_change(
            status="pending", feature="opnsense.firewall.rule", operation="create"
        )
        change.payload = {}  # safe op needs no confirmation
        svc, session = self._svc_with(monkeypatch, change)
        applier = AsyncMock(return_value={"ok": True})
        result = await svc.apply_change(change.id, force=True, applier=applier)
        applier.assert_awaited_once()
        assert result.status == "applied"

    @pytest.mark.asyncio
    async def test_non_opnsense_delete_not_gated(self, monkeypatch) -> None:
        # A non-opnsense delete must not be blocked by the OPNsense-scoped gate,
        # proving that gate is strictly prefix-scoped. We pass confirmed=True so the
        # UNIVERSAL delete backstop (which gates every delete) is satisfied — isolating
        # the OPNsense-gate-scoping assertion from the separate universal delete gate.
        change = _make_change(status="pending", feature="vpn.ipsec.policy", operation="delete")
        change.payload = {}
        svc, session = self._svc_with(monkeypatch, change)
        applier = AsyncMock(return_value={"ok": True})
        result = await svc.apply_change(change.id, force=True, confirmed=True, applier=applier)
        applier.assert_awaited_once()
        assert result.status == "applied"
