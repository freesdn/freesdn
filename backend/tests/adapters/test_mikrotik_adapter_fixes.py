# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""audit closure tests for the MikroTik adapter + client.

These tests pin the behaviour of the critical + high-severity fixes
landed:

* CRIT-1 ``delete_dhcp_scope`` exact-interface match (no substring
  cascade from ``ether1`` matching ``ether10``)
* CRIT-2 ``restart_service`` retries re-enable with backoff, refuses
  to leave a service locked-out
* CRIT-3 DHCP scope rollback accepts both ``.id`` (RouterOS 7.6+)
  and ``ret`` (7.5 and earlier) shaped responses
* CRIT-perf aggregate-read parallelisation via ``asyncio.gather``
* CRIT-correctness ``build_topology`` walks LLDP feed, parallelises,
  marks the root node degraded on partial failures
* HIGH bridge-VLAN comma-list parsing via ``_vid_in_set`` helper
* HIGH ``_mt_bool`` parser handles both ``True``/``"true"`` shapes
* HIGH ``delete_backup`` returns success when file is already absent
* HIGH ``validate_filter_rule_ids_exist`` helper for service-layer
  pre-flight check on filter-rule reorders

The HTTP layer is mocked at ``client._client.request`` exactly as in
``test_mikrotik_parity`` and ``test_mikrotik_wire_format``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.mikrotik.adapter import (
    MikroTikAdapter,
    _mt_bool,
    _vid_in_set,
)
from app.adapters.mikrotik.client import MikroTikAPIError, MikroTikClient

# ─────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────


def _make_client_with_http(
    response_body: Any = None,
    status_code: int = 200,
) -> tuple[MikroTikClient, AsyncMock]:
    """A MikroTikClient with the httpx layer stubbed out — single
    canned response for every request."""
    c = MikroTikClient(
        host="10.0.0.1",
        username="admin",
        password="x",
        port=80,
        use_ssl=False,
        verify_ssl=False,
        timeout=5,
    )
    body = response_body if response_body is not None else []
    resp = MagicMock(status_code=status_code, text="ok")
    resp.json.return_value = body
    http = AsyncMock()
    http.is_closed = False
    http.request = AsyncMock(return_value=resp)
    c._client = http
    return c, http


def _make_adapter_with_mock_api() -> tuple[MikroTikAdapter, MagicMock]:
    """A MikroTikAdapter whose ``self._api`` is a MagicMock so every
    adapter test can assert on the high-level adapter wrapper without
    touching the wire layer."""
    a = MikroTikAdapter(
        host="10.0.0.1",
        username="admin",
        password="x",
        port=80,
        use_ssl=False,
        verify_ssl=False,
    )
    api = MagicMock()
    a._api = api  # type: ignore[assignment]
    return a, api


# ─────────────────────────────────────────────────────────────────────
# HIGH: _mt_bool helper
# ─────────────────────────────────────────────────────────────────────


class TestMtBoolParser:
    """The previous code did ``v.get("running", "false") == "true"`` —
    that returns False on RouterOS 7.0/7.1 which emits real Python
    booleans rather than the 7.2+ string form. ``_mt_bool`` accepts
    both shapes + a few historical variants so the adapter is robust
    across the firmware version range we advertise (7.1 → 7.18)."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            (True, True),
            (False, False),
            (None, False),
            ("true", True),
            ("True", True),
            ("TRUE", True),
            ("false", False),
            ("False", False),
            ("yes", True),
            ("no", False),
            ("1", True),
            ("0", False),
            ("on", True),
            ("off", False),
            ("", False),
            ("garbage", False),
            (1, True),
            (0, False),
            (-1, True),  # any non-zero numeric is truthy
        ],
    )
    def test_mt_bool_parser_accepts_bool_and_string(
        self, value: Any, expected: bool
    ) -> None:
        assert _mt_bool(value) is expected


# ─────────────────────────────────────────────────────────────────────
# HIGH: _vid_in_set helper for bridge-VLAN comma-list parsing
# ─────────────────────────────────────────────────────────────────────


class TestVidInSet:
    """The previous ``delete_vlan`` did ``str(vlan_id) == str(vids)``
    which only matched single-VID rows. RouterOS lets a single bridge
    VLAN entry hold a comma-list ("10,20,30") or a range ("10-15")
    or both ("10,20-25,40"). The new helper must match any VID inside
    that spec."""

    @pytest.mark.parametrize(
        "vid,spec,expected",
        [
            # Single VID
            (10, "10", True),
            (10, "11", False),
            # Comma-list
            (10, "10,20,30", True),
            (20, "10,20,30", True),
            (30, "10,20,30", True),
            (40, "10,20,30", False),
            # Range
            (12, "10-15", True),
            (10, "10-15", True),  # inclusive low
            (15, "10-15", True),  # inclusive high
            (16, "10-15", False),
            (9, "10-15", False),
            # Mixed
            (10, "10,20-25,40", True),
            (22, "10,20-25,40", True),
            (40, "10,20-25,40", True),
            (50, "10,20-25,40", False),
            # Whitespace tolerance
            (10, "10 , 20 - 25", True),
            (22, "10 , 20 - 25", True),
            # Bad inputs
            (10, "", False),
            (10, "garbage", False),
        ],
    )
    def test_vid_in_set(self, vid: int, spec: str, expected: bool) -> None:
        assert _vid_in_set(vid, spec) is expected


# ─────────────────────────────────────────────────────────────────────
# delete_dhcp_scope exact interface match
# ─────────────────────────────────────────────────────────────────────


class TestDeleteDhcpScopeExactMatch:
    """The previous implementation deleted any DHCP network row whose
    comment contained the interface name as a substring. ``ether1``
    matched ``ether10`` so deleting the smaller scope nuked the
    larger one too. The fix uses an exact whitespace-delimited token
    match on the comment field."""

    @pytest.mark.asyncio
    async def test_delete_dhcp_scope_exact_interface_match(self) -> None:
        adapter, api = _make_adapter_with_mock_api()
        # ether1 has a managed scope; ether10 also has one with a
        # related-looking comment. Deleting the ether1 scope must NOT
        # touch the ether10 network row.
        ether1_server = {
            ".id": "*S1",
            "interface": "ether1",
            "address-pool": "FreeSdn_ether1_pool",
        }
        api.get_dhcp_servers = AsyncMock(return_value=[
            ether1_server,
            {
                ".id": "*S10",
                "interface": "ether10",
                "address-pool": "FreeSdn_ether10_pool",
            },
        ])
        api.delete_dhcp_server = AsyncMock(return_value={})
        api.get_ip_pools = AsyncMock(return_value=[
            {".id": "*P1", "name": "FreeSdn_ether1_pool"},
            {".id": "*P10", "name": "FreeSdn_ether10_pool"},
        ])
        api.delete_ip_pool = AsyncMock(return_value={})
        api.get_dhcp_networks = AsyncMock(return_value=[
            {".id": "*N1", "comment": "FreeSdn managed – ether1"},
            {".id": "*N10", "comment": "FreeSdn managed – ether10"},
        ])
        api.delete_dhcp_network = AsyncMock(return_value={})

        result = await adapter.delete_dhcp_scope("ether1")
        assert result.success

        # The ether1 row was deleted; the ether10 row was NOT.
        deleted_ids = {
            call.args[0]
            for call in api.delete_dhcp_network.await_args_list
        }
        assert "*N1" in deleted_ids
        assert "*N10" not in deleted_ids, (
            "ether1 deletion must not cascade to ether10 — substring "
            "match was the original bug"
        )
        # Pool deletion is also exact — we delete only ether1's pool.
        pool_deleted = {
            call.args[0] for call in api.delete_ip_pool.await_args_list
        }
        assert "*P1" in pool_deleted
        assert "*P10" not in pool_deleted
        # Server deletion identical
        server_deleted = {
            call.args[0]
            for call in api.delete_dhcp_server.await_args_list
        }
        assert "*S1" in server_deleted
        assert "*S10" not in server_deleted

    @pytest.mark.asyncio
    async def test_delete_dhcp_scope_records_per_row_status(self) -> None:
        """Each per-row delete is wrapped in try/except so a partial
        failure leaves a precise audit trail rather than a single
        ambiguous bubble."""
        adapter, api = _make_adapter_with_mock_api()
        api.get_dhcp_servers = AsyncMock(return_value=[
            {
                ".id": "*S1",
                "interface": "ether1",
                "address-pool": "p1",
            },
        ])
        # First network delete fails, but the server + pool succeed.
        api.delete_dhcp_server = AsyncMock(return_value={})
        api.get_ip_pools = AsyncMock(return_value=[
            {".id": "*P1", "name": "p1"},
        ])
        api.delete_ip_pool = AsyncMock(return_value={})
        api.get_dhcp_networks = AsyncMock(return_value=[
            {".id": "*N1", "comment": "FreeSdn managed – ether1"},
        ])
        api.delete_dhcp_network = AsyncMock(
            side_effect=MikroTikAPIError("network busy")
        )

        result = await adapter.delete_dhcp_scope("ether1")
        assert result.success
        # The deleted list should include both the successes AND the
        # failure so the operator can audit what happened.
        deleted = result.data["deleted"]
        kinds_ok = {d["kind"] for d in deleted if d["ok"]}
        kinds_fail = {d["kind"] for d in deleted if not d["ok"]}
        assert "server" in kinds_ok
        assert "pool" in kinds_ok
        assert "network" in kinds_fail


# ─────────────────────────────────────────────────────────────────────
# restart_service retry + idempotency
# ─────────────────────────────────────────────────────────────────────


class TestRestartServiceRetry:
    @pytest.mark.asyncio
    async def test_restart_service_retries_re_enable_on_failure(
        self,
    ) -> None:
        """Re-enable fails twice then succeeds — adapter must NOT
        leave the service disabled, must NOT raise."""
        adapter, api = _make_adapter_with_mock_api()
        api.get_services = AsyncMock(return_value=[
            {".id": "*1", "name": "api", "disabled": "false"},
        ])
        # disable succeeds; re-enable fails twice then succeeds.
        # The applier issues:
        #   call 1: disable=true (succeeds)
        #   call 2: disable=false (fails)  ← retry 1
        #   call 3: disable=false (fails)  ← retry 2
        #   call 4: disable=false (succeeds) ← final
        update_calls: list[tuple] = []

        async def _update(sid: str, body: dict, *, force: bool = False) -> Any:
            update_calls.append((sid, dict(body)))
            # First disable=false call (call_index == 1) and the
            # second (call_index == 2) raise; third (call_index == 3)
            # succeeds.
            disable_false_calls = [
                c for c in update_calls if c[1].get("disabled") == "false"
            ]
            if (
                body.get("disabled") == "false"
                and len(disable_false_calls) <= 2
            ):
                raise MikroTikAPIError("transient")
            return {}

        api.update_service = AsyncMock(side_effect=_update)

        # Patch asyncio.sleep so the test doesn't actually wait for
        # the backoff (still 3 retries are issued).
        with patch("app.adapters.mikrotik.adapter.asyncio.sleep", new=AsyncMock()):
            result = await adapter.restart_service("api")

        assert result.success, (
            f"restart_service must succeed after retries, got: "
            f"{result.message}"
        )
        # Check call count: 1 disable + 3 re-enable attempts
        disable_calls = [
            c for c in update_calls if c[1].get("disabled") == "true"
        ]
        re_enable_calls = [
            c for c in update_calls if c[1].get("disabled") == "false"
        ]
        assert len(disable_calls) == 1
        assert len(re_enable_calls) == 3

    @pytest.mark.asyncio
    async def test_restart_service_idempotent_when_already_disabled(
        self,
    ) -> None:
        """If service is already disabled, restart should NOT issue
        a redundant disable — just re-enable."""
        adapter, api = _make_adapter_with_mock_api()
        api.get_services = AsyncMock(return_value=[
            {".id": "*1", "name": "api", "disabled": "true"},
        ])
        api.update_service = AsyncMock(return_value={})

        result = await adapter.restart_service("api")
        assert result.success
        # Only one update call — the re-enable. No redundant disable.
        assert api.update_service.await_count == 1
        call = api.update_service.await_args
        assert call.args[1] == {"disabled": "false"}

    @pytest.mark.asyncio
    async def test_restart_service_lockout_on_final_failure(self) -> None:
        """Re-enable fails on all 3 attempts — adapter MUST surface
        a failure (the service is now disabled) rather than reporting
        success."""
        adapter, api = _make_adapter_with_mock_api()
        api.get_services = AsyncMock(return_value=[
            {".id": "*1", "name": "www-ssl", "disabled": "false"},
        ])

        async def _update(sid: str, body: dict, *, force: bool = False) -> Any:
            if body.get("disabled") == "false":
                raise MikroTikAPIError("network unreachable")
            return {}

        api.update_service = AsyncMock(side_effect=_update)

        with patch(
            "app.adapters.mikrotik.adapter.asyncio.sleep", new=AsyncMock()
        ):
            result = await adapter.restart_service("www-ssl")
        assert not result.success
        # AdapterResult.fail() stores the message in ``error`` —
        # surface that to the operator dashboard. The fail() message
        # path is reserved for success-with-context.
        err = (result.error or "").lower()
        assert "retries" in err


# ─────────────────────────────────────────────────────────────────────
# DHCP rollback accepts both .id and ret response shapes
# ─────────────────────────────────────────────────────────────────────


class TestDhcpRollbackResponseShapes:
    """RouterOS 7.5 and earlier return the new row's ID under ``ret``.
    7.6+ returns it under ``.id``. Rollback must walk a populated
    ``created`` list against both shapes; the previous code only read
    ``ret`` so on 7.6+ the rollback walked an empty list and leaked
    the partially-created pool/network rows."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "id_key",
        [".id", "ret"],
        ids=["routeros_7_6_plus_shape", "routeros_7_5_shape"],
    )
    async def test_dhcp_rollback_handles_both_id_and_ret_response_shapes(
        self, id_key: str
    ) -> None:
        adapter, api = _make_adapter_with_mock_api()
        # No existing server.
        api.get_dhcp_servers = AsyncMock(return_value=[])

        # add_ip_pool succeeds, add_dhcp_network succeeds,
        # add_dhcp_server FAILS — rollback should fire and delete both
        # the pool and the network using the IDs that the new shape
        # returned.
        api.add_ip_pool = AsyncMock(return_value={id_key: "*P1"})
        api.add_dhcp_network = AsyncMock(return_value={id_key: "*N1"})
        api.add_dhcp_server = AsyncMock(
            side_effect=MikroTikAPIError("server insert failed")
        )
        api.delete_ip_pool = AsyncMock(return_value={})
        api.delete_dhcp_network = AsyncMock(return_value={})
        api.delete_dhcp_server = AsyncMock(return_value={})

        result = await adapter.create_dhcp_scope(
            interface="ether1",
            range_start="10.0.0.10",
            range_end="10.0.0.50",
            subnet="10.0.0.0/24",
            gateway="10.0.0.1",
        )
        assert not result.success
        # Both rollback deletes must have fired — proving the IDs were
        # captured regardless of which key shape RouterOS emitted.
        assert api.delete_ip_pool.await_count == 1
        assert api.delete_ip_pool.await_args.args[0] == "*P1"
        assert api.delete_dhcp_network.await_count == 1
        assert api.delete_dhcp_network.await_args.args[0] == "*N1"


# ─────────────────────────────────────────────────────────────────────
# CRIT-perf: aggregate reads use asyncio.gather
# ─────────────────────────────────────────────────────────────────────


class TestAggregateReadsUseGather:
    """The 4 aggregate reads (get_vpn_status, get_device_status,
    get_device_info, get_system_info, get_firmware_info) MUST run
    their sub-calls in parallel via asyncio.gather. We verify that by
    timing: a concurrent gather of N calls each sleeping for D seconds
    completes in ~D, not N*D."""

    @pytest.mark.asyncio
    async def test_get_vpn_status_uses_gather(self) -> None:
        adapter, api = _make_adapter_with_mock_api()
        # Each sub-read sleeps 50ms. If sequential, total ~350ms.
        # Concurrent via gather, total ~50ms (plus overhead).
        delay = 0.05

        async def _slow(*args: Any, **kw: Any) -> Any:
            await asyncio.sleep(delay)
            return []

        api.get_ipsec_policies = AsyncMock(side_effect=_slow)
        api.get_ipsec_peers = AsyncMock(side_effect=_slow)
        api.get_ipsec_active = AsyncMock(side_effect=_slow)
        api.get_wireguard_interfaces = AsyncMock(side_effect=_slow)
        api.get_wireguard_peers = AsyncMock(side_effect=_slow)
        api.get_l2tp_server = AsyncMock(side_effect=_slow)
        api.get_pptp_server = AsyncMock(side_effect=_slow)

        start = time.monotonic()
        result = await adapter.get_vpn_status()
        elapsed = time.monotonic() - start

        assert result.success
        # 7 sequential calls would take ~7*50ms = 350ms. Concurrent
        # ~50ms (+ overhead). Allow generous headroom but assert
        # we're closer to max than sum.
        assert elapsed < 0.20, (
            f"get_vpn_status took {elapsed:.3f}s — expected ~{delay}s "
            "via asyncio.gather; if >200ms the calls are probably "
            "still sequential"
        )

    @pytest.mark.asyncio
    async def test_get_device_status_uses_gather(self) -> None:
        adapter, api = _make_adapter_with_mock_api()
        delay = 0.05

        async def _slow_dict(*args: Any, **kw: Any) -> Any:
            await asyncio.sleep(delay)
            return {}

        async def _slow_list(*args: Any, **kw: Any) -> Any:
            await asyncio.sleep(delay)
            return []

        api.get_system_resource = AsyncMock(side_effect=_slow_dict)
        api.get_system_health = AsyncMock(side_effect=_slow_list)
        api.get_interfaces = AsyncMock(side_effect=_slow_list)

        start = time.monotonic()
        await adapter.get_device_status("dev1")
        elapsed = time.monotonic() - start
        # 3 calls sequential = 150ms; concurrent ~50ms.
        assert elapsed < 0.12, (
            f"get_device_status took {elapsed:.3f}s — expected gather"
        )

    @pytest.mark.asyncio
    async def test_get_vpn_status_partial_failure_does_not_blank_whole(
        self,
    ) -> None:
        """If one sub-call fails, gather captures it as an exception
        but the rest of the response is still populated. That section
        becomes its safe-fallback (empty list / None)."""
        adapter, api = _make_adapter_with_mock_api()
        api.get_ipsec_policies = AsyncMock(return_value=[{"id": "p1"}])
        api.get_ipsec_peers = AsyncMock(return_value=[{"id": "pe1"}])
        api.get_ipsec_active = AsyncMock(return_value=[{"id": "a1"}])
        api.get_wireguard_interfaces = AsyncMock(
            side_effect=MikroTikAPIError("wg package missing")
        )
        api.get_wireguard_peers = AsyncMock(return_value=[])
        api.get_l2tp_server = AsyncMock(return_value={"enabled": "true"})
        api.get_pptp_server = AsyncMock(return_value={})

        result = await adapter.get_vpn_status()
        assert result.success
        # The failing section gets the fallback empty list.
        assert result.data["wireguard"]["interfaces"] == []
        # Other sections populated.
        assert result.data["ipsec"]["policies"] == [{"id": "p1"}]
        assert result.data["l2tp"] == {"enabled": "true"}


# ─────────────────────────────────────────────────────────────────────
# CRIT-correctness: build_topology includes LLDP + parallelises +
# marks the root degraded on partial failures
# ─────────────────────────────────────────────────────────────────────


class TestBuildTopologyLldp:
    @pytest.mark.asyncio
    async def test_build_topology_includes_lldp_edges(self) -> None:
        """The LLDP neighbour feed must contribute nodes/edges to the
        topology graph — peers reachable only via IEEE LLDP were
        previously invisible."""
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        ident_resp = MagicMock(status_code=200, text="ok")
        ident_resp.json.return_value = [{"name": "router01"}]
        iface_resp = MagicMock(status_code=200, text="ok")
        iface_resp.json.return_value = [{"name": "ether1"}]
        # /ip/neighbor is empty
        ip_neigh_resp = MagicMock(status_code=200, text="ok")
        ip_neigh_resp.json.return_value = []
        # /interface/lldp/neighbor has the peer
        lldp_resp = MagicMock(status_code=200, text="ok")
        lldp_resp.json.return_value = [
            {
                "chassis-id": "BB:CC:DD:EE:FF:01",
                "system-name": "cisco-switch01",
                "interface": "ether1",
                "system-description": "Cisco IOS XE",
            },
        ]
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(
            side_effect=[ident_resp, iface_resp, ip_neigh_resp, lldp_resp]
        )
        c._client = http

        with patch(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        ):
            topo = await c.build_topology()

        labels = {n.get("label") for n in topo["nodes"]}
        assert "cisco-switch01" in labels, (
            "LLDP-only peer must appear in the topology — previously "
            "build_topology skipped /interface/lldp/neighbor entirely"
        )
        # An edge tagged ``lldp`` must connect the local router to it.
        lldp_edges = [
            e for e in topo["edges"]
            if e.get("target") == "neighbor:BB:CC:DD:EE:FF:01"
        ]
        assert len(lldp_edges) == 1
        assert lldp_edges[0]["protocol"] == "lldp"

    @pytest.mark.asyncio
    async def test_build_topology_marks_degraded_when_any_read_fails(
        self,
    ) -> None:
        """If one of the 4 reads fails, the root node must carry
        ``degraded=True`` plus ``degraded_reasons=[...]`` so the
        frontend can surface a banner.

        We make ``get_system_identity`` fail because it doesn't have
        a swallow-exception wrapper (unlike ``get_neighbors`` /
        ``get_lldp_neighbours`` which catch MikroTikAPIError and
        degrade gracefully to []). The exception propagates to
        ``asyncio.gather(... return_exceptions=True)`` where the
        topology builder catches it and records the degraded reason.
        """
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        # identity fetch fails; the other 3 succeed.
        bad_resp = MagicMock(status_code=500, text="boom")
        bad_resp.json.return_value = {"message": "identity locked"}
        ok_resp = MagicMock(status_code=200, text="ok")
        ok_resp.json.return_value = []
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(
            side_effect=[bad_resp, ok_resp, ok_resp, ok_resp]
        )
        c._client = http

        with patch(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        ):
            topo = await c.build_topology()

        root = next(n for n in topo["nodes"] if n.get("type") == "router")
        assert root.get("degraded") is True
        assert "identity" in root.get("degraded_reasons", [])
        # Envelope-level flag mirrors the root degraded state.
        assert topo.get("degraded") is True


# ─────────────────────────────────────────────────────────────────────
# HIGH: delete_backup idempotency on absent file
# ─────────────────────────────────────────────────────────────────────


class TestDeleteBackupIdempotent:
    @pytest.mark.asyncio
    async def test_delete_backup_idempotent_when_absent(self) -> None:
        """File doesn't exist → must return success without raising."""
        c, http = _make_client_with_http([])
        with patch(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        ):
            result = await c.delete_backup("missing.backup", force=True)
        assert result == {"ok": True, "was_already_absent": True}
        # Only the list lookup hit the wire.
        assert http.request.await_count == 1

    @pytest.mark.asyncio
    async def test_delete_backup_handles_race_against_parallel_delete(
        self,
    ) -> None:
        """File present at list time, gone by /remove time (parallel
        client / scheduler deleted it). Must NOT raise — the goal
        state is reached."""
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        # List returns the file once, second list (after failed remove)
        # returns empty.
        list_resp_1 = MagicMock(status_code=200, text="ok")
        list_resp_1.json.return_value = [
            {"name": "freesdn.backup", ".id": "*A"}
        ]
        # /remove fails with 400 "file not found" (RouterOS shape)
        remove_resp = MagicMock(status_code=400, text="not found")
        remove_resp.json.return_value = {"message": "file not found"}
        list_resp_2 = MagicMock(status_code=200, text="ok")
        list_resp_2.json.return_value = []
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(
            side_effect=[list_resp_1, remove_resp, list_resp_2]
        )
        c._client = http

        with patch(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        ):
            result = await c.delete_backup("freesdn.backup", force=True)
        assert result == {"ok": True, "was_already_absent": True}


# ─────────────────────────────────────────────────────────────────────
# HIGH: validate_filter_rule_ids_exist helper
# ─────────────────────────────────────────────────────────────────────


class TestValidateFilterRuleIdsExist:
    @pytest.mark.asyncio
    async def test_filter_rule_id_validation_helper(self) -> None:
        """Returns ``(existing, missing)`` partitioning the input set
        based on what's in the live filter chain."""
        c, http = _make_client_with_http(
            [
                {".id": "*1", "chain": "input"},
                {".id": "*2", "chain": "forward"},
                {".id": "*3", "chain": "output"},
            ]
        )
        with patch(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        ):
            existing, missing = await c.validate_filter_rule_ids_exist(
                ["*1", "*3", "*99"]
            )
        assert existing == {"*1", "*3"}
        assert missing == {"*99"}

    @pytest.mark.asyncio
    async def test_filter_rule_id_validation_empty_input(self) -> None:
        c, _ = _make_client_with_http([])
        existing, missing = await c.validate_filter_rule_ids_exist([])
        assert existing == set()
        assert missing == set()

    @pytest.mark.asyncio
    async def test_filter_rule_id_validation_handles_get_failure(
        self,
    ) -> None:
        """If we can't read the chain at all (RouterOS down / breaker
        open), helper conservatively reports every requested ID as
        missing — the caller will refuse the reorder."""
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        fail_resp = MagicMock(status_code=500, text="boom")
        fail_resp.json.return_value = {"message": "internal"}
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(return_value=fail_resp)
        c._client = http
        existing, missing = await c.validate_filter_rule_ids_exist(
            ["*1", "*2"]
        )
        assert existing == set()
        assert missing == {"*1", "*2"}


# ─────────────────────────────────────────────────────────────────────
# Breaker tripping on 408 / 429 (was already in client.py code but
# audit listed these as test gaps)
# ─────────────────────────────────────────────────────────────────────


class TestBreakerTripsOnOverloadCodes:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [408, 429])
    async def test_breaker_trips_on_overload_codes(
        self, status_code: int
    ) -> None:
        """RouterOS REST emits 408 (request timeout) and 429 (too many
        requests) when the device is overloaded. Both should trip the
        breaker so a thundering-herd client doesn't pin the device."""
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        bad_resp = MagicMock(status_code=status_code, text="overloaded")
        bad_resp.json.return_value = {"message": "overloaded"}
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(return_value=bad_resp)
        c._client = http

        # Start with breaker closed, fresh. The CircuitBreaker
        # implementation stores the count under ``_failure_count``
        # (private attribute, but stable contract for breaker tests
        # in adapters/http_utils.py).
        starting_failures = c._breaker._failure_count
        with pytest.raises(MikroTikAPIError):
            await c.get("/system/identity")
        # Breaker recorded the failure.
        assert c._breaker._failure_count > starting_failures


# ─────────────────────────────────────────────────────────────────────
# Defensive: get_dhcp_servers does not crash on rows missing .id
# ─────────────────────────────────────────────────────────────────────


class TestDhcpServerRowMissingId:
    @pytest.mark.asyncio
    async def test_get_dhcp_servers_handles_missing_id(self) -> None:
        """Some RouterOS builds drop the ``.id`` key on rows returned
        from /ip/dhcp-server when the server has never been touched.
        The list iteration must not crash."""
        adapter, api = _make_adapter_with_mock_api()
        api.get_dhcp_servers = AsyncMock(return_value=[
            {"name": "srv1", "interface": "ether2"},  # no .id
            {"name": "srv2", "interface": "ether3", ".id": "*S2"},
        ])
        # Lookup by interface name — should find srv1 even without .id.
        helper = adapter._find_dhcp_server_for_interface
        result = await helper("ether2")
        assert result is not None
        assert result["name"] == "srv1"
        # And srv2 with .id works too.
        result2 = await helper("ether3")
        assert result2 is not None
        assert result2.get(".id") == "*S2"
