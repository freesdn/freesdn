# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Omada-parity tests for the MikroTik adapter.

These tests cover the four parity-gap categories closed in this
commit:

- A. Firmware lifecycle (``/system/package/update``, ``/system/package``)
- B. Config backup / restore extended surface (``/file``)
- C. Topology / neighbor discovery (``/ip/neighbor``)
- G. SNMP trap-targets + SNMPv3 users (``/snmp``, ``/snmp/users``)

The HTTP layer is mocked at the ``client._client.request`` boundary
exactly as ``test_mikrotik_wire_format`` does — these tests inherit
the same wire-format guarantees and would catch any regression in
the canonical RouterOS verb routing.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.exceptions import AdapterError
from app.adapters.mikrotik.client import MikroTikClient


def _client_with_mocked_http(
    response_body: Any = None,
    status_code: int = 200,
) -> tuple[MikroTikClient, AsyncMock]:
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


# ─────────────────────────────────────────────────────────────────────
# A. Firmware lifecycle
# ─────────────────────────────────────────────────────────────────────


@patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: False)
class TestFirmwareLifecycle:
    """Firmware update channel + check / download / install wire shape."""

    @pytest.mark.asyncio
    async def test_get_update_status_uses_get(self) -> None:
        c, http = _client_with_mocked_http([{"installed-version": "7.21.3"}])
        result = await c.get_update_status()
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/system/package/update")
        # Singleton unwrap: returns the first row as a dict
        assert result == {"installed-version": "7.21.3"}

    @pytest.mark.asyncio
    async def test_get_update_status_returns_empty_dict_on_error(self) -> None:
        c, _ = _client_with_mocked_http(status_code=500, response_body={})
        result = await c.get_update_status()
        # 5xx on an optional endpoint must not raise — degrade to {}
        assert result == {}

    @pytest.mark.asyncio
    async def test_set_update_channel_uses_post_set(self) -> None:
        # PATCH on a singleton routes to POST /<path>/set per the
        # wire-format contract.
        c, http = _client_with_mocked_http({})
        await c.set_update_channel("stable", force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/package/update/set")
        assert call.kwargs["json"] == {"channel": "stable"}

    @pytest.mark.asyncio
    async def test_set_update_channel_rejects_invalid(self) -> None:
        c, _ = _client_with_mocked_http({})
        with pytest.raises(ValueError) as exc:
            await c.set_update_channel("nightly", force=True)
        assert "channel must be one of" in str(exc.value)

    @pytest.mark.asyncio
    async def test_check_for_updates_canonical_post(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.check_for_updates(force=True)
        call = http.request.await_args
        # POST → wraps the path with PUT via self.post helper —
        # check-for-updates is a verb, not a sub-row, so the helper
        # emits PUT against the action path.
        assert call.args[0] == "POST"
        assert call.args[1].endswith(
            "/rest/system/package/update/check-for-updates"
        )

    @pytest.mark.asyncio
    async def test_download_update_canonical(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.download_update(force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/package/update/download")

    @pytest.mark.asyncio
    async def test_download_and_install_canonical(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.download_and_install_update(force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith(
            "/rest/system/package/update/install"
        )

    @pytest.mark.asyncio
    async def test_cancel_update_download_canonical(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.cancel_update_download(force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/package/update/cancel")

    @pytest.mark.asyncio
    async def test_get_installed_packages_uses_get(self) -> None:
        c, http = _client_with_mocked_http(
            [{"name": "system", "version": "7.21.3"}]
        )
        result = await c.get_installed_packages()
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/system/package")
        assert result == [{"name": "system", "version": "7.21.3"}]

    @pytest.mark.asyncio
    async def test_disable_package_emits_post_to_action(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.disable_package("*1", force=True)
        call = http.request.await_args
        # Routed directly through _request with method=POST to the
        # action verb — wire format matches RouterOS' ``numbers=``
        # contract on the /system/package menu.
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/package/disable")
        assert call.kwargs["json"] == {"numbers": "*1"}

    @pytest.mark.asyncio
    async def test_enable_package_emits_post_to_action(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.enable_package("*1", force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/package/enable")
        assert call.kwargs["json"] == {"numbers": "*1"}

    @pytest.mark.asyncio
    async def test_uninstall_package_emits_post_to_action(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.uninstall_package("*7", force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/package/uninstall")
        assert call.kwargs["json"] == {"numbers": "*7"}


class TestFirmwareDualGate:
    """All firmware write methods must respect the read-only gate."""

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize(
        "method,args",
        [
            ("set_update_channel", ("stable",)),
            ("check_for_updates", ()),
            ("download_update", ()),
            ("download_and_install_update", ()),
            ("cancel_update_download", ()),
            ("disable_package", ("*1",)),
            ("enable_package", ("*1",)),
            ("uninstall_package", ("*1",)),
        ],
    )
    async def test_refused_without_force(
        self, method: str, args: tuple[Any, ...]
    ) -> None:
        c, _ = _client_with_mocked_http({})
        with pytest.raises(AdapterError) as exc:
            await getattr(c, method)(*args)
        assert "ADAPTER_READ_ONLY" in str(exc.value)

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    async def test_allowed_with_force(self) -> None:
        c, http = _client_with_mocked_http({})
        # Picks one representative — the gate is shared.
        await c.set_update_channel("stable", force=True)
        assert http.request.await_count == 1


# ─────────────────────────────────────────────────────────────────────
# B. Backup / restore extended surface
# ─────────────────────────────────────────────────────────────────────


@patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: False)
class TestBackupSurface:
    """List / get / download / upload / delete / restore + export."""

    @pytest.mark.asyncio
    async def test_list_backups_filters_to_artefact_extensions(self) -> None:
        rows = [
            {"name": "freesdn.backup", "size": "1024"},
            {"name": "export.rsc", "size": "512"},
            {"name": "package.npk", "size": "20480"},
            {"name": "junk.log", "size": "100"},
            {"name": "credentials.txt", "size": "50"},
        ]
        c, http = _client_with_mocked_http(rows)
        result = await c.list_backups()
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/file")
        # The filter MUST drop the non-artefact rows; without this
        # the operator-facing list would be cluttered with random
        # files left on the box.
        names = {row["name"] for row in result}
        assert "freesdn.backup" in names
        assert "export.rsc" in names
        assert "package.npk" in names
        assert "junk.log" not in names
        assert "credentials.txt" not in names

    @pytest.mark.asyncio
    async def test_list_backups_returns_empty_on_router_error(self) -> None:
        c, _ = _client_with_mocked_http(status_code=500, response_body={})
        result = await c.list_backups()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_backup_metadata_validates_name(self) -> None:
        c, _ = _client_with_mocked_http({})
        with pytest.raises(ValueError):
            await c.get_backup_metadata("../../etc/passwd")
        with pytest.raises(ValueError):
            await c.get_backup_metadata("")
        with pytest.raises(ValueError):
            # 130-char name exceeds the 128 cap
            await c.get_backup_metadata("a" * 130)

    @pytest.mark.asyncio
    async def test_get_backup_metadata_returns_row(self) -> None:
        c, http = _client_with_mocked_http(
            [{"name": "freesdn.backup", "size": "1024"}]
        )
        result = await c.get_backup_metadata("freesdn.backup")
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/file/freesdn.backup")
        assert result == {"name": "freesdn.backup", "size": "1024"}

    @pytest.mark.asyncio
    async def test_download_backup_content_returns_contents_string(
        self,
    ) -> None:
        c, _ = _client_with_mocked_http(
            [{"name": "export.rsc", "contents": "/system identity\nset name=router01"}]
        )
        result = await c.download_backup_content("export.rsc")
        assert result == "/system identity\nset name=router01"

    @pytest.mark.asyncio
    async def test_download_backup_content_returns_empty_on_absent(
        self,
    ) -> None:
        c, _ = _client_with_mocked_http([])
        result = await c.download_backup_content("missing.rsc")
        assert result == ""

    @pytest.mark.asyncio
    async def test_upload_backup_content_uses_put(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.upload_backup_content(
            "restore.rsc", "/system identity\nset name=router01", force=True
        )
        call = http.request.await_args
        # post() wraps to PUT /file
        assert call.args[0] == "PUT"
        assert call.args[1].endswith("/rest/file")
        assert call.kwargs["json"] == {
            "name": "restore.rsc",
            "contents": "/system identity\nset name=router01",
        }

    @pytest.mark.asyncio
    async def test_upload_backup_content_validates_name(self) -> None:
        c, _ = _client_with_mocked_http({})
        with pytest.raises(ValueError):
            await c.upload_backup_content("../bad", "x", force=True)

    @pytest.mark.asyncio
    async def test_delete_backup_idempotent_when_absent(self) -> None:
        c, http = _client_with_mocked_http([])
        result = await c.delete_backup("missing.rsc", force=True)
        # Only one HTTP call — the list lookup. No /remove emitted
        # because the file wasn't found.
        assert http.request.await_count == 1
        # fix: idempotent delete now surfaces an
        # explicit ``was_already_absent`` flag so the caller can
        # distinguish "we deleted it" from "it was already gone".
        # Both shapes are success — never a raised exception.
        assert result == {"ok": True, "was_already_absent": True}

    @pytest.mark.asyncio
    async def test_delete_backup_emits_canonical_remove(self) -> None:
        # First call returns the list (lookup), second is the remove.
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        list_resp = MagicMock(status_code=200, text="ok")
        list_resp.json.return_value = [
            {"name": "freesdn.backup", ".id": "*A"}
        ]
        remove_resp = MagicMock(status_code=200, text="ok")
        remove_resp.json.return_value = {}
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(side_effect=[list_resp, remove_resp])
        c._client = http
        await c.delete_backup("freesdn.backup", force=True)
        # Second call is the remove
        remove_call = http.request.await_args_list[1]
        assert remove_call.args[0] == "POST"
        assert remove_call.args[1].endswith("/rest/file/remove")
        assert remove_call.kwargs["json"] == {".id": "*A"}

    @pytest.mark.asyncio
    async def test_restore_backup_aliases_load(self) -> None:
        c, http = _client_with_mocked_http({})
        await c.restore_backup("freesdn.backup", password="hunter2", force=True)
        call = http.request.await_args
        # Routes through load_backup → POST /system/backup/load wrapped
        # as PUT by the post() helper.
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/system/backup/load")
        assert call.kwargs["json"] == {
            "name": "freesdn.backup",
            "password": "hunter2",
        }

    @pytest.mark.asyncio
    async def test_export_config_to_text_normalises_list_response(
        self,
    ) -> None:
        c, _ = _client_with_mocked_http(
            ["/system identity", "set name=router01"]
        )
        result = await c.export_config_to_text(force=True)
        assert result == "/system identity\nset name=router01"

    @pytest.mark.asyncio
    async def test_export_config_to_text_normalises_dict_response(
        self,
    ) -> None:
        c, _ = _client_with_mocked_http({"ret": "/system identity"})
        result = await c.export_config_to_text(force=True)
        assert result == "/system identity"


# ─────────────────────────────────────────────────────────────────────
# C. Topology / neighbor discovery
# ─────────────────────────────────────────────────────────────────────


@patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: False)
class TestTopologySurface:
    @pytest.mark.asyncio
    async def test_get_neighbors_uses_get(self) -> None:
        c, http = _client_with_mocked_http(
            [{"mac-address": "AA:BB:CC:DD:EE:FF", "identity": "switch01"}]
        )
        result = await c.get_neighbors()
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/ip/neighbor")
        assert result[0]["identity"] == "switch01"

    @pytest.mark.asyncio
    async def test_get_neighbor_discovery_settings_singleton(self) -> None:
        c, http = _client_with_mocked_http(
            [{"discover-interface-list": "all", "protocol": "lldp,cdp,mndp"}]
        )
        result = await c.get_neighbor_discovery_settings()
        call = http.request.await_args
        assert call.args[0] == "GET"
        assert call.args[1].endswith("/rest/ip/neighbor/discovery-settings")
        assert result["protocol"] == "lldp,cdp,mndp"

    @pytest.mark.asyncio
    async def test_update_neighbor_discovery_settings_uses_post_set(
        self,
    ) -> None:
        c, http = _client_with_mocked_http({})
        await c.update_neighbor_discovery_settings(
            {"protocol": "lldp"}, force=True
        )
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith(
            "/rest/ip/neighbor/discovery-settings/set"
        )
        assert call.kwargs["json"] == {"protocol": "lldp"}

    @pytest.mark.asyncio
    async def test_build_topology_envelope_shape(self) -> None:
        # Compose a multi-call response sequence: identity, interfaces,
        # neighbors, lldp-neighbours. audit fix added the LLDP
        # feed so the call count grew from 3 to 4 — the gather emits
        # all four concurrently but the AsyncMock side_effect still
        # pops in call order.
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
        iface_resp.json.return_value = [
            {"name": "ether1"},
            {"name": "ether2"},
        ]
        neighbor_resp = MagicMock(status_code=200, text="ok")
        neighbor_resp.json.return_value = [
            {
                "mac-address": "AA:BB:CC:DD:EE:01",
                "identity": "switch01",
                "interface": "ether1",
                "platform": "MikroTik",
                "discovered-by": "lldp",
            },
            # Duplicate of the same MAC via MNDP — must be deduped
            {
                "mac-address": "AA:BB:CC:DD:EE:01",
                "identity": "switch01",
                "interface": "ether1",
                "discovered-by": "mndp",
            },
            {
                "mac-address": "AA:BB:CC:DD:EE:02",
                "identity": "ap01",
                "interface": "ether2",
                "platform": "MikroTik",
                "discovered-by": "lldp",
            },
        ]
        lldp_resp = MagicMock(status_code=200, text="ok")
        lldp_resp.json.return_value = []
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(
            side_effect=[ident_resp, iface_resp, neighbor_resp, lldp_resp]
        )
        c._client = http
        topo = await c.build_topology()
        # Envelope shape — degraded/degraded_reasons absent on clean run.
        assert "nodes" in topo and "edges" in topo and "warnings" in topo
        # Local router + 2 unique neighbour nodes
        assert len(topo["nodes"]) == 3
        labels = {n["label"] for n in topo["nodes"]}
        assert "router01" in labels
        assert "switch01" in labels
        assert "ap01" in labels
        # 3 edges (MNDP duplicate still emits an edge — separate
        # protocol-tagged exchange — but the node was deduped)
        assert len(topo["edges"]) == 3
        # No warnings on a clean composition
        assert topo["warnings"] == []
        # Root node should NOT be marked degraded when every read OK.
        root = next(n for n in topo["nodes"] if n.get("type") == "router")
        assert root.get("degraded") is not True

    @pytest.mark.asyncio
    async def test_build_topology_partial_with_warnings(self) -> None:
        # Identity fetch fails; the topology should still return with
        # a warning entry rather than raising. With the LLDP feed
        # added, the gather schedules 4 reads — supply 4 responses.
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        bad_resp = MagicMock(status_code=500, text="server error")
        bad_resp.json.return_value = {"message": "boom"}
        ok_resp = MagicMock(status_code=200, text="ok")
        ok_resp.json.return_value = []
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(
            side_effect=[bad_resp, ok_resp, ok_resp, ok_resp]
        )
        c._client = http
        topo = await c.build_topology()
        # Local node is still emitted with a fallback label
        assert any(n.get("type") == "router" for n in topo["nodes"])
        # Warning records the identity failure
        assert any("identity" in w for w in topo["warnings"])
        # fix: failed reads mark the root node degraded
        # and surface a reasons list so the frontend can show a banner.
        root = next(n for n in topo["nodes"] if n.get("type") == "router")
        assert root.get("degraded") is True
        assert "identity" in root.get("degraded_reasons", [])
        assert topo.get("degraded") is True


# ─────────────────────────────────────────────────────────────────────
# G. SNMP trap targets + SNMPv3 users
# ─────────────────────────────────────────────────────────────────────


@patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: False)
class TestSnmpSurface:
    @pytest.mark.asyncio
    async def test_get_snmp_trap_targets_parses_comma_list(self) -> None:
        c, _ = _client_with_mocked_http(
            [{"enabled": "true", "trap-target": "1.1.1.1,2.2.2.2"}]
        )
        result = await c.get_snmp_trap_targets()
        assert result == ["1.1.1.1", "2.2.2.2"]

    @pytest.mark.asyncio
    async def test_get_snmp_trap_targets_empty_when_unset(self) -> None:
        c, _ = _client_with_mocked_http([{"enabled": "true"}])
        result = await c.get_snmp_trap_targets()
        assert result == []

    @pytest.mark.asyncio
    async def test_add_snmp_trap_target_patches_singleton(self) -> None:
        # First call → GET /snmp returns current list; second → PATCH.
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        get_resp = MagicMock(status_code=200, text="ok")
        get_resp.json.return_value = [
            {"enabled": "true", "trap-target": "1.1.1.1"}
        ]
        set_resp = MagicMock(status_code=200, text="ok")
        set_resp.json.return_value = {}
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(side_effect=[get_resp, set_resp])
        c._client = http
        await c.add_snmp_trap_target("3.3.3.3", force=True)
        # The PATCH call (second) MUST emit a comma-list with the
        # original target plus the new one.
        set_call = http.request.await_args_list[1]
        assert set_call.args[0] == "POST"
        assert set_call.args[1].endswith("/rest/snmp/set")
        assert set_call.kwargs["json"] == {"trap-target": "1.1.1.1,3.3.3.3"}

    @pytest.mark.asyncio
    async def test_add_snmp_trap_target_idempotent(self) -> None:
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        get_resp = MagicMock(status_code=200, text="ok")
        get_resp.json.return_value = [
            {"trap-target": "1.1.1.1,2.2.2.2"}
        ]
        set_resp = MagicMock(status_code=200, text="ok")
        set_resp.json.return_value = {}
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(side_effect=[get_resp, set_resp])
        c._client = http
        await c.add_snmp_trap_target("1.1.1.1", force=True)
        set_call = http.request.await_args_list[1]
        # Existing target — list unchanged
        assert set_call.kwargs["json"] == {"trap-target": "1.1.1.1,2.2.2.2"}

    @pytest.mark.asyncio
    async def test_remove_snmp_trap_target_filters(self) -> None:
        c = MikroTikClient(
            host="10.0.0.1",
            username="admin",
            password="x",
            port=80,
            use_ssl=False,
            verify_ssl=False,
            timeout=5,
        )
        get_resp = MagicMock(status_code=200, text="ok")
        get_resp.json.return_value = [
            {"trap-target": "1.1.1.1,2.2.2.2,3.3.3.3"}
        ]
        set_resp = MagicMock(status_code=200, text="ok")
        set_resp.json.return_value = {}
        http = AsyncMock()
        http.is_closed = False
        http.request = AsyncMock(side_effect=[get_resp, set_resp])
        c._client = http
        await c.remove_snmp_trap_target("2.2.2.2", force=True)
        set_call = http.request.await_args_list[1]
        assert set_call.kwargs["json"] == {"trap-target": "1.1.1.1,3.3.3.3"}

    @pytest.mark.asyncio
    async def test_snmp_users_crud_wire_shape(self) -> None:
        # ─ list
        c, http = _client_with_mocked_http(
            [{"name": "monitor", ".id": "*1"}]
        )
        users = await c.get_snmp_users()
        get_call = http.request.await_args
        assert get_call.args[0] == "GET"
        assert get_call.args[1].endswith("/rest/snmp/users")
        assert users == [{"name": "monitor", ".id": "*1"}]

        # ─ add
        c, http = _client_with_mocked_http(
            {"name": "monitor", "auth-password": "***", ".id": "*1"}
        )
        result = await c.add_snmp_user(
            {
                "name": "monitor",
                "auth-protocol": "SHA1",
                "auth-password": "hunter2",
            },
            force=True,
        )
        call = http.request.await_args
        assert call.args[0] == "PUT"
        assert call.args[1].endswith("/rest/snmp/users")
        # Echoed password gets redacted before returning to caller
        assert result["auth-password"] != "hunter2"

        # ─ update
        c, http = _client_with_mocked_http({})
        await c.update_snmp_user("*1", {"auth-protocol": "SHA256"}, force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/snmp/users/set")
        assert call.kwargs["json"] == {
            ".id": "*1",
            "auth-protocol": "SHA256",
        }

        # ─ delete
        c, http = _client_with_mocked_http({})
        await c.delete_snmp_user("*1", force=True)
        call = http.request.await_args
        assert call.args[0] == "POST"
        assert call.args[1].endswith("/rest/snmp/users/remove")
        assert call.kwargs["json"] == {".id": "*1"}

    @pytest.mark.asyncio
    async def test_add_snmp_trap_target_validates_host(self) -> None:
        c, _ = _client_with_mocked_http({})
        with pytest.raises(ValueError):
            await c.add_snmp_trap_target("", force=True)
        with pytest.raises(ValueError):
            await c.add_snmp_trap_target("   ", force=True)


# ─────────────────────────────────────────────────────────────────────
# Cross-cutting: dual-gate must fire on every new write method
# ─────────────────────────────────────────────────────────────────────


class TestDualGateOnNewWrites:
    """Sweep across the new write surface — read-only refusal."""

    @pytest.mark.asyncio
    @patch("app.adapters.mikrotik.client._is_adapter_read_only", lambda: True)
    @pytest.mark.parametrize(
        "method,args",
        [
            # Firmware
            ("set_update_channel", ("stable",)),
            ("check_for_updates", ()),
            ("download_update", ()),
            ("download_and_install_update", ()),
            ("cancel_update_download", ()),
            # Backup / restore extended surface
            ("upload_backup_content", ("foo.rsc", "/x")),
            ("restore_backup", ("foo.backup",)),
            ("export_config_to_text", ()),
            # Topology
            ("update_neighbor_discovery_settings", ({"protocol": "lldp"},)),
            # SNMP
            ("add_snmp_user", ({"name": "x"},)),
            ("delete_snmp_user", ("*1",)),
        ],
    )
    async def test_refused_without_force(
        self, method: str, args: tuple[Any, ...]
    ) -> None:
        c, _ = _client_with_mocked_http({})
        with pytest.raises(AdapterError) as exc:
            await getattr(c, method)(*args)
        assert "ADAPTER_READ_ONLY" in str(exc.value)
