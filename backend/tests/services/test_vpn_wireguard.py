# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""WireGuard service: sidecar config materialization + connect/disconnect wiring.

Mirrors the OpenVPN fix. `wg-quick up` needs NET_ADMIN, which only the privileged
vpn sidecar holds, so in sidecar mode the api materializes the config + touches a
desired-state marker and the sidecar reconciler runs wg-quick. Previously the app
stored no wg config text and ran `wg-quick up <iface>` directly in the api, which
had neither the config file nor the privilege — so a WireGuard connect could never
succeed. These pin the materialization + the sidecar control protocol.
"""
from __future__ import annotations

import os

import pytest

from app.services.vpn_integration import VPNStatus, WireGuardService

_WG = "[Interface]\nPrivateKey = aGVsbG8=\nAddress = 10.10.0.2/32\n[Peer]\nPublicKey = d29ybGQ=\nEndpoint = wg-server:51820\nAllowedIPs = 10.10.0.1/32\n"


def _svc(tmp_path) -> WireGuardService:
    s = WireGuardService(config_dir=str(tmp_path / "wg"))
    s.run_dir = str(tmp_path / "run")
    s.desired_dir = os.path.join(s.run_dir, "desired")
    os.makedirs(s.config_dir, exist_ok=True)
    os.makedirs(s.run_dir, exist_ok=True)
    return s


def _sidecar_svc(tmp_path) -> WireGuardService:
    s = _svc(tmp_path)
    s.sidecar = True
    return s


@pytest.mark.asyncio
async def test_materialize_writes_content_and_perms(tmp_path):
    s = _svc(tmp_path)
    cfg = s._materialize_config("wgtest0", _WG)
    assert cfg == s._conf_path("wgtest0")
    with open(cfg, encoding="utf-8") as f:
        assert "PrivateKey = aGVsbG8=" in f.read()
    if os.name == "posix":  # Windows chmod only honors the write bit
        assert oct(os.stat(cfg).st_mode & 0o777) == "0o600"


@pytest.mark.asyncio
async def test_sidecar_connect_materializes_then_requests(tmp_path):
    s = _sidecar_svc(tmp_path)
    cfg = s._conf_path("wgtest0")
    assert not os.path.exists(cfg)
    r = await s.connect("wgtest0", config_content=_WG)
    assert r["success"] is True
    assert os.path.exists(cfg)  # connect wrote it
    assert os.path.exists(os.path.join(s.desired_dir, "wgtest0"))  # sidecar will enact


@pytest.mark.asyncio
async def test_sidecar_disconnect_removes_marker(tmp_path):
    s = _sidecar_svc(tmp_path)
    os.makedirs(s.desired_dir, exist_ok=True)
    with open(os.path.join(s.desired_dir, "wgtest0"), "w"):
        pass
    r = await s.disconnect("wgtest0")
    assert r["success"] is True
    assert not os.path.exists(os.path.join(s.desired_dir, "wgtest0"))


@pytest.mark.asyncio
async def test_sidecar_status_reads_published_file(tmp_path):
    s = _sidecar_svc(tmp_path)
    s._materialize_config("wgtest0", _WG)  # config exists ⇒ DISCONNECTED not NOT_CONFIGURED
    statusfile = os.path.join(s.run_dir, "wgtest0.status")
    with open(statusfile, "w") as f:
        f.write("connected\n")
    assert await s._get_connection_status("wgtest0") == VPNStatus.CONNECTED
    with open(statusfile, "w") as f:
        f.write("connecting\n")
    assert await s._get_connection_status("wgtest0") == VPNStatus.CONNECTING
    with open(statusfile, "w") as f:
        f.write("down\n")
    assert await s._get_connection_status("wgtest0") == VPNStatus.DISCONNECTED


@pytest.mark.asyncio
async def test_connect_without_content_and_no_file_fails_clearly(tmp_path):
    s = _sidecar_svc(tmp_path)
    r = await s.connect("wgtest0")  # no content, no pre-existing file
    assert r["success"] is False and "no wireguard config" in r["message"].lower()


@pytest.mark.asyncio
async def test_unsafe_interface_name_rejected(tmp_path):
    s = _sidecar_svc(tmp_path)
    for bad in ("../etc/x", "a b", "x;y", "toolong0123456789"):
        assert (await s.connect(bad, config_content=_WG))["success"] is False
        assert (await s.disconnect(bad))["success"] is False
        assert await s._get_connection_status(bad) == VPNStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_connect_rejects_postup_at_materialization(tmp_path):
    # audit fix: re-validate at the disk chokepoint — wg-quick runs PostUp as root
    s = _sidecar_svc(tmp_path)
    bad = "[Interface]\nPrivateKey = aGVsbG8=\nPostUp = id > /tmp/pwn\n[Peer]\nPublicKey = d29ybGQ=\n"
    r = await s.connect("wgtest0", config_content=bad)
    assert r["success"] is False and "rejected" in r["message"].lower()
    assert not os.path.exists(s._conf_path("wgtest0"))


@pytest.mark.asyncio
async def test_cleanup_removes_config_and_status(tmp_path):
    s = _sidecar_svc(tmp_path)
    cfg = s._materialize_config("wgtest0", _WG)
    with open(os.path.join(s.run_dir, "wgtest0.status"), "w") as f:
        f.write("connected\n")
    await s.cleanup("wgtest0")
    assert not os.path.exists(cfg)
    assert not os.path.exists(os.path.join(s.run_dir, "wgtest0.status"))


@pytest.mark.asyncio
async def test_sidecar_get_interfaces_lists_active_status_files(tmp_path):
    # audit fix: in sidecar mode get_interfaces must NOT shell out to `wg show`
    # (needs NET_ADMIN); it lists interfaces whose status file is up
    s = _sidecar_svc(tmp_path)
    with open(os.path.join(s.run_dir, "wgup.status"), "w") as f:
        f.write("connected\n")
    with open(os.path.join(s.run_dir, "wgdown.status"), "w") as f:
        f.write("down\n")
    ifaces = await s.get_interfaces()
    assert "wgup" in ifaces and "wgdown" not in ifaces


# ── Schema: WireGuard PostUp/PreUp RCE-directive rejection ────────────────────


def test_connection_create_rejects_wireguard_rce_directive():
    from app.schemas.vpn import VPNConnectionCreate

    for bad in ("PostUp = /bin/sh -c x", "PostDown = rm -rf /", "PreUp = curl evil", "PreDown = x"):
        with pytest.raises(ValueError):
            VPNConnectionCreate(
                name="w1",
                vpn_type="wireguard",
                wireguard_config_content=f"[Interface]\nPrivateKey = aGVsbG8=\n{bad}\n",
            )


def test_connection_create_accepts_safe_wireguard_config():
    from app.schemas.vpn import VPNConnectionCreate

    c = VPNConnectionCreate(name="w1", vpn_type="wireguard", wireguard_config_content=_WG)
    assert c.wireguard_config_content and "Endpoint = wg-server:51820" in c.wireguard_config_content
