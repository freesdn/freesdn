# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""OpenVPN service: container-friendly (no-systemd) process management.

The service was reworked off ``systemctl openvpn-client@`` (systemd does not run
in a container) onto a managed ``openvpn --daemon`` process tracked by pidfile.
These tests pin that behaviour. ``os.kill`` is ALWAYS mocked — on Linux (prod/CI)
``os.kill(pid, 0)`` is a no-op existence check, but on Windows it terminates the
process, so a real call in a test would be dangerous + non-portable.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock

import pytest

from app.services.vpn_integration import OpenVPNService, VPNStatus


def _svc(tmp_path) -> OpenVPNService:
    s = OpenVPNService(config_dir=str(tmp_path / "etc-openvpn"))
    s.run_dir = str(tmp_path / "run")
    s.log_dir = str(tmp_path / "log")
    os.makedirs(os.path.join(s.config_dir, "client"), exist_ok=True)
    os.makedirs(s.run_dir, exist_ok=True)
    os.makedirs(s.log_dir, exist_ok=True)
    return s


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


@pytest.mark.asyncio
async def test_status_not_configured_without_config(tmp_path):
    s = _svc(tmp_path)
    assert await s._get_connection_status("site1") == VPNStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_status_disconnected_with_config_no_process(tmp_path):
    s = _svc(tmp_path)
    cfg, _pid, _log = s._paths("site1")
    _write(cfg, "client\n")
    # no pidfile → _read_pid None → _pid_alive False (no os.kill call)
    assert await s._get_connection_status("site1") == VPNStatus.DISCONNECTED


@pytest.mark.asyncio
async def test_status_connected_when_alive_and_initialized(tmp_path, monkeypatch):
    s = _svc(tmp_path)
    cfg, pidfile, logfile = s._paths("site1")
    _write(cfg, "client\n")
    _write(pidfile, "4242\n")
    _write(logfile, "TLS handshake...\nInitialization Sequence Completed\n")
    monkeypatch.setattr(os, "kill", MagicMock(return_value=None))  # alive
    assert await s._get_connection_status("site1") == VPNStatus.CONNECTED


@pytest.mark.asyncio
async def test_status_connecting_when_alive_not_initialized(tmp_path, monkeypatch):
    s = _svc(tmp_path)
    cfg, pidfile, logfile = s._paths("site1")
    _write(cfg, "client\n")
    _write(pidfile, "4242\n")
    _write(logfile, "TLS: Initial packet...\n")  # not yet completed
    monkeypatch.setattr(os, "kill", MagicMock(return_value=None))  # alive
    assert await s._get_connection_status("site1") == VPNStatus.CONNECTING


@pytest.mark.asyncio
async def test_connect_rejects_missing_config(tmp_path):
    s = _svc(tmp_path)
    r = await s.connect("site1")
    assert r["success"] is False and "config" in r["message"].lower()


@pytest.mark.asyncio
async def test_connect_reports_missing_binary(tmp_path, monkeypatch):
    s = _svc(tmp_path)
    cfg, _pid, _log = s._paths("site1")
    _write(cfg, "client\n")  # config present; not running (no pidfile)

    async def _boom(*_a, **_k):
        raise FileNotFoundError("openvpn")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _boom)
    r = await s.connect("site1")
    assert r["success"] is False and "not installed" in r["message"].lower()


@pytest.mark.asyncio
async def test_disconnect_when_not_running_cleans_stale_pidfile(tmp_path, monkeypatch):
    s = _svc(tmp_path)
    _cfg, pidfile, _log = s._paths("site1")
    _write(pidfile, "4242\n")
    monkeypatch.setattr(os, "kill", MagicMock(side_effect=ProcessLookupError()))  # dead
    r = await s.disconnect("site1")
    assert r["success"] is True
    assert not os.path.exists(pidfile)  # stale pidfile removed


@pytest.mark.asyncio
async def test_unsafe_connection_name_rejected_everywhere(tmp_path):
    s = _svc(tmp_path)
    for bad in ("../etc/passwd", "a b", "x;y", "/abs"):
        assert (await s.connect(bad))["success"] is False
        assert (await s.disconnect(bad))["success"] is False
        assert await s._get_connection_status(bad) == VPNStatus.NOT_CONFIGURED


def _sidecar_svc(tmp_path) -> OpenVPNService:
    s = _svc(tmp_path)
    s.sidecar = True
    s.desired_dir = os.path.join(s.run_dir, "desired")
    return s


@pytest.mark.asyncio
async def test_sidecar_connect_writes_desired_marker(tmp_path):
    s = _sidecar_svc(tmp_path)
    cfg, _pid, _log = s._paths("site1")
    _write(cfg, "client\n")
    r = await s.connect("site1")
    assert r["success"] is True
    assert os.path.exists(os.path.join(s.desired_dir, "site1"))  # sidecar will enact


@pytest.mark.asyncio
async def test_sidecar_disconnect_removes_marker(tmp_path):
    s = _sidecar_svc(tmp_path)
    os.makedirs(s.desired_dir, exist_ok=True)
    _write(os.path.join(s.desired_dir, "site1"), "")
    r = await s.disconnect("site1")
    assert r["success"] is True
    assert not os.path.exists(os.path.join(s.desired_dir, "site1"))


@pytest.mark.asyncio
async def test_sidecar_status_reads_published_status_file(tmp_path):
    s = _sidecar_svc(tmp_path)
    cfg, _pid, _log = s._paths("site1")
    _write(cfg, "client\n")
    statusfile = os.path.join(s.run_dir, "site1.status")
    _write(statusfile, "connected\n")
    assert await s._get_connection_status("site1") == VPNStatus.CONNECTED
    _write(statusfile, "connecting\n")
    assert await s._get_connection_status("site1") == VPNStatus.CONNECTING
    _write(statusfile, "down\n")
    assert await s._get_connection_status("site1") == VPNStatus.DISCONNECTED  # config exists


@pytest.mark.asyncio
async def test_materialize_config_writes_content_and_perms(tmp_path):
    s = _svc(tmp_path)
    cfg = s._materialize_config("site1", "client\nremote vpn.example 1194\n")
    assert cfg == s._paths("site1")[0]
    with open(cfg, encoding="utf-8") as f:
        assert "remote vpn.example 1194" in f.read()
    if os.name == "posix":  # Windows chmod only honors the write bit
        assert oct(os.stat(cfg).st_mode & 0o777) == "0o600"


@pytest.mark.asyncio
async def test_connect_materializes_config_then_requests_sidecar(tmp_path):
    """The blocker fix: connect() with config_content writes the .conf the daemon
    needs (previously nothing did, so connect always failed 'No config found')."""
    s = _sidecar_svc(tmp_path)
    cfg = s._paths("site1")[0]
    assert not os.path.exists(cfg)  # nothing on disk yet
    r = await s.connect("site1", config_content="client\nremote vpn.example 1194\n")
    assert r["success"] is True
    assert os.path.exists(cfg)  # connect wrote it
    assert os.path.exists(os.path.join(s.desired_dir, "site1"))  # sidecar will enact


@pytest.mark.asyncio
async def test_connect_without_content_and_no_file_still_fails_clearly(tmp_path):
    s = _sidecar_svc(tmp_path)
    r = await s.connect("site1")  # no content, no pre-existing file
    assert r["success"] is False and "no openvpn config" in r["message"].lower()


@pytest.mark.asyncio
async def test_connect_rejects_dangerous_config_at_materialization(tmp_path):
    # audit fix: re-validate at the disk chokepoint so a dangerous directive can
    # never reach the root daemon, even via a row that bypassed the schema
    s = _sidecar_svc(tmp_path)
    r = await s.connect("site1", config_content="client\nmanagement 127.0.0.1 7505\n")
    assert r["success"] is False and "rejected" in r["message"].lower()
    assert not os.path.exists(s._paths("site1")[0])  # nothing written


@pytest.mark.asyncio
async def test_cleanup_removes_materialized_config_and_status(tmp_path):
    s = _sidecar_svc(tmp_path)
    cfg = s._materialize_config("site1", "client\nremote x 1194\n")
    _write(os.path.join(s.run_dir, "site1.status"), "connected\n")
    await s.cleanup("site1")
    assert not os.path.exists(cfg)
    assert not os.path.exists(os.path.join(s.run_dir, "site1.status"))


def test_no_systemctl_dependency_remains():
    """The rework must not SHELL OUT to systemd (docstrings may still mention it).

    A subprocess call passes the command as a quoted string literal
    (``"systemctl"``); the explanatory docstrings use RST backticks
    (```systemctl```), so the quoted form distinguishes a real call from prose.
    """
    import inspect

    src = inspect.getsource(OpenVPNService)
    assert '"systemctl"' not in src
    assert "openvpn-client@" not in src.replace("``systemctl start openvpn-client@``", "").replace(
        "``systemctl stop openvpn-client@``", ""
    )
