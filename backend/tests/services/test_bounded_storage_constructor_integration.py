# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Packaged constructors: real address policy, captured input and worker lifetime.

No external protocol server is contacted. The public literal controls exercise
the actual address checker; controlled resolver waits exercise input ownership.
The separate HTTP/PG/WebDAV suite retains its explicit owned-peer admission.
"""

import asyncio
import base64
import hashlib
import socket
import threading

import anyio
import httpx
import pytest

from app.services import backup, vault_native_resolution


def configuration(protocol, host="8.8.8.8"):
    shared = {"username": "owned", "password": "Owned bounded configuration password"}
    if protocol == "webdav":
        return {**shared, "url": f"https://[{host}]:8443/dav" if ":" in host else f"https://{host}:8443/dav", "path": "/backups"}
    return {
        **shared, "host": host, "port": 8022 if protocol == "sftp" else 8021,
        "remote_path": "/backups", "use_tls": True,
        "host_key_sha256": "SHA256:" + base64.b64encode(hashlib.sha256(b"Owned synthetic host key").digest()).decode().rstrip("="),
    }


def kind(protocol):
    return {"webdav": backup.WebDAVStorageBackend, "sftp": backup.SFTPStorageBackend, "ftps": backup.FTPStorageBackend}[protocol]


def forbid_connections(monkeypatch):
    def refused(*args, **kwargs):
        raise AssertionError("Construction must not allocate a protocol connection")
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(httpx, "AsyncClient", refused)


@pytest.mark.parametrize("protocol", ["webdav", "sftp", "ftps"])
async def test_public_literal_constructor_retains_protocol_identity_without_connection(monkeypatch, request, protocol):
    forbid_connections(monkeypatch)
    config = configuration(protocol)
    backend = await kind(protocol).create_bounded(config)
    pin = backend._pinned_ip if protocol == "webdav" else backend.host
    host = backend._orig_hostname if protocol == "webdav" else backend.hostname
    port = backend._port if protocol == "webdav" else backend.port
    request.node.user_properties.extend({"protocol": protocol, "actual_address_policy": True,
                                       "pin": pin, "hostname": host, "port": port,
                                       "protocol_connection_forbidden": True}.items())
    assert pin == host == "8.8.8.8"
    assert backend.username == config["username"] and backend.password == config["password"]
    assert port == (8443 if protocol == "webdav" else config["port"])
    if protocol == "webdav":
        assert backend._sni_extensions == {"sni_hostname": "8.8.8.8"}
        assert backend._client_options["follow_redirects"] is False
    else:
        assert backend.config == config and backend.config is not config
        assert backend._PREPARATION_ADMISSION.borrowed_tokens == backend._CONFIG_THREADS.borrowed_tokens == 0


@pytest.mark.parametrize("protocol", ["webdav", "sftp", "ftps"])
@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.8", "169.254.169.254", "::1"])
async def test_private_or_metadata_literal_is_refused_before_protocol_connection(monkeypatch, request, protocol, address):
    forbid_connections(monkeypatch)
    with pytest.raises(vault_native_resolution.StorageResolutionError):
        await kind(protocol).create_bounded(configuration(protocol, address))
    request.node.user_properties.extend({"protocol": protocol, "actual_address_refused": address,
                                       "actual_address_policy": True, "protocol_connection_forbidden": True}.items())
    if protocol != "webdav":
        assert kind(protocol)._PREPARATION_ADMISSION.borrowed_tokens == kind(protocol)._CONFIG_THREADS.borrowed_tokens == 0


@pytest.mark.parametrize("protocol", ["webdav", "sftp", "ftps"])
async def test_destination_configuration_cannot_change_during_resolver_wait(monkeypatch, request, protocol):
    forbid_connections(monkeypatch)
    config = configuration(protocol)
    original = dict(config)
    resolve = vault_native_resolution.resolve_storage_host
    observed = []

    async def changed(host, *, allow_private=False):
        observed.append((host, allow_private))
        pin = await resolve(host, allow_private=allow_private)
        await anyio.sleep(0)
        config.update(url="https://127.0.0.1/private", host="127.0.0.1", port=1,
                      password="Changed after admission", remote_path="/other", path="/other", use_tls=False)
        return pin

    monkeypatch.setattr(vault_native_resolution, "resolve_storage_host", changed)
    backend = await kind(protocol).create_bounded(config)
    assert observed == [("8.8.8.8", False)] and config != original
    assert backend.password == original["password"]
    if protocol == "webdav":
        assert backend._pinned_ip == backend._orig_hostname == "8.8.8.8"
        assert backend._port == 8443 and backend._storage_root == "/dav/backups"
    else:
        assert backend.config == original and backend.hostname == backend.host == "8.8.8.8"
        assert backend.port == original["port"] and backend.remote_path == "/backups"
    request.node.user_properties.extend({"protocol": protocol, "caller_input_changed_after_resolution": True,
                                       "original_destination_retained": True, "protocol_connection_forbidden": True}.items())


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
async def test_cancelled_configuration_worker_remains_owned_until_release(monkeypatch, request, protocol):
    forbid_connections(monkeypatch)
    cls = kind(protocol)
    configure = cls._configure_endpoint
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    def held(self, config, pin):
        configure(self, config, pin)
        entered.set()
        try:
            assert release.wait(5), "Owned configuration worker was not released"
        finally:
            returned.set()

    monkeypatch.setattr(cls, "_configure_endpoint", held)
    task = asyncio.create_task(cls.create_bounded(configuration(protocol)))
    try:
        with anyio.fail_after(2):
            while not entered.is_set():
                await anyio.sleep(.001)
        task.cancel()
        await anyio.sleep(.02)
        assert not task.done() and not returned.is_set()
        assert cls._PREPARATION_ADMISSION.borrowed_tokens == cls._CONFIG_THREADS.borrowed_tokens == 1
    finally:
        release.set()
        result = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 3)
    assert isinstance(result[0], asyncio.CancelledError) and returned.is_set()
    assert cls._PREPARATION_ADMISSION.borrowed_tokens == cls._CONFIG_THREADS.borrowed_tokens == 0
    request.node.user_properties.extend({"protocol": protocol, "real_configuration_thread_held": True,
                                       "cancelled_caller_waited_for_worker": True, "worker_completed_before_slots_released": True}.items())
