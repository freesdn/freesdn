"""Real SSH/FTPS mutation acknowledgments; caller cannot infer server outcome."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from types import SimpleNamespace

import paramiko
import pytest
from paramiko.sftp import CMD_REMOVE, CMD_RENAME, SFTP_OK

import app.services.backup as storage
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import TLSPeer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer

PAYLOAD = b"owned-acknowledgment-probe\x00\xff"


# The owned FTPS handler is inserted below from the exact existing peer. Only
# the two mutation boundaries gain observation/drop behavior; client code stays
# unchanged. TLS, authentication, protected data and actual file mutation run.


def faulting_ftps_handle(self, connection):
    connection.settimeout(5)
    stream = connection.makefile("rb")
    listener = None
    rename_from = None
    protected = False
    connection.sendall(b"220 Test FTPS\r\n")
    try:
        while line := stream.readline():
            command, _, argument = line.decode().rstrip("\r\n").partition(" ")
            if command == "AUTH":
                connection.sendall(b"234 TLS\r\n")
                stream.close()
                connection = self.context.wrap_socket(connection, server_side=True)
                stream = connection.makefile("rb")
                continue
            assert isinstance(connection, ssl.SSLSocket), "Authentication without TLS"
            response = b"200 OK\r\n"
            if command == "PROT":
                assert argument == "P"
                protected = True
            elif command == "USER":
                response = b"331 Password\r\n"
            elif command == "PASS":
                self.authenticated += 1
                response = b"230 Logged in\r\n"
            elif command == "PASV":
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(5)
                port = listener.getsockname()[1]
                # Ignore a malicious PASV host and use the control peer address.
                response = f"227 Passive (10,0,0,99,{port // 256},{port % 256})\r\n".encode()
            elif command in {"STOR", "RETR"}:
                assert listener is not None and protected
                connection.sendall(b"150 Data\r\n")
                data_socket, _ = listener.accept()
                listener.close()
                listener = None
                with self.context.wrap_socket(data_socket, server_side=True) as channel:
                    channel.settimeout(5)
                    self.protected_transfers += 1
                    if command == "STOR":
                        chunks = []
                        while chunk := channel.recv(8192):
                            chunks.append(chunk)
                        self.files[argument] = b"".join(chunks)
                    else:
                        channel.sendall(self.files[argument])
                    channel.unwrap().close()
                response = b"226 Transferred\r\n"
            elif command == "RNFR":
                rename_from = argument
                response = b"350 Rename\r\n"
            elif command == "RNTO":
                state = self.ack_state
                state.events.append(("rename", rename_from, argument))
                selected = state.operation == "rename" and not state.dropped
                if selected and state.stage == "before":
                    state.dropped = True
                    connection.close()
                    return
                self.files[argument] = self.files.pop(rename_from)
                if selected and state.stage == "after":
                    state.dropped = True
                    connection.close()
                    return
                response = b"250 Renamed\r\n"
            elif command == "SIZE":
                response = f"213 {len(self.files[argument])}\r\n".encode()
            elif command == "DELE":
                state = self.ack_state
                state.events.append(("delete", argument, None))
                selected = state.operation == "delete" and not state.dropped
                if selected and state.stage == "before":
                    state.dropped = True
                    connection.close()
                    return
                self.files.pop(argument)
                if selected and state.stage == "after":
                    state.dropped = True
                    connection.close()
                    return
                response = b"250 Deleted\r\n"
            elif command == "CWD":
                response = b"250 Directory\r\n"
            connection.sendall(response)
    finally:
        stream.close()
        connection.close()
        if listener is not None:
            listener.close()


def fixture(request, monkeypatch, protocol, *, operation="rename", stage="none"):
    state = SimpleNamespace(operation=operation, stage=stage, dropped=False, events=[])
    original_server = paramiko.SFTPServer

    class FaultServer(original_server):
        def _process(self, kind, number, message):
            if kind not in (CMD_REMOVE, CMD_RENAME):
                return super()._process(kind, number, message)
            first = message.get_text()
            second = message.get_text() if kind == CMD_RENAME else None
            name = "rename" if kind == CMD_RENAME else "delete"
            state.events.append((name, first, second))
            selected = name == state.operation and not state.dropped
            if selected and state.stage == "before":
                state.dropped = True
                self.sock.close()
                return None
            result = self.server.rename(first, second) if second is not None else self.server.remove(first)
            if selected and state.stage == "after" and result == SFTP_OK:
                state.dropped = True
                self.sock.close()
                return None
            return self._send_status(number, result)

    if protocol == "sftp":
        monkeypatch.setattr(paramiko, "SFTPServer", FaultServer)
        peer = request.getfixturevalue("sftp_peer")
        backend = storage.SFTPStorageBackend(dict(peer.config))

        def files():
            return {"/" + str(p.relative_to(peer.root)): p.read_bytes()
                    for p in peer.root.rglob("*") if p.is_file()}

        def auths():
            return len(peer.authentications)
    else:
        monkeypatch.setattr(TLSPeer, "handle", faulting_ftps_handle)
        peer = request.getfixturevalue("ftps_peer")
        peer.ack_state = state
        backend = storage.FTPStorageBackend({"host": "backup.test", "port": peer.port,
                                            "use_tls": True, "username": "test", "password": "test-only"})
        def files():
            return dict(peer.files)

        def auths():
            return peer.authenticated
    return SimpleNamespace(state=state, backend=backend, peer=peer, files=files, auths=auths)


async def capture(awaitable):
    try:
        return await asyncio.wait_for(awaitable, 5), None
    except Exception as error:
        return None, error


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("stage", ["before", "after"])
async def test_lost_rename_ack_retains_both_possible_locations(request, monkeypatch, protocol, stage):
    f = fixture(request, monkeypatch, protocol, stage=stage)
    destination = f.backend._new_path("owned", "archive.fsdn")
    value, error = await capture(f.backend.save("owned", PAYLOAD, "archive.fsdn"))
    contents = f.files()
    renames = [e for e in f.state.events if e[0] == "rename"]
    assert len(renames) == 1, "Fixture must observe the actual rename command"
    _, temporary, actual_destination = renames[0]
    assert actual_destination == destination
    payload_path = destination if stage == "after" else temporary
    observed = {
        "protocol": protocol, "drop_stage": stage, "actual_rename_requests": len(renames),
        "actual_authentications": f.auths(), "acknowledgment_dropped": f.state.dropped,
        "final_exists": destination in contents, "temporary_exists": temporary in contents,
        "payload_sha256": hashlib.sha256(contents.get(payload_path, b"")).hexdigest(),
        "error_type": type(error).__name__, "error_retains_destination": getattr(error, "storage_path", None) == f.backend._url(destination),
        "error_retains_temporary": getattr(error, "temporary_storage_path", None) == f.backend._url(temporary),
        "outcome_unknown": getattr(error, "outcome_unknown", False), "returned_value": value,
    }
    request.node.user_properties.extend(observed.items())
    assert f.state.dropped and error is not None and not isinstance(error, TimeoutError)
    assert f.auths() == 1 and value is None
    assert contents == {payload_path: PAYLOAD}
    # Both server outcomes look like lost acknowledgment to the actual client.
    # Retain candidates, never claim either exists or automatically replay.
    assert observed["error_retains_destination"], "Possible final locator lost after unacknowledged rename"
    assert observed["error_retains_temporary"], "Possible temporary locator lost after unacknowledged rename"
    assert observed["outcome_unknown"] is True
    assert "could not be confirmed" in str(error)


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
async def test_confirmed_save_keeps_normal_locator_and_complete_bytes(request, monkeypatch, protocol):
    f = fixture(request, monkeypatch, protocol)
    destination = f.backend._new_path("owned", "archive.fsdn")
    value, error = await capture(f.backend.save("owned", PAYLOAD, "archive.fsdn"))
    request.node.user_properties.extend({"authentications": f.auths(), "error_type": type(error).__name__,
                                        "actual_rename_requests": len(f.state.events), "dropped": f.state.dropped}.items())
    assert error is None and value == f.backend._url(destination)
    assert f.files() == {destination: PAYLOAD} and f.auths() == 1 and not f.state.dropped


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
async def test_identity_refusal_sends_no_credentials_or_mutation(request, monkeypatch, protocol):
    f = fixture(request, monkeypatch, protocol, stage="after")
    if protocol == "sftp":
        f.backend.config["host_key_sha256"] = "SHA256:" + "A" * 43
    else:
        f.backend.hostname = "wrong.test"
    value, error = await capture(f.backend.save("owned", PAYLOAD, "archive.fsdn"))
    request.node.user_properties.extend({"authentications": f.auths(), "mutation_requests": len(f.state.events),
                                        "error_type": type(error).__name__, "files": len(f.files())}.items())
    assert error is not None and not isinstance(error, TimeoutError) and value is None
    assert f.auths() == 0 and not f.state.events and not f.files()
    assert getattr(error, "storage_path", None) is None


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
async def test_lost_delete_ack_never_reports_success_or_retries(request, monkeypatch, protocol):
    f = fixture(request, monkeypatch, protocol, operation="delete", stage="after")
    path = await f.backend.save("owned", PAYLOAD, "archive.fsdn")
    value, error = await capture(f.backend.delete(path))
    deletes = [e for e in f.state.events if e[0] == "delete"]
    request.node.user_properties.extend({"actual_delete_requests": len(deletes), "actual_authentications": f.auths(),
                                        "actual_remaining_files": len(f.files()), "error_type": type(error).__name__,
                                        "acknowledgment_dropped": f.state.dropped, "returned_value": value}.items())
    assert f.state.dropped and error is not None and not isinstance(error, TimeoutError)
    assert value is None and len(deletes) == 1 and f.auths() == 2 and not f.files()
