"""Exercise the installed botocore transport inside the actual owned child.

Only destination admission is replaced for this test-owned loopback HTTP peer.
No provider credentials, external network, database or historical VM data is used.
"""

import hashlib
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import boto3
import pytest
from botocore.config import Config

from app.core.backup_downloads import DownloadPool
from app.services import vault_s3_stream as native


@pytest.fixture
def s3_peer():
    state = SimpleNamespace(body=b"owned archive\x00" * 128, status=200, requests=[])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state.requests.append((self.path, dict(self.headers)))
            self.send_response(state.status)
            self.send_header("Content-Length", str(len(state.body)))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(state.body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = boto3.session.Session().client(
        "s3", endpoint_url=f"http://127.0.0.1:{server.server_port}",
        region_name="us-east-1", aws_access_key_id="owned-fixture-access",
        aws_secret_access_key="owned-fixture-secret",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                      connect_timeout=2, read_timeout=2, retries={"max_attempts": 0}, proxies={}),
    )
    state.backend = SimpleNamespace(bucket="owned-bucket", client=client, _sni_hostname=None)
    yield state
    client.close()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.fixture
def owned_children(monkeypatch):
    children = []
    start = native._start_owned

    async def capture(state):
        children.append(state)
        await start(state)

    def owned_pin(host, *, allow_private):
        assert host == "127.0.0.1" and allow_private is False
        return host

    monkeypatch.setattr(native, "_start_owned", capture)
    monkeypatch.setattr(native, "validate_target_host", owned_pin)
    yield children
    for state in children:
        assert state.process.raw.poll() is not None
        assert state.pidfd is None and state.process.pidfd is None
        assert state.process.raw.stdin.closed and state.process.raw.stdout.closed
        assert not os.path.exists(f"/proc/{state.process.pid}")
    assert native._ADMISSION.borrowed_tokens == 0


async def test_real_botocore_child_preserves_signed_request_and_archive(
    s3_peer, owned_children, tmp_path,
):
    snapshot = DownloadPool(tmp_path / "spool", slots=1, limit=65536, free_floor=0).acquire()
    expected = {"version": 1, "bytes": len(s3_peer.body),
                "sha256": hashlib.sha256(s3_peer.body).hexdigest()}
    try:
        await native.copy_s3_into(s3_peer.backend, "s3://owned-bucket/archive", expected, snapshot)
        assert snapshot.integrity == "verified"
        assert snapshot.read_chunk() == s3_peer.body
        assert snapshot.read_chunk() == b""
        path, headers = s3_peer.requests[0]
        assert path == "/owned-bucket/archive"
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=owned-fixture-access/")
        assert len(owned_children) == 1
    finally:
        snapshot.close()


@pytest.mark.parametrize("failure", ["provider", "oversize", "digest"])
async def test_real_botocore_refusal_never_seals_archive(
    s3_peer, owned_children, tmp_path, failure,
):
    limit = 128 if failure == "oversize" else 65536
    if failure == "provider":
        s3_peer.status = 403
    snapshot = DownloadPool(tmp_path / "spool", slots=1, limit=limit, free_floor=0).acquire()
    expected = {"version": 1, "bytes": len(s3_peer.body), "sha256": "0" * 64}
    try:
        with pytest.raises(ValueError):
            await native.copy_s3_into(s3_peer.backend, "archive", expected, snapshot)
        assert snapshot.integrity is None
    finally:
        snapshot.close()
