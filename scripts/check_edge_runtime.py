#!/usr/bin/env python3
"""Exercise a built edge against an isolated HTTP/WebSocket fixture.

Run with the backend's Python dependencies and Docker access. Only uniquely
named test containers, their anonymous volumes, and their network are removed.
No production service, device, public certificate authority, or registry is used.
"""

import argparse
import asyncio
import json
import locale
import math
import re
import ssl
import subprocess
import time
import uuid

import aiohttp
from qualification.bounded_command import capture_command

UPSTREAM = """
from aiohttp import web
import asyncio
async def handler(request):
    if request.path == '/api/ws':
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for message in ws:
            await ws.send_str(message.data)
        return ws
    if request.path == '/api/events':
        response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await response.prepare(request)
        await response.write(b'data: first\\n\\n')
        await asyncio.sleep(2)
        await response.write(b'data: last\\n\\n')
        return response
    return web.json_response({'path': request.path}, headers={
        'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'none'"})
app = web.Application()
app.router.add_get('/{path:.*}', handler)
web.run_app(app, port=8000, print=None)
"""


DOCKER_COMMAND_TIMEOUT_SECONDS = 120.0
DOCKER_COMMAND_MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def docker(*args: str, deadline: float | None = None) -> str:
    """Capture bounded command output; callers may shorten the default deadline.

    Failure or CLI termination leaves daemon-side state uncertain. The caller's
    owned-resource inspection and cleanup remain required after any failure.
    """
    command_deadline = time.monotonic() + DOCKER_COMMAND_TIMEOUT_SECONDS
    if deadline is not None:
        if type(deadline) not in (int, float):
            raise ValueError("A finite monotonic deadline is required")
        try:
            finite = math.isfinite(deadline)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError("A finite monotonic deadline is required")
        command_deadline = min(command_deadline, deadline)
    if not args:
        raise ValueError("A Docker command is required")
    result = capture_command(
        ["docker", *args], deadline=command_deadline,
        max_output_bytes=DOCKER_COMMAND_MAX_OUTPUT_BYTES, max_input_bytes=1,
    )
    # Match subprocess text=True decoding and universal-newline behavior.
    encoding = locale.getpreferredencoding(False)
    stdout = result.stdout.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
    stderr = result.stderr.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, ["docker", *args], output=stdout, stderr=stderr)
    return (stdout + (stderr if args[0] == "logs" else "")).strip()


def owned_resource_id(kind: str, name: str, owner: str) -> str:
    """Resolve a planned resource inside a trusted daemon; refuse ambiguous state.

    A failed inspection is not assumed to mean absence. Labels are an ownership
    check in this fixture, not protection against a hostile Docker administrator.
    Remove by the inspected immutable ID so replacement of the name is not a
    reason to delete a different object.
    """
    raw = docker("network", "inspect", name) if kind == "network" else docker("inspect", "--type=container", name)
    if len(raw) > 65536:
        raise RuntimeError("Owned resource inspection exceeds its parse budget")
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("Ambiguous owned resource inspection")
    row = rows[0]
    config = row.get("Config")
    labels = row.get("Labels") if kind == "network" else config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or labels.get("freesdn.audit") != owner:
        raise RuntimeError("Refusing resource without this fixture ownership label")
    identity = row.get("Id")
    if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise RuntimeError("Invalid owned resource identity")
    return identity


async def probe(edge: str, tls: bool) -> None:
    port = docker("port", edge, "443/tcp" if tls else "80/tcp").rsplit(":", 1)[1]
    url = f"{'https' if tls else 'http'}://localhost:{port}"
    context: ssl.SSLContext | bool = False
    # Wait only for this test's local CA. Never disable verification for the
    # actual HTTPS assertions below.
    if tls:
        for _ in range(100):
            try:
                ca = docker("exec", edge, "cat", "/data/caddy/pki/authorities/local/root.crt")
                context = ssl.create_default_context(cadata=ca)
                break
            except subprocess.CalledProcessError:
                await asyncio.sleep(0.1)
        assert isinstance(context, ssl.SSLContext), "Caddy did not create its local CA"
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as client:
        for _ in range(100):
            try:
                async with client.get(url + "/health", ssl=context) as response:
                    assert response.status == 200
                    assert await response.text() == "healthy"
                break
            except (aiohttp.ClientError, AssertionError):
                await asyncio.sleep(0.1)
        else:
            raise AssertionError("Edge did not become healthy")
        # Edge liveness does not imply that the separate fixture process has
        # finished importing aiohttp and opening its listener.
        for _ in range(100):
            try:
                async with client.get(url + "/api/ready", ssl=context) as response:
                    if response.status == 200:
                        break
            except aiohttp.ClientError:
                pass
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("Upstream fixture did not become ready through the edge")
        async with client.get(url + "/deep/link", ssl=context) as response:
            assert response.status == 200
            assert "text/html" in response.headers["Content-Type"]
            assert "<html" in (await response.text()).lower()
            assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
            assert "object-src 'none'" in response.headers["Content-Security-Policy"]
        async with client.get(url + "/api/probe", ssl=context) as response:
            assert response.status == 200
            assert await response.json() == {"path": "/api/probe"}
            assert response.headers["X-Frame-Options"] == "DENY"
            assert response.headers["Content-Security-Policy"] == "default-src 'none'"
        async with client.ws_connect(url + "/api/ws", ssl=context) as socket:
            await socket.send_str("freesdn-edge-round-trip")
            message = await socket.receive(timeout=5)
            assert message.data == "freesdn-edge-round-trip"
        async with client.get(url + "/api/events", ssl=context) as response:
            assert response.status == 200
            # The first event must arrive before the upstream completes the
            # response; this detects accidentally buffered SSE proxying.
            first = await asyncio.wait_for(response.content.readline(), timeout=1)
            assert first == b"data: first\n"
            assert b"data: last" in await response.read()
    print(json.dumps({"transport": "verified HTTPS/WSS" if tls else "HTTP/WS", "checks": [
        "health", "SPA fallback", "security headers", "API forwarding", "WebSocket echo", "unbuffered SSE"
    ], "passed": True}), flush=True)


async def main() -> None:
    if not __debug__:
        raise RuntimeError("Qualification must run without Python optimization")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Already-built default Caddy edge image")
    parser.add_argument("--backend-image", required=True, help="Already-built backend image for aiohttp fixture")
    args = parser.parse_args()
    name = "freesdn-edge-check-" + uuid.uuid4().hex[:12]
    containers: list[str] = []
    failures: list[BaseException] = []
    cleanup: list[dict[str, object]] = []
    # Record intent before a command: a lost acknowledgement may follow creation.
    # A dedicated bridge permits Docker's loopback-only published test ports.
    try:
        docker("network", "create", "--label", "freesdn.audit=" + name, name)
        api = name + "-api"
        containers.append(api)
        docker("run", "-d", "--pull=never", "--name", api, "--network", name, "--network-alias", "api",
               "--label", "freesdn.audit=" + name, "--read-only", "--tmpfs", "/tmp",
               "--cap-drop", "ALL", "--entrypoint", "python", args.backend_image, "-c", UPSTREAM)
        for tls in (False, True):
            edge = name + ("-https" if tls else "-http")
            containers.append(edge)
            docker("run", "-d", "--pull=never", "--name", edge, "--network", name,
                   "--label", "freesdn.audit=" + name, "--read-only", "--tmpfs", "/tmp",
                   "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
                   "-v", "/data", "-v", "/config", "-p", "127.0.0.1::" + ("443" if tls else "80"),
                   "-e", "CADDY_SITE_ADDRESS=" + ("localhost" if tls else ":80"), args.image)
            await probe(edge, tls)
    except BaseException as exc:
        failures.append(exc)
        for container in containers:
            try:
                identity = owned_resource_id("container", container, name)
                print(docker("logs", "--tail", "30", identity), flush=True)
            except BaseException as diagnostic_error:
                failures.append(diagnostic_error)
    finally:
        for kind, resource in [("container", item) for item in reversed(containers)] + [("network", name)]:
            entry: dict[str, object] = {"kind": kind, "planned_name": resource, "removed": False}
            try:
                identity = owned_resource_id(kind, resource, name)
                if kind == "network":
                    docker("network", "rm", identity)
                else:
                    docker("rm", "-fv", identity)
                entry["removed"] = True
            except BaseException as cleanup_error:
                failures.append(cleanup_error)
                entry["error_type"] = type(cleanup_error).__name__
            cleanup.append(entry)
        print(json.dumps({"fixture": name, "cleanup": cleanup,
                          "qualification_complete": not failures,
                          "uncertain_or_failed_operations_require_review": bool(failures)}), flush=True)
    if failures:
        raise BaseExceptionGroup("Edge qualification or owned cleanup failed; original errors retained", failures)


if __name__ == "__main__":
    asyncio.run(main())
