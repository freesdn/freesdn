"""
MikroTik RouterOS CHR integration tests.

What this exists for
====================
The unit suite under ``tests/adapters/test_mikrotik_wire_format.py`` pins
the wire format the client *emits* — but it does so against an ``AsyncMock``.
A mock will happily accept ``PATCH /menu/<id>`` or ``DELETE /menu/<id>``,
which is exactly how the wire-format bug shipped in commit ``ea150e8``
slipped past CI: the mocks said yes; real RouterOS 7.x said HTTP 400.

This module closes that gap by exercising the real client against a real
RouterOS CHR container.  Every test that mutates state cleans up after
itself (try/finally) so concurrent runs and re-runs are safe.

How it runs
-----------
The fixture below either:

1. **Reuses an existing CHR** if ``ROUTEROS_HOST`` is set in the env.
   This is the CI-friendly path — the workflow can declare CHR as a
   service container and just point the tests at ``localhost``.
2. **Spins a container via testcontainers** otherwise, using the
   community image ``evilfreelancer/docker-routeros:7.18`` (a CHR ISO
   booted inside QEMU; ~250 MB pull, ~60 s first boot).

In either case we wait for ``GET /rest/system/identity`` to return 200
before yielding the session factory.  REST is the *last* service to
come up on CHR — by the time identity returns 200, everything else
(API, firewall, dhcp-server) is also reachable.

Image / credentials
-------------------
``evilfreelancer/docker-routeros`` ships factory-default CHR: user
``admin``, blank password.  Override with ``ROUTEROS_USERNAME`` /
``ROUTEROS_PASSWORD`` env vars if you point at a different image.

Skip conditions
---------------
- ``SKIP_CHR_INTEGRATION=1``  → user opt-out (e.g. laptops where the
  QEMU boot is too slow).
- Docker socket unreachable    → cannot manage containers, skip cleanly.
- testcontainers import fails  → unexpected, but skip rather than error.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Skip guards — evaluated at import time so collection is cheap
# ---------------------------------------------------------------------------

_SKIP_REASON: str | None = None

if os.environ.get("SKIP_CHR_INTEGRATION") == "1":
    _SKIP_REASON = "SKIP_CHR_INTEGRATION=1 set in environment"
else:
    # Reuse path doesn't need Docker; only the local-spin path does.
    if not os.environ.get("ROUTEROS_HOST"):
        try:
            import docker  # type: ignore[import-not-found]

            try:
                docker.from_env().ping()
            except Exception as exc:  # docker daemon unreachable
                _SKIP_REASON = f"Docker daemon unreachable: {exc!s}"
        except ImportError:
            # ``docker`` SDK ships with testcontainers; if it's missing
            # we genuinely cannot manage containers.
            _SKIP_REASON = "docker SDK not importable (testcontainers missing?)"

pytestmark = pytest.mark.skipif(
    _SKIP_REASON is not None,
    reason=_SKIP_REASON or "",
)

# Boot budget for QEMU-backed CHR.  The image's README claims ~30 s but
# we've seen 90 s on cold runners.  Cap at 180 s so a stuck boot fails
# fast rather than burning the whole 10-minute workflow budget.
_CHR_BOOT_TIMEOUT_S = 180.0
_CHR_POLL_INTERVAL_S = 2.0

# Default image tag.  7.18 was the latest stable in the 7.x line at the
# time of writing and matches the 7.x family this integration suite
# targets.  Override via ``ROUTEROS_IMAGE`` env if the upstream tag
# moves.
_DEFAULT_CHR_IMAGE = os.environ.get(
    "ROUTEROS_IMAGE", "evilfreelancer/docker-routeros:7.18"
)


# ---------------------------------------------------------------------------
# Container fixture — session-scoped so the QEMU boot happens once
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def chr_endpoint() -> Generator[dict[str, Any]]:
    """Yield connection info for a live CHR.

    Returns a dict::

        {
            "host": str,
            "port": int,        # REST port (HTTP, not HTTPS)
            "use_ssl": bool,
            "username": str,
            "password": str,
        }

    The QEMU-in-Docker image exposes the REST API on port 80 inside the
    container; we map it to a random host port and read it back via
    ``get_exposed_port``.
    """
    # ── Reuse path ──────────────────────────────────────────────────────
    if os.environ.get("ROUTEROS_HOST"):
        yield {
            "host": os.environ["ROUTEROS_HOST"],
            "port": int(os.environ.get("ROUTEROS_PORT", "80")),
            "use_ssl": os.environ.get("ROUTEROS_USE_SSL", "false").lower()
            == "true",
            "username": os.environ.get("ROUTEROS_USERNAME", "admin"),
            "password": os.environ.get("ROUTEROS_PASSWORD", ""),
        }
        return

    # ── Spin path — testcontainers ──────────────────────────────────────
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_utils import wait_for_logs

    container = (
        DockerContainer(_DEFAULT_CHR_IMAGE)
        .with_exposed_ports(80, 443, 8728, 8729)
        # The image requires --privileged for KVM acceleration.  Without
        # it the container falls back to TCG emulation which still works
        # but boots much slower.
        .with_kwargs(privileged=True)
    )
    container.start()
    try:
        # Don't strictly require a log line — different image revisions
        # log differently.  Best-effort wait for the most stable marker.
        try:
            wait_for_logs(container, "MikroTik", timeout=120)
        except Exception:
            # Log marker missing or timed out — fall through to the REST
            # health probe which is the authoritative readiness signal.
            pass

        host = container.get_container_host_ip()
        port = int(container.get_exposed_port(80))
        username = os.environ.get("ROUTEROS_USERNAME", "admin")
        password = os.environ.get("ROUTEROS_PASSWORD", "")

        _wait_for_rest_ready(host, port, username, password)
        yield {
            "host": host,
            "port": port,
            "use_ssl": False,
            "username": username,
            "password": password,
        }
    finally:
        container.stop()


def _wait_for_rest_ready(
    host: str, port: int, username: str, password: str
) -> None:
    """Poll ``GET /rest/system/identity`` until 200 or timeout."""
    deadline = time.monotonic() + _CHR_BOOT_TIMEOUT_S
    last_err: Exception | None = None
    url = f"http://{host}:{port}/rest/system/identity"
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, auth=(username, password), timeout=5.0)
            if r.status_code == 200 and r.headers.get(
                "content-type", ""
            ).startswith("application/json"):
                return
            # 401 means REST is up but creds are wrong — surface fast.
            if r.status_code == 401:
                raise RuntimeError(
                    f"CHR REST returned 401 — credentials "
                    f"({username!r}/****) rejected during boot probe"
                )
            last_err = RuntimeError(
                f"CHR REST not ready: HTTP {r.status_code}"
            )
        except httpx.HTTPError as exc:
            last_err = exc
        time.sleep(_CHR_POLL_INTERVAL_S)
    raise RuntimeError(
        f"CHR REST API did not come up within {_CHR_BOOT_TIMEOUT_S}s "
        f"(last error: {last_err!r})"
    )


# ---------------------------------------------------------------------------
# Session factory — builds a fresh MikroTikClient per test
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def chr_client(
    chr_endpoint: dict[str, Any],
) -> AsyncGenerator[Any]:
    """Per-test ``MikroTikClient`` bound to the live CHR.

    Tests should NOT cache this across modules — every test gets its
    own client so a hung connection in one test doesn't poison the next.
    """
    # Import inside the fixture so a missing app dependency triggers a
    # SKIP rather than a collection error.
    from app.adapters.mikrotik.client import MikroTikClient

    # The dual-gate is on by default in production.  Tests that exercise
    # writes pass ``force=True`` at the call site, OR flip the env var
    # off via monkeypatch.  Don't pre-flip it here — we want each test
    # to be explicit about which path it's verifying.
    client = MikroTikClient(
        host=chr_endpoint["host"],
        username=chr_endpoint["username"],
        password=chr_endpoint["password"],
        port=chr_endpoint["port"],
        use_ssl=chr_endpoint["use_ssl"],
        verify_ssl=False,
        timeout=15,
    )
    try:
        await client.connect()
        yield client
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Helper: tolerantly delete a filter rule by .id (best-effort cleanup)
# ---------------------------------------------------------------------------


async def _safe_delete_filter_rule(client: Any, rule_id: str) -> None:
    """Best-effort filter rule delete — swallows errors so a failing
    test doesn't mask the original assertion failure with a teardown
    exception.
    """
    if not rule_id:
        return
    try:
        await client.delete_firewall_filter_rule(rule_id, force=True)
    except Exception:  # noqa: BLE001 — teardown, never mask the test failure
        pass


async def _find_filter_rule_by_comment(
    client: Any, comment: str
) -> dict[str, Any] | None:
    rules = await client.get_firewall_filter_rules()
    for r in rules or []:
        if r.get("comment") == comment:
            return r
    return None


# ===========================================================================
# Connectivity (3 tests)
# ===========================================================================


class TestConnectivity:
    """The handshake should work on valid creds, fail loud on bad creds,
    and the body should be JSON.  These are the boring tests — but the
    HTML-instead-of-JSON case (RouterOS REST not enabled) is exactly
    what bites someone trying out the adapter for the first time.
    """

    @pytest.mark.asyncio
    async def test_auth_succeeds_with_valid_credentials(
        self, chr_client: Any
    ) -> None:
        identity = await chr_client.get_system_identity()
        assert isinstance(identity, dict) and "name" in identity

    @pytest.mark.asyncio
    async def test_auth_fails_with_bad_credentials(
        self, chr_endpoint: dict[str, Any]
    ) -> None:
        from app.adapters.exceptions import AdapterAuthenticationError
        from app.adapters.mikrotik.client import MikroTikClient

        bad = MikroTikClient(
            host=chr_endpoint["host"],
            username=chr_endpoint["username"],
            password="definitely-not-the-real-password",
            port=chr_endpoint["port"],
            use_ssl=chr_endpoint["use_ssl"],
            verify_ssl=False,
            timeout=5,
        )
        try:
            with pytest.raises(AdapterAuthenticationError):
                await bad.get_system_identity()
        finally:
            await bad.close()

    @pytest.mark.asyncio
    async def test_rest_returns_json_not_html(self, chr_client: Any) -> None:
        # If REST is disabled, CHR's webfig returns HTML and the client
        # raises AdapterConnectionError("MikroTik returned HTML...").
        # A successful identity call proves the JSON path.
        resp = await chr_client.get("/system/identity")
        assert isinstance(resp, (list, dict))


# ===========================================================================
# Read paths — sweep across all 13 domains
# ===========================================================================


class TestReadPaths:
    """One read per major RouterOS domain.  The assertion contract is
    "the call returns the shape the adapter's type hints promise" —
    dict for singletons, list for collections.  Reads should never
    require ``force=True``.
    """

    @pytest.mark.asyncio
    async def test_get_system_identity(self, chr_client: Any) -> None:
        v = await chr_client.get_system_identity()
        assert isinstance(v, dict)

    @pytest.mark.asyncio
    async def test_get_system_resource(self, chr_client: Any) -> None:
        v = await chr_client.get_system_resource()
        assert isinstance(v, dict)

    @pytest.mark.asyncio
    async def test_get_interfaces(self, chr_client: Any) -> None:
        v = await chr_client.get_interfaces()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_ip_addresses(self, chr_client: Any) -> None:
        v = await chr_client.get_ip_addresses()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_firewall_filter_rules(self, chr_client: Any) -> None:
        v = await chr_client.get_firewall_filter_rules()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_dhcp_servers(self, chr_client: Any) -> None:
        v = await chr_client.get_dhcp_servers()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_dns_settings(self, chr_client: Any) -> None:
        v = await chr_client.get_dns_settings()
        assert isinstance(v, dict)

    @pytest.mark.asyncio
    async def test_get_routes(self, chr_client: Any) -> None:
        v = await chr_client.get_routes()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_l2tp_server(self, chr_client: Any) -> None:
        v = await chr_client.get_l2tp_server()
        # Wrapped in try/except inside the client — may be {} if the
        # package isn't present on this CHR build.  Still must be dict.
        assert isinstance(v, dict)

    @pytest.mark.asyncio
    async def test_get_ipsec_policies(self, chr_client: Any) -> None:
        v = await chr_client.get_ipsec_policies()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_simple_queues(self, chr_client: Any) -> None:
        v = await chr_client.get_simple_queues()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_hotspot_servers(self, chr_client: Any) -> None:
        v = await chr_client.get_hotspot_servers()
        assert isinstance(v, list)

    @pytest.mark.asyncio
    async def test_get_capsman_manager(self, chr_client: Any) -> None:
        # ``/caps-man/manager`` is a singleton.  On x86 CHR the wireless
        # package is absent, so the client's try/except converts the
        # 404 into ``{}``.  Either case is acceptable here — what we're
        # pinning is "returns a dict, no exception bubbles up".
        v = await chr_client.get_capsman_manager()
        assert isinstance(v, dict)


# ===========================================================================
# Write paths — full CRUD cycle on a firewall filter rule
# ===========================================================================


class TestFirewallFilterCRUD:
    """Real CRUD against the live CHR.  We tag the rule with a UUID
    comment so parallel runs don't collide and so the cleanup hook can
    find the rule even if the test crashed before it captured the .id.
    """

    @pytest.mark.asyncio
    async def test_full_crud_cycle(
        self, chr_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Tests in this class need writes — flip the gate off for the
        # duration of the test.  We still pass ``force=True`` at the
        # call sites so the test mirrors how real callers (appliers)
        # invoke the client.
        monkeypatch.setattr(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        )

        marker = f"freesdn-ci-{uuid.uuid4()}"
        created_id: str | None = None
        try:
            # ── Create ──────────────────────────────────────────────
            created = await chr_client.add_firewall_filter_rule(
                {
                    "chain": "forward",
                    "action": "accept",
                    "comment": marker,
                },
                force=True,
            )
            # RouterOS REST returns the created row inline — but the
            # exact shape varies by version.  Look the rule up by its
            # marker comment to be version-independent.
            found = await _find_filter_rule_by_comment(chr_client, marker)
            assert found is not None, (
                f"created rule {marker} not present in list after add; "
                f"created response was {created!r}"
            )
            created_id = found[".id"]
            assert found["action"] == "accept"

            # ── Update ──────────────────────────────────────────────
            await chr_client.update_firewall_filter_rule(
                created_id, {"action": "drop"}, force=True
            )
            updated = await _find_filter_rule_by_comment(chr_client, marker)
            assert updated is not None and updated["action"] == "drop"

            # ── Delete ──────────────────────────────────────────────
            await chr_client.delete_firewall_filter_rule(
                created_id, force=True
            )
            gone = await _find_filter_rule_by_comment(chr_client, marker)
            assert gone is None
            created_id = None  # signal "no cleanup needed"
        finally:
            if created_id is not None:
                await _safe_delete_filter_rule(chr_client, created_id)


# ===========================================================================
# Singleton write — /system/identity (PATCH path)
# ===========================================================================


class TestSingletonWrite:
    """RouterOS singletons (identity, /ip/dns, /system/ntp/client) hit
    the ``POST /<menu>/set`` wire pattern with no ``.id`` in the body.
    The patch helper detects "no trailing *<hex>" and emits exactly that.
    """

    @pytest.mark.asyncio
    async def test_set_and_revert_system_identity(
        self, chr_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        )

        original = (await chr_client.get_system_identity()).get(
            "name", "MikroTik"
        )
        new_name = f"FreeSDN-CI-{uuid.uuid4().hex[:8]}"
        try:
            await chr_client.set_system_identity(new_name, force=True)
            after = await chr_client.get_system_identity()
            assert after.get("name") == new_name
        finally:
            # Always revert, even on assertion failure.
            try:
                await chr_client.set_system_identity(original, force=True)
            except Exception:  # noqa: BLE001 — best-effort revert
                pass


# ===========================================================================
# Dual-gate enforcement — proves the read-only safety holds against real CHR
# ===========================================================================


class TestDualGate:
    """``ADAPTER_READ_ONLY=true`` (the default) must refuse writes that
    don't pass ``force=True``.  This is the safety property the
    operator-mode UI relies on, so we verify it against the real device
    rather than just a mock.
    """

    @pytest.mark.asyncio
    async def test_write_refused_when_read_only_and_no_force(
        self, chr_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.adapters.exceptions import AdapterError

        # Belt-and-braces: explicitly set the gate ON, even though it's
        # the default.  A previous test using monkeypatch shouldn't be
        # able to bleed state, but be defensive.
        monkeypatch.setattr(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: True,
        )

        with pytest.raises(AdapterError) as excinfo:
            await chr_client.add_firewall_filter_rule(
                {
                    "chain": "forward",
                    "action": "accept",
                    "comment": f"freesdn-ci-gate-{uuid.uuid4()}",
                }
                # NOTE: no force=True — that's the whole point.
            )
        assert "ADAPTER_READ_ONLY" in str(excinfo.value)


# ===========================================================================
# Wire-format pinning — capture HTTP layer, assert canonical pattern
# ===========================================================================


def _spy_client_http(client: Any) -> AsyncMock:
    """Wrap ``client._client.request`` so we can inspect the last call.

    Returns the AsyncMock that captures kwargs; the real httpx client
    is still used for the actual request so the CHR also sees it.
    """
    real_request = client._client.request
    captured: list[Any] = []

    async def _spy(*args: Any, **kwargs: Any) -> Any:
        captured.append((args, kwargs))
        return await real_request(*args, **kwargs)

    spy = AsyncMock(side_effect=_spy)
    spy.captured = captured  # type: ignore[attr-defined]
    client._client.request = spy
    return spy


class TestWireFormatPinning:
    """Capture the exact method+path+body the client emits when talking
    to the real CHR.  These tests would have caught commit ``ea150e8``'s
    regression directly — they assert the canonical RouterOS pattern
    that real CHR accepts.
    """

    @pytest.mark.asyncio
    async def test_add_uses_put_on_menu_path(
        self, chr_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        )
        spy = _spy_client_http(chr_client)

        marker = f"freesdn-ci-wire-{uuid.uuid4()}"
        created_id: str | None = None
        try:
            await chr_client.add_firewall_filter_rule(
                {"chain": "forward", "action": "accept", "comment": marker},
                force=True,
            )
            assert spy.captured, "no HTTP request captured"
            method, path = spy.captured[-1][0][0], spy.captured[-1][0][1]
            assert method == "PUT"
            assert path == "/rest/ip/firewall/filter"

            found = await _find_filter_rule_by_comment(chr_client, marker)
            if found:
                created_id = found[".id"]
        finally:
            await _safe_delete_filter_rule(chr_client, created_id or "")

    @pytest.mark.asyncio
    async def test_update_uses_post_set_with_id_in_body(
        self, chr_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        )

        marker = f"freesdn-ci-wire-update-{uuid.uuid4()}"
        created_id: str | None = None
        try:
            await chr_client.add_firewall_filter_rule(
                {"chain": "forward", "action": "accept", "comment": marker},
                force=True,
            )
            found = await _find_filter_rule_by_comment(chr_client, marker)
            assert found is not None
            created_id = found[".id"]

            # Now spy ONLY the update call (don't include the add above).
            spy = _spy_client_http(chr_client)
            await chr_client.update_firewall_filter_rule(
                created_id, {"action": "drop"}, force=True
            )
            assert spy.captured, "no update HTTP request captured"
            method, path = spy.captured[-1][0][0], spy.captured[-1][0][1]
            body = spy.captured[-1][1].get("json")
            assert method == "POST"
            assert path == "/rest/ip/firewall/filter/set"
            assert isinstance(body, dict)
            assert body.get(".id") == created_id
            assert body.get("action") == "drop"
        finally:
            await _safe_delete_filter_rule(chr_client, created_id or "")

    @pytest.mark.asyncio
    async def test_delete_uses_post_remove_with_id_in_body(
        self, chr_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "app.adapters.mikrotik.client._is_adapter_read_only",
            lambda: False,
        )

        marker = f"freesdn-ci-wire-delete-{uuid.uuid4()}"
        created_id: str | None = None
        try:
            await chr_client.add_firewall_filter_rule(
                {"chain": "forward", "action": "accept", "comment": marker},
                force=True,
            )
            found = await _find_filter_rule_by_comment(chr_client, marker)
            assert found is not None
            created_id = found[".id"]

            spy = _spy_client_http(chr_client)
            await chr_client.delete_firewall_filter_rule(
                created_id, force=True
            )
            assert spy.captured, "no delete HTTP request captured"
            method, path = spy.captured[-1][0][0], spy.captured[-1][0][1]
            body = spy.captured[-1][1].get("json")
            assert method == "POST"
            assert path == "/rest/ip/firewall/filter/remove"
            assert isinstance(body, dict)
            assert body.get(".id") == created_id
            # Cleanup was already part of the test — nothing else to do.
            created_id = None
        finally:
            await _safe_delete_filter_rule(chr_client, created_id or "")
