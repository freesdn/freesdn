"""
Integration tests — plugin runtime end-to-end.

Exercises the install → start_for_org → emit-event → handler-fires path
against real Postgres + Redis + the actual sandboxed import / SDK
context wiring. The unit suite under ``tests/plugins/`` mocks the loader
internals; this suite runs the real code with a live DB.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from tests_integration._plugin_helpers import make_plugin_zip


pytestmark = pytest.mark.asyncio


def _get_received_list(instance: Any) -> list:
    """Return the EchoPlugin class-level ``received`` list.

    Tests run outside the plugin sandbox so ``type(instance)`` works
    here even though the plugin itself can't use it.
    """
    return type(instance).received  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Per-test plugin install dir + loader
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def plugin_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A fresh PluginLoader rooted at a per-test temp dir.

    Forces the loader to install plugins into a tmp directory so tests
    do not pollute /data/plugins on the host. Resets the singleton's
    in-memory state between tests.
    """
    install_root = tmp_path / "plugins"
    install_root.mkdir()
    monkeypatch.setenv("PLUGIN_DIR", str(install_root))

    from app.plugins import loader as loader_mod

    # Patch the module-level constant the singleton was constructed with
    monkeypatch.setattr(loader_mod, "PLUGIN_DIR", install_root, raising=False)

    instance = loader_mod.PluginLoader()
    instance.plugin_dir = install_root  # public attr used in install_plugin

    yield instance

    # Best-effort cleanup of any installed plugin directories
    for item in list(install_root.iterdir()):
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
        except OSError:
            pass


@pytest_asyncio.fixture
async def echo_org_id(integration_db: Any, super_admin: dict[str, Any]) -> UUID:
    """An organization the plugin can be started against.

    The wizard creates the super_admin with ``organization_id=None``,
    so we insert a dedicated org for plugin lifecycle tests.
    """
    from app.models.core import Organization

    org = Organization(
        id=uuid4(),
        name="Echo Test Org",
        slug=f"echo-test-{uuid4().hex[:8]}",
        contact_email="echo@example.com",
    )
    integration_db.add(org)
    await integration_db.commit()
    await integration_db.refresh(org)
    return org.id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_plugin_install_creates_db_record(
    plugin_loader: Any, integration_db: Any, super_admin: dict[str, Any]
) -> None:
    """install_plugin parses the manifest, lays down files, and writes
    an InstalledPlugin row that subsequent code can find."""
    from app.models.plugins import InstalledPlugin
    from sqlalchemy import select

    zip_bytes = make_plugin_zip(plugin_id="echo-install-test")
    installed = await plugin_loader.install_plugin(
        source=zip_bytes,
        db=integration_db,
        installed_by_id=UUID(super_admin["user_id"]),
    )
    await integration_db.commit()

    assert installed.plugin_id == "echo-install-test"
    assert installed.version == "1.0.0"

    # Round-trip via DB to confirm the row was actually written
    row = await integration_db.scalar(
        select(InstalledPlugin).where(
            InstalledPlugin.plugin_id == "echo-install-test"
        )
    )
    assert row is not None
    assert row.is_active is True
    assert row.status == "installed"
    assert (Path(plugin_loader.plugin_dir) / "echo-install-test").exists()


async def test_plugin_start_for_org_initializes_context(
    plugin_loader: Any,
    integration_db: Any,
    super_admin: dict[str, Any],
    echo_org_id: UUID,
) -> None:
    """start_for_org loads the plugin, builds the SDK context, and
    tracks the (plugin_id, org_id) pair in ``_active``."""
    zip_bytes = make_plugin_zip(plugin_id="echo-start-test")
    await plugin_loader.install_plugin(
        source=zip_bytes,
        db=integration_db,
        installed_by_id=UUID(super_admin["user_id"]),
    )
    await integration_db.commit()

    instance = await plugin_loader.start_for_org(
        "echo-start-test", echo_org_id, integration_db
    )

    assert instance is not None
    assert instance.ctx is not None, "self.ctx must be set after start_for_org"
    assert instance.ctx.organization_id == echo_org_id
    assert ("echo-start-test", echo_org_id) in plugin_loader._active


async def test_plugin_start_is_idempotent(
    plugin_loader: Any,
    integration_db: Any,
    super_admin: dict[str, Any],
    echo_org_id: UUID,
) -> None:
    """Calling start_for_org twice returns the same running instance,
    not a second one (lifecycle invariant)."""
    zip_bytes = make_plugin_zip(plugin_id="echo-idempotent")
    await plugin_loader.install_plugin(
        source=zip_bytes,
        db=integration_db,
        installed_by_id=UUID(super_admin["user_id"]),
    )
    await integration_db.commit()

    a = await plugin_loader.start_for_org(
        "echo-idempotent", echo_org_id, integration_db
    )
    b = await plugin_loader.start_for_org(
        "echo-idempotent", echo_org_id, integration_db
    )
    assert a is b, "start_for_org must be idempotent for (plugin, org) pairs"


async def test_plugin_event_subscription_fires(
    plugin_loader: Any,
    integration_db: Any,
    super_admin: dict[str, Any],
    echo_org_id: UUID,
) -> None:
    """Manifest event_subscriptions actually wire into the event_bus.

    Install a plugin that subscribes to ``device.offline``, start it,
    publish an event, and assert the plugin's on_event handler ran.
    """
    from app.core.events import Event, event_bus, get_event_bus

    zip_bytes = make_plugin_zip(
        plugin_id="echo-events",
        event_subscriptions=["device.offline"],
    )
    await plugin_loader.install_plugin(
        source=zip_bytes,
        db=integration_db,
        installed_by_id=UUID(super_admin["user_id"]),
    )
    await integration_db.commit()

    instance = await plugin_loader.start_for_org(
        "echo-events", echo_org_id, integration_db
    )

    # Reset class-level trace from any prior test runs in this module
    _get_received_list(instance).clear()

    # Verify the bus actually has a subscription for our pattern. ``event_bus`` is
    # a lazy shim that forwards attribute access to the real singleton, so reach
    # the underlying EventBus via get_event_bus() (the old ``event_bus._instance``
    # attribute no longer exists — the shim would forward it and AttributeError).
    bus_inst = get_event_bus()
    assert bus_inst is not None
    subs = bus_inst._subscriptions
    assert any(
        any(sub.pattern == "device.offline" for sub in patterns)
        for patterns in subs.values()
    ), f"plugin did not register a subscription on the bus; subs={list(subs.keys())}"

    matching_subs = [
        sub for patterns in subs.values() for sub in patterns
        if sub.matches("device.offline")
    ]
    print(f"\n[DEBUG] matching_subs={len(matching_subs)} bus._redis={bus_inst._redis!r}")

    # Do NOT connect Redis — when ``event_bus._redis is None`` the publish
    # path falls through to ``_dispatch_local`` which iterates the in-process
    # subscription registry. This is exactly what we want to test (the
    # ``bind_event_subscriptions`` → ``event_bus.subscribe`` wiring).
    # The Redis-pub/sub-then-local-listener path is exercised by the live
    # docker stack, not by this unit-of-integration test.
    await event_bus.publish(
        Event(
            event_type="device.offline",
            payload={"device_id": "test-device-1", "reason": "ping_timeout"},
            source="integration-test",
            organization_id=str(echo_org_id),
        )
    )

    received = _get_received_list(instance)
    assert any(
        evt_type == "device.offline" for evt_type, _ in received
    ), f"plugin did not receive device.offline event; got {received!r}"


async def test_plugin_stop_for_org_clears_active(
    plugin_loader: Any,
    integration_db: Any,
    super_admin: dict[str, Any],
    echo_org_id: UUID,
) -> None:
    """stop_for_org must remove the (plugin_id, org_id) entry from _active."""
    zip_bytes = make_plugin_zip(plugin_id="echo-stop")
    await plugin_loader.install_plugin(
        source=zip_bytes,
        db=integration_db,
        installed_by_id=UUID(super_admin["user_id"]),
    )
    await integration_db.commit()

    await plugin_loader.start_for_org(
        "echo-stop", echo_org_id, integration_db
    )
    assert ("echo-stop", echo_org_id) in plugin_loader._active

    stopped = await plugin_loader.stop_for_org(
        "echo-stop", echo_org_id, integration_db
    )
    assert stopped is True
    assert ("echo-stop", echo_org_id) not in plugin_loader._active

    # Stopping again is a no-op (returns False)
    stopped_again = await plugin_loader.stop_for_org(
        "echo-stop", echo_org_id, integration_db
    )
    assert stopped_again is False
