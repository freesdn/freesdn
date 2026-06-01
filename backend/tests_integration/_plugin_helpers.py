"""
Helpers for building minimal valid plugin ZIPs in-memory for tests.

Avoids checking large binary fixtures into the repo while still
exercising the real plugin loader pipeline (parse manifest, sandbox
import, register, on_install hook).
"""

from __future__ import annotations

import textwrap
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile


_DEFAULT_ENTRY_POINT = textwrap.dedent(
    '''\
    """Minimal test plugin used by integration tests."""

    from app.plugins.sdk import FreeSDNPlugin


    class EchoPlugin(FreeSDNPlugin):
        """Plugin that records every event it receives.

        Tests assert against ``EchoPlugin.received`` after firing an
        event through the bus.

        Note: the plugin sandbox blocks ``type()`` (no metaclass tricks
        allowed), so we reference the class by name from inside the
        method.
        """

        # Class-level so multiple instances share the trace (one per org)
        received: list = []  # populated as (event_type, payload) tuples

        async def on_event(self, event):
            payload = getattr(event, "payload", None)
            evt_type = getattr(event, "event_type", str(event))
            EchoPlugin.received.append((evt_type, payload))
    '''
)


def make_plugin_zip(
    *,
    plugin_id: str = "echo-plugin",
    name: str = "Echo Plugin",
    version: str = "1.0.0",
    class_name: str = "EchoPlugin",
    entry_point_src: str | None = None,
    event_subscriptions: list[str] | None = None,
    permissions: list[dict] | None = None,
) -> bytes:
    """Return the bytes of a valid plugin ZIP suitable for ``install_plugin``.

    Args:
        plugin_id: matches the ``id`` in the manifest. Must be unique
            across tests if installed against the same DB.
        event_subscriptions: list of event-type patterns the plugin
            subscribes to (e.g. ``["device.offline"]``).
        permissions: list of ``{"code": "...", "name": "...", "description": "..."}``
            entries declared in the manifest.
    """
    if event_subscriptions is None:
        event_subscriptions = []
    if permissions is None:
        permissions = []
    if entry_point_src is None:
        entry_point_src = _DEFAULT_ENTRY_POINT

    manifest_lines = [
        f"id: {plugin_id}",
        f"name: {name}",
        f"version: {version}",
        f"class_name: {class_name}",
        "entry_point: plugin.py",
        "description: Test plugin",
        'author: Integration Tests',
        "license: MIT",
        "min_core_version: 1.0.0",
    ]
    if event_subscriptions:
        manifest_lines.append("event_subscriptions:")
        for evt in event_subscriptions:
            manifest_lines.append(f"  - {evt}")
    if permissions:
        manifest_lines.append("permissions:")
        for p in permissions:
            manifest_lines.append(f"  - code: {p['code']}")
            manifest_lines.append(f"    name: {p.get('name', p['code'])}")
            if p.get("description"):
                manifest_lines.append(f"    description: {p['description']}")
    manifest_yaml = "\n".join(manifest_lines) + "\n"

    buf = BytesIO()
    with ZipFile(buf, "w", ZIP_DEFLATED) as zf:
        zf.writestr("plugin.yaml", manifest_yaml)
        zf.writestr("plugin.py", entry_point_src)
    return buf.getvalue()
