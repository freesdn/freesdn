# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A webhook template may only subscribe to events the platform publishes.

"Apply template" creates a real, enabled webhook from the template's event
list. Eleven of the names those templates used were never published by
anything (device.offline/online, discovery.complete, alert.created/escalated,
audit.login_failed, security.anomaly/ip_blocked, backup.started/complete/
failed, camera.motion/offline), so most templates produced a webhook that could
not fire. Their example payloads also showed a body shape no delivery has.

Same ratchet as the Integrations menu (test_integration_event_names), applied to
the templates; a ``prefix.*`` entry must match at least one published name.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.api.v1.endpoints.webhook_templates import WEBHOOK_TEMPLATES
from tests.api.test_integration_event_names import _published_event_names


def _published_by_fstring(prefix: str) -> bool:
    """``event_type=f"camera.alert.{kind}"``: a published family the literal scan misses."""
    app = pathlib.Path(__file__).resolve().parents[2] / "app"
    pattern = re.compile(r"event_type\s*=\s*f[\"']" + re.escape(prefix) + r"\{")
    return any(
        pattern.search(path.read_text(encoding="utf-8", errors="ignore"))
        for path in app.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def _template_ids() -> list[str]:
    return [t["id"] for t in WEBHOOK_TEMPLATES]


@pytest.mark.parametrize("template_id", _template_ids())
def test_every_template_event_is_published(template_id):
    published = _published_event_names()
    template = next(t for t in WEBHOOK_TEMPLATES if t["id"] == template_id)
    phantom = []
    for name in template["events"]:
        if name.endswith(".*"):
            prefix = name[:-1]
            if not (any(p.startswith(prefix) for p in published) or _published_by_fstring(prefix)):
                phantom.append(name)
        elif name not in published:
            phantom.append(name)
    assert not phantom, f"{template_id} subscribes to events nothing publishes: {phantom}"


@pytest.mark.parametrize("template_id", _template_ids())
def test_every_example_payload_has_the_shape_a_delivery_has(template_id):
    template = next(t for t in WEBHOOK_TEMPLATES if t["id"] == template_id)
    example = template["example_payload"]
    assert {"id", "event", "timestamp", "organization_id", "data"} <= set(example)
    assert example["event"].startswith(template["events"][0].rstrip("*"))
