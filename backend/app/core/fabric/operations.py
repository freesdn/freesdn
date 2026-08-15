# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — Operation & Event types (the "services" plane).

A single canonical representation of "a thing an app can do" (``Operation``) and
"a thing an app emits" (``EventSpec``), each tagged with the trust **tier** of
its provider. These types are deliberately transport-agnostic and additive: a
module/adapter/plugin *declares* them; the :class:`FabricRegistry` discovers
them; the Negotiator and Executor consume them.

Design notes
------------
* ``Operation`` is modeled on the existing ``AITool`` (``app/modules/ai/tools``)
  — ``input_schema`` is a JSON Schema, exactly like ``AITool.parameters`` — plus
  the staged-write binding (``write`` + ``feature``) so a write operation can be
  routed through ``AdapterStagingService`` rather than executed raw.
* ``produces`` / ``accepts`` carry media-types (``image/jpeg``, ``application/
  json``, ``text/plain``, the sentinel ``blob`` for any binary) so the Negotiator
  can match a source's output to a compatible target's input.
* ``tier`` is the trust provenance and drives the cross-tier safety rules:
  native operations are full-trust; plugin operations are SDK-bounded,
  permission-declared, and namespaced ``plugin.{id}.*``.

No behavior is wired here — this is the catalog vocabulary only.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class OperationTier(StrEnum):
    """Trust tier of the app that provides an operation/event."""

    NATIVE = "native"  # first-party in-tree module — full trust
    PLUGIN = "plugin"  # external app — SDK-bounded, permission-declared, namespaced


# Operation/event ids are dotted, lowercase, segment-structured. Native ids look
# like ``storage.pool.read``; plugin ids are forced to ``plugin.{id}.<verb>`` by
# the plugin bridge. Segments allow ``-`` because plugin ids may be hyphenated
# (``plugin.acme-monitoring.sync``). We validate shape only (not the ``plugin.``
# prefix here — the registry asserts that per-tier so one regex stays reusable).
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$")

#: Sentinel media-type meaning "any binary payload" (handed via the Artifact
#: Broker rather than inline JSON). Operations that move snapshots/clips/log
#: batches use this in ``produces`` / ``accepts``.
MEDIA_BLOB = "blob"


def validate_operation_id(op_id: str) -> str:
    """Return ``op_id`` if it is a well-formed dotted Fabric id, else raise."""
    if not _ID_PATTERN.match(op_id):
        raise ValueError(
            f"Invalid Fabric id {op_id!r}: must be dotted lowercase segments "
            "(e.g. 'storage.pool.read' or 'plugin.acme.sync')"
        )
    return op_id


def media_compatible(produced: Iterable[str], accepts: Iterable[str]) -> bool:
    """Can an operation that ``accepts`` these media-types consume an event/step
    that ``produced`` those media-types?

    This is the Negotiator's matchmaking primitive (used by the builder's
    "suggest compatible targets"):

    * An operation with **no** ``accepts`` needs no input artifact — it takes its
      params from the trigger payload via templating — so it is compatible with
      *any* source. (Empty ``accepts`` ⇒ always ``True``.)
    * An operation that DOES accept an artifact needs the source to actually
      produce one: a source producing NOTHING (``produced`` empty) can never feed
      it, so it is incompatible — even for a ``blob``-accepting op. (Without this
      the matchmaker recommends e.g. ``storage.store_blob`` for the artifact-less
      ``ingest.external``, and the staged write then 400s at sign-off with no blob.)
    * Otherwise the source must produce a media-type the operation accepts.
    * :data:`MEDIA_BLOB` ("any binary") is a wildcard on *either* side: an op that
      accepts ``blob`` takes any binary the source produces; a source that produces
      ``blob`` satisfies any binary accept.
    """
    acc = set(accepts)
    if not acc:
        return True
    prod = set(produced)
    if not prod:
        return False  # op requires an input artifact; this source produces none
    return MEDIA_BLOB in acc or MEDIA_BLOB in prod or bool(acc & prod)


@dataclass(frozen=True)
class Operation:
    """A normalized, invokable capability declared by an app.

    The single representation that the AI tool registry, the automation action
    handlers, the Negotiator, and the Distribution Engine all read.
    """

    id: str
    """Dotted id. Native: ``{module}.{verb}``; plugin: ``plugin.{id}.{verb}``."""

    title: str
    description: str = ""

    input_schema: dict[str, Any] = field(default_factory=dict)
    """JSON Schema for the invocation params (same shape as ``AITool.parameters``)."""

    produces: tuple[str, ...] = ()
    """Media-types this operation outputs (for negotiation). ``()`` = no payload."""

    accepts: tuple[str, ...] = ()
    """Media-types this operation can consume as an input artifact."""

    permission: str | None = None
    """FreeSDN permission required to invoke (enforced by the Negotiator/executor)."""

    write: bool = False
    """True ⇒ a device write; MUST be routed through the staged-change pipeline."""

    feature: str | None = None
    """Staging ``feature`` key used when ``write`` is True (else ``None``)."""

    handler: Callable[..., Any] | None = None
    """Direct callable for reads / safe ops. ``None`` for declaration-only or
    staged writes (the executor resolves those via the feature/applier)."""

    tier: OperationTier = OperationTier.NATIVE
    provider_id: str = ""
    """Module id (native) or plugin id (plugin) that declared this operation."""

    def __post_init__(self) -> None:
        validate_operation_id(self.id)
        if self.write and not self.feature:
            raise ValueError(f"Operation {self.id!r} is a write but declares no staging 'feature'")
        if self.write and not self.permission:
            # Every device-write capability MUST declare the RBAC grant the
            # negotiator will enforce — a permissionless write would otherwise
            # run for any Connection author (fail-closed contract).
            raise ValueError(f"Operation {self.id!r} is a write but declares no 'permission'")
        if self.tier is OperationTier.PLUGIN and not self.id.startswith("plugin."):
            raise ValueError(f"Plugin operation {self.id!r} must be namespaced 'plugin.<id>.*'")
        if self.tier is OperationTier.NATIVE and self.id.startswith("plugin."):
            raise ValueError(
                f"Native operation {self.id!r} must not use the reserved 'plugin.' namespace"
            )

    def to_catalog_dict(self) -> dict[str, Any]:
        """Serialize for the ``GET /fabric/catalog`` response (no handler)."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_schema,
            "produces": list(self.produces),
            "accepts": list(self.accepts),
            "permission": self.permission,
            "write": self.write,
            "feature": self.feature,
            "tier": self.tier.value,
            "provider_id": self.provider_id,
        }


@dataclass(frozen=True)
class EventSpec:
    """A normalized event an app emits — a Fabric trigger source."""

    event_type: str
    """Bus event type. Native: ``{domain}.{entity}.{action}``; plugin:
    ``plugin.{id}.{type}``."""

    title: str
    description: str = ""

    payload_schema: dict[str, Any] = field(default_factory=dict)
    """JSON Schema for the event payload (so the Negotiator can map fields)."""

    produces: tuple[str, ...] = ()
    """Media-type of any artifact the event references (e.g. ``image/jpeg`` for a
    motion event that carries a snapshot handle). ``()`` = pure data event."""

    tier: OperationTier = OperationTier.NATIVE
    provider_id: str = ""

    def __post_init__(self) -> None:
        validate_operation_id(self.event_type)
        if self.tier is OperationTier.PLUGIN and not self.event_type.startswith("plugin."):
            raise ValueError(f"Plugin event {self.event_type!r} must be namespaced 'plugin.<id>.*'")
        if self.tier is OperationTier.NATIVE and self.event_type.startswith("plugin."):
            raise ValueError(
                f"Native event {self.event_type!r} must not use the reserved 'plugin.' namespace"
            )

    def to_catalog_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "payload_schema": self.payload_schema,
            "produces": list(self.produces),
            "tier": self.tier.value,
            "provider_id": self.provider_id,
        }
