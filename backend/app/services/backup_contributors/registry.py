# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Contributor registry + dependency-ordered iteration.

The registry is a process-wide singleton (one per FastAPI process)
keyed by ``contributor_id``. Module authors register contributors
in two ways:

1. **Module-discovered (preferred)**: a ``BaseModule`` subclass
   exposes ``get_backup_contributor() -> BackupContributor | None``.
   The Backup service calls ``registry.discover_from_modules()`` on
   first use (and during lifespan startup) and walks the module
   registry, registering every contributor it finds.

2. **Explicit (testing + plugins)**: ``registry.register(contrib)``.
   Used by unit tests, by future plugin-provided contributors, and
   internally by the core contributor (which is registered by the
   Backup service itself, not a module).

Cycles in the dependency graph are detected at iteration time and
raise ``CyclicDependencyError`` with a helpful message.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from .protocol import BackupContributor

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class DuplicateContributorError(ValueError):
    """Raised on attempt to register a contributor whose ``contributor_id``
    is already taken. Modules MUST use unique ids."""


class CyclicDependencyError(ValueError):
    """Raised on attempt to iterate the registry when the contributor
    dependency graph contains a cycle. Carries the offending cycle
    in the message."""


class UnknownDependencyError(ValueError):
    """Raised on iteration when a contributor declares a dependency on
    an id that isn't registered. Either the dependency was renamed
    without updating ``depends_on``, or the module providing it isn't
    loaded in this deployment."""


class BackupContributorRegistry:
    """In-memory registry of backup contributors.

    Thread-unsafe by design (FastAPI is async single-event-loop). For
    the production lifecycle, ``discover_from_modules`` is called once
    during startup and again on demand if modules are hot-loaded.
    """

    def __init__(self) -> None:
        self._contributors: dict[str, BackupContributor] = {}

    # ── registration ──────────────────────────────────────────────────

    def register(self, contributor: BackupContributor) -> None:
        """Register a contributor. Raises ``DuplicateContributorError``
        if the id is already taken (modules MUST coordinate on ids)."""
        if not isinstance(contributor, BackupContributor):
            raise TypeError(
                f"{type(contributor).__name__} does not satisfy the "
                f"BackupContributor protocol (missing collect/restore/"
                f"contributor_id/schema_version/depends_on/default_included)"
            )
        cid = contributor.contributor_id
        if cid in self._contributors:
            existing = type(self._contributors[cid]).__name__
            incoming = type(contributor).__name__
            raise DuplicateContributorError(
                f"contributor_id {cid!r} already registered by {existing}; "
                f"refusing to overwrite with {incoming}. Either rename one "
                f"contributor, or call ``unregister({cid!r})`` first."
            )
        self._contributors[cid] = contributor
        logger.info(
            "Backup contributor registered: id=%s schema=%s depends_on=%s",
            cid,
            contributor.schema_version,
            contributor.depends_on,
        )

    def unregister(self, contributor_id: str) -> bool:
        """Remove a contributor. Returns True if it was registered.
        Primarily for unit tests; production registrations stick for
        the process lifetime."""
        return self._contributors.pop(contributor_id, None) is not None

    def clear(self) -> None:
        """Remove all contributors. Test-only — production code should
        never need to clear."""
        self._contributors.clear()

    # ── lookup ────────────────────────────────────────────────────────

    def get(self, contributor_id: str) -> BackupContributor | None:
        return self._contributors.get(contributor_id)

    def get_or_raise(self, contributor_id: str) -> BackupContributor:
        contrib = self._contributors.get(contributor_id)
        if contrib is None:
            raise KeyError(
                f"no contributor registered with id {contributor_id!r}; "
                f"registered: {sorted(self._contributors)}"
            )
        return contrib

    def all_ids(self) -> list[str]:
        return list(self._contributors)

    def __contains__(self, contributor_id: str) -> bool:
        return contributor_id in self._contributors

    def __len__(self) -> int:
        return len(self._contributors)

    # ── dependency-ordered iteration ──────────────────────────────────

    def topological_order(self) -> list[BackupContributor]:
        """Return contributors in an order that satisfies their
        ``depends_on`` declarations: a contributor X with
        ``depends_on=("core",)`` will appear AFTER ``core`` in the
        returned list.

        Used by the Backup service's restore loop so that, e.g., VoIP
        extensions (which FK to sites in the core schema) are restored
        AFTER the core contributor has created the sites.

        Raises:
          UnknownDependencyError: a contributor depends on an id that
            isn't registered.
          CyclicDependencyError: the dependency graph contains a cycle.

        Algorithm: Kahn's topological sort. Within each level (nodes
        with the same in-degree) we sort by contributor_id so the
        result is deterministic across runs — useful for tests and for
        operator-visible reports.
        """
        in_degree: dict[str, int] = defaultdict(int)
        # adjacency: id → list of ids that depend on it
        rev_edges: dict[str, list[str]] = defaultdict(list)

        for cid, contrib in self._contributors.items():
            for dep in contrib.depends_on:
                if dep not in self._contributors:
                    raise UnknownDependencyError(
                        f"contributor {cid!r} depends on {dep!r}, but "
                        f"no such contributor is registered. Registered: "
                        f"{sorted(self._contributors)}. Either load the "
                        f"module providing it, or drop the dependency."
                    )
                in_degree[cid] += 1
                rev_edges[dep].append(cid)

        # Start with nodes that have no dependencies.
        ready: deque[str] = deque(sorted(cid for cid in self._contributors if in_degree[cid] == 0))
        ordered: list[BackupContributor] = []

        while ready:
            cid = ready.popleft()
            ordered.append(self._contributors[cid])
            # Sort dependents for deterministic output.
            for dependent in sorted(rev_edges[cid]):
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    ready.append(dependent)

        if len(ordered) < len(self._contributors):
            # Cycle: the remaining nodes form one or more cycles.
            remaining = sorted(
                cid for cid in self._contributors if cid not in {c.contributor_id for c in ordered}
            )
            raise CyclicDependencyError(
                f"cycle in contributor dependency graph; cannot topologically "
                f"order. Remaining contributors involved in the cycle: "
                f"{remaining}. Inspect their ``depends_on`` declarations."
            )

        return ordered

    # ── module discovery ──────────────────────────────────────────────

    def discover_from_modules(self) -> int:
        """Walk the loaded module registry and register every
        contributor exposed via ``BaseModule.get_backup_contributor()``.

        Idempotent: already-registered contributors are silently
        skipped (logged at DEBUG). Returns the count of NEW
        contributors registered this call.

        Called from the Backup service's first-use path and from the
        FastAPI lifespan startup hook (idempotency makes both safe).
        """
        try:
            from app.modules.registry import module_registry
        except ImportError:
            logger.debug("module registry unavailable; no discovery")
            return 0

        count = 0
        for module in module_registry.modules.values():
            hook = getattr(module, "get_backup_contributor", None)
            if hook is None:
                continue
            try:
                contrib = hook()
            except Exception:
                logger.exception(
                    "module %r raised in get_backup_contributor; skipping",
                    getattr(module, "manifest", module),
                )
                continue
            if contrib is None:
                continue
            if contrib.contributor_id in self._contributors:
                logger.debug(
                    "contributor %s already registered; skipping",
                    contrib.contributor_id,
                )
                continue
            self.register(contrib)
            count += 1
        return count


# ── Singleton accessor (module-level, FastAPI-friendly) ───────────────


_global_registry: BackupContributorRegistry | None = None


def get_registry() -> BackupContributorRegistry:
    """Lazy module-level singleton. Mirrors the EventBus + adapter_pool
    patterns used elsewhere in the codebase."""
    global _global_registry
    if _global_registry is None:
        _global_registry = BackupContributorRegistry()
    return _global_registry


def reset_registry_for_tests() -> None:
    """TEST-ONLY: drop the singleton so a clean slate can be installed.
    Calling this from production code is a bug — log loudly if used."""
    global _global_registry
    if _global_registry is not None:
        logger.warning(
            "reset_registry_for_tests called — should only happen in tests",
        )
    _global_registry = None


__all__ = [
    "BackupContributorRegistry",
    "CyclicDependencyError",
    "DuplicateContributorError",
    "UnknownDependencyError",
    "get_registry",
    "reset_registry_for_tests",
]
