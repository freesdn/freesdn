# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Foundation tests for the enterprise backup chapter:

  - ``BackupContributor`` protocol + duck-typing
  - ``BackupContributorRegistry`` registration + duplicate rejection +
    topological iteration + cycle detection + unknown-dep detection +
    module-registry discovery
  - ``version`` strict-semver compatibility + descriptive errors
  - ``manifest`` legacy-v1 detection + wrap-as-archive backwards-compat

Concrete contributors (Core, VoIP, Cameras, Firewall) land in their
own test files in Phases 2-5. These tests pin the foundation against
silent regression of the abstract contracts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.services.backup_contributors import (
    BackupArchive,
    BackupContributor,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    ContributorPayload,
    CyclicDependencyError,
    DuplicateContributorError,
    InvalidSchemaVersion,
    MigratingContributor,
    RestoreResult,
    UnknownDependencyError,
    describe_mismatch,
    get_registry,
    is_compatible,
    is_legacy_v1_payload,
    parse,
    reset_registry_for_tests,
    wrap_legacy_v1_as_archive,
)


# ── Test helpers ────────────────────────────────────────────────────────


@dataclass
class _Stub:
    """Minimal concrete contributor for registry tests. Doesn't touch
    the DB — collect/restore return canned shapes. Real contributors
    live in their respective module test files."""
    contributor_id: str
    schema_version: str = "1.0.0"
    depends_on: tuple[str, ...] = ()
    default_included: bool = True
    _collected: ContributorPayload = field(
        default_factory=lambda: ContributorPayload(
            schema_version="1.0.0", counts={}, data={},
        ),
    )

    async def collect(self, session, organization_id, options):
        return self._collected

    async def restore(self, session, organization_id, payload, *, dry_run, options):
        return RestoreResult(contributor_id=self.contributor_id, status="ok")


# ── version: strict semver gate (style: refuse silent corruption) ──


class TestVersionGate:
    @pytest.mark.parametrize("v", ["1.0.0", "0.1.0", "2.4.7", "10.20.30"])
    def test_parse_accepts_strict_semver(self, v: str) -> None:
        major, minor, patch = parse(v)
        assert (major, minor, patch) == tuple(int(p) for p in v.split("."))

    @pytest.mark.parametrize(
        "bad",
        [
            "1.0",           # missing patch
            "1.0.0.0",       # four segments
            "1.0.0-beta",    # pre-release — deliberately rejected
            "1.0.0+abc",     # build metadata — rejected
            "v1.0.0",        # leading 'v'
            "1.0.x",         # non-numeric
            "",              # empty
            "main",          # not even close
        ],
    )
    def test_parse_rejects_non_semver(self, bad: str) -> None:
        with pytest.raises(InvalidSchemaVersion):
            parse(bad)

    def test_same_major_is_compatible(self) -> None:
        assert is_compatible("1.0.0", "1.0.0")
        assert is_compatible("1.0.0", "1.4.7")  # code newer minor
        assert is_compatible("1.5.2", "1.0.0")  # code older minor

    def test_different_major_is_incompatible(self) -> None:
        # Code newer major (upgrade across major) — refused.
        assert not is_compatible("1.5.7", "2.0.0")
        # Code older major (downgrade) — refused.
        assert not is_compatible("2.0.0", "1.5.7")

    def test_describe_mismatch_explains_upgrade_path(self) -> None:
        msg = describe_mismatch("1.5.7", "2.0.0")
        # The error message must mention BOTH the migration hook AND
        # the operator-visible refusal so the catalog UI surfaces it
        # without further interpretation.
        assert "migrate_from" in msg
        assert "skipped" in msg

    def test_describe_mismatch_explains_downgrade_refused(self) -> None:
        msg = describe_mismatch("2.0.0", "1.5.7")
        assert "newer" in msg.lower()
        assert "skipped" in msg


# ── manifest: v1 legacy detection + wrap ─────────────────────────────────


class TestManifestLegacy:
    def test_v2_payload_is_not_legacy(self) -> None:
        # Smallest possible v2 payload — just needs a ``manifest`` key.
        assert not is_legacy_v1_payload({"manifest": {}, "contributors": {}})

    def test_v1_monolithic_is_legacy(self) -> None:
        # Pre-v2 monolithic shape: top-level sites/controllers/etc.
        legacy = {
            "sites": [{"id": "1"}, {"id": "2"}],
            "controllers": [],
            "devices": [{"id": "d1"}],
            "users": [],
            "automation": [],
        }
        assert is_legacy_v1_payload(legacy)

    def test_v1_partial_with_sites_only_still_detected(self) -> None:
        # Only ``sites`` present → still pre-v2 monolithic.
        assert is_legacy_v1_payload({"sites": []})

    def test_random_dict_is_not_legacy(self) -> None:
        # A dict without manifest AND without any known legacy keys
        # is NEITHER v1 nor v2 — neither path applies.
        assert not is_legacy_v1_payload({"foo": "bar"})

    def test_non_dict_is_not_legacy(self) -> None:
        assert not is_legacy_v1_payload([])  # type: ignore[arg-type]
        assert not is_legacy_v1_payload("string")  # type: ignore[arg-type]
        assert not is_legacy_v1_payload(None)  # type: ignore[arg-type]

    def test_enveloped_pre_v2_is_legacy(self) -> None:
        """REGRESSION (live-verification finding): the REAL pre-v2
        on-disk format is the ``collect_backup_data`` ENVELOPE
        ``{version, schema_version, created_at, freesdn_version,
        organization_id, data:{...}}`` — NOT a flat top-level
        sites/controllers dict. The original detector only matched the
        flat shape, so restoring a genuine pre-chapter .fsdn fell
        through to BackupArchive.model_validate and crashed."""
        envelope = {
            "version": "2.0",
            "schema_version": 2,
            "created_at": "2026-05-01T00:00:00Z",
            "freesdn_version": "2026.04.0",
            "organization_id": "org-1",
            "data": {"sites": [{"id": "s1"}], "devices": [{"id": "d1"}]},
        }
        assert is_legacy_v1_payload(envelope)

    def test_enveloped_pre_v2_wraps_to_inner_content(self) -> None:
        """wrap must unwrap the envelope's ``data`` so the core section
        is the FLAT content _restore_data reads, not the envelope."""
        envelope = {
            "version": "2.0", "schema_version": 2,
            "organization_id": "org-1",
            "data": {
                "sites": [{"id": "s1"}, {"id": "s2"}],
                "devices": [{"id": "d1"}],
            },
        }
        archive = wrap_legacy_v1_as_archive(
            envelope, backup_id=str(uuid4()),
            created_at=datetime.now(UTC), organization_id="org-1",
        )
        core = archive.contributors["core"]
        # The core section is the INNER content (flat), not the envelope.
        assert "sites" in core and "data" not in core
        assert core["sites"] == [{"id": "s1"}, {"id": "s2"}]
        # Counts come from the inner lists.
        entry = archive.manifest.contributors[0]
        assert entry.counts["sites"] == 2
        assert entry.counts["devices"] == 1

    def test_wrap_legacy_produces_valid_archive(self) -> None:
        legacy = {
            "sites": [{"id": "s1"}, {"id": "s2"}, {"id": "s3"}],
            "controllers": [{"id": "c1"}],
            "devices": [{"id": "d1"}, {"id": "d2"}],
            "users": [{"id": "u1"}],
            "automation_rules": [],
        }
        org = uuid4()
        backup_id = uuid4()
        now = datetime.now(UTC)

        archive = wrap_legacy_v1_as_archive(
            legacy,
            backup_id=str(backup_id),
            created_at=now,
            organization_id=str(org),
        )

        # The wrapper produces a valid BackupArchive Pydantic instance.
        assert isinstance(archive, BackupArchive)
        # Single contributor section, keyed ``"core"``, with the entire
        # legacy payload as its data.
        assert list(archive.contributors) == ["core"]
        assert archive.contributors["core"] == legacy
        # Counts pulled from the legacy lists for the manifest header.
        core_entry = archive.manifest.contributors[0]
        assert core_entry.id == "core"
        assert core_entry.schema_version == "1.0.0"
        assert core_entry.counts["sites"] == 3
        assert core_entry.counts["devices"] == 2
        # Provenance: the metadata flags this as a legacy v1 archive.
        assert core_entry.metadata.get("legacy_v1") is True


# ── registry: register + dedup + iteration order + cycle detection ─────


class TestRegistry:
    def setup_method(self) -> None:
        # Each test starts with a clean per-test registry. We do NOT
        # touch the module-level singleton — that's for the discovery
        # test below.
        self.reg = BackupContributorRegistry()

    def test_register_and_get(self) -> None:
        c = _Stub(contributor_id="x")
        self.reg.register(c)
        assert self.reg.get("x") is c
        assert "x" in self.reg
        assert len(self.reg) == 1

    def test_register_duplicate_id_rejected(self) -> None:
        self.reg.register(_Stub(contributor_id="x"))
        with pytest.raises(DuplicateContributorError, match="already registered"):
            self.reg.register(_Stub(contributor_id="x"))

    def test_register_non_protocol_rejected(self) -> None:
        # Something that doesn't implement the protocol (missing
        # ``collect`` method) is refused at registration time, not at
        # first use — fail fast.
        class Broken:
            contributor_id = "broken"
            schema_version = "1.0.0"
            depends_on = ()
            default_included = True
            # missing collect + restore

        with pytest.raises(TypeError, match="does not satisfy"):
            self.reg.register(Broken())  # type: ignore[arg-type]

    def test_unregister(self) -> None:
        self.reg.register(_Stub(contributor_id="x"))
        assert self.reg.unregister("x") is True
        assert self.reg.unregister("x") is False  # already gone
        assert "x" not in self.reg

    def test_get_or_raise(self) -> None:
        self.reg.register(_Stub(contributor_id="x"))
        assert self.reg.get_or_raise("x").contributor_id == "x"
        with pytest.raises(KeyError, match="no contributor"):
            self.reg.get_or_raise("missing")

    def test_topological_order_respects_dependencies(self) -> None:
        # Set up a small graph: voip depends on core; cameras depends
        # on core. Registration order is intentionally NOT the topo
        # order, so we know the sort is doing real work.
        self.reg.register(_Stub(contributor_id="voip", depends_on=("core",)))
        self.reg.register(_Stub(contributor_id="cameras", depends_on=("core",)))
        self.reg.register(_Stub(contributor_id="core"))

        ordered = [c.contributor_id for c in self.reg.topological_order()]
        # core must come first; the order of voip vs cameras is
        # deterministic (sorted by id within each level) so we can
        # assert exact equality.
        assert ordered == ["core", "cameras", "voip"]

    def test_topological_order_with_chained_deps(self) -> None:
        # core ← firewall ← network_policy
        # Plus an independent ``ai`` with no deps.
        self.reg.register(_Stub(
            contributor_id="network_policy", depends_on=("firewall",),
        ))
        self.reg.register(_Stub(contributor_id="firewall", depends_on=("core",)))
        self.reg.register(_Stub(contributor_id="ai"))
        self.reg.register(_Stub(contributor_id="core"))

        ordered = [c.contributor_id for c in self.reg.topological_order()]
        assert ordered.index("core") < ordered.index("firewall")
        assert ordered.index("firewall") < ordered.index("network_policy")
        # ``ai`` has no deps so it appears at the first level alongside
        # ``core``; deterministic alphabetic sort places ai before core.
        assert ordered.index("ai") < ordered.index("firewall")

    def test_cyclic_dependency_raises(self) -> None:
        # a → b → a: cycle of length 2.
        self.reg.register(_Stub(contributor_id="a", depends_on=("b",)))
        self.reg.register(_Stub(contributor_id="b", depends_on=("a",)))
        with pytest.raises(CyclicDependencyError, match="cycle"):
            self.reg.topological_order()

    def test_unknown_dependency_raises(self) -> None:
        self.reg.register(_Stub(contributor_id="x", depends_on=("ghost",)))
        with pytest.raises(UnknownDependencyError, match="ghost"):
            self.reg.topological_order()

    def test_singleton_accessor_isolated_for_tests(self) -> None:
        # The module-level singleton is reset between tests to avoid
        # state bleed.
        reset_registry_for_tests()
        reg1 = get_registry()
        reg1.register(_Stub(contributor_id="leaked"))
        assert "leaked" in get_registry()

        reset_registry_for_tests()
        # After reset, the next get_registry() returns a fresh empty one.
        assert "leaked" not in get_registry()
