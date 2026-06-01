# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for VoipBackupContributor (enterprise backup chapter).

The test env has no live Postgres (the integration suite uses one), so
these tests drive the contributor against a hand-rolled
``FakeAsyncSession`` that:
  - returns queued results from ``execute(...).scalars().all()`` in call
    order, and
  - serves ``get(model, pk)`` from a dict, records ``add(...)``, no-ops
    ``flush()``.

What we verify:
  - secret redaction (recursive, drops not masks, keeps non-secrets)
  - collect() produces the right payload shape + counts + EXCLUDES
    secrets (the *_enc columns + voicemail_pin + settings secret keys)
  - restore() honours tenant guards (PBX/template site must be in org),
    FK ordering (extensions need a restored PBX), nullable-FK nulling
    (extension.user_id pointing at a missing user), blocked fields,
    dry-run-no-write, and the per-resource counts
"""

from __future__ import annotations

from collections import deque
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.modules.voip.backup import VoipBackupContributor, _redact
from app.services.backup_contributors import (
    BackupContributor,
    ContributorPayload,
)


# ── fake async session ──────────────────────────────────────────────────


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> "_Result":
        return self

    def all(self) -> list[Any]:
        return self._rows


class FakeAsyncSession:
    """Minimal async session double. ``execute`` pops queued results in
    FIFO order; ``get`` serves from a dict; ``add`` records; ``flush``
    is a no-op."""

    def __init__(
        self,
        *,
        execute_results: list[list[Any]] | None = None,
        store: dict[tuple, Any] | None = None,
    ) -> None:
        self._execute_q: deque[list[Any]] = deque(execute_results or [])
        self._store = store or {}
        self.added: list[Any] = []
        self.flush_count = 0

    async def execute(self, _query: Any) -> _Result:
        rows = self._execute_q.popleft() if self._execute_q else []
        return _Result(rows)

    async def get(self, model_cls: type, pk: Any) -> Any:
        return self._store.get((model_cls.__name__, str(pk)))

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flush_count += 1


# ── redaction ────────────────────────────────────────────────────────────


class TestRedact:
    def test_drops_top_level_secret_keys(self) -> None:
        out = _redact({"server": "sip.x", "web_password": "p", "api_key": "k"})
        assert out == {"server": "sip.x"}

    def test_recurses_into_nested_dicts(self) -> None:
        out = _redact({"sip": {"host": "h", "sip_password": "p"}})
        assert out == {"sip": {"host": "h"}}

    def test_recurses_into_lists_of_dicts(self) -> None:
        # PBX admin_users / line_key_settings nest dicts inside lists.
        out = _redact({
            "admin_users": [
                {"user": "a", "secret": "s1"},
                {"user": "b", "password": "s2", "role": "ops"},
            ],
        })
        assert out == {
            "admin_users": [{"user": "a"}, {"user": "b", "role": "ops"}],
        }

    def test_case_insensitive(self) -> None:
        out = _redact({"Web_Password": "p", "API_KEY": "k", "Name": "ok"})
        assert out == {"Name": "ok"}

    def test_passes_through_scalars_and_empty(self) -> None:
        assert _redact("string") == "string"
        assert _redact(42) == 42
        assert _redact(None) is None
        assert _redact({}) == {}
        assert _redact([]) == []


# ── protocol compliance ─────────────────────────────────────────────────


def test_satisfies_protocol() -> None:
    c = VoipBackupContributor()
    assert isinstance(c, BackupContributor)
    assert c.contributor_id == "voip"
    assert c.schema_version == "1.0.0"
    assert c.depends_on == ("core",)  # FK ordering after core
    assert c.default_included is True


# ── collect ──────────────────────────────────────────────────────────────


def _pbx_row(**kw):
    base = dict(
        id=uuid4(), site_id=uuid4(), name="HQ PBX", description=None,
        pbx_type="freepbx", ip_address="10.0.0.5", api_port=443, sip_port=5060,
        is_active=True, api_client_id="client-abc",
        tls_verify_disabled_acknowledged=False,
        settings={"timezone": "UTC", "web_password": "SHOULD-NOT-EXPORT"},
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _ext_row(pbx_id, **kw):
    base = dict(
        id=uuid4(), pbx_id=pbx_id, user_id=None,
        extension_number="1001", display_name="Reception",
        caller_id_name="Front Desk", caller_id_number="1001",
        voicemail_enabled=True, is_active=True,
        settings={"vm_email": "a@x.test"},
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _rg_row(pbx_id, **kw):
    base = dict(
        id=uuid4(), pbx_id=pbx_id, name="Support", description=None,
        group_number="600", ring_strategy="ringall", ring_time=20,
        members=["ext1", "ext2"], is_active=True, settings={},
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _ct_row(**kw):
    base = dict(
        id=uuid4(), site_id=uuid4(), name="GRP26xx", description=None,
        vendor="grandstream", model_pattern="GRP26*", is_default=True,
        sip_settings={"transport": "tls"}, network_settings={"vlan_id": 10},
        provisioning_settings={"server_url": "https://prov"},
        feature_settings={"timezone": "UTC", "admin_password": "LEAK"},
        line_key_settings=[{"index": 1, "label": "L1"}],
        raw_overrides={}, firmware_version="1.0.5.2",
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestCollect:
    @pytest.mark.asyncio
    async def test_collect_full_shape_and_counts(self) -> None:
        org = uuid4()
        pbx = _pbx_row()
        ext = _ext_row(pbx.id)
        rg = _rg_row(pbx.id)
        ct = _ct_row()
        # Call order in collect(): pbx, extensions, ring_groups, config_templates
        session = FakeAsyncSession(execute_results=[[pbx], [ext], [rg], [ct]])

        payload = await VoipBackupContributor().collect(session, org, {})

        assert isinstance(payload, ContributorPayload)
        assert payload.schema_version == "1.0.0"
        assert payload.counts == {
            "pbx": 1, "extensions": 1, "ring_groups": 1, "config_templates": 1,
        }
        assert payload.metadata["secrets_excluded"] is True

    @pytest.mark.asyncio
    async def test_collect_excludes_pbx_secrets(self) -> None:
        org = uuid4()
        pbx = _pbx_row(settings={"timezone": "UTC", "web_password": "LEAK",
                                 "ami_secret": "LEAK2"})
        session = FakeAsyncSession(execute_results=[[pbx], [], [], []])

        payload = await VoipBackupContributor().collect(session, org, {})

        exported = payload.data["pbx"][0]
        # No *_enc fields are ever serialized.
        for k in exported:
            assert not k.endswith("_enc"), f"{k} leaked into backup"
        # Secret keys stripped from settings.
        assert "web_password" not in exported["settings"]
        assert "ami_secret" not in exported["settings"]
        assert exported["settings"]["timezone"] == "UTC"
        # api_client_id (opaque, not secret) IS carried.
        assert exported["api_client_id"] == "client-abc"

    @pytest.mark.asyncio
    async def test_collect_excludes_voicemail_pin(self) -> None:
        org = uuid4()
        pbx = _pbx_row()
        ext = _ext_row(pbx.id)  # _ext_row never includes voicemail_pin
        session = FakeAsyncSession(execute_results=[[pbx], [ext], [], []])

        payload = await VoipBackupContributor().collect(session, org, {})

        exported_ext = payload.data["extensions"][0]
        assert "voicemail_pin" not in exported_ext
        # The non-secret voicemail_enabled flag IS carried.
        assert exported_ext["voicemail_enabled"] is True

    @pytest.mark.asyncio
    async def test_collect_redacts_config_template_admin_password(self) -> None:
        org = uuid4()
        ct = _ct_row(feature_settings={"timezone": "UTC",
                                       "admin_password": "LEAK"})
        # No PBX → ext/rg queries are skipped; only pbx + config_templates
        # execute calls fire.
        session = FakeAsyncSession(execute_results=[[], [ct]])

        payload = await VoipBackupContributor().collect(session, org, {})

        feat = payload.data["config_templates"][0]["feature_settings"]
        assert "admin_password" not in feat
        assert feat["timezone"] == "UTC"

    @pytest.mark.asyncio
    async def test_collect_no_pbx_skips_child_queries(self) -> None:
        """When the org has no PBX, extensions + ring_groups queries are
        skipped entirely (only pbx + config_templates execute). The
        FakeSession is given exactly 2 results; if the contributor tried
        a 3rd/4th child query it would get [] and still work, but we
        assert the counts come out empty."""
        org = uuid4()
        session = FakeAsyncSession(execute_results=[[], []])  # pbx, config_templates

        payload = await VoipBackupContributor().collect(session, org, {})

        assert payload.counts == {
            "pbx": 0, "extensions": 0, "ring_groups": 0, "config_templates": 0,
        }


# ── restore ──────────────────────────────────────────────────────────────


class TestRestore:
    def _payload(self, data: dict[str, Any]) -> ContributorPayload:
        return ContributorPayload(
            schema_version="1.0.0", counts={}, data=data, metadata={},
        )

    @pytest.mark.asyncio
    async def test_restore_rejects_cross_tenant_pbx(self) -> None:
        """A PBX whose site_id is NOT in the caller's org is rejected as
        cross-tenant and surfaced as a warning."""
        org = uuid4()
        org_site = uuid4()
        foreign_site = uuid4()
        pbx_id = uuid4()

        # execute results: [1] org site ids
        session = FakeAsyncSession(execute_results=[[org_site]])

        data = {
            "pbx": [{"id": str(pbx_id), "site_id": str(foreign_site),
                     "name": "Evil PBX", "ip_address": "1.2.3.4"}],
            "extensions": [], "ring_groups": [], "config_templates": [],
        }
        result = await VoipBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )

        assert result.skipped["pbx"] == 1
        assert result.created["pbx"] == 0
        assert any("cross-tenant" in w for w in result.warnings)
        # Nothing inserted.
        assert session.added == []

    @pytest.mark.asyncio
    async def test_restore_inserts_valid_pbx_and_extension(self) -> None:
        org = uuid4()
        site = uuid4()
        pbx_id = uuid4()
        ext_id = uuid4()

        # execute results: [1] org site ids
        session = FakeAsyncSession(execute_results=[[site]])

        data = {
            "pbx": [{"id": str(pbx_id), "site_id": str(site),
                     "name": "HQ", "ip_address": "10.0.0.5"}],
            "extensions": [{"id": str(ext_id), "pbx_id": str(pbx_id),
                            "extension_number": "1001",
                            "display_name": "Reception"}],
            "ring_groups": [], "config_templates": [],
        }
        result = await VoipBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )

        assert result.created["pbx"] == 1
        assert result.created["extensions"] == 1
        # Two model instances were added (PBX + Extension).
        assert len(session.added) == 2

    @pytest.mark.asyncio
    async def test_restore_skips_orphan_extension(self) -> None:
        """An extension whose pbx_id was NOT restored (orphan) is
        skipped, not inserted with a dangling FK."""
        org = uuid4()
        site = uuid4()
        good_pbx = uuid4()
        missing_pbx = uuid4()

        session = FakeAsyncSession(execute_results=[[site]])

        data = {
            "pbx": [{"id": str(good_pbx), "site_id": str(site),
                     "name": "HQ", "ip_address": "10.0.0.5"}],
            "extensions": [{"id": str(uuid4()), "pbx_id": str(missing_pbx),
                            "extension_number": "9999",
                            "display_name": "Orphan"}],
            "ring_groups": [], "config_templates": [],
        }
        result = await VoipBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )

        assert result.created["pbx"] == 1
        assert result.created["extensions"] == 0
        assert result.skipped["extensions"] == 1
        assert any("orphan" in w.lower() for w in result.warnings)

    @pytest.mark.asyncio
    async def test_restore_nulls_dangling_user_fk(self) -> None:
        """extension.user_id pointing at a user NOT in this org must be
        nulled, not cause an FK violation."""
        org = uuid4()
        site = uuid4()
        pbx_id = uuid4()
        valid_user = uuid4()
        ghost_user = uuid4()

        # execute results: [1] org sites, [2] valid user ids (lazy)
        session = FakeAsyncSession(execute_results=[[site], [valid_user]])

        data = {
            "pbx": [{"id": str(pbx_id), "site_id": str(site),
                     "name": "HQ", "ip_address": "10.0.0.5"}],
            "extensions": [{"id": str(uuid4()), "pbx_id": str(pbx_id),
                            "user_id": str(ghost_user),
                            "extension_number": "1001",
                            "display_name": "Reception"}],
            "ring_groups": [], "config_templates": [],
        }
        await VoipBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )

        # The Extension instance that was added must have user_id=None.
        ext_instances = [
            o for o in session.added
            if type(o).__name__ == "Extension"
        ]
        assert len(ext_instances) == 1
        assert ext_instances[0].user_id is None

    @pytest.mark.asyncio
    async def test_restore_dry_run_writes_nothing(self) -> None:
        org = uuid4()
        site = uuid4()
        session = FakeAsyncSession(execute_results=[[site]])

        data = {
            "pbx": [{"id": str(uuid4()), "site_id": str(site),
                     "name": "HQ", "ip_address": "10.0.0.5"}],
            "extensions": [], "ring_groups": [], "config_templates": [],
        }
        result = await VoipBackupContributor().restore(
            session, org, self._payload(data), dry_run=True, options={},
        )

        # Counted as created in the report, but NOTHING added to the session.
        assert result.created["pbx"] == 1
        assert result.status == "dry_run_ok"
        assert session.added == []

    @pytest.mark.asyncio
    async def test_restore_existing_skipped_without_overwrite(self) -> None:
        """A PBX whose id already exists is skipped when
        overwrite_existing is False (the default)."""
        from app.modules.voip.models import PBX

        org = uuid4()
        site = uuid4()
        pbx_id = uuid4()
        existing = SimpleNamespace(id=pbx_id, name="OLD")

        session = FakeAsyncSession(
            execute_results=[[site]],
            store={("PBX", str(pbx_id)): existing},
        )

        data = {
            "pbx": [{"id": str(pbx_id), "site_id": str(site),
                     "name": "NEW", "ip_address": "10.0.0.5"}],
            "extensions": [], "ring_groups": [], "config_templates": [],
        }
        result = await VoipBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )

        assert result.created["pbx"] == 0
        assert result.skipped["pbx"] == 1
        # The existing row was NOT mutated (overwrite=False).
        assert existing.name == "OLD"
        assert session.added == []

    @pytest.mark.asyncio
    async def test_restore_overwrite_updates_existing(self) -> None:
        from app.modules.voip.models import PBX

        org = uuid4()
        site = uuid4()
        pbx_id = uuid4()
        existing = SimpleNamespace(id=pbx_id, name="OLD", ip_address="0.0.0.0")

        session = FakeAsyncSession(
            execute_results=[[site]],
            store={("PBX", str(pbx_id)): existing},
        )

        data = {
            "pbx": [{"id": str(pbx_id), "site_id": str(site),
                     "name": "NEW", "ip_address": "10.0.0.5"}],
            "extensions": [], "ring_groups": [], "config_templates": [],
        }
        result = await VoipBackupContributor().restore(
            session, org, self._payload(data),
            dry_run=False, options={"overwrite_existing": True},
        )

        assert result.updated["pbx"] == 1
        # The existing row WAS mutated in place.
        assert existing.name == "NEW"
        assert existing.ip_address == "10.0.0.5"
