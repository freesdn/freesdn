# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Withdrawing a plugin from the registry did nothing to anyone who already had it.

The sync loop only ever upserted. A plugin the registry DROPPED -- retired,
renamed, or pulled because it turned out to be harmful -- stayed listed and
installable for ever on every deployment that had synced it once. Withdrawal was
the only lever the project had over a bad plugin, and it reached exactly the
installs that had never fetched the catalogue.

Found by driving the marketplace install button end to end against the live
registry. Two plugins retired days earlier because they shadowed native
subsystems, ``notify-hub`` and ``ai-ops-tools``, were still on offer, and
``notify-hub`` installed cleanly on HTTP 201.

Reproduced and then fixed:

    BEFORE sync -- listed: 11, retired plugins still on offer: notify-hub, ai-ops-tools
    sync        -- "Synced 9 plugins from registry (0 skipped).
                    Withdrawn (no longer in the registry): ai-ops-tools, notify-hub"
    AFTER sync  -- listed: 9,  retired plugins still on offer: none
    install     -- HTTP 410, and the copy already installed is still running

The three properties below are each a decision, and the third is the one that
matters most: the registry decides what is on OFFER, the operator decides what
RUNS. An upstream index change must never stop production work.
"""

from __future__ import annotations

import inspect

import pytest


class _Row:
    """Stands in for a MarketplacePlugin row."""

    def __init__(self, plugin_id: str, status: str = "published"):
        self.plugin_id = plugin_id
        self.slug = plugin_id
        self.status = status
        self.name = plugin_id
        self.version = "1.0.0"


class _FakeSession:
    """Enough SQLAlchemy to run the real sync loop against an in-memory table."""

    def __init__(self, rows: list[_Row]):
        self.rows = rows
        self.added: list[object] = []
        self.deleted: list[object] = []

    async def execute(self, stmt, *a, **k):
        sql = str(stmt).upper()
        # An expanding ``notin_`` binds the whole collection under ONE key, so
        # a scalars-only sweep of .params sees an empty set and every row looks
        # stale. Flatten sequences too.
        values: list[str] = []
        for v in stmt.compile().params.values():
            if isinstance(v, str):
                values.append(v)
            elif isinstance(v, (list, tuple, set)):
                values.extend(x for x in v if isinstance(x, str))
        if "NOT IN" in sql:  # the de-list sweep
            seen = {v for v in values if v != "published"}
            matched = [r for r in self.rows if r.status == "published" and r.plugin_id not in seen]
        else:  # the per-entry upsert lookup
            matched = [r for r in self.rows if r.plugin_id in values]

        class _Result:
            def scalar_one_or_none(self_inner):
                return matched[0] if matched else None

            def scalars(self_inner):
                class _S:
                    def all(self_s):
                        return matched

                return _S()

        return _Result()

    def add(self, obj):
        self.added.append(obj)

    def delete(self, obj):
        self.deleted.append(obj)

    async def commit(self):
        pass

    async def flush(self):
        pass

    async def rollback(self):
        pass

    def begin_nested(self):
        class _Savepoint:
            async def __aenter__(self_inner):
                return self_inner

            async def __aexit__(self_inner, *exc):
                return False

        return _Savepoint()


class _User:
    id = None
    organization_id = None
    role = "super_admin"
    is_superuser = True

    def has_permission(self, _p):
        return True


def _catalog(*plugin_ids: str) -> dict:
    return {
        "plugins": [
            {
                "plugin_id": p,
                "slug": p,
                "name": p,
                "latest_version": "1.0.0",
                "download_url": "https://registry.freesdn.org/plugins/" + p + "-1.0.0.zip",
                "checksum_sha256": "0" * 64,
            }
            for p in plugin_ids
        ],
        "signature": "unused-the-verifier-is-stubbed",
    }


async def _sync(monkeypatch, catalog: dict, rows: list[_Row], *, remote: bool = True):
    from fastapi import HTTPException

    from app.api.v1.endpoints import marketplace as mp

    if remote:

        async def _ok(_url):
            return catalog

        monkeypatch.setattr(mp, "_fetch_registry_catalog", _ok)
    else:

        async def _dead(_url):
            raise HTTPException(status_code=400, detail="SSRF blocked: Cannot resolve hostname")

        monkeypatch.setattr(mp, "_fetch_registry_catalog", _dead)

    monkeypatch.setattr(mp, "_verify_catalog_signature", lambda _c: None)
    monkeypatch.setattr(mp, "is_unscoped_superuser", lambda _u: True)

    session = _FakeSession(rows)
    out = await mp.sync_marketplace(current_user=_User(), session=session)
    return out, session


# ── the fix ─────────────────────────────────────────────────────


async def test_a_plugin_the_registry_dropped_is_withdrawn(monkeypatch):
    """
    The bug, driven directly: a row present locally and absent from the fetched
    catalogue used to survive untouched and stay installable for ever.
    """
    rows = [_Row("netbox-sync"), _Row("notify-hub"), _Row("ai-ops-tools")]

    out, _ = await _sync(monkeypatch, _catalog("netbox-sync"), rows)

    assert sorted(out["withdrawn"]) == ["ai-ops-tools", "notify-hub"]
    assert {r.plugin_id: r.status for r in rows} == {
        "netbox-sync": "published",
        "notify-hub": "withdrawn",
        "ai-ops-tools": "withdrawn",
    }


async def test_the_operator_is_told_which_ones(monkeypatch):
    """A silent de-list is indistinguishable from a sync that lost entries."""
    rows = [_Row("netbox-sync"), _Row("notify-hub")]

    out, _ = await _sync(monkeypatch, _catalog("netbox-sync"), rows)

    assert "notify-hub" in out["message"]
    assert "withdraw" in out["message"].lower()


async def test_a_withdrawn_row_is_not_deleted(monkeypatch):
    """
    De-list, do not delete. Reviews, download counts and history are worth
    keeping, and a hard delete would take the row out from under anyone who
    happened to be reading its page.
    """
    rows = [_Row("notify-hub")]

    _, session = await _sync(monkeypatch, _catalog("netbox-sync"), rows)

    assert session.deleted == [], "a withdrawn plugin was deleted rather than de-listed"
    assert rows[0].plugin_id == "notify-hub", "the row is gone"


async def test_a_relisted_plugin_comes_back(monkeypatch):
    """
    ``status`` is deliberately stripped from every catalogue entry, so nothing
    in the upsert restores it. Without an explicit re-publish a plugin that the
    registry listed again would stay invisible for ever, with no way back short
    of editing the database.
    """
    rows = [_Row("netbox-sync", status="withdrawn")]

    out, _ = await _sync(monkeypatch, _catalog("netbox-sync"), rows)

    assert rows[0].status == "published", "a re-listed plugin stayed withdrawn"
    assert out["withdrawn"] == []


# ── what it must NOT do ─────────────────────────────────────────


async def test_the_seed_fallback_never_withdraws_anything(monkeypatch):
    """
    The bundled seed is a fallback for an unreachable registry, not an authority
    on what has been withdrawn. Reconciling against it would let a single failed
    fetch de-list every plugin of a private registry that was merely down.
    """
    rows = [_Row("some-private-plugin"), _Row("another-one")]

    out, _ = await _sync(monkeypatch, {}, rows, remote=False)

    assert out["used_seed"] is True, "this test is not exercising the seed path"
    assert out["withdrawn"] == [], "an unreachable registry de-listed a private catalogue"
    assert all(r.status == "published" for r in rows)


async def test_an_empty_catalogue_does_not_empty_the_marketplace(monkeypatch):
    """
    A registry serving a valid but empty catalogue -- a build accident, a bad
    deploy -- must not withdraw everything. Nothing seen means nothing to
    reconcile against, not "everything is gone".
    """
    rows = [_Row("netbox-sync"), _Row("hello-world")]

    out, _ = await _sync(monkeypatch, {"plugins": []}, rows)

    assert out["withdrawn"] == []
    assert all(r.status == "published" for r in rows)


def test_sync_never_touches_an_installed_plugin():
    """
    THE property. The registry decides what is on offer; the operator decides
    what runs. Uninstalling somebody's running integration because an upstream
    index changed would be a remote actor stopping production work.

    Verified live too: after notify-hub was withdrawn, GET /plugins/notify-hub
    still answered 200 and the plugin kept running.
    """
    from app.api.v1.endpoints.marketplace import sync_marketplace

    src = inspect.getsource(sync_marketplace)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    for forbidden in ("uninstall", "plugin_loader", "InstalledPlugin"):
        assert forbidden not in body, f"sync reaches into installed plugins via {forbidden!r}"


# ── the install refusal ─────────────────────────────────────────


def test_a_withdrawn_plugin_says_so():
    """
    A flat 404 made a plugin the registry had deliberately pulled look like a
    typo. The two need opposite reactions from whoever is reading.
    """
    from app.api.v1.endpoints.marketplace import _resolve_published

    src = inspect.getsource(_resolve_published)
    assert '"withdrawn"' in src, "cannot tell withdrawn from unknown"
    assert "410" in src, "a withdrawn plugin is not reported as gone"
    assert "404" in src, "an unknown slug is no longer a 404"


def test_resolution_still_requires_a_published_row():
    """
    The de-listing is only worth anything because this filters on it. If that
    filter ever goes, withdrawal becomes cosmetic.
    """
    from app.api.v1.endpoints.marketplace import _resolve_published

    assert 'status == "published"' in inspect.getsource(_resolve_published)


@pytest.mark.parametrize("endpoint", ["install_from_marketplace", "upgrade_from_marketplace"])
def test_every_entry_point_goes_through_that_check(endpoint: str):
    """
    Both buttons load third-party code, so both have to refuse a withdrawn
    plugin. Having the check in one shared place is the point -- an install path
    that resolved its own row would be the obvious way for the two to drift.
    """
    import app.api.v1.endpoints.marketplace as mp

    src = inspect.getsource(getattr(mp, endpoint))
    assert "_resolve_published(" in src, f"{endpoint} resolves the catalogue row itself"
