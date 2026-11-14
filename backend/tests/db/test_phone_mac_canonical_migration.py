# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Migration 032 canonicalises phone MACs and flags, never merges, shared ones.

Runs the real Alembic CLI against a scratch database upgraded from the frozen
baseline, seeded with the spellings an older install can hold: two live phones
whose MACs are one MAC spelled two ways, a soft-deleted third spelling, a phone
that is already canonical, one whose MAC does not parse, and one with none.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.orm import Session

from app.models.core import Organization, Site
from tests.db.conftest import (
    BACKEND_ROOT,
    build_pre_fix_database,
    drop_scratch_database,
    run_alembic,
    scratch_engine,
)

REVISION = "032_phone_mac_canonical"
SHARED = "00:0b:82:12:34:56"


def _previous_revision() -> str:
    """The revision 032 sits on (re-pointed at merge time, so never hard-coded)."""
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    down = ScriptDirectory.from_config(config).get_revision(REVISION).down_revision
    assert isinstance(down, str)
    return down


def _seed(engine: sa.Engine) -> dict[str, object]:
    with Session(engine) as db:
        org = Organization(name="MAC migration", slug=f"mac-mig-{uuid4().hex[:8]}")
        db.add(org)
        db.flush()
        sites = [
            Site(organization_id=org.id, name=f"Site {i}", slug=f"mac-site-{i}-{uuid4().hex[:6]}")
            for i in range(2)
        ]
        db.add_all(sites)
        db.flush()
        site_ids = [s.id for s in sites]
        db.commit()

    phones = {
        "a": (site_ids[0], "00:0B:82:12:34:56", False),
        "b": (site_ids[1], "000b82123456", False),
        "c": (site_ids[0], "AA-BB-CC-DD-EE-FF", False),
        "d": (site_ids[0], "00:11:22:33:44:55", False),
        "e": (site_ids[0], "00-0B-82-12-34-56", True),
        "f": (site_ids[0], "not-a-mac", False),
        "g": (site_ids[0], None, False),
    }
    ids: dict[str, object] = {"site": site_ids[0]}
    with engine.begin() as conn:
        for key, (site_id, mac, deleted) in phones.items():
            ids[key] = uuid4()
            conn.execute(
                sa.text(
                    "INSERT INTO voip.phones (id, site_id, name, mac_address, status, "
                    "lifecycle_state, sip_registered, settings, tags, deleted_at) VALUES "
                    "(:id, :site, :name, :mac, 'offline', 'discovered', false, '{}', '[]', "
                    "CASE WHEN :deleted THEN now() END)"
                ),
                {
                    "id": ids[key],
                    "site": site_id,
                    "name": f"phone {key}",
                    "mac": mac,
                    "deleted": deleted,
                },
            )
    return ids


def _rows(engine: sa.Engine) -> dict[object, tuple[str | None, str | None]]:
    with engine.connect() as conn:
        return {
            r.id: (r.mac_address, r.mac_review)
            for r in conn.execute(sa.text("SELECT id, mac_address, mac_review FROM voip.phones"))
        }


def _macs(engine: sa.Engine) -> dict[object, str | None]:
    """MACs only: usable after a downgrade has dropped mac_review."""
    with engine.connect() as conn:
        return dict(conn.execute(sa.text("SELECT id, mac_address FROM voip.phones")).all())


def _index(engine: sa.Engine) -> tuple[bool, str | None]:
    with engine.connect() as conn:
        row = conn.execute(
            sa.text(
                "SELECT i.indisunique, pg_get_expr(i.indpred, i.indrelid) "
                "FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'voip' AND c.relname = 'ix_phones_mac_address'"
            )
        ).one()
    return row[0], row[1]


def _insert_live(engine: sa.Engine, site_id: object, mac: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO voip.phones (id, site_id, name, mac_address, status, "
                "lifecycle_state, sip_registered, settings, tags) VALUES "
                "(:id, :site, 'late', :mac, 'offline', 'discovered', false, '{}', '[]')"
            ),
            {"id": uuid4(), "site": site_id, "mac": mac},
        )


@pytest.fixture
def legacy_phones(maintenance_engine):
    name = "freesdn_phone_mac_032"
    url = build_pre_fix_database(maintenance_engine, name)
    engine = scratch_engine(url)
    try:
        run_alembic(url, "upgrade", _previous_revision())
        ids = _seed(engine)
        yield engine, url, ids
    finally:
        engine.dispose()
        drop_scratch_database(maintenance_engine, name)


def test_upgrade_canonicalises_flags_and_reports(legacy_phones) -> None:
    engine, url, ids = legacy_phones

    result = run_alembic(url, "upgrade", REVISION)

    rows = _rows(engine)
    assert rows[ids["a"]] == (SHARED, "duplicate")
    assert rows[ids["b"]] == (SHARED, "duplicate")
    assert rows[ids["c"]] == ("aa:bb:cc:dd:ee:ff", None)
    assert rows[ids["d"]] == ("00:11:22:33:44:55", None)
    # soft-deleted: canonicalised, but a deleted phone is nobody's twin
    assert rows[ids["e"]] == (SHARED, None)
    assert rows[ids["f"]] == ("not-a-mac", None)
    assert rows[ids["g"]] == (None, None)
    log = result.stderr + result.stdout
    assert "4 phone MAC(s) rewritten" in log
    assert "2 phone(s) flagged" in log
    assert "1 MAC(s) left as stored" in log


def test_upgrade_leaves_one_unflagged_live_phone_per_mac(legacy_phones) -> None:
    engine, url, ids = legacy_phones
    run_alembic(url, "upgrade", REVISION)

    unique, predicate = _index(engine)
    assert unique
    assert predicate is not None
    assert "deleted_at IS NULL" in predicate and "mac_review IS NULL" in predicate
    with pytest.raises(sa.exc.IntegrityError):
        _insert_live(engine, ids["site"], "aa:bb:cc:dd:ee:ff")


def test_downgrade_is_refused_while_a_mac_is_shared(legacy_phones) -> None:
    engine, url, _ = legacy_phones
    run_alembic(url, "upgrade", REVISION)
    before = _rows(engine)

    refused = run_alembic(url, "downgrade", _previous_revision(), expect_success=False)

    assert refused.returncode != 0
    assert "Phone MAC downgrade refused" in refused.stderr
    assert _rows(engine) == before
    with engine.connect() as conn:
        assert conn.scalar(sa.text("SELECT version_num FROM alembic_version")) == REVISION


def test_rerun_on_canonical_data_changes_nothing(legacy_phones) -> None:
    """Idempotent: the second pass over canonical data is a logged no-op."""
    engine, url, ids = legacy_phones
    run_alembic(url, "upgrade", REVISION)
    with engine.begin() as conn:
        conn.execute(
            sa.text("DELETE FROM voip.phones WHERE id IN (:b, :e)"), {"b": ids["b"], "e": ids["e"]}
        )
    run_alembic(url, "downgrade", _previous_revision())
    assert _index(engine) == (True, None)
    before = _macs(engine)

    again = run_alembic(url, "upgrade", REVISION)

    log = again.stderr + again.stdout
    assert "0 phone MAC(s) rewritten" in log
    assert "0 phone(s) flagged" in log
    assert _macs(engine) == before
    assert all(review is None for _, review in _rows(engine).values())
