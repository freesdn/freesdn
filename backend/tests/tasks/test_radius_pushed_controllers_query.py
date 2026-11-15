"""radius.sync_dot1x_events finds its controllers without a SQLAlchemy warning.

``select(distinct(col))`` made SQLAlchemy warn "Column-expression-level unary
distinct() should not be used outside of an aggregate" on every run, so the
workers logged it every five minutes.
"""

from __future__ import annotations

import warnings
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import SAWarning

from app.core.crypto import encrypt_credential
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.radius import Dot1xPortConfig, RadiusServerProfile
from app.tasks.radius import _controllers_with_pushed_configs


def test_the_query_compiles_without_a_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", SAWarning)
        sql = str(_controllers_with_pushed_configs().compile(dialect=postgresql.dialect()))
    assert sql.startswith("SELECT DISTINCT")


async def test_each_controller_with_a_live_pushed_config_is_listed_once(db_session) -> None:
    org = Organization(name="radius sync", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    pushed, pending = (
        Controller(name=n, site_id=site.id, controller_type="omada", host=h, port=443)
        for n, h in (("c1", "192.0.2.71"), ("c2", "192.0.2.72"))
    )
    db_session.add_all([pushed, pending])
    profile = RadiusServerProfile(
        organization_id=org.id,
        name="radius",
        host="192.0.2.70",
        port=1812,
        shared_secret_encrypted=encrypt_credential("synthetic"),
    )
    db_session.add(profile)
    await db_session.flush()
    for ctrl, status, deleted in (
        (pushed, "pushed", None),
        (pushed, "pushed", None),
        (pending, "pending", None),
        (pending, "pushed", datetime.now(UTC)),
    ):
        db_session.add(
            Dot1xPortConfig(
                controller_id=ctrl.id,
                radius_profile_id=profile.id,
                push_status=status,
                deleted_at=deleted,
            )
        )
    await db_session.commit()

    rows = (await db_session.execute(_controllers_with_pushed_configs())).scalars().all()

    assert rows == [pushed.id]
