# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the Alembic migration chain itself.

Everything else in the suite runs against a schema built by ``scripts/migrate.py``,
which takes the fresh-install path: ``Base.metadata.create_all()`` + ``alembic stamp
head``. That path never executes a single migration, so nothing in CI exercised the
chain an UPGRADED appliance actually runs. These tests build a throwaway database with
``alembic upgrade head`` instead.

Note the same trap one level down: the "upgraded appliance" fixture cannot build its
STARTING database by replaying the chain either, because ``001_initial`` is itself
``Base.metadata.create_all()`` over the live models -- a replay hands the old appliance
every model change made since, and the comparison then confirms nothing. That baseline
is a checked-in schema dump (``baseline_007_schema.sql``) for exactly this reason.
"""
