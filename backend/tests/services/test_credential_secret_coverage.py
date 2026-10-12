# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Every secret column on ``Credential`` must be known to the backup layer.

In 26.09.0, restoring a config-only backup with "Overwrite existing" NULLed
every credential secret in the organization and reported success. The fix was
``_BLOCKED_FIELDS`` in ``app/services/backup.py``, which derives the protected
columns from ``CREDENTIAL_SECRET_FIELDS`` so a config-only restore cannot write
its ``None`` placeholders over live ciphertext.

That fix is only as good as the tuple it derives from. Add a secret column to
``Credential`` -- the next vendor that needs a passphrase, a bearer token, a
client assertion -- forget to list it, and a config-only restore silently wipes
it again, reporting success exactly as before. Nothing would fail: the new
column is simply not in the blocked set.

So this asserts that every column is accounted for, as a secret or explicitly
as not one. A new column forces a decision instead of defaulting to the unsafe
answer. The failure message says what to do, because the person who trips this
will be adding an unrelated feature and will not have read any of the above.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.models.core import Credential
from app.services.backup import CREDENTIAL_SECRET_FIELDS

# Columns reviewed and found NOT to carry a secret. Everything here is either
# an identifier, a label, or operational metadata that is safe to restore from
# a config-only backup. Adding to this list is a deliberate statement that the
# column cannot leak or be destroyed by a config restore.
REVIEWED_NOT_SECRET = frozenset(
    {
        "id",
        "organization_id",
        "site_id",
        "name",
        "description",
        "credential_type",
        "scope",
        "vendor",
        # The identity half of a credential. Restoring it is the point of a
        # config backup; it is the password column beside it that must survive.
        "username",
        # Non-secret connection options. If a secret is ever stashed in here,
        # it belongs in its own column, not in a JSON blob the backup layer
        # treats as configuration.
        "options",
        "is_default",
        "is_active",
        "last_used",
        "last_test_result",
        # Audit / soft-delete bookkeeping from the shared mixins.
        "created_at",
        "updated_at",
        "created_by",
        "updated_by",
        "deleted_at",
        "deleted_by",
        "is_deleted",
    }
)

# Names that look like they hold a secret. Used only to make the failure
# message sharper, never to decide the outcome.
_SECRET_SHAPED = re.compile(
    r"password|secret|token|api_key|private_key|certificate|community|passphrase",
    re.I,
)


def test_every_credential_column_is_classified() -> None:
    columns = set(Credential.__table__.columns.keys())
    known = set(CREDENTIAL_SECRET_FIELDS) | REVIEWED_NOT_SECRET

    unclassified = sorted(columns - known)
    assert not unclassified, (
        f"{unclassified} on Credential are neither in CREDENTIAL_SECRET_FIELDS "
        "nor in REVIEWED_NOT_SECRET.\n"
        "If a column holds a secret, add it to CREDENTIAL_SECRET_FIELDS in "
        "app/services/backup.py -- otherwise a config-only restore writes NULL "
        "over it and reports success, which is the 26.09.0 outage.\n"
        "If it does not hold a secret, add it to REVIEWED_NOT_SECRET here.\n"
        "Secret-shaped names among them: "
        + (str([c for c in unclassified if _SECRET_SHAPED.search(c)]) or "none")
    )


def test_the_secret_list_matches_real_columns() -> None:
    """A protected column that no longer exists protects nothing.

    Renaming a column while leaving the old name in the tuple leaves the new
    one unprotected and the guard looking complete.
    """
    columns = set(Credential.__table__.columns.keys())
    missing = sorted(set(CREDENTIAL_SECRET_FIELDS) - columns)
    assert not missing, (
        f"CREDENTIAL_SECRET_FIELDS names {missing}, which are not columns on "
        "Credential. If they were renamed, the new names are unprotected."
    )


def test_a_config_only_restore_still_derives_its_block_list() -> None:
    """The config-only branch must keep splatting CREDENTIAL_SECRET_FIELDS.

    ``_BLOCKED_FIELDS`` is a local inside ``_restore_data``, so it cannot be
    imported and compared. This reads the source instead, which is coarse but
    pins the one line that stands between a config-only restore and the live
    credential vault. Someone replacing the splat with a hand-written list is
    exactly how the derivation stops tracking the tuple.
    """
    source = Path(__file__).resolve().parents[2] / "app" / "services" / "backup.py"
    text = source.read_text(encoding="utf-8")

    block = re.search(r"_BLOCKED_FIELDS\s*=\s*\((.*?)\n\s*\)\n", text, re.S)
    assert block, "_BLOCKED_FIELDS is no longer assigned in the expected shape"
    assert "*CREDENTIAL_SECRET_FIELDS" in block.group(1), (
        "the config-only branch of _BLOCKED_FIELDS no longer derives from "
        "CREDENTIAL_SECRET_FIELDS. Without that splat a config-only restore "
        "can write NULL over live credential ciphertext, which is the 26.09.0 "
        "outage."
    )
    assert "include_secrets" in block.group(1), (
        "_BLOCKED_FIELDS no longer distinguishes a secret-bearing restore from "
        "a config-only one"
    )
