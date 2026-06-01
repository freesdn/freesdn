# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Backups are fail-closed to encrypted.

A backup archive carries decrypted secrets (controller/device credentials,
config), so a plaintext archive at rest is a leak. Encryption defaults on
(create_backup is_encrypted=True); this pins the production fail-closed gate that
UPGRADES an explicit plaintext request to encrypted unless an operator opted into
the risk via BACKUP_ALLOW_PLAINTEXT.
"""
from __future__ import annotations

import pytest

from app.services.backup import _must_force_encryption


@pytest.mark.parametrize(
    "is_encrypted,environment,allow_plaintext,expected",
    [
        # plaintext request in prod/staging without opt-in → force encryption
        (False, "production", False, True),
        (False, "staging", False, True),
        # explicit operator opt-in → honor the plaintext request
        (False, "production", True, False),
        (False, "staging", True, False),
        # dev keeps plaintext available for testing
        (False, "development", False, False),
        # already-encrypted is never touched, regardless of env
        (True, "production", False, False),
        (True, "development", False, False),
    ],
)
def test_must_force_encryption(is_encrypted, environment, allow_plaintext, expected) -> None:
    assert _must_force_encryption(is_encrypted, environment, allow_plaintext) is expected
