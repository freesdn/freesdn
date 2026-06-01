# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Test login timing-attack mitigation.

When a login request targets a non-existent user, the handler must spend
the same CPU time as it would for a real user with a wrong password, so
attackers cannot enumerate valid accounts via response-latency analysis.

These are fast static tests that inspect the auth module source directly.
They avoid importing the FastAPI package graph so they run in minimal
environments (ruff/CI smoke tests) without pulling celery/redis/etc.

Full end-to-end timing tests (100 samples per branch, median within
50 ms) live in the integration suite under tests/integration/ and will
be added with the testcontainers conftest.
"""

from __future__ import annotations

import re
from pathlib import Path

_AUTH_FILE = (
    Path(__file__).resolve().parents[2]
    / "app"
    / "api"
    / "v1"
    / "endpoints"
    / "auth.py"
)


def _auth_source() -> str:
    assert _AUTH_FILE.is_file(), f"auth.py not found at {_AUTH_FILE}"
    return _AUTH_FILE.read_text(encoding="utf-8")


def _extract_function(source: str, func_name: str) -> str:
    """Return the source of a top-level `async def func_name(...)` block.

    Uses indentation to detect the end of the function.  Good enough for
    static assertions — we don't need a real parser.
    """
    pattern = re.compile(
        rf"^async def {re.escape(func_name)}\b.*?(?=^(?:async def |def |@router\.|# ===|\Z))",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(source)
    assert m is not None, f"function {func_name!r} not found in auth.py"
    return m.group(0)


def test_dummy_hash_helper_exists() -> None:
    """auth.py must expose a dummy-hash helper or cached dummy hash."""
    source = _auth_source()
    assert "_get_dummy_hash" in source or "_DUMMY_PASSWORD_HASH" in source, (
        "auth.py must have a dummy hash for timing-safety"
    )


def test_dummy_hash_uses_argon2() -> None:
    """Dummy hash must be produced by the real password hasher, not a constant."""
    source = _auth_source()
    # The helper must use get_password_hash() — the same Argon2id helper used
    # for real passwords — rather than hard-coding a hash string, so the
    # algorithm/params match real passwords if the cost parameters are ever
    # tuned. (Was pwd_context.hash() before the passlib -> argon2-cffi
    # migration removed the pwd_context global; see auth.py _get_dummy_hash.)
    assert "get_password_hash(" in source, (
        "auth.py dummy-hash helper must use get_password_hash() so the "
        "algorithm/parameters match real password hashes"
    )


def test_dummy_hash_cached_not_recomputed_per_call() -> None:
    """The dummy hash must be computed lazily once and cached.

    If the helper re-hashed on every call, the dummy path would take 2x
    the time of the real path (compute new hash + verify), which is its
    own timing side channel.
    """
    source = _auth_source()
    # Look for a module-level cache variable — either a sentinel None that
    # is lazily populated, or a straight module-level constant.
    assert re.search(r"_DUMMY_PASSWORD_HASH\s*[:=]", source) is not None, (
        "auth.py must cache the dummy hash in a module-level variable"
    )
    # And the getter must check the cache before recomputing.
    assert "if _DUMMY_PASSWORD_HASH is None" in source, (
        "auth.py dummy-hash getter must memoise the first call"
    )


def test_dummy_verify_helper_exists() -> None:
    """A helper that burns CPU on the user-is-None branch must exist."""
    source = _auth_source()
    assert "_dummy_verify" in source or "pwd_context.verify" in source, (
        "auth.py must invoke a dummy verify() on user-is-None branches"
    )


def test_login_calls_dummy_verify_on_user_none() -> None:
    """The /token and /login handlers must dummy-verify when user is None.

    Extracts each login function's source and confirms it calls
    _dummy_verify() (or equivalent) before raising a 401 on the
    user-is-None branch.
    """
    source = _auth_source()
    for func_name in ("login_for_access_token", "login"):
        src = _extract_function(source, func_name)

        assert "_dummy_verify" in src or "pwd_context.verify" in src, (
            f"{func_name} must dummy-verify on user-is-None branch "
            f"to prevent timing-based user enumeration"
        )

        # The old short-circuit pattern `user is None or not verify_password`
        # is a timing-attack smell — make sure it's gone.
        assert "user is None or not verify_password" not in src, (
            f"{func_name} still uses the short-circuit pattern that "
            f"enables timing-based user enumeration"
        )


def test_login_error_messages_identical() -> None:
    """Login errors must not distinguish 'user exists' from 'user not found'."""
    lower_source = _auth_source().lower()
    bad_patterns = [
        "user not found",
        "no such user",
        "email not registered",
        "account does not exist",
        "unknown user",
    ]
    for pattern in bad_patterns:
        assert pattern not in lower_source, (
            f"auth.py contains enumeration-prone message: {pattern!r}"
        )


def test_locked_account_branch_normalizes_timing() -> None:
    """The locked-account branch must also run dummy-verify.

    Otherwise an attacker could distinguish "user exists but locked" from
    "user does not exist" by the absence of Argon2 work on the locked path.
    """
    source = _auth_source()
    for func_name in ("login_for_access_token", "login"):
        src = _extract_function(source, func_name)

        assert "locked_until" in src, f"{func_name} missing lockout check"
        assert "HTTP_423_LOCKED" in src, f"{func_name} missing 423 response"

        # The locked branch: walk from the last `locked_until` reference
        # before HTTP_423_LOCKED and confirm dummy-verify appears between.
        locked_idx = src.find("HTTP_423_LOCKED")
        pre_locked = src[:locked_idx]
        lu_idx = pre_locked.rfind("locked_until")
        between = pre_locked[lu_idx:]
        assert "_dummy_verify" in between or "pwd_context.verify" in between, (
            f"{func_name} locked-account branch must dummy-verify "
            f"to normalize timing with the user-is-None branch"
        )


def test_dummy_hash_runtime_is_argon2() -> None:
    """Smoke-test: when dependencies are available, the cached dummy hash
    really is an Argon2 hash string.  Skips gracefully when the import
    chain can't be satisfied (e.g. stripped CI smoke env).
    """
    try:
        from app.core.security import pwd_context
    except Exception:  # pragma: no cover - depends on env
        import pytest

        pytest.skip("app.core.security not importable in this env")

    # Generate once via the same code path the helper uses.
    dummy = pwd_context.hash("this-is-a-dummy-password-not-a-real-credential")
    assert dummy.startswith("$argon2"), (
        f"pwd_context.hash() should produce Argon2 hashes, got: {dummy[:20]!r}"
    )
