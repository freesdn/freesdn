# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for X-Forwarded-For spoofing.

These tests verify the *configuration* is safe — they don't actually run
gunicorn. The invariant they guard is that nothing in the repo hardcodes
``--forwarded-allow-ips=*`` (or equivalent), because that would let any
caller spoof ``X-Forwarded-For`` and defeat the per-IP rate limiter in
``app/api/v1/endpoints/auth.py``.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


def _find_backend_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (
            (parent / "Dockerfile").exists()
            and (parent / "docker-entrypoint.sh").exists()
            and (parent / "app").is_dir()
        ):
            return parent
    raise AssertionError("Could not locate backend root from test file path")


BACKEND_ROOT = _find_backend_root()
REPO_ROOT = BACKEND_ROOT.parent if (BACKEND_ROOT.parent / ".env.example").exists() else BACKEND_ROOT


def _read(path: Path) -> str:
    assert path.exists(), f"Expected file to exist: {path}"
    return path.read_text(encoding="utf-8")


# --- Dockerfile ------------------------------------------------------------


def test_dockerfile_does_not_use_wildcard_forwarded_ips() -> None:
    """The production Dockerfile must not hardcode --forwarded-allow-ips=*."""
    content = _read(BACKEND_ROOT / "Dockerfile")

    # Any literal '*' as the value of --forwarded-allow-ips is forbidden,
    # whether passed as "--forwarded-allow-ips=*", "--forwarded-allow-ips *",
    # or "--forwarded-allow-ips", "*".
    bad_patterns = [
        r'--forwarded-allow-ips\s*=\s*["\']?\*["\']?',
        r'--forwarded-allow-ips["\']?\s*,\s*["\']?\*["\']?',
        r'--forwarded-allow-ips\s+["\']?\*["\']?(?:\s|$)',
    ]
    for pattern in bad_patterns:
        matches = re.findall(pattern, content)
        assert not matches, (
            f"Dockerfile contains wildcard forwarded-allow-ips "
            f"(pattern={pattern!r}, matches={matches!r})"
        )


def test_dockerfile_references_forwarded_allow_ips_env_var() -> None:
    """The production Dockerfile must pass FORWARDED_ALLOW_IPS through."""
    content = _read(BACKEND_ROOT / "Dockerfile")
    assert "FORWARDED_ALLOW_IPS" in content, (
        "Dockerfile must reference the FORWARDED_ALLOW_IPS env var so "
        "operators can override the reverse-proxy trust list without "
        "rebuilding the image."
    )


def test_dockerfile_default_forwarded_allow_ips_is_loopback() -> None:
    """The baked-in default must be loopback, not a wildcard or RFC1918."""
    content = _read(BACKEND_ROOT / "Dockerfile")
    # Expect an `ENV FORWARDED_ALLOW_IPS=127.0.0.1` line.
    m = re.search(
        r"^ENV\s+FORWARDED_ALLOW_IPS\s*=\s*(\S+)",
        content,
        re.MULTILINE,
    )
    assert m, "Dockerfile must declare ENV FORWARDED_ALLOW_IPS with a safe default"
    default = m.group(1).strip('"').strip("'")
    assert default == "127.0.0.1", (
        f"Dockerfile default FORWARDED_ALLOW_IPS must be 127.0.0.1, "
        f"got {default!r}"
    )


# --- Entrypoint ------------------------------------------------------------


def test_entrypoint_does_not_hardcode_wildcard() -> None:
    """docker-entrypoint.sh must not pass --forwarded-allow-ips=*."""
    content = _read(BACKEND_ROOT / "docker-entrypoint.sh")
    assert "--forwarded-allow-ips=*" not in content
    assert '--forwarded-allow-ips "*"' not in content
    assert "--forwarded-allow-ips '*'" not in content


def test_entrypoint_rejects_wildcard_at_runtime() -> None:
    """Entrypoint should actively refuse to boot when FORWARDED_ALLOW_IPS=*."""
    content = _read(BACKEND_ROOT / "docker-entrypoint.sh")
    # Must contain a guard that checks for "*" and exits.
    assert 'FORWARDED_ALLOW_IPS" = "*"' in content or "FORWARDED_ALLOW_IPS = \"*\"" in content, (
        "Entrypoint must guard against FORWARDED_ALLOW_IPS=* at runtime "
        "(expected a shell `if` test that exits on wildcard)."
    )
    assert "exit 1" in content, (
        "Entrypoint wildcard guard must exit non-zero so the container "
        "fails fast instead of starting in an unsafe configuration."
    )


def test_entrypoint_default_is_loopback() -> None:
    """Entrypoint fallback default (when env var unset) must be 127.0.0.1."""
    content = _read(BACKEND_ROOT / "docker-entrypoint.sh")
    # Look for the parameter expansion pattern ${FORWARDED_ALLOW_IPS:-127.0.0.1}
    assert "${FORWARDED_ALLOW_IPS:-127.0.0.1}" in content, (
        "Entrypoint must default FORWARDED_ALLOW_IPS to 127.0.0.1 when unset"
    )
    # And make sure the old unsafe RFC1918 default is gone.
    assert "172.16.0.0/12,192.168.0.0/16,10.0.0.0/8" not in content, (
        "Entrypoint still has the old permissive RFC1918 default for "
        "FORWARDED_ALLOW_IPS — shrink it to loopback."
    )


# --- .env.example ----------------------------------------------------------


def test_env_example_documents_forwarded_ips() -> None:
    """The .env.example must document FORWARDED_ALLOW_IPS and warn against *."""
    env_example = REPO_ROOT / ".env.example"
    if not env_example.exists():
        pytest.skip(".env.example is not present in this backend test environment")

    content = _read(env_example)

    assert "FORWARDED_ALLOW_IPS" in content, (
        ".env.example must document FORWARDED_ALLOW_IPS"
    )

    lower = content.lower()
    assert "never" in lower, (
        ".env.example must explicitly warn 'NEVER' set FORWARDED_ALLOW_IPS "
        "to a wildcard in production"
    )
    # And should call out the wildcard by name so operators can grep for it.
    assert '"*"' in content or "'*'" in content or "= *" in content, (
        ".env.example should mention the literal wildcard so operators "
        "can grep for guidance before using it"
    )


# --- docker-compose.prod.yml ----------------------------------------------


def test_compose_prod_does_not_pass_wildcard() -> None:
    """docker-compose.prod.yml must not hardcode wildcard forwarded-allow-ips."""
    path = REPO_ROOT / "docker-compose.prod.yml"
    if not path.exists():
        return
    content = _read(path)
    # Exact wildcard assignment — allow variable fallbacks like ${X:-127.0.0.1}
    assert "FORWARDED_ALLOW_IPS=*" not in content
    assert 'FORWARDED_ALLOW_IPS="*"' not in content
    assert "FORWARDED_ALLOW_IPS: '*'" not in content
