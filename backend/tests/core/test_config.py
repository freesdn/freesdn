# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for app.core.config — Settings class with validators.

All tests use environment variable overrides so no .env file or real
DB/Redis is needed.
"""

import warnings

import pytest
from pydantic import ValidationError

# Env vars that can leak from the host and interfere with Settings construction.
_AMBIENT_ENV_VARS = [
    "DATABASE_URL",
    "REDIS_URL",
    "REDIS_PASSWORD",
    "LOGDB_URL",
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
    "REDIS_HOST",
    "REDIS_PORT",
    "REDIS_DB",
    "SECRET_KEY",
    "ENCRYPTION_SALT",
    "ENVIRONMENT",
]


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Remove ambient env vars that could leak into Settings construction."""
    for var in _AMBIENT_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
        monkeypatch.delenv(f"FREESDN_{var}", raising=False)


def _make_settings(**overrides):
    """Create a Settings instance with safe defaults and optional overrides.

    Sets a strong SECRET_KEY, ENCRYPTION_SALT, and POSTGRES_PASSWORD so the
    validators don't auto-generate values or raise in production mode.
    """
    env = {
        "SECRET_KEY": "a" * 64,
        "ENCRYPTION_SALT": "b" * 32,
        "POSTGRES_PASSWORD": "strong-test-password-1234",
        "ENVIRONMENT": "development",
    }
    env.update(overrides)

    # Patch env vars, then import fresh Settings each time
    patched = {f"FREESDN_{k}" if not k.startswith("FREESDN_") else k: v for k, v in env.items()}
    # Settings reads bare names (case_sensitive=False), not FREESDN_ prefix.
    # Pydantic-settings reads the exact field names from env.
    from app.core.config import Settings

    return Settings(**env)


# ── Default values ──────────────────────────────────────────────────────────


class TestDefaults:
    def test_app_name(self):
        s = _make_settings()
        assert s.APP_NAME == "FreeSDN"

    def test_app_version(self):
        import app

        s = _make_settings()
        # APP_VERSION derives from the single source of truth (app.__version__),
        # not a duplicated literal.
        assert s.APP_VERSION == app.__version__

    def test_app_license(self):
        import app

        s = _make_settings()
        assert s.APP_LICENSE == app.__license__ == "AGPL-3.0-only"

    def test_debug_off(self):
        s = _make_settings()
        assert s.DEBUG is False

    def test_environment_default(self):
        s = _make_settings()
        assert s.ENVIRONMENT == "development"

    def test_api_prefix(self):
        s = _make_settings()
        assert s.API_V1_PREFIX == "/api/v1"

    def test_algorithm(self):
        s = _make_settings()
        assert s.ALGORITHM == "HS256"

    def test_access_token_expire(self):
        s = _make_settings()
        assert s.ACCESS_TOKEN_EXPIRE_MINUTES == 60

    def test_refresh_token_expire(self):
        s = _make_settings()
        assert s.REFRESH_TOKEN_EXPIRE_DAYS == 14

    def test_remember_me_refresh_token_expire(self):
        s = _make_settings()
        # "Remember me" extends the session window beyond the default.
        assert s.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS == 30
        assert s.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS > s.REFRESH_TOKEN_EXPIRE_DAYS

    def test_password_min_length(self):
        s = _make_settings()
        assert s.PASSWORD_MIN_LENGTH == 12

    def test_cors_origins(self):
        s = _make_settings()
        assert "http://localhost:3000" in s.CORS_ORIGINS
        assert "http://localhost:5173" in s.CORS_ORIGINS

    def test_postgres_defaults(self):
        s = _make_settings()
        assert s.POSTGRES_HOST == "localhost"
        assert s.POSTGRES_PORT == 5432
        assert s.POSTGRES_USER == "freesdn"
        assert s.POSTGRES_DB == "freesdn"

    def test_redis_defaults(self):
        s = _make_settings()
        assert s.REDIS_HOST == "localhost"
        assert s.REDIS_PORT == 6379
        assert s.REDIS_DB == 0

    def test_pool_defaults(self):
        s = _make_settings()
        assert s.DB_POOL_SIZE == 20
        assert s.DB_MAX_OVERFLOW == 30

    def test_log_level(self):
        s = _make_settings()
        assert s.LOG_LEVEL == "INFO"

    def test_feature_flags(self):
        s = _make_settings()
        assert s.ENABLE_METRICS is True
        assert s.ENABLE_DOCS is True
        assert s.ENABLE_PROFILING is False


# ── DATABASE_URL builder ────────────────────────────────────────────────────


class TestDatabaseUrl:
    def test_built_from_components(self):
        s = _make_settings(
            POSTGRES_HOST="db.example.com",
            POSTGRES_PORT=5433,
            POSTGRES_USER="admin",
            POSTGRES_PASSWORD="s3cret-long-password",
            POSTGRES_DB="mydb",
        )
        url = str(s.DATABASE_URL)
        assert "postgresql+asyncpg://" in url
        assert "db.example.com" in url
        assert "5433" in url
        assert "admin" in url
        assert "mydb" in url

    def test_not_overwritten_when_provided(self):
        explicit = "postgresql+asyncpg://u:p@host:5432/db"
        s = _make_settings(DATABASE_URL=explicit)
        assert str(s.DATABASE_URL) == explicit


# ── REDIS_URL builder ───────────────────────────────────────────────────────


class TestRedisUrl:
    def test_built_from_components(self):
        s = _make_settings(
            REDIS_HOST="redis.local",
            REDIS_PORT=6380,
            REDIS_DB=2,
        )
        url = str(s.REDIS_URL)
        assert "redis://" in url
        assert "redis.local" in url
        assert "6380" in url

    def test_includes_password_when_set(self):
        s = _make_settings(REDIS_PASSWORD="redispass")
        url = str(s.REDIS_URL)
        assert "redispass" in url

    def test_not_overwritten_when_provided(self):
        explicit = "redis://localhost:6379/0"
        s = _make_settings(REDIS_URL=explicit)
        assert str(s.REDIS_URL) == explicit


# ── SECRET_KEY validator ────────────────────────────────────────────────────


class TestSecretKeyValidator:
    def test_rejects_empty_in_production(self):
        with pytest.raises(ValidationError, match="SECRET_KEY"):
            _make_settings(SECRET_KEY="", ENVIRONMENT="production", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test")

    def test_rejects_insecure_default_in_production(self):
        with pytest.raises(ValidationError, match="SECRET_KEY"):
            _make_settings(
                SECRET_KEY="CHANGE-ME-IN-PRODUCTION-USE-STRONG-KEY",
                ENVIRONMENT="production",
                LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test",
            )

    def test_rejects_changeme_in_staging(self):
        with pytest.raises(ValidationError, match="SECRET_KEY"):
            _make_settings(SECRET_KEY="changeme", ENVIRONMENT="staging", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test")

    def test_rejects_short_key_in_production(self):
        with pytest.raises(ValidationError, match="SECRET_KEY"):
            _make_settings(SECRET_KEY="short", ENVIRONMENT="production", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test")

    def test_auto_generates_in_development(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = _make_settings(SECRET_KEY="")
            assert len(s.SECRET_KEY) >= 32

    def test_warns_short_key_in_development(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            s = _make_settings(SECRET_KEY="x" * 20, ENVIRONMENT="development")
            warning_msgs = [str(x.message) for x in w]
            assert any("shorter than 32" in m for m in warning_msgs)

    def test_accepts_strong_key(self):
        s = _make_settings(SECRET_KEY="a" * 64, ENVIRONMENT="production", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test", REDIS_PASSWORD="test-redis-pw")
        assert s.SECRET_KEY == "a" * 64


# ── ENCRYPTION_SALT validator ───────────────────────────────────────────────


class TestEncryptionSaltValidator:
    def test_rejects_empty_in_production(self):
        with pytest.raises(ValidationError, match="ENCRYPTION_SALT"):
            _make_settings(ENCRYPTION_SALT="", ENVIRONMENT="production", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test")

    def test_rejects_default_salt_in_production(self):
        with pytest.raises(ValidationError, match="ENCRYPTION_SALT"):
            _make_settings(
                ENCRYPTION_SALT="freesdn-credential-salt-v1",
                ENVIRONMENT="production",
                LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test",
            )

    def test_auto_generates_in_development(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = _make_settings(ENCRYPTION_SALT="")
            assert len(s.ENCRYPTION_SALT) > 0

    def test_accepts_custom_salt(self):
        s = _make_settings(ENCRYPTION_SALT="my-custom-salt-value-12345")
        assert s.ENCRYPTION_SALT == "my-custom-salt-value-12345"


# ── POSTGRES_PASSWORD validator ─────────────────────────────────────────────


class TestPostgresPasswordValidator:
    def test_rejects_empty_in_production(self):
        with pytest.raises(ValidationError, match="POSTGRES_PASSWORD"):
            _make_settings(POSTGRES_PASSWORD="", ENVIRONMENT="production", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test")

    def test_rejects_insecure_in_production(self):
        for pwd in ("freesdn_dev", "postgres", "password", "changeme"):
            with pytest.raises(ValidationError, match="POSTGRES_PASSWORD"):
                _make_settings(POSTGRES_PASSWORD=pwd, ENVIRONMENT="production", LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test")

    def test_auto_generates_in_development(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = _make_settings(POSTGRES_PASSWORD="")
            assert len(s.POSTGRES_PASSWORD) > 0

    def test_warns_insecure_default_in_development(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _make_settings(POSTGRES_PASSWORD="freesdn_dev", ENVIRONMENT="development")
            warning_msgs = [str(x.message) for x in w]
            assert any("insecure default" in m for m in warning_msgs)

    def test_accepts_strong_password(self):
        s = _make_settings(
            POSTGRES_PASSWORD="super-strong-pw-9876",
            ENVIRONMENT="production",
            LOGDB_URL="postgresql+asyncpg://test:test@localhost:5432/logdb_test",
            REDIS_PASSWORD="test-redis-pw",
        )
        assert s.POSTGRES_PASSWORD == "super-strong-pw-9876"


# ── version single-source drift gate ─────────────────────────────────────────


class TestVersionSingleSource:
    """The runtime version (``app.__version__``) and the packaging version
    (``pyproject.toml``) MUST stay equal. ``app.__version__`` is the single
    human-edited source of truth; pyproject carries the same value because the
    packaging and release tooling both read it. This test fails loudly if a bump
    touches one and not the other - the exact drift that left ``__version__``
    stale at an old release before."""

    def _pyproject_version(self) -> str:
        import tomllib
        from pathlib import Path

        # tests/core/test_config.py -> backend/pyproject.toml
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        return data["tool"]["poetry"]["version"]

    def test_pyproject_matches_app_version(self):
        import app

        assert self._pyproject_version() == app.__version__, (
            "Version drift: pyproject.toml and app.__version__ disagree. "
            "Bump BOTH (they are the same release) — app/__init__.py is the "
            "source of truth, pyproject.toml mirrors it for packaging/tagging."
        )

    def test_pyproject_license_matches(self):
        import app

        import tomllib
        from pathlib import Path

        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        assert data["tool"]["poetry"]["license"] == app.__license__
