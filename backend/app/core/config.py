# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Core Settings Configuration
==========================================

Uses Pydantic Settings for environment variable management with validation.
Supports .env files and environment variable overrides.
"""

import os
from functools import lru_cache

from pydantic import PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Version + license come from the one source of truth in app/__init__.py.
# Importing the bare package is cheap (it only defines these constants) so this
# introduces no import cycle.
from app import __license__ as _APP_LICENSE
from app import __version__ as _APP_VERSION


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ===========================================
    # Application Settings
    # ===========================================
    APP_NAME: str = "FreeSDN"
    APP_VERSION: str = _APP_VERSION
    APP_LICENSE: str = _APP_LICENSE
    DEBUG: bool = False
    ENVIRONMENT: str = "development"  # development, staging, production

    # API Settings
    API_V1_PREFIX: str = "/api/v1"

    # Public base URL — the externally-reachable URL for this FreeSDN instance.
    # Set to your production domain in deployment (e.g., "https://freesdn.example.com").
    # Used to build agent WebSocket URLs and other external-facing links.
    PUBLIC_BASE_URL: str = "http://localhost:8000"

    # ===========================================
    # Multi-tenancy / SaaS
    # ===========================================
    # Per-organization tier QUOTAS (max sites/devices/users/controllers/...).
    # OFF by default: a self-hosted FreeSDN install is unlimited — the tier
    # ladder is a SaaS monetization construct and must not gate someone who
    # owns the deployment (e.g. capping a self-hoster at 1 site). A SaaS
    # operator running FreeSDN multi-tenant can opt IN by setting
    # FREESDN_ENFORCE_ORG_QUOTAS=true and assigning each org a tier via
    # ``organization.settings["tier"]``.
    ENFORCE_ORG_QUOTAS: bool = False

    # ===========================================
    # Security Settings
    # ===========================================
    SECRET_KEY: str = ""  # Required — set via FREESDN_SECRET_KEY env var
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    # "Remember me" opt-in at login extends the refresh window (and thus how
    # long the session survives without re-authentication) to this many days.
    # Defaults to 30 (matches the login UI copy). Revocation is unaffected —
    # only the expiry changes: a password change / logout-all (token_version
    # bump) and a per-device logout (UserSession.revoked_at) still end a
    # remember-me session immediately.
    REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Password Requirements
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Credential encryption salt — set via FREESDN_ENCRYPTION_SALT env var
    ENCRYPTION_SALT: str = ""

    # Self-registration (disabled by default for security)
    ALLOW_REGISTRATION: bool = False

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # ===========================================
    # Database Settings
    # ===========================================
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "freesdn"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "freesdn"

    # Connection Pool — sized for 1000+ devices / 50+ controllers
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30
    DB_POOL_TIMEOUT: int = 30

    # Computed database URL
    DATABASE_URL: PostgresDsn | None = None

    # ===========================================
    # LogDB (TimescaleDB) Settings
    # ===========================================
    LOGDB_URL: str | None = None  # Set via env: LOGDB_URL=postgresql+asyncpg://...
    LOGDB_POOL_SIZE: int = 10
    LOGDB_MAX_OVERFLOW: int = 15

    @field_validator("ENVIRONMENT", mode="before")
    @classmethod
    def _normalize_environment(cls, v: object) -> str:
        """Normalize + allowlist ENVIRONMENT so a deploy typo can't fail OPEN.

        Every production guard matches the EXACT lowercase strings
        ``"production"``/``"staging"`` (e.g. is_production, the insecure-default
        SECRET_KEY/POSTGRES_PASSWORD checks, Secure-cookie selection, Swagger
        gating). A value like ``"Production"``, ``"PROD"`` or ``"prod"``
        previously slipped past every one of them — the operator believed they
        were running hardened while actually running with development fail-open.
        Lowercasing fixes case typos; the allowlist rejects abbreviations by
        refusing to start (fail-closed) rather than silently degrading.
        """
        if v is None:
            return "development"
        normalized = str(v).strip().lower()
        allowed = {"development", "staging", "production"}
        if normalized not in allowed:
            raise ValueError(
                f"Invalid ENVIRONMENT {v!r} (normalized {normalized!r}): must be "
                f"one of {sorted(allowed)}. Refusing to start to avoid silently "
                f"running with development fail-open security in a deployment "
                f"that intended production hardening."
            )
        return normalized

    @model_validator(mode="after")
    def check_logdb_url(self) -> "Settings":
        """Require LOGDB_URL in production/staging; warn in development."""
        import warnings

        if not self.LOGDB_URL:
            if self.ENVIRONMENT in ("production", "staging"):
                raise ValueError(
                    "CRITICAL: LOGDB_URL is required. The LogDB (TimescaleDB) "
                    "database is mandatory for time-series data (metrics, health "
                    "checks, heartbeats, events). Set LOGDB_URL via environment "
                    "variable before deploying to production or staging."
                )
            warnings.warn(
                "LOGDB_URL not set — time-series features will be unavailable. "
                "Set LOGDB_URL for full functionality.",
                stacklevel=2,
            )
        return self

    @model_validator(mode="after")
    def build_database_url(self) -> "Settings":
        """Build database URL from components if not provided."""
        if self.DATABASE_URL is None:
            self.DATABASE_URL = PostgresDsn.build(
                scheme="postgresql+asyncpg",
                username=self.POSTGRES_USER,
                password=self.POSTGRES_PASSWORD,
                host=self.POSTGRES_HOST,
                port=self.POSTGRES_PORT,
                path=self.POSTGRES_DB,
            )
        return self

    @model_validator(mode="after")
    def check_secret_key(self) -> "Settings":
        """Block insecure SECRET_KEY in production/staging; auto-generate for dev."""
        import warnings

        _INSECURE_DEFAULTS = {
            "CHANGE-ME-IN-PRODUCTION-USE-STRONG-KEY",
            "CHANGE_ME_generate_a_64_char_random_string",
            "__CHANGE_ME__",  # the literal placeholder shipped in the tier .env.*.example files
            "changeme",
            "secret",
        }
        if not self.SECRET_KEY or self.SECRET_KEY in _INSECURE_DEFAULTS:
            if self.ENVIRONMENT in ("production", "staging"):
                raise ValueError(
                    "CRITICAL: SECRET_KEY is set to a default/insecure value. "
                    "Set a strong random SECRET_KEY via environment variable before "
                    "deploying to production or staging."
                )
            # Auto-generate for development
            import secrets

            self.SECRET_KEY = secrets.token_urlsafe(32)
            warnings.warn(
                "Auto-generated ephemeral SECRET_KEY for development. "
                "Set FREESDN_SECRET_KEY for persistence.",
                stacklevel=2,
            )
        if len(self.SECRET_KEY) < 32:
            if self.ENVIRONMENT in ("production", "staging"):
                raise ValueError(
                    "SECRET_KEY must be at least 32 characters for production/staging."
                )
            warnings.warn(
                "SECRET_KEY is shorter than 32 characters — use a longer key.",
                stacklevel=2,
            )
        return self

    @model_validator(mode="after")
    def check_encryption_salt(self) -> "Settings":
        """Block insecure ENCRYPTION_SALT in production/staging; auto-generate for dev."""
        import warnings

        _INSECURE_SALTS = {
            "freesdn-credential-salt-v1",
            "CHANGE_ME_generate_a_unique_salt",
            "__CHANGE_ME__",  # the literal placeholder shipped in the tier .env.*.example files
        }
        if not self.ENCRYPTION_SALT or self.ENCRYPTION_SALT in _INSECURE_SALTS:
            if self.ENVIRONMENT in ("production", "staging"):
                raise ValueError(
                    "CRITICAL: ENCRYPTION_SALT must be changed from the default "
                    "before deploying to production or staging."
                )
            # Auto-generate for development
            import secrets

            self.ENCRYPTION_SALT = secrets.token_urlsafe(16)
            warnings.warn(
                "Auto-generated ephemeral ENCRYPTION_SALT for development. "
                "Set FREESDN_ENCRYPTION_SALT for persistence.",
                stacklevel=2,
            )
        return self

    @model_validator(mode="after")
    def check_postgres_password(self) -> "Settings":
        """Block insecure POSTGRES_PASSWORD in production/staging; auto-generate for dev."""
        import warnings

        _INSECURE_PASSWORDS = {
            "freesdn_dev",
            "postgres",
            "password",
            "changeme",
            "CHANGE_ME_postgres_strong_password",
            "__CHANGE_ME__",  # the literal placeholder shipped in the tier .env.*.example files
        }
        if not self.POSTGRES_PASSWORD or self.POSTGRES_PASSWORD in _INSECURE_PASSWORDS:
            if self.ENVIRONMENT in ("production", "staging"):
                raise ValueError(
                    "CRITICAL: POSTGRES_PASSWORD is set to a default/insecure value. "
                    "Set a strong POSTGRES_PASSWORD via environment variable before "
                    "deploying to production or staging."
                )
            # Auto-generate for development
            if not self.POSTGRES_PASSWORD:
                import secrets

                self.POSTGRES_PASSWORD = secrets.token_urlsafe(16)
                warnings.warn(
                    "Auto-generated ephemeral POSTGRES_PASSWORD for development. "
                    "Set FREESDN_POSTGRES_PASSWORD for persistence.",
                    stacklevel=2,
                )
            else:
                warnings.warn(
                    "POSTGRES_PASSWORD is using an insecure default. "
                    "Set a strong POSTGRES_PASSWORD before deploying.",
                    stacklevel=2,
                )
        elif self.ENVIRONMENT in ("production", "staging") and len(self.POSTGRES_PASSWORD) < 12:
            raise ValueError(
                "POSTGRES_PASSWORD must be at least 12 characters for production/staging. "
                "The installer generates a 32-character password; set a strong value."
            )
        return self

    @model_validator(mode="after")
    def check_cors_origins(self) -> "Settings":
        """Validate CORS_ORIGINS — reject wildcards, paths, cleartext in prod.

        Rules:
          - no ``*`` wildcard
          - no ``null`` origin
          - each origin must be a full absolute URL (scheme + netloc)
          - no path, query, or fragment components
          - in production/staging, ``http://`` is only allowed for
            localhost/127.0.0.1/::1, and those hosts are then stripped
            entirely from the final list (existing behavior)
        """
        import logging as _logging
        from urllib.parse import urlparse

        is_production = self.ENVIRONMENT in ("production", "staging")

        cleaned: list[str] = []
        removed_localhost: list[str] = []

        for origin in self.CORS_ORIGINS:
            # Reject wildcards (Starlette would error later — fail early)
            if origin == "*":
                raise ValueError("CORS_ORIGINS must not contain '*' wildcard")

            # Reject null origin (rare, dangerous)
            if origin.lower() == "null":
                raise ValueError("CORS_ORIGINS must not contain 'null'")

            try:
                parsed = urlparse(origin)
            except Exception as exc:
                raise ValueError(f"invalid CORS origin URL: {origin}") from exc

            # Must have scheme + netloc
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"CORS origin must be absolute URL: {origin}")

            # Only http/https are valid CORS schemes
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"CORS origin must use http or https scheme: {origin}")

            # Must not have path or query (CORS origins are scheme+host+port only)
            if parsed.path not in ("", "/"):
                raise ValueError(f"CORS origin must not contain path: {origin}")
            if parsed.query or parsed.fragment:
                raise ValueError(f"CORS origin must not contain query/fragment: {origin}")

            host = (parsed.hostname or "").lower()

            if is_production:
                # In production, only https:// is allowed (except for
                # local loopback which is stripped below anyway).
                if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
                    raise ValueError(
                        f"CORS origin must use https:// in {self.ENVIRONMENT}: {origin}"
                    )
                # Strip localhost entirely in production (existing behavior)
                if host in {"localhost", "127.0.0.1", "::1"}:
                    removed_localhost.append(origin)
                    continue

            cleaned.append(origin)

        if is_production and removed_localhost:
            _logging.getLogger(__name__).warning(
                "SECURITY: Removed localhost CORS origins in %s: %s. "
                "Set FREESDN_CORS_ORIGINS to your production domain.",
                self.ENVIRONMENT,
                removed_localhost,
            )

        self.CORS_ORIGINS = cleaned

        if is_production and not self.CORS_ORIGINS:
            _logging.getLogger(__name__).error(
                "SECURITY: No CORS origins configured for %s! "
                "API will reject all cross-origin requests. "
                "Set FREESDN_CORS_ORIGINS to your production domain.",
                self.ENVIRONMENT,
            )

        return self

    # ===========================================
    # Redis Settings
    # ===========================================
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    REDIS_DB: int = 0
    # ── Redis/Valkey high availability (Sentinel) ──────────────────────────────
    # When REDIS_SENTINELS is set (comma-separated host:port list, e.g.
    # "redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379"),
    # every client created via app.core.redis_client resolves the current master
    # through Sentinel and therefore follows an automatic failover. Empty = a
    # single-node direct connection to REDIS_HOST (dev / lite / pro). The server
    # may be Redis or Valkey — both speak RESP and ship the same Sentinel.
    REDIS_SENTINELS: str = ""
    REDIS_MASTER_NAME: str = "freesdn-master"

    # go2rtc restream sidecar (live MSE/WebRTC). The backend registers streams
    # via this API and proxies MSE to the browser; go2rtc is not exposed publicly.
    GO2RTC_URL: str = "http://go2rtc:1984"

    # ===========================================
    # WebPush (browser push notifications for camera alerts)
    # ===========================================
    # VAPID keypair (ECDSA P-256, base64url). Generate once per deployment:
    #   python -c "from py_vapid import Vapid01; v=Vapid01(); v.generate_keys(); \
    #     import base64; \
    #     print('priv', base64.urlsafe_b64encode(v.private_key.private_numbers().private_value.to_bytes(32,'big')).decode().rstrip('=')); \
    #     print('pub',  base64.urlsafe_b64encode(v.public_key.public_bytes(... )).decode())"
    # (or `vapid --gen` from the py-vapid CLI). Leave blank to disable push.
    VAPID_PUBLIC_KEY: str = ""
    VAPID_PRIVATE_KEY: str = ""
    # ``mailto:`` (or https) contact, sent in the VAPID JWT `sub` claim.
    VAPID_SUBJECT: str = "mailto:admin@freesdn.local"

    # Camera event (alert) retention — the cameras.camera_events table grows as
    # NVRs stream alerts; a daily task prunes rows older than this.
    CAMERA_EVENT_RETENTION_DAYS: int = 90

    # Evidence archive (legal hold): durable on-disk store for exported clips kept
    # off the NVR with a SHA-256 integrity hash. Mount a persistent volume here.
    EVIDENCE_DIR: str = "/data/evidence"

    # Fabric durable-artifact store: when a Fabric write Connection stages a blob
    # (e.g. a camera snapshot bound for a TrueNAS dataset), the bytes are copied
    # here so they survive the transient ArtifactBroker TTL until an operator
    # signs off the staged change (which can be hours/days later). Mount a
    # PERSISTENT volume here in production — the default is ephemeral on a fresh
    # container and a restart would lose pending blobs.
    FABRIC_ARTIFACT_DURABLE_DIR: str = "/data/fabric_artifacts"

    # Fabric webhook trusted destinations — comma-separated hostnames / IPs that
    # the ``fabric.webhook`` operation may reach EVEN IF they are private / LAN /
    # tailnet (e.g. a self-hosted n8n, Home Assistant, Node-RED, Zapier-relay).
    # Deploy-owner controlled (NOT per-org/operator input). These are still
    # DNS-pinned + TLS-verified by the SSRF guard; cloud-metadata is NEVER
    # reachable. Empty (default) = only public destinations are allowed.
    # Example: "n8n.example.net,10.0.0.50"
    FABRIC_WEBHOOK_ALLOWED_HOSTS: str = ""

    # Optional shared secret for signing outbound ``fabric.webhook`` bodies. When
    # set, every fabric.webhook POST carries ``X-Fabric-Signature: sha256=<hmac>``
    # over the exact request body, so the receiver (n8n/Zapier/…) can verify the
    # callback genuinely came from FreeSDN and wasn't spoofed by anyone who knows
    # the webhook URL. Empty = unsigned. Rotate via the env, not in code.
    FABRIC_WEBHOOK_SIGNING_SECRET: str = ""

    # Computed Redis URL
    REDIS_URL: RedisDsn | None = None

    @model_validator(mode="after")
    def build_redis_url(self) -> "Settings":
        """Build Redis URL from components if not provided."""
        if self.ENVIRONMENT in ("production", "staging"):
            if not self.REDIS_PASSWORD:
                raise ValueError(
                    f"SECURITY: Redis password is required in {self.ENVIRONMENT}. "
                    "Set FREESDN_REDIS_PASSWORD."
                )
            if self.REDIS_PASSWORD == "__CHANGE_ME__" or len(self.REDIS_PASSWORD) < 12:
                raise ValueError(
                    f"SECURITY: REDIS_PASSWORD is a placeholder or too short in {self.ENVIRONMENT}. "
                    "Use the installer-generated value or set a strong (12+ char) password."
                )
        if self.REDIS_URL is None:
            self.REDIS_URL = RedisDsn.build(
                scheme="redis",
                password=self.REDIS_PASSWORD,
                host=self.REDIS_HOST,
                port=self.REDIS_PORT,
                path=str(self.REDIS_DB),
            )
        return self

    # ===========================================
    # Celery Settings
    # ===========================================
    CELERY_BROKER_URL: str | None = None
    CELERY_RESULT_BACKEND: str | None = None

    @model_validator(mode="after")
    def build_celery_urls(self) -> "Settings":
        """Build Celery URLs from Redis URL."""
        redis_url = str(self.REDIS_URL)
        if self.CELERY_BROKER_URL is None:
            self.CELERY_BROKER_URL = redis_url
        if self.CELERY_RESULT_BACKEND is None:
            self.CELERY_RESULT_BACKEND = redis_url
        return self

    @model_validator(mode="after")
    def warn_unauthenticated_metrics(self) -> "Settings":
        """Warn when /metrics is enabled without a token in production/staging.

        The Prometheus endpoint leaks the route inventory, in-progress-request
        gauges, and auth-failure counters to anyone who can reach the API port.
        the real fail-closed lives in ``setup_metrics`` (metrics.py),
        which only exposes the UNAUTHENTICATED ``/metrics`` endpoint in
        development — in production/staging without a token it is simply not
        served (no telemetry leak). We do NOT raise here, because /metrics is
        internal-only in the shipped compose (the API publishes no host port) and
        crashing boot would be disproportionate; an operator who wants prod
        scraping must set METRICS_AUTH_TOKEN (and point Prometheus at a
        matching bearer_token_file). This warning nudges them. Mirrors the CORS
        nudge above.
        """
        if (
            self.ENVIRONMENT in ("production", "staging")
            and self.ENABLE_METRICS
            and not self.METRICS_AUTH_TOKEN
        ):
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "SECURITY: /metrics is enabled but no METRICS_AUTH_TOKEN "
                "is set in %s — the unauthenticated endpoint will NOT be served "
                "(fail-closed). Set METRICS_AUTH_TOKEN to enable "
                "authenticated Prometheus scraping.",
                self.ENVIRONMENT,
            )
        return self

    # ===========================================
    # Feature Flags
    # ===========================================
    # Read-only / staging mode for Omada (and other adapters that use this gate).
    # When True, every write operation against an external controller is staged
    # to the local DB (adapter_pending_changes) and the controller is NOT touched.
    # Operators can review staged changes and explicitly opt in to push them in
    # a non-prod environment. Default safe-by-default for production deploys.
    OMADA_READ_ONLY: bool = True
    # Same gate, generalised — when True, writes to ANY managed controller
    # (Omada / OPNsense / Hikvision / etc.) go through staging instead of
    # touching the live device. OMADA_READ_ONLY is kept as an alias for clarity.
    ADAPTER_READ_ONLY: bool = True

    # ── VPN / connectivity mode ────────────────────────────────────────────────
    # FreeSDN is a controller, not a firewall OS — it is CAPLESS by default.
    #   off       - no VPN (default; no privileged container, matches Omada/UniFi)
    #   sidecar   - privileged vpn sidecar (docker-compose.vpn.yml + COMPOSE_PROFILES=vpn)
    #   userspace - unprivileged userspace overlay (roadmap)
    # Legacy env flags are reconciled onto this by `resolved_vpn_mode` so existing
    # deployments keep working. See docs.freesdn.org.
    VPN_MODE: str = "off"

    # Credential key-canary override. At startup the app verifies SECRET_KEY can
    # still decrypt EXISTING stored credentials; on a mismatch (wrong SECRET_KEY
    # / wrong env file) it refuses to boot in production so it never silently
    # re-encrypts new secrets under a key that can't read the old ones. Set True
    # ONLY for an intentional key rotation after the creds have been re-encrypted.
    ALLOW_CREDENTIAL_KEY_MISMATCH: bool = False

    # Backups contain decrypted secrets (controller/device credentials, config).
    # They are encrypted at rest by default (is_encrypted defaults True). In
    # production/staging a caller/policy asking for a PLAINTEXT backup is upgraded
    # to encrypted (fail-closed) unless an operator explicitly opts into the risk
    # here — e.g. for portability to a host without this SECRET_KEY.
    BACKUP_ALLOW_PLAINTEXT: bool = False

    # Ollama is a "local LLM by design", so its provider base_url historically
    # accepted any host — which let an org_admin point it at internal services
    # (Redis/Postgres/other tenants) as a blind SSRF pivot. We now block
    # private/loopback/link-local base_url hosts (resolving hostnames too) UNLESS
    # an operator who genuinely runs a local/LAN Ollama opts in here.
    AI_OLLAMA_ALLOW_PRIVATE_HOSTS: bool = False

    # Sandbox directory the Proxmox storage-upload applier may read from.
    # Stops a malicious staging payload from setting ``file_path`` to
    # ``/etc/passwd`` or ``/app/.env`` and exfiltrating arbitrary host
    # files via the Proxmox upload API.
    PROXMOX_UPLOAD_DIR: str = "/var/lib/freesdn/uploads"

    ENABLE_METRICS: bool = True
    ENABLE_DOCS: bool = True  # Swagger/ReDoc
    ENABLE_PROFILING: bool = False
    # Structural soft-delete defence (Pattern 1). When True, a global
    # do_orm_execute listener injects ``deleted_at IS NULL`` into every ORM
    # SELECT / Session.get() / relationship load against a SoftDeleteMixin
    # model, retiring the whole soft-delete-leak class at once. Opt out per
    # query with ``.execution_options(include_deleted=True)``. Defaults OFF:
    # it is a broad behavioural change that must be validated against a real
    # Postgres in staging before enabling. Bulk UPDATE/DELETE and ON CONFLICT
    # bypass the listener and must keep their explicit deleted_at filters.
    ENABLE_SOFT_DELETE_GLOBAL_FILTER: bool = False
    # when set, /metrics requires Authorization: Bearer <token>.
    # Leave empty for local/dev (metrics exposed without auth - leaks labels).
    # Generate with: openssl rand -hex 32
    METRICS_AUTH_TOKEN: str | None = None
    # High-trust plugin distribution defaults. Direct URL installs and
    # runtime dependency installation stay opt-in even for admins.
    PLUGIN_ENABLE_DIRECT_URL_INSTALLS: bool = False
    PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS: bool = False

    # ===========================================
    # Startup Behavior
    # ===========================================
    # If True, the application will refuse to start when critical subsystems
    # (event_bus, modules) fail during startup.  Non-critical subsystems
    # (automation, plugins, device_sync, dpi_rules) always degrade gracefully.
    STRICT_STARTUP: bool = False

    # Readiness probe (/health/ready) gating. By default only the per-instance
    # primary DB + critical subsystems hard-gate readiness; Redis/LogDB are
    # probed and REPORTED but do NOT 503, because hard-gating readiness on a
    # SHARED dependency makes a transient Redis blip (or the Sentinel failover
    # window) pull every instance at once → a cascading outage. Set True only if
    # you want strict readiness that also 503s when Redis/LogDB are unreachable.
    READINESS_STRICT_DEPS: bool = False

    # ===========================================
    # Logging
    # ===========================================
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text

    # ===========================================
    # Rate Limiting
    # ===========================================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "5/minute"
    # Global per-principal request limit enforced by RateLimitMiddleware.
    # Keyed by authenticated user (signature-verified JWT ``sub``) when a
    # valid access cookie is present, falling back to client IP otherwise.
    # Defaults are intentionally generous so a busy SPA (many parallel
    # XHRs) and several users behind one NAT don't hit 429s. Tune down in
    # production via env if a single principal should be throttled harder.
    # The stricter auth-endpoint limits (RATE_LIMIT_AUTH) are unaffected.
    RATE_LIMIT_RPM: int = 600
    RATE_LIMIT_BURST: int = 120

    # ===========================================
    # Audit Tamper-Evidence
    # ===========================================
    # HMAC key used to chain audit log rows. Each new audit row stores
    # ``HMAC-SHA256(AUDIT_HMAC_KEY, prev_hash || canonical_json)`` in
    # ``row_hmac`` so a later replay/UPDATE on a single row breaks the
    # chain and can be detected via ``GET /audit/validate``. This is
    # tamper-EVIDENCE, not tamper-PREVENTION — a DB admin can still
    # delete the table, but they cannot surgically edit a single row
    # without invalidating the HMAC.
    #
    # Leave unset to derive from SECRET_KEY at startup (deterministic
    # per-deployment without forcing operators to manage a second key).
    AUDIT_HMAC_KEY: str | None = None

    # ===========================================
    # Plugin Supply-Chain Hardening
    # ===========================================
    # When PLUGIN_ALLOW_RUNTIME_PYTHON_DEPS is on, pip installs for
    # plugin Python deps are run with ``--require-hashes`` and pinned to
    # this index URL. Plugins MUST ship a ``requirements.txt`` containing
    # ``--hash=sha256:...`` annotations or the install is refused.
    PLUGIN_PYPI_INDEX_URL: str = "https://pypi.org/simple/"

    @property
    def resolved_vpn_mode(self) -> str:
        """Single source of truth for the VPN mode.

        Prefers the explicit VPN_MODE setting; falls back to reconciling the
        legacy env flags (FREESDN_OPENVPN_SIDECAR / FREESDN_WIREGUARD_SIDECAR ->
        sidecar; FREESDN_VPN_AUTOSTART -> userspace) so pre-existing deployments
        keep their behavior. Returns one of: "off", "sidecar", "userspace".
        """
        mode = (self.VPN_MODE or "off").strip().lower()
        if mode in ("sidecar", "userspace"):
            return mode
        if mode not in ("off", ""):
            # unknown value -> fail safe to off
            return "off"
        truthy = ("1", "true", "yes", "on")
        if (
            os.environ.get("FREESDN_OPENVPN_SIDECAR", "").strip().lower() in truthy
            or os.environ.get("FREESDN_WIREGUARD_SIDECAR", "").strip().lower() in truthy
        ):
            return "sidecar"
        if os.environ.get("FREESDN_VPN_AUTOSTART", "").strip().lower() in truthy:
            return "userspace"
        return "off"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Export settings instance
settings = get_settings()
