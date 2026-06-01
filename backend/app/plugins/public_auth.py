# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Public Route Authentication
============================================

Security helpers for unauthenticated plugin routes such as inbound webhooks.

The model is intentionally strict:
- public access is only allowed on manifest-declared routes
- each request must carry an org-scoped HMAC signature
- signatures are timestamped and nonce-protected to block replay
- secrets are stored in PluginSetting using encrypted-at-rest helpers
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis_client import get_async_redis
from app.core.security_utils import decrypt_webhook_secret, encrypt_webhook_secret
from app.models.plugins import PluginSetting

logger = logging.getLogger(__name__)

PLUGIN_PUBLIC_ORG_HEADER = "X-FreeSDN-Plugin-Org"
PLUGIN_PUBLIC_TIMESTAMP_HEADER = "X-FreeSDN-Plugin-Timestamp"
PLUGIN_PUBLIC_NONCE_HEADER = "X-FreeSDN-Plugin-Nonce"
PLUGIN_PUBLIC_SIGNATURE_HEADER = "X-FreeSDN-Plugin-Signature"

PLUGIN_PUBLIC_SECRET_SETTING_KEY = "__public_webhook_secret:encrypted"
PLUGIN_PUBLIC_REPLAY_PREFIX = "plugin:public:nonce:"
PLUGIN_PUBLIC_MAX_SKEW_SECONDS = 300
PLUGIN_PUBLIC_NONCE_MIN_LENGTH = 16
PLUGIN_PUBLIC_NONCE_MAX_LENGTH = 128

_redis_client: aioredis.Redis | None = None


@dataclass(frozen=True)
class PublicPluginRequest:
    organization_id: UUID
    timestamp: int
    nonce: str


class PublicPluginAuthError(HTTPException):
    """Structured authentication error for public plugin routes."""

    def __init__(
        self,
        detail: str,
        *,
        status_code: int = status.HTTP_401_UNAUTHORIZED,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail)


async def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = get_async_redis(decode_responses=True)
    return _redis_client


def _canonical_message(
    *,
    timestamp: int,
    nonce: str,
    method: str,
    path: str,
    query: str,
    organization_id: UUID,
    body: bytes,
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join(
        [
            str(timestamp),
            nonce,
            method.upper(),
            path,
            query,
            str(organization_id),
            body_hash,
        ]
    )


def sign_public_plugin_request(
    secret: str,
    *,
    timestamp: int,
    nonce: str,
    method: str,
    path: str,
    query: str,
    organization_id: UUID,
    body: bytes,
) -> str:
    """Create the canonical HMAC signature for a public plugin request."""
    message = _canonical_message(
        timestamp=timestamp,
        nonce=nonce,
        method=method,
        path=path,
        query=query,
        organization_id=organization_id,
        body=body,
    )
    digest = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


async def get_public_webhook_secret(
    session: AsyncSession,
    plugin_id: str,
    organization_id: UUID,
) -> str | None:
    """Return the decrypted public webhook secret for the plugin/org pair."""
    result = await session.execute(
        select(PluginSetting).where(
            PluginSetting.plugin_id == plugin_id,
            PluginSetting.organization_id == organization_id,
            PluginSetting.key == PLUGIN_PUBLIC_SECRET_SETTING_KEY,
        )
    )
    row = result.scalar_one_or_none()
    if row is None or row.value is None:
        return None
    return decrypt_webhook_secret(str(row.value))


async def rotate_public_webhook_secret(
    session: AsyncSession,
    plugin_id: str,
    organization_id: UUID,
) -> str:
    """Generate and persist a new HMAC secret for public plugin routes."""
    secret = secrets.token_urlsafe(48)
    encrypted = encrypt_webhook_secret(secret)
    result = await session.execute(
        select(PluginSetting).where(
            PluginSetting.plugin_id == plugin_id,
            PluginSetting.organization_id == organization_id,
            PluginSetting.key == PLUGIN_PUBLIC_SECRET_SETTING_KEY,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        session.add(
            PluginSetting(
                plugin_id=plugin_id,
                organization_id=organization_id,
                key=PLUGIN_PUBLIC_SECRET_SETTING_KEY,
                value=encrypted,
            )
        )
    else:
        row.value = encrypted
    return secret


def normalize_public_route_path(path: str) -> str:
    """Normalize a plugin-local public route path for manifest matching."""
    normalized = path.rstrip("/")
    if not normalized:
        return "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


async def verify_public_plugin_request(
    request: Request,
    session: AsyncSession,
    plugin_id: str,
) -> PublicPluginRequest:
    """Verify the HMAC headers for an unauthenticated public plugin request."""
    org_header = request.headers.get(PLUGIN_PUBLIC_ORG_HEADER)
    timestamp_header = request.headers.get(PLUGIN_PUBLIC_TIMESTAMP_HEADER)
    nonce = request.headers.get(PLUGIN_PUBLIC_NONCE_HEADER)
    signature = request.headers.get(PLUGIN_PUBLIC_SIGNATURE_HEADER)

    if org_header is None or timestamp_header is None or nonce is None or signature is None:
        raise PublicPluginAuthError(
            "Public plugin routes require signed HMAC headers",
        )

    try:
        organization_id = UUID(str(org_header))
    except ValueError as exc:
        raise PublicPluginAuthError("Invalid plugin organization header") from exc

    try:
        timestamp = int(timestamp_header)
    except ValueError as exc:
        raise PublicPluginAuthError("Invalid plugin timestamp header") from exc

    now = int(time.time())
    if abs(now - timestamp) > PLUGIN_PUBLIC_MAX_SKEW_SECONDS:
        raise PublicPluginAuthError("Plugin request timestamp is outside the allowed window")

    if not (PLUGIN_PUBLIC_NONCE_MIN_LENGTH <= len(nonce) <= PLUGIN_PUBLIC_NONCE_MAX_LENGTH):
        raise PublicPluginAuthError("Plugin nonce length is invalid")

    secret = await get_public_webhook_secret(session, plugin_id, organization_id)
    if secret is None:
        raise PublicPluginAuthError("No public webhook secret is configured for this organization")

    body = await request.body()
    expected_signature = sign_public_plugin_request(
        secret,
        timestamp=timestamp,
        nonce=nonce,
        method=request.method,
        path=request.url.path,
        query=request.url.query,
        organization_id=organization_id,
        body=body,
    )
    if not hmac.compare_digest(expected_signature, signature):
        raise PublicPluginAuthError("Plugin request signature verification failed")

    replay_key = f"{PLUGIN_PUBLIC_REPLAY_PREFIX}{plugin_id}:{organization_id}:{nonce}"
    try:
        redis = await _get_redis()
        accepted = await redis.set(
            replay_key,
            "1",
            ex=PLUGIN_PUBLIC_MAX_SKEW_SECONDS,
            nx=True,
        )
    except Exception as exc:
        logger.warning(
            "Public plugin replay check failed for %s/%s",
            plugin_id,
            organization_id,
            exc_info=True,
        )
        raise PublicPluginAuthError(
            "Public plugin replay protection is unavailable",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from exc

    if not accepted:
        raise PublicPluginAuthError("Plugin request replay detected")

    return PublicPluginRequest(
        organization_id=organization_id,
        timestamp=timestamp,
        nonce=nonce,
    )
