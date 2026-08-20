# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Notification Service
===================================

Multi-channel notification system with templates and preferences.

Features:
- Email notifications (SMTP, SendGrid, SES)
- Slack/Teams webhooks
- In-app notifications
- Template rendering with Jinja2
- User notification preferences
- Delivery tracking
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

# ---------------------------------------------------------------------------
# Email header injection hardening
# ---------------------------------------------------------------------------
# Any CR, LF, or NUL byte inside a header value allows an attacker to inject
# additional headers ("BCC: attacker@evil.tld", a fresh message body, etc.).
# We reject these characters outright rather than trying to encode them.
_EMAIL_HEADER_INJECTION_PATTERN = re.compile(r"[\r\n\x00]")


def _sanitize_header_value(value: str, max_length: int = 998) -> str:
    """Sanitize a value for use in an email header.

    Rejects newlines (CR/LF) and NUL bytes which are used for header
    injection. Truncates to ``max_length`` characters (default 998, the
    RFC 5322 line length limit).
    """
    if not isinstance(value, str):
        raise ValueError(f"Email header value must be a string, got {type(value).__name__}")
    if _EMAIL_HEADER_INJECTION_PATTERN.search(value):
        raise ValueError(
            "Email header value contains newline or NUL byte (header injection attempt)"
        )
    return value[:max_length]


def _validate_email_address(address: str) -> str:
    """Validate an email address and return it sanitized.

    Performs injection-safe sanitization then a permissive RFC 5322 shape
    check via :func:`email.utils.parseaddr`.
    """
    # RFC 5321 caps a complete path at 256 octets; we allow a little more slack
    # for display-name + angle-addr forms commonly used in From headers.
    sanitized = _sanitize_header_value(address, max_length=320)

    from email.utils import parseaddr

    _name, addr = parseaddr(sanitized)
    if not addr or "@" not in addr:
        raise ValueError(f"Invalid email address: {address!r}")
    # Re-check the parsed components for injection, just in case parseaddr
    # ever returns unsanitized content.
    if _EMAIL_HEADER_INJECTION_PATTERN.search(addr):
        raise ValueError("Email address contains newline or NUL byte (header injection attempt)")
    return addr


import jinja2
from jinja2 import BaseLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from sqlalchemy import and_, func, select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.core.security_utils import safe_http_request
from app.models.notification import (
    InAppNotification,
    NotificationDelivery,
    NotificationPreference,
    NotificationProviderRecord,
)

logger = logging.getLogger(__name__)

# Notification template directory
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "notifications"
_TEMPLATE_CACHE: dict[str, dict[str, Any]] = {}


def _load_notification_templates(locale: str = "en") -> dict[str, Any]:
    """Load notification templates for the given locale, with English fallback."""
    if locale in _TEMPLATE_CACHE:
        return _TEMPLATE_CACHE[locale]

    template_file = _TEMPLATES_DIR / f"{locale}.json"
    if not template_file.exists():
        # Fallback to English
        template_file = _TEMPLATES_DIR / "en.json"
        if not template_file.exists():
            return {}

    try:
        with open(template_file, encoding="utf-8") as f:
            templates = json.load(f)
        _TEMPLATE_CACHE[locale] = templates
        return templates
    except Exception as e:
        logger.error("Failed to load notification templates for locale '%s': %s", locale, e)
        return {}


# =============================================================================
# Enums
# =============================================================================


class NotificationChannel(StrEnum):
    """Notification delivery channels."""

    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    IN_APP = "in_app"
    SMS = "sms"
    WHATSAPP = "whatsapp"


class NotificationSeverity(StrEnum):
    """Notification severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationCategory(StrEnum):
    """Notification categories."""

    SYSTEM = "system"
    SECURITY = "security"
    DEVICE = "device"
    NETWORK = "network"
    ALERT = "alert"
    USER = "user"
    BILLING = "billing"


class DeliveryStatus(StrEnum):
    """Notification delivery status.

    SKIPPED is returned (with ``success=True``) when a channel send was
    intentionally suppressed by user preferences, category mute, quiet
    hours, or similar policy gates. Analytics MUST bucket SKIPPED
    separately from SENT — counting skips as "delivered" inflates the
    success rate. See ``NotificationService.send()`` for the gate points.
    """

    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"
    SKIPPED = "skipped"


# =============================================================================
# Exceptions
# =============================================================================


class NotificationError(Exception):
    """Base notification error."""

    pass


class DeliveryError(NotificationError):
    """Delivery failed error."""

    pass


class ProviderError(NotificationError):
    """Provider configuration error."""

    pass


class TemplateError(NotificationError):
    """Template rendering error."""

    pass


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class NotificationPayload:
    """Notification content payload."""

    title: str
    body: str
    body_html: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    action_url: str | None = None
    action_text: str | None = None


@dataclass
class DeliveryResult:
    """Result of a notification delivery attempt."""

    success: bool
    channel: NotificationChannel
    status: DeliveryStatus
    message_id: str | None = None
    error: str | None = None
    provider_response: dict[str, Any] | None = None
    # NOTE: Provider type string (e.g. "smtp", "slack_webhook", "gmail_smtp")
    # used to populate ``NotificationDelivery.provider``. Each runtime
    # provider sets this before returning so analytics can break down
    # delivery success rates by provider. Previously this field did not
    # exist and ``_track_delivery`` raised AttributeError on every send,
    # silently breaking delivery tracking.
    provider: str | None = None


@dataclass
class NotificationPreferences:
    """User notification preferences.

    ``category_settings`` holds per-category overrides as JSONB-shape, including
    mute state, e.g.::

        {
          "security": {"muted_until": "2026-06-01T00:00:00+00:00"},
          "billing":  {"muted_until": null},  # permanent mute
        }

    A category is considered muted when an entry exists and either
    ``muted_until`` is ``null`` (permanent) or is a future ISO-8601 timestamp.
    Past timestamps mean the snooze has expired (effectively unmuted).
    """

    user_id: UUID
    enabled_channels: list[NotificationChannel] = field(default_factory=list)
    category_settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    quiet_hours: tuple[int, int] | None = None  # (start_hour, end_hour)
    email: str | None = None
    slack_user_id: str | None = None

    def is_category_muted(self, category: str | None) -> tuple[bool, str | None]:
        """Return ``(muted, reason)`` for a given category.

        ``muted_until=null`` -> permanently muted.
        Future ISO-8601 timestamp -> snoozed until that point.
        Past timestamp / missing entry -> not muted.
        """
        if not category:
            return False, None
        entry = self.category_settings.get(category) or {}
        if "muted_until" not in entry:
            return False, None
        muted_until_raw = entry.get("muted_until")
        if muted_until_raw is None:
            return True, f"category '{category}' permanently muted"
        try:
            muted_until = datetime.fromisoformat(str(muted_until_raw))
        except (TypeError, ValueError):
            return False, None
        if muted_until.tzinfo is None:
            muted_until = muted_until.replace(tzinfo=UTC)
        if muted_until > datetime.now(UTC):
            return True, f"category '{category}' snoozed until {muted_until.isoformat()}"
        return False, None

    def is_in_quiet_hours(self, now: datetime | None = None) -> bool:
        """Return True if ``now`` falls inside the user's quiet-hours window.

        Quiet hours that wrap midnight (e.g. 22:00 → 07:00) are handled.
        """
        if self.quiet_hours is None:
            return False
        start, end = self.quiet_hours
        current = (now or datetime.now(UTC)).hour
        if start == end:
            return False
        if start < end:
            return start <= current < end
        # Wraps midnight
        return current >= start or current < end


# =============================================================================
# Template Renderer
# =============================================================================


class TemplateRenderer:
    """Jinja2-based notification template renderer."""

    def __init__(self):
        self.env = SandboxedEnvironment(
            loader=BaseLoader(),
            autoescape=select_autoescape(["html"]),
            undefined=jinja2.StrictUndefined,
        )
        # Add custom filters
        self.env.filters["datetime"] = self._format_datetime
        self.env.filters["truncate"] = self._truncate

    @staticmethod
    def _format_datetime(value: Any, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        if isinstance(value, datetime):
            return value.strftime(fmt)
        return str(value)

    @staticmethod
    def _truncate(value: str, length: int = 100) -> str:
        if len(value) > length:
            return value[: length - 3] + "..."
        return value

    def render(self, template_str: str, variables: dict[str, Any]) -> str:
        """Render a template string with variables."""
        try:
            template = self.env.from_string(template_str)
            return template.render(**variables)
        except Exception as e:
            logger.error("Template rendering error: %s", e)
            raise TemplateError(f"Failed to render template: {e}")

    def render_notification(
        self,
        title_template: str,
        body_template: str,
        body_html_template: str | None,
        variables: dict[str, Any],
    ) -> NotificationPayload:
        """Render a full notification from templates."""
        title = self.render(title_template, variables)
        body = self.render(body_template, variables)
        body_html = None
        if body_html_template:
            body_html = self.render(body_html_template, variables)

        return NotificationPayload(
            title=title,
            body=body,
            body_html=body_html,
            data=variables,
        )


# =============================================================================
# Notification Providers
# =============================================================================


class NotificationProvider:
    """Base class for notification providers."""

    channel: NotificationChannel
    # Identifier persisted on NotificationDelivery.provider so analytics
    # can attribute deliveries to a specific provider type. Subclasses
    # override.
    provider_type: str = "unknown"
    #: Set by NotificationService._attach_limits when built from a DB record.
    #: Zero or None means "no limit", which is what an unconfigured provider
    #: and every legacy in-memory provider get.
    provider_record_id: UUID | None = None
    rate_limit_per_hour: int = 0
    rate_limit_per_day: int = 0

    def __init__(self, config: dict[str, Any]):
        self.config = config

    async def send(
        self,
        recipient: str,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send a notification."""
        raise NotImplementedError

    async def verify(self) -> tuple[bool, str]:
        """Verify provider configuration."""
        raise NotImplementedError


# Per-socket and whole-conversation bounds for the blocking SMTP client.
# Neither existed on the send path, so a silent SMTP host froze the worker.
_SMTP_TIMEOUT_SECONDS = 10
_SMTP_TOTAL_TIMEOUT_SECONDS = 30


class SMTPProvider(NotificationProvider):
    """SMTP email provider."""

    channel = NotificationChannel.EMAIL
    provider_type = "smtp"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.from_email = config.get("from_email")
        self.from_name = config.get("from_name", "FreeSDN")
        self.use_tls = config.get("use_tls", True)

    async def send(
        self,
        recipient: str,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send email via SMTP.

        All user-controlled header fields (recipient, sender, subject,
        display name) are sanitized against header injection
        before being placed into the :class:`EmailMessage`. The message is
        dispatched via ``send_message`` (never raw string concatenation) so
        that the standard library handles header encoding.
        """
        try:
            import smtplib
            from email.message import EmailMessage

            # --- sanitize every user-supplied header field ----------------
            safe_recipient = _validate_email_address(recipient)
            safe_from_email = _validate_email_address(self.from_email or "")
            safe_from_name = _sanitize_header_value(self.from_name or "", max_length=255)
            safe_subject = _sanitize_header_value(payload.title or "", max_length=255)

            msg = EmailMessage()
            msg["Subject"] = safe_subject
            # ``EmailMessage`` will properly quote the display name.
            if safe_from_name:
                msg["From"] = f"{safe_from_name} <{safe_from_email}>"
            else:
                msg["From"] = safe_from_email
            msg["To"] = safe_recipient

            # Bodies are safe — only headers are injectable.
            msg.set_content(payload.body or "")
            if payload.body_html:
                msg.add_alternative(payload.body_html, subtype="html")

            # smtplib is BLOCKING, and this is an async method running on the
            # event loop. Two things were wrong with calling it directly:
            #
            #  * No timeout. smtplib.SMTP() with timeout=None waits on the
            #    socket indefinitely, so an SMTP host that accepts the TCP
            #    connection and then goes quiet -- a firewall blackhole, an
            #    overloaded relay, a greylister -- froze the ENTIRE worker.
            #    Not just notifications: every request that worker was serving,
            #    forever, with no error and nothing in the logs.
            #  * Even bounded, a multi-second SMTP conversation on the loop
            #    stalls every other coroutine for its duration.
            #
            # verify() ten lines below already passed timeout=10, which is what
            # makes the omission here an oversight rather than a policy.
            #
            # to_thread moves the whole conversation off the loop; the timeout
            # bounds the socket itself.
            def _deliver() -> None:
                with smtplib.SMTP(self.host, self.port, timeout=_SMTP_TIMEOUT_SECONDS) as server:
                    if self.use_tls:
                        server.starttls()
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.send_message(
                        msg,
                        from_addr=safe_from_email,
                        to_addrs=[safe_recipient],
                    )

            # Outer bound too: a timeout on the socket does not cover a server
            # that trickles one byte at a time through a long conversation.
            await asyncio.wait_for(
                asyncio.to_thread(_deliver),
                timeout=_SMTP_TOTAL_TIMEOUT_SECONDS,
            )

            return DeliveryResult(
                success=True,
                channel=self.channel,
                status=DeliveryStatus.SENT,
                message_id=str(uuid4()),
                provider=self.provider_type,
            )
        except Exception as e:
            logger.error("SMTP delivery failed: %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=str(e),
                provider=self.provider_type,
            )

    async def verify(self) -> tuple[bool, str]:
        """Verify SMTP configuration."""
        try:
            import smtplib

            def _probe() -> None:
                with smtplib.SMTP(self.host, self.port, timeout=_SMTP_TIMEOUT_SECONDS) as server:
                    if self.use_tls:
                        server.starttls()
                    if self.username and self.password:
                        server.login(self.username, self.password)

            # Same reasoning as send(): bounded, and off the event loop.
            await asyncio.wait_for(asyncio.to_thread(_probe), timeout=_SMTP_TOTAL_TIMEOUT_SECONDS)
            return True, "SMTP connection successful"
        except Exception as e:
            return False, f"SMTP error: {e}"


class GmailOAuthProvider(NotificationProvider):
    """Google Gmail OAuth2 email provider.

    Uses Gmail API via OAuth2 refresh-token flow so users can send email
    directly from their own Gmail account without an app-specific password.

    Required config:
      - client_id        – Google OAuth2 client ID
      - client_secret     – Google OAuth2 client secret
      - refresh_token     – Long-lived OAuth2 refresh token
      - from_email        – Sender address (the Gmail account)

    Optional:
      - from_name         – Display name (default "FreeSDN")
    """

    channel = NotificationChannel.EMAIL
    provider_type = "google_gmail"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.client_id = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")
        self.refresh_token = config.get("refresh_token", "")
        self.from_email = config.get("from_email", "")
        self.from_name = config.get("from_name", "FreeSDN")
        self._access_token: str = ""

    # -- helpers -----------------------------------------------------------

    def _validate_config(self) -> str | None:
        """Return an error string if required config is missing, else None."""
        if not self.client_id:
            return "Missing client_id"
        if not self.client_secret:
            return "Missing client_secret"
        if not self.refresh_token:
            return "Missing refresh_token"
        if not self.from_email or "@" not in self.from_email:
            return "Missing or invalid from_email"
        return None

    async def _get_access_token(self, force_refresh: bool = False) -> str:
        """Exchange the refresh token for a fresh access token."""
        if self._access_token and not force_refresh:
            return self._access_token

        # DNS-rebinding-safe request
        resp = await safe_http_request(
            "POST",
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        return self._access_token

    @staticmethod
    def _build_raw_email(
        from_email: str,
        from_name: str,
        to: str,
        subject: str,
        body_plain: str,
        body_html: str | None = None,
    ) -> str:
        """Build a RFC 5322 email and return its base64url-encoded form.

        All user-controlled header fields are sanitized against header
        injection before being placed into the ``EmailMessage``.
        """
        import base64
        from email.message import EmailMessage

        safe_from_email = _validate_email_address(from_email or "")
        safe_to = _validate_email_address(to)
        safe_from_name = _sanitize_header_value(from_name or "", max_length=255)
        safe_subject = _sanitize_header_value(subject or "", max_length=255)

        msg = EmailMessage()
        msg["Subject"] = safe_subject
        if safe_from_name:
            msg["From"] = f"{safe_from_name} <{safe_from_email}>"
        else:
            msg["From"] = safe_from_email
        msg["To"] = safe_to
        msg.set_content(body_plain or "")
        if body_html:
            msg.add_alternative(body_html, subtype="html")
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        return raw

    # -- send / verify -----------------------------------------------------

    async def send(
        self,
        recipient: str,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send email via Gmail API (users.messages.send)."""
        # Validate config before attempting network calls
        config_err = self._validate_config()
        if config_err:
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=f"Gmail config error: {config_err}",
                provider=self.provider_type,
            )
        try:
            raw = self._build_raw_email(
                from_email=self.from_email,
                from_name=self.from_name,
                to=recipient,
                subject=payload.title,
                body_plain=payload.body,
                body_html=payload.body_html,
            )

            gmail_send_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
            token = await self._get_access_token()
            # DNS-rebinding-safe request
            resp = await safe_http_request(
                "POST",
                gmail_send_url,
                headers={"Authorization": f"Bearer {token}"},
                json={"raw": raw},
                timeout=30.0,
            )

            # Retry once on 401 (expired cached token)
            if resp.status_code == 401:
                token = await self._get_access_token(force_refresh=True)
                resp = await safe_http_request(
                    "POST",
                    gmail_send_url,
                    headers={"Authorization": f"Bearer {token}"},
                    json={"raw": raw},
                    timeout=30.0,
                )

            resp.raise_for_status()
            data = resp.json()

            return DeliveryResult(
                success=True,
                channel=self.channel,
                status=DeliveryStatus.SENT,
                message_id=data.get("id", str(uuid4())),
                provider=self.provider_type,
            )
        except Exception as e:
            logger.error("Gmail API delivery failed for %s: %s", self.from_email, type(e).__name__)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=str(e),
                provider=self.provider_type,
            )

    async def verify(self) -> tuple[bool, str]:
        """Verify Gmail OAuth2 credentials by fetching the user profile."""
        config_err = self._validate_config()
        if config_err:
            return False, f"Gmail config error: {config_err}"
        try:
            token = await self._get_access_token(force_refresh=True)
            # DNS-rebinding-safe request
            resp = await safe_http_request(
                "GET",
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15.0,
            )
            resp.raise_for_status()
            profile = resp.json()
            email = profile.get("emailAddress", "unknown")
            return True, f"Gmail OAuth2 verified — authenticated as {email}"
        except Exception as e:
            return False, f"Gmail OAuth2 error: {type(e).__name__}: {e}"


class SlackProvider(NotificationProvider):
    """Slack webhook provider."""

    channel = NotificationChannel.SLACK
    provider_type = "slack_webhook"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.default_channel = config.get("channel", "#alerts")

    async def send(
        self,
        recipient: str,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send notification via Slack webhook."""
        try:
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": payload.title}},
                {"type": "section", "text": {"type": "mrkdwn", "text": payload.body}},
            ]

            if payload.action_url:
                blocks.append(
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": payload.action_text or "View",
                                },
                                "url": payload.action_url,
                            }
                        ],
                    }
                )

            slack_payload = {
                "channel": recipient or self.default_channel,
                "blocks": blocks,
            }

            # DNS-rebinding-safe request
            response = await safe_http_request(
                "POST",
                self.webhook_url,
                json=slack_payload,
                timeout=15.0,
            )
            response.raise_for_status()

            return DeliveryResult(
                success=True,
                channel=self.channel,
                status=DeliveryStatus.SENT,
                message_id=str(uuid4()),
                provider=self.provider_type,
            )
        except ValueError as e:
            logger.warning("Slack webhook URL blocked (SSRF): %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=f"Webhook URL blocked (SSRF): {e}",
                provider=self.provider_type,
            )
        except Exception as e:
            logger.error("Slack delivery failed: %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=str(e),
                provider=self.provider_type,
            )

    async def verify(self) -> tuple[bool, str]:
        """Verify Slack webhook."""
        try:
            # DNS-rebinding-safe request
            response = await safe_http_request(
                "POST",
                self.webhook_url,
                json={"text": "FreeSDN verification test"},
                timeout=15.0,
            )
            if response.status_code == 200:
                return True, "Slack webhook verified"
            return False, f"Slack returned: {response.text}"
        except ValueError as e:
            return False, f"Slack webhook URL blocked (SSRF): {e}"
        except Exception as e:
            return False, f"Slack error: {e}"


class WebhookProvider(NotificationProvider):
    """Generic webhook provider."""

    channel = NotificationChannel.WEBHOOK
    provider_type = "generic_webhook"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.url = config.get("url")
        self.headers = config.get("headers", {})
        self.secret = config.get("secret")

    async def send(
        self,
        recipient: str,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send notification via webhook."""
        try:
            import hashlib
            import hmac

            body = json.dumps(
                {
                    "title": payload.title,
                    "body": payload.body,
                    "data": payload.data,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )

            headers = dict(self.headers)
            headers["Content-Type"] = "application/json"

            # Add signature if secret configured
            if self.secret:
                signature = hmac.new(
                    self.secret.encode(),
                    body.encode(),
                    hashlib.sha256,
                ).hexdigest()
                headers["X-Signature"] = f"sha256={signature}"

            # DNS-rebinding-safe request
            response = await safe_http_request(
                "POST",
                self.url,
                content=body,
                headers=headers,
                timeout=30.0,
            )
            response.raise_for_status()

            return DeliveryResult(
                success=True,
                channel=self.channel,
                status=DeliveryStatus.SENT,
                message_id=str(uuid4()),
                provider_response={"status_code": response.status_code},
                provider=self.provider_type,
            )
        except ValueError as e:
            logger.warning("Webhook URL blocked (SSRF): %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=f"Webhook URL blocked (SSRF): {e}",
                provider=self.provider_type,
            )
        except Exception as e:
            logger.error("Webhook delivery failed: %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=str(e),
                provider=self.provider_type,
            )

    async def verify(self) -> tuple[bool, str]:
        """Verify webhook endpoint.

        This used to return ``True`` for ANY status code that came back, so a
        404, a 500 or an auth-rejecting 403 all set ``is_verified`` and showed
        the provider as Verified in the UI. That is worse than not verifying:
        the operator gets a green check on an endpoint that will drop every
        alert. The Slack and Teams verifies right beside it already checked the
        status; this one did not.

        OPTIONS is the right probe -- it must not deliver a real notification --
        but plenty of endpoints answer it with 405 while accepting POST
        perfectly well, so 405 counts as reachable. 501 likewise: it means
        "method not implemented", not "endpoint absent".
        """
        if not self.url:
            return False, "No webhook URL configured"
        try:
            # DNS-rebinding-safe request
            response = await safe_http_request("OPTIONS", self.url, timeout=15.0)
        except ValueError as e:
            return False, f"Webhook URL blocked (SSRF): {e}"
        except Exception as e:
            return False, f"Webhook error: {e}"

        code = response.status_code
        if code < 400 or code in (405, 501):
            return True, f"Webhook reachable (status: {code})"
        if code in (401, 403):
            return False, f"Webhook rejected the request (HTTP {code}) — check the URL secret"
        return False, f"Webhook returned HTTP {code}"


class TeamsProvider(NotificationProvider):
    """Microsoft Teams incoming-webhook provider (Adaptive Card)."""

    channel = NotificationChannel.TEAMS
    provider_type = "teams_webhook"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.theme_color = config.get("theme_color", "#0078D4")

    async def send(
        self,
        recipient: str,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        try:
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": self.theme_color,
                "summary": payload.title,
                "sections": [
                    {
                        "activityTitle": payload.title,
                        "text": payload.body_html or payload.body,
                        "markdown": True,
                    }
                ],
            }
            if payload.action_url:
                card["potentialAction"] = [
                    {
                        "@type": "OpenUri",
                        "name": payload.action_text or "View",
                        "targets": [{"os": "default", "uri": payload.action_url}],
                    }
                ]

            # DNS-rebinding-safe request
            response = await safe_http_request("POST", self.webhook_url, json=card, timeout=15.0)
            response.raise_for_status()

            return DeliveryResult(
                success=True,
                channel=self.channel,
                status=DeliveryStatus.SENT,
                message_id=str(uuid4()),
                provider=self.provider_type,
            )
        except ValueError as e:
            logger.warning("Teams webhook URL blocked (SSRF): %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=f"Webhook URL blocked (SSRF): {e}",
                provider=self.provider_type,
            )
        except Exception as e:
            logger.error("Teams delivery failed: %s", e)
            return DeliveryResult(
                success=False,
                channel=self.channel,
                status=DeliveryStatus.FAILED,
                error=str(e),
                provider=self.provider_type,
            )

    async def verify(self) -> tuple[bool, str]:
        try:
            # DNS-rebinding-safe request
            response = await safe_http_request(
                "POST",
                self.webhook_url,
                json={
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": "FreeSDN verification",
                    "text": "FreeSDN connectivity test — you can ignore this.",
                },
                timeout=15.0,
            )
            if response.status_code in (200, 202):
                return True, "Teams webhook verified"
            return False, f"Teams returned HTTP {response.status_code}"
        except ValueError as e:
            return False, f"Teams webhook URL blocked (SSRF): {e}"
        except Exception as e:
            return False, f"Teams error: {e}"


# =============================================================================
# Transactional email + SMS providers
# =============================================================================
#
# Every type below was ADVERTISED in `get_provider_catalog` with a complete,
# provider-specific config schema (Mailgun wants an api_key + domain + region,
# SendGrid a bearer key, SES a SigV4 credential pair, Twilio an account SID),
# and each one was then built as a bare `WebhookProvider`.
#
# WebhookProvider reads exactly one config key: `url`. None of these schemas
# has a `url` field, so `self.url` was always None and every send hit
# `safe_http_request("POST", None, ...)`, raised, and returned
# `DeliveryResult(success=False)`. Eight of the fifteen offered provider types
# could be configured, enabled, marked default and shown as healthy in the UI,
# and could never deliver a single message. The failure only surfaced at the
# moment an alert actually needed to go out.
#
# The generic body WebhookProvider posts (`{title, body, data, timestamp}`) is
# not a shape any of these APIs accept either, so a URL alone would not have
# been enough — each needs its own request. These classes are that request,
# written against each vendor's documented API and the config schema the
# catalogue already collects.
#
# HONESTY NOTE, in the spirit of `app/adapters/maturity.py`: these are
# implemented against published API specifications and covered by tests that
# pin the exact wire shape. They are NOT live-validated against a real vendor
# account — nobody here holds one. `verify()` is what proves a given
# deployment's credentials work, and it makes a real authenticated call rather
# than returning True.


class _HTTPEmailProvider(NotificationProvider):
    """Shared plumbing for the HTTP-API email providers.

    Subclasses supply `_endpoint()`, `_headers()` and `_body()`. Everything
    else -- header sanitisation, the SSRF-safe request, success classification,
    error shaping -- is identical across vendors and belongs in one place.
    """

    channel = NotificationChannel.EMAIL
    #: Status codes the vendor returns for "accepted for delivery".
    accepted_statuses: tuple[int, ...] = (200, 201, 202)

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.from_email = config.get("from_email") or ""
        self.from_name = config.get("from_name") or "FreeSDN"

    # -- subclass contract ------------------------------------------------

    def _endpoint(self) -> str:
        raise NotImplementedError

    def _headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        """Return kwargs for the request (`json=` or `data=`)."""
        raise NotImplementedError

    def _missing_config(self) -> str | None:
        """Name the first required setting that is absent, if any."""
        if not self.from_email:
            return "from_email"
        return None

    # -- shared behaviour -------------------------------------------------

    def _safe_fields(self, recipient: str, payload: NotificationPayload) -> tuple[str, str, str]:
        """Validated recipient / from / subject, same rules as SMTPProvider."""
        return (
            _validate_email_address(recipient),
            _validate_email_address(self.from_email),
            _sanitize_header_value(payload.title or "", max_length=255),
        )

    async def send(self, recipient: str, payload: NotificationPayload) -> DeliveryResult:
        missing = self._missing_config()
        if missing:
            # Loud and specific. The whole point of this class is that a
            # misconfigured provider must not look like a transient send
            # failure the retry queue will eventually resolve.
            return self._failure(f"{self.provider_type} is missing required setting: {missing}")
        # Build the request FIRST, in its own guard. _safe_fields raises
        # ValueError on a header-injection attempt, and folding that into the
        # request's own except would report an injection attempt as an SSRF
        # block -- the wrong incident in the operator's log.
        try:
            request_kwargs = self._body(recipient, payload)
        except ValueError as e:
            return self._failure(f"{self.provider_type} rejected the message: {e}")

        try:
            response = await safe_http_request(
                "POST",
                self._endpoint(),
                headers=self._headers(),
                timeout=30.0,
                **request_kwargs,
            )
        except ValueError as e:
            return self._failure(f"{self.provider_type} endpoint blocked (SSRF): {e}")
        except Exception as e:
            logger.error("%s delivery failed: %s", self.provider_type, e)
            return self._failure(str(e))

        if response.status_code not in self.accepted_statuses:
            # A 4xx here is a real refusal -- unverified sender, bad key, over
            # quota -- and the operator needs the vendor's own words for it.
            return self._failure(
                f"{self.provider_type} returned HTTP {response.status_code}: "
                f"{self._response_text(response)[:500]}"
            )

        return DeliveryResult(
            success=True,
            channel=self.channel,
            status=DeliveryStatus.SENT,
            message_id=self._message_id(response),
            provider_response={"status_code": response.status_code},
            provider=self.provider_type,
        )

    @staticmethod
    def _response_text(response: Any) -> str:
        try:
            return response.text or ""
        except Exception:
            return ""

    def _message_id(self, response: Any) -> str:
        """The vendor's own id when it gives one, so a bounce can be traced."""
        try:
            data = response.json()
        except Exception:
            return str(uuid4())
        if isinstance(data, dict):
            for key in ("id", "MessageID", "messageId", "message-id"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    return value
        return str(uuid4())

    def _failure(self, error: str) -> DeliveryResult:
        return DeliveryResult(
            success=False,
            channel=self.channel,
            status=DeliveryStatus.FAILED,
            error=error,
            provider=self.provider_type,
        )

    async def verify(self) -> tuple[bool, str]:
        """Prove the credential works, without sending mail to anyone.

        Subclasses that have a cheap authenticated read override
        `_verify_request`. The default reports what is missing rather than
        claiming success it has not established.
        """
        missing = self._missing_config()
        if missing:
            return False, f"Missing required setting: {missing}"
        probe = self._verify_request()
        if probe is None:
            return True, f"{self.provider_type} configuration is complete"
        method, url, kwargs = probe
        try:
            response = await safe_http_request(method, url, timeout=15.0, **kwargs)
        except ValueError as e:
            return False, f"Endpoint blocked (SSRF): {e}"
        except Exception as e:
            return False, f"{self.provider_type} error: {e}"
        if response.status_code in (200, 201, 202, 204):
            return True, f"{self.provider_type} credentials verified"
        if response.status_code in (401, 403):
            return (
                False,
                f"{self.provider_type} rejected the credentials (HTTP {response.status_code})",
            )
        return False, f"{self.provider_type} returned HTTP {response.status_code}"

    def _verify_request(self) -> tuple[str, str, dict[str, Any]] | None:
        return None


class MailgunProvider(_HTTPEmailProvider):
    """Mailgun Messages API (form-encoded, HTTP basic auth as ``api:<key>``)."""

    provider_type = "mailgun"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key") or ""
        self.domain = config.get("domain") or ""
        # Mailgun runs two independent stacks; a EU-region key is rejected by
        # the US host, which is why the catalogue asks for the region.
        self.region = (config.get("region") or "us").lower()

    @property
    def _base(self) -> str:
        host = "api.eu.mailgun.net" if self.region == "eu" else "api.mailgun.net"
        return f"https://{host}/v3"

    def _missing_config(self) -> str | None:
        for name, value in (("api_key", self.api_key), ("domain", self.domain)):
            if not value:
                return name
        return super()._missing_config()

    def _endpoint(self) -> str:
        return f"{self._base}/{self.domain}/messages"

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"api:{self.api_key}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        to, sender, subject = self._safe_fields(recipient, payload)
        name = _sanitize_header_value(self.from_name, max_length=255)
        data = {
            "from": f"{name} <{sender}>" if name else sender,
            "to": to,
            "subject": subject,
            "text": payload.body or "",
        }
        if payload.body_html:
            data["html"] = payload.body_html
        return {"data": data}

    def _verify_request(self) -> tuple[str, str, dict[str, Any]] | None:
        # Cheapest authenticated read that also proves the domain exists.
        return ("GET", f"{self._base}/domains/{self.domain}", {"headers": self._headers()})


class SendGridProvider(_HTTPEmailProvider):
    """SendGrid v3 Mail Send API."""

    provider_type = "sendgrid"
    accepted_statuses = (200, 202)

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key") or ""

    def _missing_config(self) -> str | None:
        if not self.api_key:
            return "api_key"
        return super()._missing_config()

    def _endpoint(self) -> str:
        return "https://api.sendgrid.com/v3/mail/send"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        to, sender, subject = self._safe_fields(recipient, payload)
        content = [{"type": "text/plain", "value": payload.body or ""}]
        if payload.body_html:
            # SendGrid requires content parts in increasing MIME preference.
            content.append({"type": "text/html", "value": payload.body_html})
        return {
            "json": {
                "personalizations": [{"to": [{"email": to}]}],
                "from": {
                    "email": sender,
                    "name": _sanitize_header_value(self.from_name, max_length=255),
                },
                "subject": subject,
                "content": content,
            }
        }

    def _verify_request(self) -> tuple[str, str, dict[str, Any]] | None:
        return (
            "GET",
            "https://api.sendgrid.com/v3/scopes",
            {"headers": {"Authorization": f"Bearer {self.api_key}"}},
        )


class BrevoProvider(_HTTPEmailProvider):
    """Brevo (formerly Sendinblue) transactional email API."""

    provider_type = "brevo"
    accepted_statuses = (200, 201, 202)

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key") or ""

    def _missing_config(self) -> str | None:
        if not self.api_key:
            return "api_key"
        return super()._missing_config()

    def _endpoint(self) -> str:
        return "https://api.brevo.com/v3/smtp/email"

    def _headers(self) -> dict[str, str]:
        return {"api-key": self.api_key, "Content-Type": "application/json"}

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        to, sender, subject = self._safe_fields(recipient, payload)
        body: dict[str, Any] = {
            "sender": {
                "email": sender,
                "name": _sanitize_header_value(self.from_name, max_length=255),
            },
            "to": [{"email": to}],
            "subject": subject,
            "textContent": payload.body or "",
        }
        if payload.body_html:
            body["htmlContent"] = payload.body_html
        return {"json": body}

    def _verify_request(self) -> tuple[str, str, dict[str, Any]] | None:
        return ("GET", "https://api.brevo.com/v3/account", {"headers": {"api-key": self.api_key}})


class PostmarkProvider(_HTTPEmailProvider):
    """Postmark single-send API."""

    provider_type = "postmark"
    accepted_statuses = (200,)

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.server_token = config.get("server_token") or ""
        self.message_stream = config.get("message_stream") or "outbound"

    def _missing_config(self) -> str | None:
        if not self.server_token:
            return "server_token"
        return super()._missing_config()

    def _endpoint(self) -> str:
        return "https://api.postmarkapp.com/email"

    def _headers(self) -> dict[str, str]:
        return {
            "X-Postmark-Server-Token": self.server_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        to, sender, subject = self._safe_fields(recipient, payload)
        name = _sanitize_header_value(self.from_name, max_length=255)
        body: dict[str, Any] = {
            "From": f"{name} <{sender}>" if name else sender,
            "To": to,
            "Subject": subject,
            "TextBody": payload.body or "",
            "MessageStream": self.message_stream,
        }
        if payload.body_html:
            body["HtmlBody"] = payload.body_html
        return {"json": body}

    def _verify_request(self) -> tuple[str, str, dict[str, Any]] | None:
        return (
            "GET",
            "https://api.postmarkapp.com/server",
            {
                "headers": {
                    "X-Postmark-Server-Token": self.server_token,
                    "Accept": "application/json",
                }
            },
        )


class ResendProvider(_HTTPEmailProvider):
    """Resend email API."""

    provider_type = "resend"
    accepted_statuses = (200, 201, 202)

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key") or ""

    def _missing_config(self) -> str | None:
        if not self.api_key:
            return "api_key"
        return super()._missing_config()

    def _endpoint(self) -> str:
        return "https://api.resend.com/emails"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        to, sender, subject = self._safe_fields(recipient, payload)
        name = _sanitize_header_value(self.from_name, max_length=255)
        body: dict[str, Any] = {
            "from": f"{name} <{sender}>" if name else sender,
            "to": [to],
            "subject": subject,
            "text": payload.body or "",
        }
        if payload.body_html:
            body["html"] = payload.body_html
        return {"json": body}

    def _verify_request(self) -> tuple[str, str, dict[str, Any]] | None:
        return (
            "GET",
            "https://api.resend.com/domains",
            {"headers": {"Authorization": f"Bearer {self.api_key}"}},
        )


class AmazonSESProvider(_HTTPEmailProvider):
    """Amazon SES v2 SendEmail, signed with SigV4.

    SES is the only provider here that cannot authenticate with a static
    header: every request carries a signature over its own method, path, query,
    headers, body and timestamp. The signing below is the documented SigV4
    algorithm, kept inline rather than pulling boto3 in for one call.
    """

    provider_type = "amazon_ses"
    accepted_statuses = (200,)
    _SERVICE = "ses"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.access_key_id = config.get("access_key_id") or ""
        self.secret_access_key = config.get("secret_access_key") or ""
        self.region = config.get("region") or "us-east-1"
        self.configuration_set = config.get("configuration_set") or ""

    def _missing_config(self) -> str | None:
        for name, value in (
            ("access_key_id", self.access_key_id),
            ("secret_access_key", self.secret_access_key),
            ("region", self.region),
        ):
            if not value:
                return name
        return super()._missing_config()

    @property
    def _host(self) -> str:
        return f"email.{self.region}.amazonaws.com"

    _PATH = "/v2/email/outbound-emails"

    def _endpoint(self) -> str:
        return f"https://{self._host}{self._PATH}"

    def _headers(self) -> dict[str, str]:
        # Signed per-request in _body, which is the only place the payload
        # (and therefore its hash) is known.
        return {}

    @staticmethod
    def _sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode(), hashlib.sha256).digest()

    def _sigv4_headers(self, body: str, now: datetime) -> dict[str, str]:
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body.encode()).hexdigest()

        canonical_headers = (
            f"content-type:application/json\n"
            f"host:{self._host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date"
        canonical_request = "\n".join(
            ["POST", self._PATH, "", canonical_headers, signed_headers, payload_hash]
        )

        scope = f"{date_stamp}/{self.region}/{self._SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )

        k_date = self._sign(f"AWS4{self.secret_access_key}".encode(), date_stamp)
        k_region = self._sign(k_date, self.region)
        k_service = self._sign(k_region, self._SERVICE)
        k_signing = self._sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        return {
            "Content-Type": "application/json",
            "X-Amz-Date": amz_date,
            "X-Amz-Content-Sha256": payload_hash,
            "Authorization": (
                f"AWS4-HMAC-SHA256 Credential={self.access_key_id}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}"
            ),
        }

    def _body(self, recipient: str, payload: NotificationPayload) -> dict[str, Any]:
        to, sender, subject = self._safe_fields(recipient, payload)
        name = _sanitize_header_value(self.from_name, max_length=255)
        content: dict[str, Any] = {
            "Simple": {
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": payload.body or "", "Charset": "UTF-8"}},
            }
        }
        if payload.body_html:
            content["Simple"]["Body"]["Html"] = {"Data": payload.body_html, "Charset": "UTF-8"}
        request: dict[str, Any] = {
            "FromEmailAddress": f"{name} <{sender}>" if name else sender,
            "Destination": {"ToAddresses": [to]},
            "Content": content,
        }
        if self.configuration_set:
            request["ConfigurationSetName"] = self.configuration_set

        raw = json.dumps(request, separators=(",", ":"))
        return {"content": raw, "headers": self._sigv4_headers(raw, datetime.now(UTC))}

    async def send(self, recipient: str, payload: NotificationPayload) -> DeliveryResult:
        # _body already carries the signed headers; passing _headers() as well
        # would overwrite them with an empty dict.
        missing = self._missing_config()
        if missing:
            return self._failure(f"{self.provider_type} is missing required setting: {missing}")
        try:
            kwargs = self._body(recipient, payload)
        except ValueError as e:
            return self._failure(f"{self.provider_type} rejected the message: {e}")

        try:
            response = await safe_http_request("POST", self._endpoint(), timeout=30.0, **kwargs)
        except ValueError as e:
            return self._failure(f"{self.provider_type} endpoint blocked (SSRF): {e}")
        except Exception as e:
            logger.error("%s delivery failed: %s", self.provider_type, e)
            return self._failure(str(e))

        if response.status_code not in self.accepted_statuses:
            return self._failure(
                f"{self.provider_type} returned HTTP {response.status_code}: "
                f"{self._response_text(response)[:500]}"
            )
        return DeliveryResult(
            success=True,
            channel=self.channel,
            status=DeliveryStatus.SENT,
            message_id=self._message_id(response),
            provider_response={"status_code": response.status_code},
            provider=self.provider_type,
        )

    def _message_id(self, response: Any) -> str:
        try:
            data = response.json()
        except Exception:
            return str(uuid4())
        if isinstance(data, dict):
            value = data.get("MessageId")
            if isinstance(value, str) and value:
                return value
        return str(uuid4())


class TwilioSMSProvider(NotificationProvider):
    """Twilio Messages API (form-encoded, HTTP basic auth)."""

    channel = NotificationChannel.SMS
    provider_type = "twilio_sms"
    #: Prefix Twilio requires on the To/From addresses for this channel.
    address_prefix = ""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.account_sid = config.get("account_sid") or ""
        self.auth_token = config.get("auth_token") or ""
        self.from_number = config.get("from_number") or ""

    def _missing_config(self) -> str | None:
        for name, value in (
            ("account_sid", self.account_sid),
            ("auth_token", self.auth_token),
            ("from_number", self.from_number),
        ):
            if not value:
                return name
        return None

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self.account_sid}:{self.auth_token}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _address(self, number: str) -> str:
        """Apply the channel prefix, without doubling one already present."""
        number = number.strip()
        if not self.address_prefix or number.startswith(self.address_prefix):
            return number
        return f"{self.address_prefix}{number}"

    def _failure(self, error: str) -> DeliveryResult:
        return DeliveryResult(
            success=False,
            channel=self.channel,
            status=DeliveryStatus.FAILED,
            error=error,
            provider=self.provider_type,
        )

    async def send(self, recipient: str, payload: NotificationPayload) -> DeliveryResult:
        missing = self._missing_config()
        if missing:
            return self._failure(f"{self.provider_type} is missing required setting: {missing}")

        # SMS is one field: title and body run together, capped at the
        # concatenated-segment limit so Twilio does not reject the request.
        text = " ".join(part for part in (payload.title, payload.body) if part).strip()
        try:
            response = await safe_http_request(
                "POST",
                f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json",
                headers=self._headers(),
                data={
                    "To": self._address(recipient),
                    "From": self._address(self.from_number),
                    "Body": text[:1600],
                },
                timeout=30.0,
            )
        except ValueError as e:
            return self._failure(f"{self.provider_type} endpoint blocked (SSRF): {e}")
        except Exception as e:
            logger.error("%s delivery failed: %s", self.provider_type, e)
            return self._failure(str(e))

        if response.status_code not in (200, 201):
            try:
                detail = response.text or ""
            except Exception:
                detail = ""
            return self._failure(
                f"{self.provider_type} returned HTTP {response.status_code}: {detail[:500]}"
            )

        message_id = str(uuid4())
        try:
            data = response.json()
            if isinstance(data, dict) and isinstance(data.get("sid"), str):
                message_id = data["sid"]
        except Exception:
            pass
        return DeliveryResult(
            success=True,
            channel=self.channel,
            status=DeliveryStatus.SENT,
            message_id=message_id,
            provider_response={"status_code": response.status_code},
            provider=self.provider_type,
        )

    async def verify(self) -> tuple[bool, str]:
        missing = self._missing_config()
        if missing:
            return False, f"Missing required setting: {missing}"
        try:
            response = await safe_http_request(
                "GET",
                f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}.json",
                headers=self._headers(),
                timeout=15.0,
            )
        except ValueError as e:
            return False, f"Endpoint blocked (SSRF): {e}"
        except Exception as e:
            return False, f"{self.provider_type} error: {e}"
        if response.status_code == 200:
            return True, "Twilio credentials verified"
        if response.status_code in (401, 403):
            return False, "Twilio rejected the Account SID / Auth Token"
        return False, f"Twilio returned HTTP {response.status_code}"


class TwilioWhatsAppProvider(TwilioSMSProvider):
    """Twilio WhatsApp — same API, addresses prefixed ``whatsapp:``."""

    channel = NotificationChannel.WHATSAPP
    provider_type = "twilio_whatsapp"
    address_prefix = "whatsapp:"


# =============================================================================
# Notification Service
# =============================================================================


class NotificationService:
    """
    Multi-channel notification service.

    Features:
    - Multiple providers per channel
    - Template rendering
    - User preferences
    - Delivery tracking
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.renderer = TemplateRenderer()
        self._providers: dict[NotificationChannel, NotificationProvider] = {}

    def register_provider(
        self,
        channel: NotificationChannel,
        provider: NotificationProvider,
    ) -> None:
        """Register a notification provider for a channel."""
        self._providers[channel] = provider
        logger.info("Registered provider for channel: %s", channel)

    def configure_providers(self, config: dict[str, dict[str, Any]]) -> None:
        """Configure providers from settings."""
        if smtp_config := config.get("smtp"):
            self.register_provider(
                NotificationChannel.EMAIL,
                SMTPProvider(smtp_config),
            )

        if slack_config := config.get("slack"):
            self.register_provider(
                NotificationChannel.SLACK,
                SlackProvider(slack_config),
            )

        if webhook_config := config.get("webhook"):
            self.register_provider(
                NotificationChannel.WEBHOOK,
                WebhookProvider(webhook_config),
            )

    # =========================================================================
    # Sending Notifications
    # =========================================================================

    async def send(
        self,
        channel: NotificationChannel,
        recipient: str,
        title: str,
        body: str,
        body_html: str | None = None,
        data: dict[str, Any] | None = None,
        action_url: str | None = None,
        action_text: str | None = None,
        user_id: UUID | None = None,
        organization_id: UUID | None = None,
        category: str | None = None,
        severity: str | None = None,
    ) -> DeliveryResult:
        """
        Send a notification through a specific channel.

        Args:
            channel: Delivery channel
            recipient: Recipient address (email, channel, URL, etc.)
            title: Notification title
            body: Plain text body
            body_html: HTML body (optional)
            data: Additional data
            action_url: Action button URL
            action_text: Action button text
            user_id: Target user ID (for preferences/tracking)
            organization_id: Organization context
            category: Optional category for preference/mute checks.
            severity: Optional severity. Critical+ severities route through
                push/SMS during quiet hours; lower severities are suppressed.

        Returns:
            DeliveryResult. ``status == DeliveryStatus.SKIPPED`` (with
            ``success=True``) when suppressed by user preferences,
            category mute, or quiet hours. Analytics bucket SKIPPED
            separately from SENT.
        """
        provider = self._providers.get(channel)
        if not provider:
            return DeliveryResult(
                success=False,
                channel=channel,
                status=DeliveryStatus.FAILED,
                error=f"No provider configured for channel: {channel}",
            )

        payload = NotificationPayload(
            title=title,
            body=body,
            body_html=body_html,
            data=data or {},
            action_url=action_url,
            action_text=action_text,
        )

        # Check user preferences (channel-disabled / category-muted / quiet-hours).
        # When any gate fires we return a SKIPPED result with success=True so
        # callers do not retry, but analytics can bucket skips separately
        # from successful sends. _track_delivery records SKIPPED rows too,
        # giving ops visibility into mute volume.
        if user_id:
            prefs = await self._get_user_preferences(user_id)
            if prefs:
                if channel not in prefs.enabled_channels:
                    skip = DeliveryResult(
                        success=True,
                        channel=channel,
                        status=DeliveryStatus.SKIPPED,
                        message_id=None,
                        error=f"Channel {channel.value} disabled in user preferences",
                    )
                    await self._track_delivery(
                        user_id=user_id,
                        organization_id=organization_id,
                        channel=channel,
                        result=skip,
                        payload=payload,
                        category_override=category,
                        severity_override=severity,
                    )
                    return skip
                muted, reason = prefs.is_category_muted(category)
                if muted:
                    skip = DeliveryResult(
                        success=True,
                        channel=channel,
                        status=DeliveryStatus.SKIPPED,
                        message_id=None,
                        error=reason or f"Category '{category}' muted",
                    )
                    await self._track_delivery(
                        user_id=user_id,
                        organization_id=organization_id,
                        channel=channel,
                        result=skip,
                        payload=payload,
                        category_override=category,
                        severity_override=severity,
                    )
                    return skip
                # Quiet hours: suppress non-urgent channels. Critical
                # severity may still page via SMS / push; lower
                # severities are skipped on email/in-app/slack/teams.
                if prefs.is_in_quiet_hours():
                    is_critical = (severity or "").lower() in {"critical", "error"}
                    urgent_channels = {NotificationChannel.SMS, NotificationChannel.WHATSAPP}
                    if not (is_critical and channel in urgent_channels):
                        skip = DeliveryResult(
                            success=True,
                            channel=channel,
                            status=DeliveryStatus.SKIPPED,
                            message_id=None,
                            error="Suppressed during user quiet hours",
                        )
                        await self._track_delivery(
                            user_id=user_id,
                            organization_id=organization_id,
                            channel=channel,
                            result=skip,
                            payload=payload,
                            category_override=category,
                            severity_override=severity,
                        )
                        return skip

        # Spend cap, checked immediately before the send so nothing slips
        # between the check and the call.
        limited = await self._rate_limit_exceeded(provider)
        if limited:
            capped = DeliveryResult(
                success=False,
                channel=channel,
                status=DeliveryStatus.FAILED,
                error=f"Provider {limited}",
                provider=getattr(provider, "provider_type", None),
            )
            await self._track_delivery(
                user_id=user_id,
                organization_id=organization_id,
                channel=channel,
                result=capped,
                payload=payload,
                category_override=category,
                severity_override=severity,
            )
            return capped

        # Send
        result = await provider.send(recipient, payload)

        # Track delivery
        await self._track_delivery(
            user_id=user_id,
            organization_id=organization_id,
            channel=channel,
            result=result,
            payload=payload,
            category_override=category,
            severity_override=severity,
        )

        return result

    async def send_template(
        self,
        template_id: str,
        channel: NotificationChannel,
        recipient: str,
        variables: dict[str, Any],
        user_id: UUID | None = None,
        organization_id: UUID | None = None,
        locale: str = "en",
    ) -> DeliveryResult:
        """
        Send a notification using a template.

        Args:
            template_id: Template identifier
            channel: Delivery channel
            recipient: Recipient address
            variables: Template variables
            user_id: Target user ID
            organization_id: Organization context
            locale: Locale for template translation (default: en)

        Returns:
            DeliveryResult
        """
        template = await self._get_template(template_id, locale=locale)
        if not template:
            return DeliveryResult(
                success=False,
                channel=channel,
                status=DeliveryStatus.FAILED,
                error=f"Template not found: {template_id}",
            )

        # Render template
        payload = self.renderer.render_notification(
            title_template=template.get("title", "Notification"),
            body_template=template.get("body", ""),
            body_html_template=template.get("body_html"),
            variables=variables,
        )

        return await self.send(
            channel=channel,
            recipient=recipient,
            title=payload.title,
            body=payload.body,
            body_html=payload.body_html,
            data=variables,
            user_id=user_id,
            organization_id=organization_id,
        )

    async def send_multi_channel(
        self,
        channels: list[NotificationChannel],
        recipients: dict[NotificationChannel, str],
        title: str,
        body: str,
        body_html: str | None = None,
        user_id: UUID | None = None,
        organization_id: UUID | None = None,
    ) -> dict[NotificationChannel, DeliveryResult]:
        """Send notification through multiple channels."""
        results = {}
        for channel in channels:
            recipient = recipients.get(channel)
            if recipient:
                results[channel] = await self.send(
                    channel=channel,
                    recipient=recipient,
                    title=title,
                    body=body,
                    body_html=body_html,
                    user_id=user_id,
                    organization_id=organization_id,
                )
        return results

    # =========================================================================
    # In-App Notifications
    # =========================================================================

    async def create_in_app(
        self,
        user_id: UUID,
        title: str,
        body: str,
        category: NotificationCategory = NotificationCategory.SYSTEM,
        severity: NotificationSeverity = NotificationSeverity.INFO,
        action_url: str | None = None,
        data: dict[str, Any] | None = None,
        organization_id: UUID | None = None,
        commit: bool = True,
    ) -> dict[str, Any]:
        """
        Create an in-app notification.

        These are stored in the database and retrieved by the frontend.

        NOTE: ``commit`` defaults to ``True``. Previously this method only
        called ``db.flush()`` and never committed — when invoked from an
        event-bus handler running on its own short-lived session, the
        session would close without committing and the INSERT was rolled
        back. Callers participating in a larger transaction can pass
        ``commit=False`` to defer the commit to the outer caller.
        """
        notification = {
            "id": str(uuid4()),
            "user_id": str(user_id),
            "title": title,
            "body": body,
            "category": category.value,
            "severity": severity.value,
            "action_url": action_url,
            "data": data or {},
            "read": False,
            "created_at": datetime.now(UTC).isoformat(),
        }

        # Persist to database
        record = InAppNotification(
            user_id=user_id,
            organization_id=organization_id,
            title=title,
            body=body,
            category=category.value,
            severity=severity.value,
            action_url=action_url,
            data=data or {},
        )
        try:
            self.db.add(record)
            await self.db.flush()
            notification["id"] = str(record.id)
            if commit:
                await self.db.commit()
        except Exception as exc:
            logger.error("Failed to persist in-app notification: %s", exc)
            if commit:
                with __import__("contextlib").suppress(Exception):
                    await self.db.rollback()

        # Publish via event bus for real-time delivery.
        # NOTE: EventBus.publish() takes a single Event dataclass — the
        # previous call passed a string + dict (kwargs of an older API)
        # which raised TypeError. The error was swallowed by the caller's
        # blanket ``except Exception`` so real-time WebSocket delivery of
        # notifications was silently broken.
        from app.core.events import (
            Event,
            EventCategory,
            EventPriority,
            get_event_bus,
        )

        try:
            severity_priority = (
                EventPriority.CRITICAL
                if severity == NotificationSeverity.CRITICAL
                else EventPriority.HIGH
                if severity == NotificationSeverity.ERROR
                else EventPriority.NORMAL
            )
            bus = get_event_bus()
            await bus.publish(
                Event(
                    event_type="notification.created",
                    category=EventCategory.USER,
                    priority=severity_priority,
                    payload={
                        "notification": notification,
                        "user_id": str(user_id),
                    },
                    organization_id=str(organization_id) if organization_id else None,
                )
            )
        except Exception as exc:
            logger.warning("Failed to publish notification event: %s", exc)

        logger.info("In-app notification created for user %s", user_id)
        return notification

    async def get_in_app_notifications(
        self,
        user_id: UUID,
        unread_only: bool = False,
        limit: int = 20,
        offset: int = 0,
        include_dismissed: bool = False,
    ) -> dict[str, Any]:
        """Get paginated in-app notifications for a user.

        Returns ``{items, total, limit, offset, unread_count}``. Previously
        returned a bare list — the envelope is required for the bell
        drawer to know when to stop paging and for the badge to stay in
        sync without a separate roundtrip.

        - ``include_dismissed=False`` (default) returns Active items only.
        - ``include_dismissed=True`` returns dismissed (Archive) rows only.

        ``total`` reflects the count matching the active filter (so the
        Active tab and Archive tab show their own totals). ``unread_count``
        is always the global unread count for the badge.
        """
        conditions = [InAppNotification.user_id == user_id]
        if include_dismissed:
            conditions.append(InAppNotification.dismissed == True)  # noqa: E712
        else:
            conditions.append(InAppNotification.dismissed == False)  # noqa: E712
        if unread_only:
            conditions.append(InAppNotification.read == False)  # noqa: E712

        # Total matching the filter (for pagination terminus on the FE).
        total_q = select(func.count(InAppNotification.id)).where(and_(*conditions))
        total = (await self.db.execute(total_q)).scalar() or 0

        result = await self.db.execute(
            select(InAppNotification)
            .where(and_(*conditions))
            .order_by(InAppNotification.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = result.scalars().all()

        items = [
            {
                "id": str(r.id),
                "user_id": str(r.user_id),
                "title": r.title,
                "body": r.body,
                "category": r.category,
                "severity": r.severity,
                "action_url": r.action_url,
                "data": r.data or {},
                "read": r.read,
                "dismissed": r.dismissed,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
        unread_count = await self.get_unread_count(user_id)
        return {
            "items": items,
            "total": int(total),
            "limit": limit,
            "offset": offset,
            "unread_count": unread_count,
        }

    async def mark_read(
        self,
        notification_id: UUID,
        user_id: UUID,
    ) -> bool:
        """Mark a notification as read."""
        result = await self.db.execute(
            sa_update(InAppNotification)
            .where(
                InAppNotification.id == notification_id,
                InAppNotification.user_id == user_id,
            )
            .values(read=True, read_at=datetime.now(UTC))
        )
        return (result.rowcount or 0) > 0

    async def mark_all_read(self, user_id: UUID) -> int:
        """Mark all notifications as read for a user."""
        result = await self.db.execute(
            sa_update(InAppNotification)
            .where(
                InAppNotification.user_id == user_id,
                InAppNotification.read == False,  # noqa: E712
            )
            .values(read=True, read_at=datetime.now(UTC))
        )
        return result.rowcount or 0

    async def get_unread_count(self, user_id: UUID) -> int:
        """Get count of unread notifications for a user."""
        result = await self.db.execute(
            select(func.count(InAppNotification.id)).where(
                InAppNotification.user_id == user_id,
                InAppNotification.read == False,  # noqa: E712
                InAppNotification.dismissed == False,  # noqa: E712
            )
        )
        return result.scalar() or 0

    async def dismiss(self, notification_id: UUID, user_id: UUID) -> bool:
        """Dismiss a notification (mark as dismissed/hidden)."""
        result = await self.db.execute(
            sa_update(InAppNotification)
            .where(
                InAppNotification.id == notification_id,
                InAppNotification.user_id == user_id,
            )
            .values(dismissed=True)
        )
        return (result.rowcount or 0) > 0

    # =========================================================================
    # User Preferences
    # =========================================================================

    async def _get_user_preferences(
        self,
        user_id: UUID,
    ) -> NotificationPreferences | None:
        """Get notification preferences for a user."""
        result = await self.db.execute(
            select(NotificationPreference).where(NotificationPreference.user_id == user_id)
        )
        record = result.scalar_one_or_none()
        if not record:
            return None

        channels = []
        for ch in record.enabled_channels or []:
            try:
                channels.append(NotificationChannel(ch))
            except ValueError:
                continue

        quiet = None
        if record.quiet_hours:
            start = record.quiet_hours.get("start")
            end = record.quiet_hours.get("end")
            if start is not None and end is not None:
                quiet = (start, end)

        return NotificationPreferences(
            user_id=user_id,
            enabled_channels=channels or list(NotificationChannel),
            category_settings=record.category_settings or {},
            quiet_hours=quiet,
        )

    # =========================================================================
    # Mute / Snooze API
    # =========================================================================

    async def mute_categories(
        self,
        user_id: UUID,
        categories: list[str],
        expires_at: datetime | None,
    ) -> dict[str, Any]:
        """Mute one or more notification categories.

        ``expires_at=None`` → permanent mute. A timezone-aware datetime
        snoozes until that point; past timestamps are rejected.

        Stored in ``NotificationPreference.category_settings`` JSONB as::

            {category: {"muted_until": "<iso8601>" | null}}

        Returns the updated muted-categories map (sanitized for response).
        """
        if not categories:
            raise ValueError("At least one category is required")
        if expires_at is not None:
            # Normalize to UTC and reject past timestamps.
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at <= datetime.now(UTC):
                raise ValueError("expires_at must be in the future")
        result = await self.db.execute(
            select(NotificationPreference).where(NotificationPreference.user_id == user_id)
        )
        record = result.scalar_one_or_none()
        if record is None:
            record = NotificationPreference(
                user_id=user_id,
                enabled_channels=[c.value for c in NotificationChannel],
                category_settings={},
            )
            self.db.add(record)
            await self.db.flush()

        settings = dict(record.category_settings or {})
        muted_until_value = expires_at.isoformat() if expires_at else None
        for cat in categories:
            entry = dict(settings.get(cat) or {})
            entry["muted_until"] = muted_until_value
            settings[cat] = entry
        # Reassign to trigger SQLAlchemy change tracking on JSONB.
        record.category_settings = settings
        record.updated_at = datetime.now(UTC)
        try:
            await self.db.flush()
        except Exception as exc:
            logger.error("Failed to persist mute state: %s", exc)
            raise
        return {
            "muted_categories": {
                c: {"muted_until": (settings[c] or {}).get("muted_until")} for c in categories
            },
        }

    async def unmute_category(
        self,
        user_id: UUID,
        category: str,
    ) -> bool:
        """Remove the mute entry for a single category.

        Returns True if a mute entry existed and was removed.
        """
        result = await self.db.execute(
            select(NotificationPreference).where(NotificationPreference.user_id == user_id)
        )
        record = result.scalar_one_or_none()
        if record is None or not record.category_settings:
            return False
        settings = dict(record.category_settings)
        entry = settings.get(category)
        if not entry or "muted_until" not in entry:
            return False
        # Drop only the mute key — preserve other per-category overrides.
        new_entry = {k: v for k, v in entry.items() if k != "muted_until"}
        if new_entry:
            settings[category] = new_entry
        else:
            settings.pop(category, None)
        record.category_settings = settings
        record.updated_at = datetime.now(UTC)
        try:
            await self.db.flush()
        except Exception as exc:
            logger.error("Failed to persist unmute: %s", exc)
            raise
        return True

    async def update_preferences(
        self,
        user_id: UUID,
        enabled_channels: list[NotificationChannel] | None = None,
        category_settings: dict[str, dict[str, Any]] | None = None,
        quiet_hours: tuple[int, int] | None = None,
    ) -> NotificationPreferences:
        """Update user notification preferences."""
        prefs = NotificationPreferences(
            user_id=user_id,
            enabled_channels=enabled_channels or list(NotificationChannel),
            category_settings=category_settings or {},
            quiet_hours=quiet_hours,
        )

        # Upsert to database
        result = await self.db.execute(
            select(NotificationPreference).where(NotificationPreference.user_id == user_id)
        )
        record = result.scalar_one_or_none()
        if not record:
            record = NotificationPreference(user_id=user_id)
            self.db.add(record)

        record.enabled_channels = [ch.value for ch in prefs.enabled_channels]
        record.category_settings = prefs.category_settings
        record.quiet_hours = (
            {"start": quiet_hours[0], "end": quiet_hours[1]} if quiet_hours else None
        )
        record.updated_at = datetime.now(UTC)

        try:
            await self.db.flush()
        except Exception as exc:
            logger.error("Failed to persist notification preferences: %s", exc)

        return prefs

    # =========================================================================
    # Templates
    # =========================================================================

    async def _get_template(self, template_id: str, locale: str = "en") -> dict[str, Any] | None:
        """Get a notification template with locale support.

        Loads templates from app/templates/notifications/{locale}.json.
        Falls back to English if the requested locale file doesn't exist.
        """
        templates = _load_notification_templates(locale)
        template = templates.get(template_id)
        if template is None and locale != "en":
            # Fallback to English for missing individual templates
            en_templates = _load_notification_templates("en")
            template = en_templates.get(template_id)
        return template

    # =========================================================================
    # Delivery Tracking
    # =========================================================================

    async def _track_delivery(
        self,
        user_id: UUID | None,
        organization_id: UUID | None,
        channel: NotificationChannel,
        result: DeliveryResult,
        payload: NotificationPayload,
        category_override: str | None = None,
        severity_override: str | None = None,
    ) -> None:
        """Track notification delivery for analytics.

        ``category_override`` / ``severity_override`` take precedence over
        the values embedded in ``payload.data``; callers should pass them
        explicitly so SKIPPED rows record the policy that suppressed the
        send rather than falling back to ``"system"`` / ``"info"``.
        """
        record = NotificationDelivery(
            user_id=user_id,
            organization_id=organization_id,
            channel=channel.value,
            category=(
                category_override
                or (payload.data.get("category") if payload.data else None)
                or "system"
            ),
            severity=(
                severity_override
                or (payload.data.get("severity") if payload.data else None)
                or "info"
            ),
            subject=payload.title,
            success=result.success,
            status=result.status,
            error_message=result.error,
            provider=result.provider,
            message_id=result.message_id,
        )
        try:
            self.db.add(record)
            await self.db.flush()
        except Exception as exc:
            logger.error("Failed to track notification delivery: %s", exc)

        logger.debug(
            f"Notification delivery: channel={channel}, "
            f"success={result.success}, status={result.status}"
        )

    # =========================================================================
    # Provider Management (persistent CRUD)
    # =========================================================================

    # ---- Provider type registry -------------------------------------------

    PROVIDER_TYPES: list[dict[str, Any]] = [
        {
            "type": "smtp",
            "name": "SMTP Email",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "host": {
                    "type": "string",
                    "label": "SMTP Host",
                    "required": True,
                    "placeholder": "smtp.example.com",
                },
                "port": {"type": "number", "label": "Port", "required": True, "default": 587},
                "username": {"type": "string", "label": "Username", "required": False},
                "password": {"type": "password", "label": "Password", "required": False},
                "from_email": {
                    "type": "string",
                    "label": "From Email",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
                "use_tls": {
                    "type": "boolean",
                    "label": "Use TLS",
                    "required": False,
                    "default": True,
                },
            },
        },
        {
            "type": "slack_webhook",
            "name": "Slack Incoming Webhook",
            "channel": "slack",
            "icon": "hash",
            "config_schema": {
                "webhook_url": {
                    "type": "password",
                    "label": "Webhook URL",
                    "required": True,
                    "placeholder": "https://hooks.slack.com/services/...",
                },
                "channel": {
                    "type": "string",
                    "label": "Default Channel",
                    "required": False,
                    "default": "#alerts",
                },
                "username": {
                    "type": "string",
                    "label": "Bot Name",
                    "required": False,
                    "default": "FreeSDN",
                },
                "icon_emoji": {
                    "type": "string",
                    "label": "Icon Emoji",
                    "required": False,
                    "default": ":bell:",
                },
            },
        },
        {
            "type": "teams_webhook",
            "name": "Microsoft Teams Webhook",
            "channel": "teams",
            "icon": "message-square",
            "config_schema": {
                "webhook_url": {
                    "type": "password",
                    "label": "Webhook URL",
                    "required": True,
                    "placeholder": "https://outlook.office.com/webhook/...",
                },
                "theme_color": {
                    "type": "string",
                    "label": "Theme Color",
                    "required": False,
                    "default": "#0078D4",
                },
            },
        },
        {
            "type": "generic_webhook",
            "name": "Generic Webhook",
            "channel": "webhook",
            "icon": "globe",
            "config_schema": {
                "url": {
                    "type": "string",
                    "label": "Endpoint URL",
                    "required": True,
                    "placeholder": "https://api.example.com/hooks/...",
                },
                "secret": {"type": "password", "label": "HMAC Secret", "required": False},
                "headers": {
                    "type": "json",
                    "label": "Custom Headers",
                    "required": False,
                    "default": {},
                },
                "method": {
                    "type": "select",
                    "label": "HTTP Method",
                    "required": False,
                    "default": "POST",
                    "options": ["POST", "PUT"],
                },
            },
        },
        {
            "type": "twilio_sms",
            "name": "Twilio SMS",
            "channel": "sms",
            "icon": "smartphone",
            "config_schema": {
                "account_sid": {"type": "string", "label": "Account SID", "required": True},
                "auth_token": {"type": "password", "label": "Auth Token", "required": True},
                "from_number": {
                    "type": "string",
                    "label": "From Number",
                    "required": True,
                    "placeholder": "+15551234567",
                },
            },
        },
        {
            "type": "twilio_whatsapp",
            "name": "Twilio WhatsApp",
            "channel": "whatsapp",
            "icon": "message-circle",
            "config_schema": {
                "account_sid": {"type": "string", "label": "Account SID", "required": True},
                "auth_token": {"type": "password", "label": "Auth Token", "required": True},
                "from_number": {
                    "type": "string",
                    "label": "WhatsApp Number",
                    "required": True,
                    "placeholder": "+15551234567",
                },
            },
        },
        # ── Transactional Email Providers ──────────────────────────────
        {
            "type": "mailgun",
            "name": "Mailgun",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "api_key": {
                    "type": "password",
                    "label": "API Key",
                    "required": True,
                    "placeholder": "key-xxxxxxxx",
                },
                "domain": {
                    "type": "string",
                    "label": "Sending Domain",
                    "required": True,
                    "placeholder": "mg.example.com",
                },
                "from_email": {
                    "type": "string",
                    "label": "From Email",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
                "region": {
                    "type": "select",
                    "label": "Region",
                    "required": False,
                    "default": "us",
                    "options": ["us", "eu"],
                },
            },
        },
        {
            "type": "sendgrid",
            "name": "SendGrid",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "api_key": {
                    "type": "password",
                    "label": "API Key",
                    "required": True,
                    "placeholder": "SG.xxxx",
                },
                "from_email": {
                    "type": "string",
                    "label": "From Email",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
            },
        },
        {
            "type": "brevo",
            "name": "Brevo (Sendinblue)",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "api_key": {"type": "password", "label": "API Key", "required": True},
                "from_email": {
                    "type": "string",
                    "label": "From Email",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
            },
        },
        {
            "type": "amazon_ses",
            "name": "Amazon SES",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "access_key_id": {"type": "string", "label": "Access Key ID", "required": True},
                "secret_access_key": {
                    "type": "password",
                    "label": "Secret Access Key",
                    "required": True,
                },
                "region": {
                    "type": "select",
                    "label": "AWS Region",
                    "required": True,
                    "default": "us-east-1",
                    "options": [
                        "us-east-1",
                        "us-east-2",
                        "us-west-2",
                        "eu-west-1",
                        "eu-central-1",
                        "ap-south-1",
                        "ap-southeast-1",
                        "ap-southeast-2",
                        "ap-northeast-1",
                    ],
                },
                "from_email": {
                    "type": "string",
                    "label": "From Email (verified)",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
                "configuration_set": {
                    "type": "string",
                    "label": "Configuration Set",
                    "required": False,
                    "placeholder": "optional",
                },
            },
        },
        {
            "type": "postmark",
            "name": "Postmark",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "server_token": {"type": "password", "label": "Server API Token", "required": True},
                "from_email": {
                    "type": "string",
                    "label": "From Email (sender signature)",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
                "message_stream": {
                    "type": "string",
                    "label": "Message Stream",
                    "required": False,
                    "default": "outbound",
                },
            },
        },
        {
            "type": "resend",
            "name": "Resend",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "api_key": {
                    "type": "password",
                    "label": "API Key",
                    "required": True,
                    "placeholder": "re_xxxx",
                },
                "from_email": {
                    "type": "string",
                    "label": "From Email",
                    "required": True,
                    "placeholder": "noreply@example.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
            },
        },
        {
            "type": "google_gmail",
            "name": "Google Gmail (OAuth2)",
            "channel": "email",
            "icon": "mail",
            "config_schema": {
                "client_id": {
                    "type": "string",
                    "label": "OAuth2 Client ID",
                    "required": True,
                    "placeholder": "123456789-abc.apps.googleusercontent.com",
                },
                "client_secret": {
                    "type": "password",
                    "label": "OAuth2 Client Secret",
                    "required": True,
                    "placeholder": "GOCSPX-xxxx",
                },
                "refresh_token": {
                    "type": "password",
                    "label": "OAuth2 Refresh Token",
                    "required": True,
                    "placeholder": "1//0xxxx",
                },
                "from_email": {
                    "type": "string",
                    "label": "Gmail Address",
                    "required": True,
                    "placeholder": "you@gmail.com",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
            },
        },
        {
            "type": "gmail_smtp",
            "name": "Gmail SMTP (App Password)",
            "channel": "email",
            "icon": "mail",
            "description": "Send email via Gmail SMTP using an App Password. Simpler setup than OAuth2 — just enable 2FA on your Google account and generate an App Password.",
            "config_schema": {
                "email": {
                    "type": "string",
                    "label": "Gmail Address",
                    "required": True,
                    "placeholder": "you@gmail.com",
                },
                "app_password": {
                    "type": "password",
                    "label": "App Password",
                    "required": True,
                    "placeholder": "xxxx xxxx xxxx xxxx",
                    "description": "Generate at myaccount.google.com/apppasswords (requires 2FA enabled)",
                },
                "from_name": {
                    "type": "string",
                    "label": "From Name",
                    "required": False,
                    "default": "FreeSDN",
                },
            },
        },
    ]

    @classmethod
    def get_provider_types(cls) -> list[dict[str, Any]]:
        """Return the static list of supported provider types."""
        return cls.PROVIDER_TYPES

    # ---- CRUD helpers -----------------------------------------------------

    async def list_providers(
        self,
        organization_id: UUID | None = None,
        channel: str | None = None,
        enabled_only: bool = False,
    ) -> list[NotificationProviderRecord]:
        """List all stored provider records, optionally filtered."""
        clauses = []
        if organization_id:
            clauses.append(NotificationProviderRecord.organization_id == organization_id)
        if channel:
            clauses.append(NotificationProviderRecord.channel == channel)
        if enabled_only:
            clauses.append(NotificationProviderRecord.is_enabled.is_(True))

        q = select(NotificationProviderRecord)
        if clauses:
            q = q.where(and_(*clauses))
        q = q.order_by(NotificationProviderRecord.created_at.desc())

        result = await self.db.execute(q)
        return list(result.scalars().all())

    async def get_provider(
        self,
        provider_id: UUID,
        organization_id: UUID | None = None,
    ) -> NotificationProviderRecord | None:
        """Fetch a single provider by ID, optionally scoped to an organization."""
        clauses = [NotificationProviderRecord.id == provider_id]
        if organization_id is not None:
            clauses.append(NotificationProviderRecord.organization_id == organization_id)
        result = await self.db.execute(select(NotificationProviderRecord).where(and_(*clauses)))
        return result.scalar_one_or_none()

    # Fields safe to update via partial update
    _UPDATABLE_FIELDS: frozenset[str] = frozenset(
        {
            "name",
            "config",
            "is_enabled",
            "is_default",
            "rate_limit_per_hour",
            "rate_limit_per_day",
        }
    )

    async def _demote_other_defaults(
        self,
        channel: str,
        organization_id: UUID | None,
        keep_id: UUID | None = None,
    ) -> None:
        """Unset ``is_default`` on every other provider in the same channel.

        Without this two concurrent "Set as default" calls (or two
        ``create_provider(is_default=True)`` in quick succession) both
        succeed and ``load_providers_from_db`` then non-deterministically
        picks one — the others are silently shadowed.
        """
        clauses = [
            NotificationProviderRecord.channel == channel,
            NotificationProviderRecord.is_default.is_(True),
        ]
        if organization_id is not None:
            clauses.append(NotificationProviderRecord.organization_id == organization_id)
        if keep_id is not None:
            clauses.append(NotificationProviderRecord.id != keep_id)
        await self.db.execute(
            sa_update(NotificationProviderRecord).where(and_(*clauses)).values(is_default=False)
        )

    async def create_provider(
        self,
        *,
        name: str,
        provider_type: str,
        config: dict[str, Any],
        is_enabled: bool = True,
        is_default: bool = False,
        rate_limit_per_hour: int = 500,
        rate_limit_per_day: int = 10000,
        organization_id: UUID | None = None,
    ) -> NotificationProviderRecord:
        """Create a new provider record."""
        # Validate provider_type against known types
        valid_types = {t["type"] for t in self.PROVIDER_TYPES}
        if provider_type not in valid_types:
            raise ValueError(
                f"Unsupported provider type: {provider_type}. "
                f"Valid types: {', '.join(sorted(valid_types))}"
            )
        # Resolve channel from provider_type
        channel = self._channel_for_provider_type(provider_type)
        if is_default:
            await self._demote_other_defaults(channel, organization_id)
        # NOTE: Encrypt sensitive keys (SMTP password, webhook URL,
        # OAuth refresh token, …) BEFORE persisting. Previously these
        # were written plaintext to JSONB, exposing them to anyone with
        # DB read access including backup operators.
        safe_config = self._encrypt_sensitive_config(config)
        record = NotificationProviderRecord(
            name=name,
            provider_type=provider_type,
            channel=channel,
            config=safe_config,
            is_enabled=is_enabled,
            is_default=is_default,
            rate_limit_per_hour=rate_limit_per_hour,
            rate_limit_per_day=rate_limit_per_day,
            organization_id=organization_id,
        )
        self.db.add(record)
        await self.db.flush()
        await self.db.refresh(record)
        return record

    async def update_provider(
        self,
        provider_id: UUID,
        organization_id: UUID | None = None,
        **kwargs: Any,
    ) -> NotificationProviderRecord | None:
        """Partial update of a provider record (org-scoped, whitelisted fields only)."""
        record = await self.get_provider(provider_id, organization_id=organization_id)
        if not record:
            return None
        for key, value in kwargs.items():
            if key not in self._UPDATABLE_FIELDS:
                logger.warning("Ignored disallowed update field: %s", key)
                continue
            if key == "config" and isinstance(value, dict):
                # PATCH ``{"config": {}}`` used to wipe the entire
                # encrypted-secret blob. Merge into the existing config
                # so admins can update non-secret keys without having
                # to re-enter SMTP password / webhook URL on every
                # save. Sensitive keys still get re-encrypted on write.
                existing = dict(record.config or {})
                # Decrypt existing values so the merge sees plaintext on
                # both sides; the result is re-encrypted below.
                existing_plain = self._decrypt_sensitive_config(existing)
                # the edit dialog seeds its form from the
                # MASKED ``config_summary`` (secrets shown as "••••••••",
                # *url keys truncated to ``value[:25] + "…"``) and submits
                # the whole config back. Drop those masked echoes so a
                # routine save does not re-encrypt the mask over the real
                # secret/URL and silently break delivery; keep the stored
                # plaintext whenever the client echoed the display mask.
                clean = {
                    k: v for k, v in value.items() if not self._is_masked_echo(k, v, existing_plain)
                }
                merged = {**existing_plain, **clean}
                value = self._encrypt_sensitive_config(merged)
            if key == "is_default" and value is True:
                await self._demote_other_defaults(
                    record.channel,
                    organization_id,
                    keep_id=record.id,
                )
            setattr(record, key, value)
        record.updated_at = datetime.now(UTC)
        await self.db.flush()
        await self.db.refresh(record)
        return record

    async def delete_provider(
        self,
        provider_id: UUID,
        organization_id: UUID | None = None,
    ) -> bool:
        """Delete a provider record (org-scoped). Returns True if deleted."""
        record = await self.get_provider(provider_id, organization_id=organization_id)
        if not record:
            return False
        await self.db.delete(record)
        await self.db.flush()
        return True

    @staticmethod
    def _sanitize_last_error(msg: str | None) -> str | None:
        """Strip URLs from provider error messages and cap length.

        ``httpx.HTTPStatusError.__str__`` includes the full request URL.
        For ``slack_webhook`` / ``teams_webhook`` / ``generic_webhook``
        that URL embeds the org's bearer-equivalent secret. Without
        this, anyone with ``provider:read`` listing providers can read
        another admin's webhook secrets out of ``last_error``.
        """
        if msg is None:
            return None
        # Replace any http(s) URL with the scheme + opaque marker.
        msg = re.sub(r"https?://\S+", "<redacted-url>", msg)
        return msg[:1024]

    async def verify_stored_provider(
        self,
        provider_id: UUID,
        organization_id: UUID | None = None,
    ) -> tuple[bool, str]:
        """Instantiate the runtime provider from a stored record and verify it (org-scoped)."""
        record = await self.get_provider(provider_id, organization_id=organization_id)
        if not record:
            return False, "Provider not found"
        runtime = self._build_runtime_provider(record)
        if not runtime:
            return False, f"Unsupported provider type: {record.provider_type}"
        ok, msg = await runtime.verify()
        record.is_verified = ok
        record.last_verified_at = datetime.now(UTC)
        record.last_error = None if ok else self._sanitize_last_error(msg)
        await self.db.flush()
        return ok, msg

    async def test_stored_provider(
        self,
        provider_id: UUID,
        recipient: str,
        organization_id: UUID | None = None,
    ) -> DeliveryResult:
        """Send a test notification through a stored provider (org-scoped)."""
        record = await self.get_provider(provider_id, organization_id=organization_id)
        if not record:
            return DeliveryResult(
                success=False,
                channel=NotificationChannel.EMAIL,
                status=DeliveryStatus.FAILED,
                error="Provider not found",
            )
        runtime = self._build_runtime_provider(record)
        if not runtime:
            return DeliveryResult(
                success=False,
                channel=NotificationChannel(record.channel),
                status=DeliveryStatus.FAILED,
                error=f"Unsupported provider type: {record.provider_type}",
            )
        payload = NotificationPayload(
            title="FreeSDN Test Notification",
            body="This is a test notification from FreeSDN. If you received this, the provider is configured correctly.",
            body_html="<p>This is a <strong>test notification</strong> from FreeSDN.</p><p>If you received this, the provider is configured correctly.</p>",
        )
        result = await runtime.send(recipient, payload)
        # Update last_error on the record (URL-redacted + length-capped
        # to avoid leaking webhook secrets from httpx error messages).
        if not result.success:
            record.last_error = self._sanitize_last_error(result.error)
        else:
            record.last_error = None
            record.is_verified = True
            record.last_verified_at = datetime.now(UTC)
        await self.db.flush()
        return result

    # ---- In-memory provider registry (legacy) -----------------------------

    async def verify_provider(
        self,
        channel: NotificationChannel,
    ) -> tuple[bool, str]:
        """Verify a provider's configuration."""
        provider = self._providers.get(channel)
        if not provider:
            return False, f"No provider for channel: {channel}"
        return await provider.verify()

    async def test_provider(
        self,
        channel: NotificationChannel,
        recipient: str,
    ) -> DeliveryResult:
        """Send a test notification through a provider."""
        return await self.send(
            channel=channel,
            recipient=recipient,
            title="FreeSDN Test Notification",
            body="This is a test notification from FreeSDN.",
            body_html="<p>This is a <strong>test notification</strong> from FreeSDN.</p>",
        )

    # ---- internal helpers -------------------------------------------------

    @staticmethod
    def _channel_for_provider_type(provider_type: str) -> str:
        """Map a provider_type string to its channel."""
        mapping = {
            "smtp": "email",
            "slack_webhook": "slack",
            "teams_webhook": "teams",
            "generic_webhook": "webhook",
            "twilio_sms": "sms",
            "twilio_whatsapp": "whatsapp",
            # Transactional email providers
            "mailgun": "email",
            "sendgrid": "email",
            "brevo": "email",
            "amazon_ses": "email",
            "postmark": "email",
            "resend": "email",
            "google_gmail": "email",
            "gmail_smtp": "email",
        }
        return mapping.get(provider_type, "webhook")

    @staticmethod
    def _attach_limits(provider: NotificationProvider, record: NotificationProviderRecord) -> None:
        """Carry the record's rate limits onto the runtime instance.

        ``load_providers_from_db`` copies runtime providers into the in-memory
        ``_providers`` dict and drops the record, so without this the limits
        are unreachable from the send path.
        """
        provider.provider_record_id = record.id
        provider.rate_limit_per_hour = record.rate_limit_per_hour
        provider.rate_limit_per_day = record.rate_limit_per_day

    async def _rate_limit_exceeded(self, provider: NotificationProvider) -> str | None:
        """Name the window a send would breach, or None to proceed.

        ``rate_limit_per_hour`` / ``rate_limit_per_day`` were collected by the
        provider form, stored on the record, returned by the API and rendered
        in the UI -- and read by nothing. An operator who set "200/hour" on a
        Twilio account to cap their bill got no cap at all, and an alert storm
        billed every message.

        Counters live in Redis keyed on the provider record and the wall-clock
        bucket, so they hold across API workers and Celery retry workers alike.
        FAIL-OPEN by design: a Redis outage must not silence alerting, which is
        the failure this system exists to prevent. That is a deliberate trade,
        and it is why this is a spend cap rather than a security control.
        """
        record_id = getattr(provider, "provider_record_id", None)
        if record_id is None:
            return None
        windows = (
            ("hour", getattr(provider, "rate_limit_per_hour", 0), 3600, "%Y%m%d%H"),
            ("day", getattr(provider, "rate_limit_per_day", 0), 86400, "%Y%m%d"),
        )
        if not any(limit and limit > 0 for _, limit, _, _ in windows):
            return None

        try:
            from app.core.redis_client import get_async_redis

            redis = get_async_redis(decode_responses=True)
            now = datetime.now(UTC)
            for name, limit, ttl, fmt in windows:
                if not limit or limit <= 0:
                    continue
                key = f"notif:ratelimit:{record_id}:{name}:{now.strftime(fmt)}"
                used = await redis.incr(key)
                if used == 1:
                    # Only the first writer sets the TTL, so a long-running
                    # bucket is not repeatedly extended into never expiring.
                    await redis.expire(key, ttl)
                if used > limit:
                    return f"{name}ly rate limit reached ({limit}/{name})"
        except Exception:
            logger.debug("Notification rate-limit check unavailable", exc_info=True)
            return None
        return None

    def _build_runtime_provider(
        self, record: NotificationProviderRecord
    ) -> NotificationProvider | None:
        """Instantiate a runtime provider from a DB record."""
        builders: dict[str, type[NotificationProvider]] = {
            "smtp": SMTPProvider,
            "slack_webhook": SlackProvider,
            "teams_webhook": TeamsProvider,
            "generic_webhook": WebhookProvider,
            "twilio_sms": TwilioSMSProvider,
            "twilio_whatsapp": TwilioWhatsAppProvider,
            "mailgun": MailgunProvider,
            "sendgrid": SendGridProvider,
            "brevo": BrevoProvider,
            "amazon_ses": AmazonSESProvider,
            "postmark": PostmarkProvider,
            "resend": ResendProvider,
            "google_gmail": GmailOAuthProvider,
            "gmail_smtp": SMTPProvider,
        }
        # Decrypt sensitive config keys before instantiating the runtime
        # provider. Backward-compatible with rows persisted before the
        # encryption-at-rest fix (those keys are still plaintext).
        cfg = self._decrypt_sensitive_config(dict(record.config))
        # Gmail SMTP: remap config keys to standard SMTP fields
        if record.provider_type == "gmail_smtp":
            cfg.setdefault("host", "smtp.gmail.com")
            cfg.setdefault("port", 587)
            cfg.setdefault("use_tls", True)
            cfg.setdefault("username", cfg.get("email", ""))
            cfg.setdefault("password", cfg.get("app_password", ""))
            cfg.setdefault("from_email", cfg.get("email", ""))
            cls_type = builders.get(record.provider_type)
            if cls_type is None:
                return None
            inst = cls_type(cfg)
            # Override provider_type so DeliveryResult.provider reflects
            # gmail_smtp rather than the bare smtp identifier.
            inst.provider_type = "gmail_smtp"
            self._attach_limits(inst, record)
            return inst
        cls = builders.get(record.provider_type)
        if cls is None:
            logger.warning("No runtime builder for provider type: %s", record.provider_type)
            return None
        inst = cls(cfg)
        # Reflect the *stored* provider_type in delivery analytics. Each type
        # now has its own class, so this is normally a no-op; it still matters
        # for gmail_smtp, which reuses SMTPProvider.
        inst.provider_type = record.provider_type
        self._attach_limits(inst, record)
        return inst

    async def load_providers_from_db(self, organization_id: UUID | None = None) -> None:
        """
        Load all enabled providers from the database and register them
        into the in-memory _providers dict so that send() can use them.
        """
        records = await self.list_providers(
            organization_id=organization_id,
            enabled_only=True,
        )
        for rec in records:
            runtime = self._build_runtime_provider(rec)
            if runtime:
                try:
                    channel = NotificationChannel(rec.channel)
                    # Prefer the default provider when multiple exist
                    if rec.is_default or channel not in self._providers:
                        self._providers[channel] = runtime
                except ValueError:
                    logger.warning("Unknown channel '%s' for provider %s", rec.channel, rec.id)

    @staticmethod
    def _is_masked_echo(key: str, value: Any, existing_plain: dict[str, Any]) -> bool:
        """True when the client echoed back a value produced by
        :meth:`_safe_config_summary` rather than a real edit, so the merge
        in :meth:`update_provider` must keep the existing stored secret.

        Matches both mask forms: the "••••••••" bullet string and the
        ``value[:25] + "…"`` URL truncation. Only applies when a stored
        value already exists for the key (so a genuinely new value is never
        dropped).
        """
        if key not in existing_plain or not isinstance(value, str):
            return False
        return value == "••••••••" or value.endswith("…")

    @staticmethod
    def _safe_config_summary(config: dict[str, Any]) -> dict[str, Any]:
        """Strip secrets from config for API responses."""
        _SECRET_KEYWORDS = ("password", "token", "secret", "auth", "api_key", "apikey")
        safe = {}
        for key, value in config.items():
            k = key.lower()
            if any(s in k for s in _SECRET_KEYWORDS):
                safe[key] = "••••••••" if value else None
            elif k.endswith("url") and isinstance(value, str):
                # Mask webhook URLs — they often embed secrets in the path
                safe[key] = value[:25] + "…" if len(value) > 25 else "••••••••"
            else:
                safe[key] = value
        return safe

    # ---------------------------------------------------------------------
    # Encryption helpers for provider config secrets
    # ---------------------------------------------------------------------
    # NOTE: Provider configs are stored in a JSONB column. Several keys
    # are sensitive (SMTP passwords, webhook URLs that embed secrets,
    # Slack/Twilio tokens, OAuth refresh tokens). Previously they went
    # straight to the database in plaintext. The encryption helpers wrap
    # ``app.core.crypto`` (Fernet) and use :func:`is_encrypted` to remain
    # backward-compatible with rows persisted before this fix.
    _SENSITIVE_CONFIG_KEYS: frozenset[str] = frozenset(
        {
            "smtp_password",
            "password",
            "app_password",
            "token",
            "auth_token",
            "client_secret",
            "refresh_token",
            "api_key",
            "api_secret",
            "secret",
            "server_token",
            "secret_access_key",
            "webhook_url",
        }
    )

    @classmethod
    def _encrypt_sensitive_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of ``config`` with known-sensitive string values encrypted."""
        out: dict[str, Any] = {}
        for k, v in config.items():
            key_l = k.lower()
            if (
                key_l in cls._SENSITIVE_CONFIG_KEYS
                and isinstance(v, str)
                and v
                and not is_encrypted(v)
            ):
                try:
                    out[k] = encrypt_credential(v)
                except Exception as exc:
                    logger.error("Failed to encrypt config key %s: %s", k, exc)
                    out[k] = v
            else:
                out[k] = v
        return out

    @classmethod
    def _decrypt_sensitive_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of ``config`` with known-sensitive Fernet-encoded values decrypted.

        Plaintext rows persisted before the encryption fix are passed
        through unchanged (backward compatible).
        """
        out: dict[str, Any] = {}
        for k, v in config.items():
            if isinstance(v, str) and v and is_encrypted(v):
                try:
                    out[k] = decrypt_credential(v)
                except Exception as exc:
                    logger.warning("Failed to decrypt config key %s: %s", k, exc)
                    out[k] = v
            else:
                out[k] = v
        return out
