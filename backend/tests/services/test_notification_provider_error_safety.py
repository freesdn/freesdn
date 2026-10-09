# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Provider diagnostics must omit private replies while retaining retry policy."""

import json
import smtplib
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.services import notification as nt
from app.tasks.notification_retry import is_transient_error

CANARY = "owned-provider-private-canary"
PAYLOAD = nt.NotificationPayload("Owned title", "Synthetic body")
HTTP_PROVIDERS = [
    "GmailOAuthProvider",
    "SlackProvider",
    "WebhookProvider",
    "TeamsProvider",
    "DiscordProvider",
    "NtfyProvider",
    "GotifyProvider",
    "MailgunProvider",
    "SendGridProvider",
    "BrevoProvider",
    "PostmarkProvider",
    "ResendProvider",
    "AmazonSESProvider",
    "TwilioSMSProvider",
    "TwilioWhatsAppProvider",
]


def provider(name):
    config = {
        "api_key": CANARY,
        "server_token": CANARY,
        "token": CANARY,
        "domain": "mail.example.invalid",
        "region": "us-east-1",
        "from_email": f"sender+{CANARY}@example.invalid",
        "access_key_id": "owned-access",
        "secret_access_key": CANARY,
        "account_sid": "owned-account",
        "auth_token": CANARY,
        "from_number": "+15555550100",
        "client_id": "owned-client",
        "client_secret": CANARY,
        "refresh_token": CANARY,
        "url": f"https://notify.example.invalid/{CANARY}",
        "webhook_url": f"https://discord.com/api/webhooks/1/{CANARY}",
        "server": "https://notify.example.invalid",
        "topic": "owned",
    }
    return getattr(nt, name)(config)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HTTP_PROVIDERS)
@pytest.mark.parametrize("outcome", ["connection", 400, 401, 429, 503, "success"])
async def test_http_delivery_omits_private_details_and_keeps_retry_policy(
    monkeypatch, caplog, name, outcome
):
    calls = []

    async def request(method, url, **_kwargs):
        calls.append((method, url))
        if outcome == "connection":
            raise httpx.ConnectError(CANARY, request=httpx.Request(method, url))
        code = 200 if outcome == "success" else outcome
        text = (
            json.dumps({"id": "owned-message", "sid": "owned-message"}) if code == 200 else CANARY
        )
        return httpx.Response(code, text=text, request=httpx.Request(method, url))

    monkeypatch.setattr(nt, "safe_http_request", request)
    monkeypatch.setattr(
        nt.GmailOAuthProvider, "_get_access_token", AsyncMock(return_value="owned-access")
    )
    instance = provider(name)
    recipient = "+15555550200" if name.startswith("Twilio") else "owned@example.invalid"
    result = await instance.send(recipient, PAYLOAD)
    assert calls, "The configured provider did not reach the synthetic transport"
    assert result.success is (outcome == "success")
    assert result.status == (
        nt.DeliveryStatus.SENT if outcome == "success" else nt.DeliveryStatus.FAILED
    )
    assert CANARY not in (result.error or "") and CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    if isinstance(outcome, int):
        assert str(outcome) in result.error
        assert is_transient_error(result.error) is (outcome in [429, 503])
    elif outcome == "connection":
        assert is_transient_error(result.error)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        "GmailOAuthProvider",
        "SlackProvider",
        "WebhookProvider",
        "TeamsProvider",
        "MailgunProvider",
        "SendGridProvider",
        "BrevoProvider",
        "PostmarkProvider",
        "ResendProvider",
        "TwilioSMSProvider",
        "TwilioWhatsAppProvider",
    ],
)
async def test_verification_does_not_echo_transport_exception(monkeypatch, caplog, name):
    request = AsyncMock(side_effect=RuntimeError(CANARY))
    monkeypatch.setattr(nt, "safe_http_request", request)
    monkeypatch.setattr(
        nt.GmailOAuthProvider, "_get_access_token", AsyncMock(return_value="owned-access")
    )
    ok, message = await provider(name).verify()
    request.assert_awaited_once()
    assert not ok
    assert CANARY not in message and CANARY not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["send", "verify"])
@pytest.mark.parametrize(
    "kind",
    [
        "authentication",
        "temporary",
        "permanent",
        "recipient",
        "connection",
        "unexpected",
        "success",
    ],
)
async def test_smtp_diagnostics_are_safe_and_keep_reply_classification(
    monkeypatch, caplog, operation, kind
):
    error = {
        "authentication": smtplib.SMTPAuthenticationError(535, CANARY.encode()),
        "temporary": smtplib.SMTPDataError(451, CANARY.encode()),
        "permanent": smtplib.SMTPDataError(550, CANARY.encode()),
        "recipient": smtplib.SMTPRecipientsRefused(
            {"owned@example.invalid": (550, CANARY.encode())}
        ),
        "connection": OSError(CANARY),
        "unexpected": RuntimeError(CANARY),
        "success": None,
    }[kind]
    smtp = MagicMock()
    smtp.return_value.__enter__.return_value.login.side_effect = error
    monkeypatch.setattr(smtplib, "SMTP", smtp)
    instance = nt.SMTPProvider(
        {
            "host": "owned.invalid",
            "port": 587,
            "username": "owned-user",
            "password": CANARY,
            "from_email": "sender@example.invalid",
        }
    )
    if operation == "send":
        result = await instance.send("owned@example.invalid", PAYLOAD)
        ok, message = result.success, result.error or ""
    else:
        ok, message = await instance.verify()
    assert ok is (kind == "success")
    assert CANARY not in message and CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    if kind != "success":
        assert is_transient_error(message) is (kind in ["temporary", "connection", "unexpected"])


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["SMTPProvider", "GmailOAuthProvider", "SendGridProvider"])
async def test_invalid_email_is_not_copied_into_public_diagnostics(monkeypatch, caplog, name):
    instance = (
        provider(name)
        if name != "SMTPProvider"
        else nt.SMTPProvider({"from_email": "sender@example.invalid"})
    )
    transport = AsyncMock(side_effect=AssertionError("Invalid recipient reached transport"))
    monkeypatch.setattr(nt, "safe_http_request", transport)
    monkeypatch.setattr(
        nt.GmailOAuthProvider, "_get_access_token", AsyncMock(return_value="owned-access")
    )
    result = await instance.send(CANARY, PAYLOAD)
    assert not result.success
    assert CANARY not in (result.error or "") and CANARY not in caplog.text
    assert not is_transient_error(result.error)
    transport.assert_not_awaited()


@pytest.mark.asyncio
async def test_malformed_provider_json_is_private_and_not_a_configuration_refusal(
    monkeypatch, caplog
):
    monkeypatch.setattr(
        nt.GmailOAuthProvider, "_get_access_token", AsyncMock(return_value="owned-access")
    )
    monkeypatch.setattr(
        nt,
        "safe_http_request",
        AsyncMock(return_value=httpx.Response(200, text=CANARY)),
    )
    # Give raise_for_status its real HTTP request without introducing a network call.
    nt.safe_http_request.return_value.request = httpx.Request(
        "POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    )
    result = await provider("GmailOAuthProvider").send("owned@example.invalid", PAYLOAD)
    assert not result.success and result.error
    assert CANARY not in result.error and CANARY not in caplog.text
    assert is_transient_error(result.error)
