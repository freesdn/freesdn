# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The notification stack advertised more than it could do, and failed quietly.

1. EIGHT OF FIFTEEN PROVIDER TYPES COULD NEVER SEND
   ``get_provider_catalog`` advertises each with a complete, provider-specific
   config schema -- Mailgun wants api_key + domain + region, SES a SigV4
   credential pair, Twilio an account SID -- and ``_build_runtime_provider``
   then built every one of them as a bare ``WebhookProvider``.

   WebhookProvider reads exactly one config key: ``url``. None of those schemas
   has one, so ``self.url`` was always None, every send hit
   ``safe_http_request("POST", None, ...)``, raised, and returned
   ``DeliveryResult(success=False)``. Mailgun, SendGrid, Brevo, Amazon SES,
   Postmark, Resend, Twilio SMS and Twilio WhatsApp could each be configured,
   enabled, marked default and shown as healthy -- and could never deliver a
   message. It only surfaced when an alert actually needed to go out.

   A URL alone would not have fixed it: the generic body WebhookProvider posts
   (``{title, body, data, timestamp}``) is not a shape any of these APIs
   accepts. Each needed its own request, which is what these tests pin.

2. SMTP FROZE THE WHOLE WORKER
   ``SMTPProvider.send`` is ``async`` and called blocking ``smtplib`` with NO
   timeout. Default ``timeout=None`` waits on the socket forever, so an SMTP
   host that accepts the TCP connection and then goes quiet -- a firewall
   blackhole, an overloaded relay, a greylister -- froze the entire event loop.
   Not just notifications: every request that worker was serving, with no error
   and nothing in the logs. ``verify()`` ten lines below already passed
   ``timeout=10``, which is what makes the omission an oversight.

3. THE RETRY QUEUE NEVER RETRIED ANYTHING
   ``_providers`` is an INSTANCE attribute filled by ``load_providers_from_db``
   at API startup. The retry task runs in a Celery worker -- a different
   process, a brand-new service, ``_providers == {}`` -- and nothing loaded it.
   The dispatcher enqueues with ``provider_id=None`` ("dispatch path uses
   in-memory provider"), true of the API process and false of the worker. So
   every retry dead-lettered on attempt 1 with "No provider available". The
   feature logged ``retry_scheduled``, enqueued a real Celery task, and threw
   it away.

4. A 500 ENDPOINT WAS MARKED "VERIFIED"
   ``WebhookProvider.verify`` returned True for any status that came back. A
   green check on an endpoint that will drop every alert is worse than no
   check. Slack's and Teams' verifies right beside it already checked status.

5. RATE LIMITS WERE COLLECTED, STORED, DISPLAYED AND IGNORED
   ``rate_limit_per_hour`` / ``rate_limit_per_day`` were read by nothing. An
   operator who capped a Twilio provider at 200/hour to bound their bill got no
   cap, and an alert storm billed every message.

HONESTY NOTE, in the spirit of ``app/adapters/maturity.py``: the provider
classes are written against each vendor's published API and pinned here at the
wire level. They are NOT live-validated against a real vendor account.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import time
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.services import notification as nt
from app.services.notification import (
    AmazonSESProvider,
    BrevoProvider,
    DeliveryStatus,
    MailgunProvider,
    NotificationPayload,
    NotificationService,
    PostmarkProvider,
    ResendProvider,
    SendGridProvider,
    SMTPProvider,
    TwilioSMSProvider,
    TwilioWhatsAppProvider,
    WebhookProvider,
)

PAYLOAD = NotificationPayload(
    title="Switch core-01 is down",
    body="No response for 3 minutes.",
    body_html="<p>No response for 3 minutes.</p>",
)
TO = "ops@example.com"


class _Response:
    def __init__(self, status_code: int = 200, body: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture
def captured(monkeypatch):
    """Record every outgoing request instead of making one."""
    calls: list[dict] = []
    response = {"value": _Response(200, {"id": "vendor-msg-1"})}

    async def _request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        return response["value"]

    monkeypatch.setattr(nt, "safe_http_request", _request)
    return SimpleNamespace(calls=calls, set=lambda r: response.update(value=r))


# ── 1. every advertised provider reaches its real API ────────────


_CONFIGS: dict[str, tuple[type, dict]] = {
    "mailgun": (
        MailgunProvider,
        {
            "api_key": "key-abc",
            "domain": "mg.example.com",
            "from_email": "noreply@example.com",
            "from_name": "FreeSDN",
        },
    ),
    "sendgrid": (
        SendGridProvider,
        {"api_key": "SG.abc", "from_email": "noreply@example.com", "from_name": "FreeSDN"},
    ),
    "brevo": (
        BrevoProvider,
        {"api_key": "xkeysib-abc", "from_email": "noreply@example.com", "from_name": "FreeSDN"},
    ),
    "postmark": (
        PostmarkProvider,
        {"server_token": "tok", "from_email": "noreply@example.com", "from_name": "FreeSDN"},
    ),
    "resend": (
        ResendProvider,
        {"api_key": "re_abc", "from_email": "noreply@example.com", "from_name": "FreeSDN"},
    ),
    "amazon_ses": (
        AmazonSESProvider,
        {
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret",
            "region": "eu-west-1",
            "from_email": "noreply@example.com",
            "from_name": "FreeSDN",
        },
    ),
    "twilio_sms": (
        TwilioSMSProvider,
        {"account_sid": "ACxxx", "auth_token": "tok", "from_number": "+15551234567"},
    ),
    "twilio_whatsapp": (
        TwilioWhatsAppProvider,
        {"account_sid": "ACxxx", "auth_token": "tok", "from_number": "+15551234567"},
    ),
}


@pytest.mark.parametrize("kind", sorted(_CONFIGS))
async def test_every_advertised_provider_sends_successfully(captured, kind: str) -> None:
    """
    The regression, one assertion per provider. Pre-fix each of these was a
    WebhookProvider with url=None and this returned success=False every time.
    """
    cls, cfg = _CONFIGS[kind]
    recipient = "+15559876543" if kind.startswith("twilio") else TO

    result = await cls(cfg).send(recipient, PAYLOAD)

    assert result.success is True, result.error
    assert result.status == DeliveryStatus.SENT
    assert result.provider == kind
    assert len(captured.calls) == 1


@pytest.mark.parametrize("kind", sorted(_CONFIGS))
async def test_no_provider_posts_to_a_none_url(captured, kind: str) -> None:
    """
    Names the exact mechanism: WebhookProvider's ``config.get("url")`` was
    None for every one of these, so the request went to nowhere.
    """
    cls, cfg = _CONFIGS[kind]
    recipient = "+15559876543" if kind.startswith("twilio") else TO
    await cls(cfg).send(recipient, PAYLOAD)

    url = captured.calls[0]["url"]
    assert isinstance(url, str) and url.startswith("https://"), url


async def test_mailgun_posts_the_documented_request(captured) -> None:
    await MailgunProvider(_CONFIGS["mailgun"][1]).send(TO, PAYLOAD)
    call = captured.calls[0]

    assert call["url"] == "https://api.mailgun.net/v3/mg.example.com/messages"
    # Mailgun's Messages endpoint is form-encoded, not JSON.
    assert "data" in call and "json" not in call
    assert call["data"]["to"] == TO
    assert call["data"]["subject"] == PAYLOAD.title
    assert call["data"]["text"] == PAYLOAD.body
    assert call["data"]["html"] == PAYLOAD.body_html
    expected = base64.b64encode(b"api:key-abc").decode()
    assert call["headers"]["Authorization"] == f"Basic {expected}"


async def test_mailgun_eu_keys_reach_the_eu_stack(captured) -> None:
    """
    Mailgun runs two independent stacks and a EU key is rejected by the US
    host -- which is exactly why the catalogue asks for a region.
    """
    cfg = dict(_CONFIGS["mailgun"][1], region="eu")
    await MailgunProvider(cfg).send(TO, PAYLOAD)
    assert captured.calls[0]["url"].startswith("https://api.eu.mailgun.net/")


async def test_sendgrid_orders_content_parts_correctly(captured) -> None:
    """SendGrid requires content in increasing MIME preference; html last."""
    await SendGridProvider(_CONFIGS["sendgrid"][1]).send(TO, PAYLOAD)
    body = captured.calls[0]["json"]

    assert captured.calls[0]["url"] == "https://api.sendgrid.com/v3/mail/send"
    assert body["personalizations"][0]["to"][0]["email"] == TO
    assert body["from"]["email"] == "noreply@example.com"
    assert [c["type"] for c in body["content"]] == ["text/plain", "text/html"]


async def test_brevo_uses_its_own_header_not_a_bearer(captured) -> None:
    await BrevoProvider(_CONFIGS["brevo"][1]).send(TO, PAYLOAD)
    call = captured.calls[0]

    assert call["url"] == "https://api.brevo.com/v3/smtp/email"
    assert call["headers"]["api-key"] == "xkeysib-abc"
    assert "Authorization" not in call["headers"]
    assert call["json"]["to"] == [{"email": TO}]


async def test_postmark_sends_its_message_stream(captured) -> None:
    await PostmarkProvider(_CONFIGS["postmark"][1]).send(TO, PAYLOAD)
    call = captured.calls[0]

    assert call["url"] == "https://api.postmarkapp.com/email"
    assert call["headers"]["X-Postmark-Server-Token"] == "tok"
    assert call["json"]["MessageStream"] == "outbound"
    assert call["json"]["To"] == TO


async def test_resend_wraps_recipients_in_a_list(captured) -> None:
    await ResendProvider(_CONFIGS["resend"][1]).send(TO, PAYLOAD)
    call = captured.calls[0]

    assert call["url"] == "https://api.resend.com/emails"
    assert call["headers"]["Authorization"] == "Bearer re_abc"
    assert call["json"]["to"] == [TO]


async def test_ses_signs_the_request_for_its_own_region(captured) -> None:
    """
    SES is the only provider here that cannot authenticate with a static
    header: the signature covers the method, path, headers, body and timestamp.
    """
    await AmazonSESProvider(_CONFIGS["amazon_ses"][1]).send(TO, PAYLOAD)
    call = captured.calls[0]

    assert call["url"] == "https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails"
    auth = call["headers"]["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/")
    assert "/eu-west-1/ses/aws4_request" in auth
    assert "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date" in auth
    assert len(call["headers"]["X-Amz-Date"]) == 16  # YYYYMMDDTHHMMSSZ

    body = json.loads(call["content"])
    assert body["Destination"]["ToAddresses"] == [TO]
    assert body["Content"]["Simple"]["Subject"]["Data"] == PAYLOAD.title


async def test_the_ses_signature_covers_the_body(captured) -> None:
    """
    A signature that did not change with the payload would be decorative --
    SES would reject every request and the failure would look like bad
    credentials.
    """
    provider = AmazonSESProvider(_CONFIGS["amazon_ses"][1])
    await provider.send(TO, PAYLOAD)
    first = captured.calls[0]["headers"]["Authorization"]

    captured.calls.clear()
    await provider.send("someone-else@example.com", PAYLOAD)
    second = captured.calls[0]["headers"]["Authorization"]

    assert first != second


async def test_the_ses_content_hash_matches_the_body_sent(captured) -> None:
    """The header and the bytes must agree, or SES 403s every send."""
    import hashlib

    await AmazonSESProvider(_CONFIGS["amazon_ses"][1]).send(TO, PAYLOAD)
    call = captured.calls[0]
    assert (
        call["headers"]["X-Amz-Content-Sha256"]
        == hashlib.sha256(call["content"].encode()).hexdigest()
    )


async def test_twilio_posts_form_fields_to_the_messages_endpoint(captured) -> None:
    await TwilioSMSProvider(_CONFIGS["twilio_sms"][1]).send("+15559876543", PAYLOAD)
    call = captured.calls[0]

    assert call["url"] == "https://api.twilio.com/2010-04-01/Accounts/ACxxx/Messages.json"
    assert "data" in call and "json" not in call
    assert call["data"]["To"] == "+15559876543"
    assert call["data"]["From"] == "+15551234567"
    assert PAYLOAD.title in call["data"]["Body"]


async def test_whatsapp_prefixes_both_addresses(captured) -> None:
    """Twilio refuses a WhatsApp send whose addresses are not prefixed."""
    await TwilioWhatsAppProvider(_CONFIGS["twilio_whatsapp"][1]).send("+15559876543", PAYLOAD)
    data = captured.calls[0]["data"]

    assert data["To"] == "whatsapp:+15559876543"
    assert data["From"] == "whatsapp:+15551234567"


async def test_an_already_prefixed_number_is_not_doubled(captured) -> None:
    cfg = dict(_CONFIGS["twilio_whatsapp"][1], from_number="whatsapp:+15551234567")
    await TwilioWhatsAppProvider(cfg).send("whatsapp:+15559876543", PAYLOAD)
    data = captured.calls[0]["data"]

    assert data["To"] == "whatsapp:+15559876543"
    assert data["From"] == "whatsapp:+15551234567"


async def test_an_sms_body_is_capped(captured) -> None:
    """Twilio rejects a body past the concatenated-segment limit outright."""
    long_payload = NotificationPayload(title="x", body="y" * 5000)
    await TwilioSMSProvider(_CONFIGS["twilio_sms"][1]).send("+15559876543", long_payload)
    assert len(captured.calls[0]["data"]["Body"]) <= 1600


# ── failure shapes ───────────────────────────────────────────────


@pytest.mark.parametrize("kind", sorted(_CONFIGS))
async def test_a_vendor_rejection_is_a_failure_not_a_success(captured, kind: str) -> None:
    """
    A 4xx here is a real refusal -- unverified sender, bad key, over quota --
    and must not be recorded as delivered.
    """
    captured.set(_Response(422, text="Sender identity not verified"))
    cls, cfg = _CONFIGS[kind]
    recipient = "+15559876543" if kind.startswith("twilio") else TO

    result = await cls(cfg).send(recipient, PAYLOAD)

    assert result.success is False
    assert result.status == DeliveryStatus.FAILED
    assert "422" in (result.error or "")
    assert "Sender identity not verified" in (result.error or "")


@pytest.mark.parametrize(
    ("kind", "drop"),
    [
        ("mailgun", "api_key"),
        ("mailgun", "domain"),
        ("sendgrid", "api_key"),
        ("brevo", "api_key"),
        ("postmark", "server_token"),
        ("resend", "api_key"),
        ("amazon_ses", "secret_access_key"),
        ("twilio_sms", "account_sid"),
        ("twilio_sms", "from_number"),
    ],
)
async def test_a_missing_setting_fails_loudly_and_names_itself(captured, kind, drop) -> None:
    """
    The original defect was silent: no URL, generic exception, indistinguishable
    from a transient network blip the retry queue would eventually resolve. A
    misconfigured provider has to say so.
    """
    cls, cfg = _CONFIGS[kind]
    broken = {k: v for k, v in cfg.items() if k != drop}
    recipient = "+15559876543" if kind.startswith("twilio") else TO

    result = await cls(broken).send(recipient, PAYLOAD)

    assert result.success is False
    assert drop in (result.error or ""), result.error
    assert not captured.calls, "a provider missing required config must not call out"


@pytest.mark.parametrize("kind", ["mailgun", "sendgrid", "postmark"])
async def test_the_vendors_message_id_is_kept(captured, kind: str) -> None:
    """Without it a bounce investigation has nothing to correlate on."""
    captured.set(_Response(200, {"id": "vendor-msg-42"}))
    cls, cfg = _CONFIGS[kind]
    result = await cls(cfg).send(TO, PAYLOAD)
    assert result.message_id == "vendor-msg-42"


async def test_header_injection_is_refused_and_named_correctly(captured) -> None:
    """
    SMTPProvider validated recipient / sender / subject; the HTTP providers
    must not be a way around that.

    And the error must say what happened. Folding this ValueError into the
    request's own handler reported a header-injection attempt as an SSRF
    block -- the wrong incident in the operator's log, and the wrong thing
    to go looking for.
    """
    result = await MailgunProvider(_CONFIGS["mailgun"][1]).send(
        "victim@example.com" + chr(10) + "Bcc: everyone@example.com", PAYLOAD
    )

    assert result.success is False
    assert "SSRF" not in (result.error or ""), result.error
    assert not captured.calls, "a malformed recipient must not reach the vendor"


def test_no_advertised_provider_type_still_falls_back_to_webhook() -> None:
    """
    Guard the class. Any future catalogue entry wired to WebhookProvider
    without a `url` field in its schema is this same bug again.
    """
    service = NotificationService.__new__(NotificationService)
    builders = inspect.getsource(NotificationService._build_runtime_provider)
    catalog = service.get_provider_types()

    offenders = []
    for entry in catalog:
        ptype = entry["type"]
        schema = entry.get("config_schema", {})
        if "url" in schema or "webhook_url" in schema:
            continue  # genuinely a webhook
        if f'"{ptype}": WebhookProvider' in builders:
            offenders.append(ptype)
    assert not offenders, f"{offenders} build as WebhookProvider but collect no url"


# ── 2. SMTP must not block the loop ──────────────────────────────


def test_smtp_send_passes_a_socket_timeout() -> None:
    """
    ``smtplib.SMTP(host, port)`` with no timeout waits forever. verify() ten
    lines below always passed one, which is what makes this an oversight.
    """
    src = inspect.getsource(SMTPProvider.send)
    assert "smtplib.SMTP(self.host, self.port)" not in src, "no timeout on the send socket"
    assert "_SMTP_TIMEOUT_SECONDS" in src


def test_smtp_send_runs_off_the_event_loop() -> None:
    src = inspect.getsource(SMTPProvider.send)
    assert "asyncio.to_thread" in src
    assert "asyncio.wait_for" in src, "no outer bound on the whole conversation"


async def test_a_hanging_smtp_server_does_not_freeze_the_worker(monkeypatch) -> None:
    """
    The behaviour, not the source. A server that accepts the connection and
    then goes quiet must produce a failed DeliveryResult, not an unfinishable
    coroutine -- and the loop must stay responsive throughout.
    """
    monkeypatch.setattr(nt, "_SMTP_TOTAL_TIMEOUT_SECONDS", 0.3)

    class _Hanging:
        def __init__(self, host, port, timeout=None):
            time.sleep(5)  # blocking, exactly like a silent relay

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import smtplib

    monkeypatch.setattr(smtplib, "SMTP", _Hanging)

    provider = SMTPProvider({"host": "smtp.example.com", "from_email": "a@example.com"})

    ticks = 0

    async def _heartbeat():
        nonlocal ticks
        for _ in range(10):
            await asyncio.sleep(0.02)
            ticks += 1

    send_task = asyncio.create_task(provider.send(TO, PAYLOAD))
    await _heartbeat()
    assert ticks == 10, "the event loop stalled while SMTP was blocking"

    result = await asyncio.wait_for(send_task, timeout=5)
    assert result.success is False


# ── 3. the retry queue ───────────────────────────────────────────


def test_the_retry_task_loads_providers_before_dead_lettering() -> None:
    """
    The dispatcher enqueues with ``provider_id=None`` because the API process
    holds the provider in memory. The Celery worker is a different process and
    holds nothing, so without an explicit load every retry dead-letters on
    attempt 1.
    """
    from app.tasks import notification_retry

    src = inspect.getsource(notification_retry)
    load_at = src.index("load_providers_from_db")
    dead_at = src.index("_mark_dead_letter(\n", load_at - 4000)
    assert load_at < src.index("No provider available"), (
        "the dead-letter still fires before any attempt to load providers"
    )
    assert dead_at >= 0


def test_the_dispatcher_still_enqueues_without_a_provider_id() -> None:
    """
    Premise check. If the dispatch path ever starts passing a real provider_id,
    the load in the worker becomes belt-and-braces rather than the whole fix,
    and this test says so out loud.
    """
    from app.services import notification_helpers

    src = inspect.getsource(notification_helpers)
    assert "provider_id=None" in src


# ── 4. verify must not bless a broken endpoint ───────────────────


@pytest.mark.parametrize("code", [200, 204, 405, 501])
async def test_a_reachable_webhook_verifies(captured, code: int) -> None:
    """
    405 and 501 are reachable: plenty of endpoints refuse OPTIONS while
    accepting POST perfectly well, and failing them would be a false negative.
    """
    captured.set(_Response(code))
    ok, msg = await WebhookProvider({"url": "https://hooks.example.com/abc"}).verify()
    assert ok is True, msg


@pytest.mark.parametrize("code", [400, 401, 403, 404, 410, 500, 502, 503])
async def test_a_broken_webhook_does_not_verify(captured, code: int) -> None:
    """
    The regression: any status at all used to return True, so the UI showed a
    green check on an endpoint that would drop every alert.
    """
    captured.set(_Response(code))
    ok, msg = await WebhookProvider({"url": "https://hooks.example.com/abc"}).verify()
    assert ok is False
    assert str(code) in msg


async def test_a_webhook_with_no_url_does_not_verify(captured) -> None:
    ok, _ = await WebhookProvider({}).verify()
    assert ok is False
    assert not captured.calls


# ── 5. the rate limits that were never applied ───────────────────


class _Redis:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.expires: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, ttl: int) -> None:
        self.expires[key] = ttl


@pytest.fixture
def redis(monkeypatch):
    fake = _Redis()
    monkeypatch.setattr("app.core.redis_client.get_async_redis", lambda **_kw: fake)
    return fake


def _limited_provider(*, per_hour: int = 0, per_day: int = 0):
    provider = WebhookProvider({"url": "https://hooks.example.com/abc"})
    provider.provider_record_id = uuid4()
    provider.rate_limit_per_hour = per_hour
    provider.rate_limit_per_day = per_day
    return provider


async def test_an_hourly_limit_is_actually_enforced(redis) -> None:
    """The regression: these numbers were stored, shown, and read by nothing."""
    service = NotificationService.__new__(NotificationService)
    provider = _limited_provider(per_hour=2)

    assert await service._rate_limit_exceeded(provider) is None
    assert await service._rate_limit_exceeded(provider) is None
    breach = await service._rate_limit_exceeded(provider)
    assert breach is not None and "hour" in breach


async def test_a_daily_limit_is_enforced_independently(redis) -> None:
    service = NotificationService.__new__(NotificationService)
    provider = _limited_provider(per_hour=100, per_day=1)

    assert await service._rate_limit_exceeded(provider) is None
    breach = await service._rate_limit_exceeded(provider)
    assert breach is not None and "day" in breach


async def test_a_provider_with_no_limits_is_never_capped(redis) -> None:
    service = NotificationService.__new__(NotificationService)
    provider = _limited_provider()
    for _ in range(50):
        assert await service._rate_limit_exceeded(provider) is None
    assert not redis.counts, "an unlimited provider should not even touch Redis"


async def test_a_provider_built_outside_the_db_is_never_capped(redis) -> None:
    """Legacy in-memory providers have no record and therefore no limits."""
    service = NotificationService.__new__(NotificationService)
    provider = WebhookProvider({"url": "https://hooks.example.com/abc"})
    assert await service._rate_limit_exceeded(provider) is None


async def test_the_counter_key_expires(redis) -> None:
    """Without a TTL the buckets accumulate forever and the cap never resets."""
    service = NotificationService.__new__(NotificationService)
    await service._rate_limit_exceeded(_limited_provider(per_hour=5, per_day=10))
    assert sorted(redis.expires.values()) == [3600, 86400]


async def test_the_ttl_is_set_once_not_extended_every_send(redis) -> None:
    """Re-arming the TTL on every send would make the bucket never expire."""
    service = NotificationService.__new__(NotificationService)
    provider = _limited_provider(per_hour=100)
    await service._rate_limit_exceeded(provider)
    redis.expires.clear()
    await service._rate_limit_exceeded(provider)
    assert not redis.expires


async def test_a_redis_outage_does_not_silence_alerting(monkeypatch) -> None:
    """
    Deliberate fail-open. This is a spend cap, not a security control, and
    losing Redis must not stop the alert that says Redis is down.
    """

    def _broken(**_kw):
        raise RuntimeError("redis unreachable")

    monkeypatch.setattr("app.core.redis_client.get_async_redis", _broken)
    service = NotificationService.__new__(NotificationService)
    assert await service._rate_limit_exceeded(_limited_provider(per_hour=1)) is None


def test_the_limits_survive_the_trip_through_the_in_memory_registry() -> None:
    """
    ``load_providers_from_db`` copies runtime providers into ``_providers`` and
    drops the record, so the limits have to be stamped onto the instance or
    they are unreachable from the send path.
    """
    src = inspect.getsource(NotificationService._build_runtime_provider)
    assert src.count("_attach_limits") == 2, "one of the two build paths skips the limits"


def test_the_send_path_checks_before_it_sends() -> None:
    src = inspect.getsource(NotificationService.send)
    assert src.index("_rate_limit_exceeded") < src.index("await provider.send(")
