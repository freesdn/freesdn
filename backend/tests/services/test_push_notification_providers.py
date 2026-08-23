# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Discord, ntfy and Gotify as native providers.

These three were previously reachable only through the ``notify-hub`` plugin,
which had to bypass the notification system entirely to offer them. That was not
a design choice, it was the only option: ``NotificationService._providers`` is
keyed by ``NotificationChannel``, a closed StrEnum, so a plugin cannot register
a channel. A plugin doing its own HTTP POST is invisible to alert rules, SLA
policies, agent schedules, delivery history, retry queues and per-user
preferences -- every one of which routes through the provider registry.

They ride the WEBHOOK channel with distinct ``provider_type`` values, the same
way SMTP and Gmail OAuth both ride EMAIL. No enum change, and everything that
already dispatches picks them up.

Payloads were verified against a captured wire format before these were written.
The SSRF guard refuses loopback -- correctly -- so the capture point is ``_post``,
the last place before the bytes leave.
"""

from __future__ import annotations

import pytest

from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    DiscordProvider,
    GotifyProvider,
    NotificationChannel,
    NotificationPayload,
    NotificationService,
    NtfyProvider,
    _PushProvider,
)


@pytest.fixture
def sent(monkeypatch):
    """Capture what would go on the wire."""
    box: list[dict] = []

    async def _capture(self, url, body, headers=None):
        box.append({"url": url, "body": body, "headers": headers or {}})
        return DeliveryResult(
            success=True,
            channel=self.channel,
            status=DeliveryStatus.SENT,
            provider=self.provider_type,
        )

    monkeypatch.setattr(_PushProvider, "_post", _capture)
    return box


def _payload(severity="critical", body="ap-kitchen has been offline for 12 minutes"):
    return NotificationPayload(
        title="Device offline",
        body=body,
        data={"severity": severity},
        action_url="https://freesdn.local/devices/abc",
        action_text="Open device",
    )


# ── they are real providers, not a parallel system ──────────────


@pytest.mark.parametrize("provider_type", ["discord_webhook", "ntfy", "gotify"])
def test_each_is_offered_in_the_operators_provider_list(provider_type: str):
    """
    The whole point. Being in ``PROVIDER_TYPES`` is what makes them configurable
    in the same place as SMTP and Slack, rather than in a plugin's own settings
    blob that nothing else can see.
    """
    offered = {t["type"]: t for t in NotificationService.get_provider_types()}
    assert provider_type in offered, f"{provider_type} is not offered to operators"
    assert offered[provider_type]["channel"] == "webhook"
    assert offered[provider_type]["config_schema"], "no config schema; the UI has nothing to render"


@pytest.mark.parametrize(
    ("cls", "secret_field"),
    [(NtfyProvider, "token"), (GotifyProvider, "token")],
)
def test_credentials_are_declared_as_passwords(cls, secret_field: str):
    """
    A token declared as a plain string renders as a visible text input and is
    echoed back on read. The schema type is what makes the platform treat it as
    a secret.
    """
    offered = {t["type"]: t for t in NotificationService.get_provider_types()}
    schema = offered[cls.provider_type]["config_schema"]
    assert schema[secret_field]["type"] == "password"


@pytest.mark.parametrize("cls", [DiscordProvider, NtfyProvider, GotifyProvider])
def test_they_ride_the_webhook_channel(cls):
    """No new enum member. Adding one would be a migration and a UI change for
    three services that are all just an HTTP POST."""
    assert cls.channel is NotificationChannel.WEBHOOK


# ── Discord ─────────────────────────────────────────────────────


async def test_discord_sends_an_embed_coloured_by_severity(sent):
    """
    A colour band is what makes severity readable at a glance in a busy channel.
    Plain ``content`` would be a wall of grey text.
    """
    await DiscordProvider({"webhook_url": "https://discord.com/api/webhooks/1/x"}).send(
        "https://discord.com/api/webhooks/1/x", _payload("critical")
    )
    embed = sent[-1]["body"]["embeds"][0]
    assert embed["title"] == "Device offline"
    assert embed["color"] == 0xDC2626
    assert embed["url"] == "https://freesdn.local/devices/abc"


async def test_discord_severities_are_distinct(sent):
    """Four severities that render as the same colour convey nothing."""
    d = DiscordProvider({"webhook_url": "https://discord.com/api/webhooks/1/x"})
    colours = set()
    for sev in ("info", "warning", "error", "critical"):
        await d.send("https://discord.com/api/webhooks/1/x", _payload(sev))
        colours.add(sent[-1]["body"]["embeds"][0]["color"])
    assert len(colours) == 4


async def test_discord_refuses_a_url_that_is_not_discord():
    """
    ``verify`` is what an operator clicks before saving. Accepting any URL turns
    a notification provider into an arbitrary-POST primitive with a friendly
    name on it.
    """
    ok, msg = await DiscordProvider({"webhook_url": "https://evil.test/collect"}).verify()
    assert ok is False
    assert "Discord" in msg

    ok, _ = await DiscordProvider(
        {"webhook_url": "https://discord.com/api/webhooks/1/abc"}
    ).verify()
    assert ok is True


async def test_discord_title_respects_the_api_limit(sent):
    """Over 256 is a 400 from Discord, not a truncation -- the message never
    arrives at all."""
    p = _payload()
    p.title = "T" * 900
    await DiscordProvider({"webhook_url": "https://discord.com/api/webhooks/1/x"}).send(
        "https://discord.com/api/webhooks/1/x", p
    )
    assert len(sent[-1]["body"]["embeds"][0]["title"]) <= 256


# ── ntfy ────────────────────────────────────────────────────────


async def test_ntfy_maps_severity_to_priority_and_tags(sent):
    await NtfyProvider({"server": "https://ntfy.example.com", "topic": "freesdn"}).send(
        "", _payload("critical")
    )
    body = sent[-1]["body"]
    assert body["topic"] == "freesdn"
    assert body["priority"] == 5
    assert body["tags"], "no tags; ntfy renders these as the notification icon"


async def test_ntfy_honours_a_self_hosted_server(sent):
    """
    Self-hosting is the norm for ntfy. Hardcoding ntfy.sh would send an
    operator's alert contents to a third party they never chose.
    """
    await NtfyProvider({"server": "https://ntfy.internal.example", "topic": "t"}).send(
        "", _payload()
    )
    assert sent[-1]["url"] == "https://ntfy.internal.example"


async def test_ntfy_sends_its_token_as_a_header(sent):
    """Not in the URL, where it lands in access logs and proxies."""
    await NtfyProvider({"server": "https://x.test", "topic": "t", "token": "tk_secret"}).send(
        "", _payload()
    )
    assert "Authorization" in sent[-1]["headers"]
    assert "tk_secret" not in sent[-1]["url"]


async def test_ntfy_requires_a_topic():
    ok, msg = await NtfyProvider({"server": "https://x.test"}).verify()
    assert ok is False and "topic" in msg


# ── Gotify ──────────────────────────────────────────────────────


async def test_gotify_posts_to_the_message_endpoint(sent):
    await GotifyProvider({"server": "https://gotify.example.com/", "token": "t"}).send(
        "", _payload()
    )
    # Trailing slash normalised, or the URL becomes //message.
    assert sent[-1]["url"] == "https://gotify.example.com/message"


async def test_gotify_keeps_the_token_out_of_the_url(sent):
    """
    Gotify's own docs show ``?token=``. That puts an application token into
    every access log, proxy and error report between here and there. The header
    form works identically.
    """
    await GotifyProvider({"server": "https://x.test", "token": "AbCdEf"}).send("", _payload())
    assert "X-Gotify-Key" in sent[-1]["headers"]
    assert "AbCdEf" not in sent[-1]["url"]


async def test_gotify_priority_spans_the_useful_range(sent):
    """8+ is what most Gotify clients treat as "make a noise". An info message
    and a critical one must not both be silent, or both be an alarm."""
    g = GotifyProvider({"server": "https://x.test", "token": "t"})
    seen = {}
    for sev in ("info", "warning", "error", "critical"):
        await g.send("", _payload(sev))
        seen[sev] = sent[-1]["body"]["priority"]
    assert seen["info"] < seen["warning"] < seen["error"] < seen["critical"]
    assert seen["critical"] >= 8


@pytest.mark.parametrize("missing", ["server", "token"])
async def test_gotify_requires_both_halves(missing: str):
    config = {"server": "https://x.test", "token": "t"}
    del config[missing]
    ok, msg = await GotifyProvider(config).verify()
    assert ok is False and missing in msg


# ── shared behaviour ────────────────────────────────────────────


async def test_a_long_body_is_trimmed_rather_than_rejected(sent):
    """
    Each service truncates or rejects differently and none say so clearly, so a
    long alert message would either be silently mangled or dropped.
    """
    await GotifyProvider({"server": "https://x.test", "token": "t"}).send(
        "", _payload(body="x" * 9000)
    )
    assert len(sent[-1]["body"]["message"]) <= GotifyProvider.MAX_BODY


async def test_outbound_requests_go_through_the_ssrf_guard():
    """
    A notification provider is a perfect SSRF pivot: it takes an operator-supplied
    URL from config and posts to it on a schedule. Verified live -- a send to
    169.254.169.254 is refused, which is also why these tests capture at _post
    rather than running a loopback sink.
    """
    import inspect

    # Comment-insensitive: the note explaining the choice names the thing being
    # searched for. Third time this trap has bitten in this codebase.
    code = "".join(
        line
        for line in inspect.getsource(_PushProvider._post).splitlines(keepends=True)
        if not line.lstrip().startswith("#")
    )
    assert "safe_http_request" in code
    assert "httpx" not in code


@pytest.mark.parametrize("cls", [DiscordProvider, NtfyProvider, GotifyProvider])
async def test_a_delivery_failure_returns_a_result_rather_than_raising(cls, monkeypatch):
    """
    Every dispatcher treats a provider as returning a DeliveryResult. One that
    raises would take down a whole fan-out of notifications with it.
    """

    async def _boom(*a, **kw):
        raise ConnectionError("host unreachable")

    monkeypatch.setattr("app.services.notification.safe_http_request", _boom)
    provider = cls({"server": "https://x.test", "token": "t", "webhook_url": "https://x.test"})
    result = await provider._post("https://x.test", {"a": 1})
    assert result.success is False
    assert result.status is DeliveryStatus.FAILED
    assert "unreachable" in (result.error or "")


# ── self-hosted destinations ────────────────────────────────────


async def test_a_self_hosted_push_server_is_reachable_when_declared(monkeypatch):
    """
    The gap these providers walked into. Every notification provider posts
    through the SSRF guard with no allowlist, so anything on the operator's own
    network is refused. Tolerable while the webhook targets were Slack and
    Teams, both public. Not tolerable for ntfy and Gotify, which are
    self-hosted by default -- a push server FreeSDN cannot reach is not a
    channel at all.
    """
    from app.core.config import settings
    from app.services.notification import _notification_allowed_hosts

    monkeypatch.setattr(settings, "NOTIFICATION_ALLOWED_HOSTS", "gotify.internal, ntfy.lan")
    assert _notification_allowed_hosts() == frozenset({"gotify.internal", "ntfy.lan"})


async def test_the_allowlist_is_empty_by_default(monkeypatch):
    """Opt-in. A default that allowed private ranges would turn every
    notification provider into an internal port scanner."""
    from app.core.config import settings
    from app.services.notification import _notification_allowed_hosts

    monkeypatch.setattr(settings, "NOTIFICATION_ALLOWED_HOSTS", "")
    assert _notification_allowed_hosts() == frozenset()


async def test_the_allowlist_is_read_per_call(monkeypatch):
    """An operator adding their Gotify host should not have to restart the API."""
    from app.core.config import settings
    from app.services.notification import _notification_allowed_hosts

    monkeypatch.setattr(settings, "NOTIFICATION_ALLOWED_HOSTS", "a.test")
    assert "a.test" in _notification_allowed_hosts()
    monkeypatch.setattr(settings, "NOTIFICATION_ALLOWED_HOSTS", "b.test")
    assert "b.test" in _notification_allowed_hosts()


@pytest.mark.parametrize("func", ["_post", "send"])
def test_every_outbound_notification_path_passes_the_allowlist(func: str):
    """
    The push providers and the generic webhook. Threading it through one and not
    the other would leave half the destinations unreachable with no hint why.
    """
    import inspect

    from app.services.notification import WebhookProvider

    target = _PushProvider._post if func == "_post" else WebhookProvider.send
    assert "allow_hosts=_notification_allowed_hosts()" in inspect.getsource(target)
