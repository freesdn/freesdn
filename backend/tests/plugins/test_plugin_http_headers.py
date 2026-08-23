# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A plugin could not authenticate to any external API, and was not told why.

``PluginHTTPClient`` blocked the ``authorization`` header. Since almost every
REST API a plugin would want to call -- NetBox, Grafana, PagerDuty, Jira --
authenticates with a bearer or token header, that made the SDK's whole outbound
story unusable for anything but a webhook with the secret in its URL. Worse, the
header was dropped SILENTLY: the author saw a 401 from the remote service and
nothing pointing at FreeSDN.

Blocking it bought nothing:

  * the request goes to a host the PLUGIN chose, so there is no FreeSDN
    credential to forge;
  * reaching FreeSDN's own API is refused by the SSRF guard, which is the
    control that actually applies here;
  * a plugin set on exfiltrating a token can put it in a body or a query string
    just as easily, so the block does not even raise the cost.

``proxy-authorization`` stays blocked, and the distinction is the point: that
header authenticates to an INTERMEDIARY rather than the destination, which is a
different trust boundary and not one a plugin has any business addressing.

The rest of the list is unchanged, and this file exists to keep it that way.
"""

from __future__ import annotations

import inspect

import pytest

from app.plugins.sdk import PluginHTTPClient


def test_authorization_reaches_the_destination():
    """The header the fix is about."""
    assert "authorization" not in PluginHTTPClient._BLOCKED_HEADERS, (
        "authorization is blocked again; no plugin can authenticate to an "
        "external API, and it fails as a 401 from the remote with no clue why"
    )


def test_proxy_authorization_is_still_blocked():
    """A different trust boundary, and still not the plugin's to address."""
    assert "proxy-authorization" in PluginHTTPClient._BLOCKED_HEADERS


@pytest.mark.parametrize(
    "header",
    [
        "host",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "cookie",
        "set-cookie",
        "transfer-encoding",
    ],
)
def test_the_rest_of_the_blocklist_is_intact(header):
    """
    Request smuggling (transfer-encoding), origin spoofing (x-forwarded-*,
    x-real-ip, host) and session injection (cookie) are all still refused. Only
    one entry was removed and it was removed on its own merits.
    """
    assert header in PluginHTTPClient._BLOCKED_HEADERS


def test_cookies_remain_reachable_through_the_kwarg():
    """
    Blocking the raw cookie HEADER is only reasonable because the client
    accepts a ``cookies`` kwarg, which httpx encodes properly. If that were
    ever removed, blocking the header would make cookies unreachable entirely.
    """
    assert "cookies" in PluginHTTPClient._ALLOWED_KWARGS


def test_a_dropped_header_is_logged():
    """
    The silent drop is half the original defect. A blocked header must leave a
    trace, or the author debugs the wrong system.
    """
    src = inspect.getsource(PluginHTTPClient._request)
    assert "dropped" in src, "blocked headers are dropped without a word again"
    assert "logger.warning" in src


def test_transport_and_auth_kwargs_are_still_refused():
    """
    The kwarg allowlist is the other half of this client's containment: it is
    what stops a plugin passing its own transport, proxy or auth object and
    routing around every guard above.
    """
    for forbidden in (
        "transport",
        "proxy",
        "proxies",
        "auth",
        "verify",
        "cert",
        "follow_redirects",
    ):
        assert forbidden not in PluginHTTPClient._ALLOWED_KWARGS, (
            f"{forbidden!r} is now an allowed kwarg; a plugin can bypass the SSRF guard"
        )


# ── outbound reach ───────────────────────────────────────────────


def test_a_plugin_can_reach_a_deploy_owner_trusted_lan_host():
    """
    A plugin could previously only reach the PUBLIC internet, because the
    client passed no ``allow_hosts`` to the SSRF guard at all. For a
    self-hosted infrastructure controller that rules out nearly every
    integration worth having: NetBox, Gotify, Grafana, Home Assistant and
    Uptime Kuma all live on the operator's own network. notify-hub could reach
    ntfy.sh and not the Gotify in the next rack.

    The fix mirrors what Fabric already had (FABRIC_WEBHOOK_ALLOWED_HOSTS)
    rather than inventing a second mechanism: one deploy-owner setting, read
    from config, never from per-org or operator input, so a plugin cannot widen
    its own reach. Entries stay DNS-pinned and TLS-verified, and cloud metadata
    is unreachable regardless.
    """
    from app.core.config import Settings

    assert "PLUGIN_HTTP_ALLOWED_HOSTS" in Settings.model_fields, (
        "the plugin outbound allow list is gone; plugins can only reach the public internet"
    )
    assert Settings.model_fields["PLUGIN_HTTP_ALLOWED_HOSTS"].default == "", (
        "the allow list must default to empty, i.e. public destinations only"
    )

    src = inspect.getsource(PluginHTTPClient._request)
    assert "allow_hosts=allow_hosts" in src, "the client no longer passes the allow list"
    assert "PLUGIN_HTTP_ALLOWED_HOSTS" in src, "the client no longer reads the deploy-owner setting"


def test_the_allow_list_is_not_reachable_from_plugin_input():
    """
    The property that makes the allow list safe. If it were ever sourced from
    a plugin setting or a request, a plugin could trust its own targets and the
    SSRF guard would be advisory.
    """
    src = inspect.getsource(PluginHTTPClient._request)
    window = src.split("allow_hosts", 1)[0][-500:]
    for reachable in ("settings.get(", "self.ctx", 'kwargs.get("allow', "params"):
        assert reachable not in window, (
            f"allow_hosts appears to be influenced by {reachable!r}; it must come "
            "only from deploy-owner configuration"
        )
