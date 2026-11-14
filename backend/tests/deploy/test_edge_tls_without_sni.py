# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""HTTPS on an IP address must not depend on the client sending SNI.

A browser that opens ``https://192.0.2.76/`` sends no TLS server name: SNI
carries host NAMES only. Behind Docker's port mapping Caddy also cannot fall
back to the address the client dialled (it sees the container's own address),
so without ``default_sni`` it has no certificate to offer and aborts the
handshake with ``tlsv1 alert internal error``. ``install.sh --domain <ip>``
accepts an IP, and the Caddyfile documented IP mode, yet no browser could load
the UI. Found on the 2026-11 soak VM: the installer's own health probe timed out
with status 000 although Caddy had issued the certificate.

Verified by running the built edge image in every mode with a client that sends
no SNI (curl to an IP literal): before, localhost / 127.0.0.1 / an IP all failed
the handshake; with ``default_sni`` following CADDY_SITE_ADDRESS all three return
200, and ``:80`` is unchanged. That run needs Docker, so this test pins the
configuration that produced it.
"""

from __future__ import annotations

import pathlib
import re

import pytest


def _caddyfile() -> pathlib.Path | None:
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "Caddyfile"
        if candidate.is_file():
            return candidate
    return None


_CADDYFILE = _caddyfile()

pytestmark = pytest.mark.skipif(
    _CADDYFILE is None, reason="frontend/ is not in this checkout (backend-only mount)"
)


def _global_options(text: str) -> str:
    """The first top-level ``{ ... }`` block, which Caddy reads as global options."""
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    body = "\n".join(lines)
    match = re.search(r"^\{\n(.*?)^\}", body, re.S | re.M)
    assert match, "the Caddyfile has no global options block"
    return match.group(1)


def test_clients_without_sni_get_the_sites_certificate():
    assert _CADDYFILE is not None
    options = _global_options(_CADDYFILE.read_text(encoding="utf-8"))
    values = re.findall(r"^\s*default_sni\s+(\S+)\s*$", options, re.M)
    assert values == ["{$CADDY_SITE_ADDRESS:localhost}"], (
        "default_sni must follow CADDY_SITE_ADDRESS, or https://<ip>/ fails the TLS "
        f"handshake for every browser; found {values or 'none'}"
    )


def test_the_site_block_is_still_driven_by_the_same_variable():
    assert _CADDYFILE is not None
    text = _CADDYFILE.read_text(encoding="utf-8")
    assert re.search(r"^\{\$CADDY_SITE_ADDRESS::80\} \{$", text, re.M), (
        "default_sni names CADDY_SITE_ADDRESS; if the site block stops using it the "
        "two can disagree and clients without SNI get no certificate again"
    )
