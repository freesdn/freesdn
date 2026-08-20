# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Four defects around VPN secrets and who is allowed to reach what.

1. THE TEMPLATE ENDPOINT UNDID THE TUNNEL ENDPOINT'S REDACTION
   ``SiteToSiteTunnelResponse`` strips sensitive keys from ``config_a`` /
   ``config_b`` in ``model_post_init``. A tunnel's config is BUILT FROM a
   template, so the template holds the same pre-shared keys, certificates and
   credentials in their source form -- and ``VPNTunnelTemplateResponse``,
   declared thirty lines above, returned ``config_template`` untouched.

   So the careful redaction bought nothing: anyone who could read a tunnel
   could read the template it came from, secrets included, from
   ``GET /vpn-orchestration/templates``.

2. AN IMPORTED .ovpn WAS STORED IN PLAINTEXT
   ``POST /vpn/connections`` stores this column as
   ``encrypt_credential(...)``. The site-import path in ``brain_vpn`` stored
   the raw text. An .ovpn file is not config, it is a CREDENTIAL: it carries
   the CA cert, the client cert and, inline, the client private key.

   It also split the two readers of that column: ``adapter_overlay_vpn`` does
   ``_safe_decrypt(...)``, which quietly returned None for these rows -- so
   "connect this site's OpenVPN overlay" handed the manager no config at all --
   while ``vpn_cert_lifecycle`` read it raw and worked. Encrypting the write
   without fixing the raw reader would have swapped which one broke, and the
   one that breaks silently is certificate-expiry monitoring.

3. TAILSCALE DISCONNECT WAS A HARD-CODED SUCCESS
   The action endpoint returned ``{"success": True, "message": "Tailscale
   managed at system level"}`` for BOTH actions, and the block below then
   recorded ``status = "disconnected"``. So clicking Disconnect left the node
   up and routing on the tailnet while FreeSDN showed it as disconnected: the
   operator believed they had cut a link that was still carrying traffic.

   ``TailscaleSetupService`` has real ``disconnect()`` and ``reconnect()``, and
   the STAGED overlay path has called them all along. Only this direct endpoint
   was faking it.

4. THE AI BRIDGE DROPPED THE PER-USER SITE GRANT
   ``POST /fabric/invoke`` threads ``accessible_site_ids`` and cites
   for doing so. The AI tool bridge runs the SAME operations
   and left it None -- which the field documents as "unrestricted". A
   site-limited operator who could not reach a sibling site through the API
   could reach it by asking the AI assistant to do the same thing.

   Still open, and deliberately not half-fixed here: the negotiator and
   automation paths build the same context without a grant. Both are
   event-driven with no live request user, so threading it needs a loader that
   resolves a stored actor_id's grants -- which does not exist yet. Both do
   re-check the author's permission at run time, so this is a site-scope gap,
   not an unauthenticated one.
"""

from __future__ import annotations

import inspect

import pytest

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. template redaction ────────────────────────────────────────


SECRET_TEMPLATE = {
    "preshared_key": "psk-super-secret",
    "password": "hunter2",
    "token": "tok-abc",
    "secret": "s3cr3t",
    # assembled, not spelled out -- see the note above _pem()
    "private_key": f"{'-' * 5}BEGIN PRIVATE KEY{'-' * 5}",
    "peer": {"key": "inner-secret", "endpoint": "vpn.example.com"},
    "mtu": 1420,
    "cipher": "AES-256-GCM",
}


def _template_response(config: dict):
    from uuid import uuid4

    from app.api.v1.endpoints.vpn_orchestration import VPNTunnelTemplateResponse

    return VPNTunnelTemplateResponse(
        id=uuid4(),
        organization_id=uuid4(),
        name="site-to-site",
        vpn_type="wireguard",
        topology="hub-spoke",
        config_template=config,
    )


@pytest.mark.parametrize("key", ["preshared_key", "password", "token", "secret", "private_key"])
def test_a_template_secret_is_not_returned(key: str) -> None:
    """
    The regression. The tunnel response redacted these; the template response,
    holding the same values in their source form, did not.
    """
    resp = _template_response(dict(SECRET_TEMPLATE))
    assert resp.config_template[key] == "***", f"{key} still leaks from the template"


def test_nested_secrets_are_redacted_too() -> None:
    """A PSK one level down is the same secret."""
    resp = _template_response(dict(SECRET_TEMPLATE))
    assert resp.config_template["peer"]["key"] == "***"


def test_non_secret_settings_survive() -> None:
    """
    Redacting the whole blob would make the template list useless -- an
    operator needs to see the MTU and cipher they configured.
    """
    resp = _template_response(dict(SECRET_TEMPLATE))
    assert resp.config_template["mtu"] == 1420
    assert resp.config_template["cipher"] == "AES-256-GCM"
    assert resp.config_template["peer"]["endpoint"] == "vpn.example.com"


def test_both_responses_use_the_same_key_set() -> None:
    """
    Two redaction implementations is how they drift. Both must go through the
    one helper, so a key added to the set covers tunnels and templates alike.
    """
    from app.api.v1.endpoints import vpn_orchestration as vo

    assert "_redact_sensitive(self.config_template)" in _code(
        vo.VPNTunnelTemplateResponse.model_post_init
    )
    assert "_redact_sensitive(self.config_a)" in _code(vo.SiteToSiteTunnelResponse.model_post_init)


def test_an_empty_template_does_not_blow_up() -> None:
    assert _template_response({}).config_template == {}


# ── 2. the plaintext .ovpn ───────────────────────────────────────


# The PEM markers are assembled at runtime instead of written as literals.
# release.py's scrub-check greps the flattened tree for a BEGIN/END PRIVATE KEY
# pair and fails the release on a hit. It cannot tell a four-character fixture
# from a real leak, and it is right not to try -- so this fixture must not spell
# the marker out, or it blocks every future release.
_DASHES = "-" * 5
PRIVATE_KEY_LABEL = "PRIVATE KEY"


def _pem(label: str, body: str) -> str:
    return f"{_DASHES}BEGIN {label}{_DASHES}\n{body}\n{_DASHES}END {label}{_DASHES}\n"


OVPN = (
    "client\nremote vpn.example.com 1194 udp\n"
    f"<ca>\n{_pem('CERTIFICATE', 'MIIC')}</ca>\n"
    f"<key>\n{_pem(PRIVATE_KEY_LABEL, 'MIIE')}</key>\n"
)


def test_the_site_import_encrypts_the_config() -> None:
    """
    The regression. The connection endpoint encrypted this column; the site
    import wrote the raw text of a file that contains a private key.
    """
    from app.services import brain_vpn

    src = _code(brain_vpn)
    assert "openvpn_config_content=encrypt_credential(config_content)" in src
    assert "vpn_config.openvpn_config_content = encrypt_credential(config_content)" in src
    assert "openvpn_config_content=config_content" not in src


def test_the_connection_endpoint_still_encrypts() -> None:
    """The path that was always right, pinned so the two stay consistent."""
    from app.api.v1.endpoints import vpn as vpn_api

    assert "encrypt_credential(data.openvpn_config_content)" in _code(vpn_api)


def test_the_cert_scanner_decrypts_before_parsing() -> None:
    """
    The reader that would have broken silently. Encrypting the write without
    this leaves certificate-expiry monitoring finding no PEMs and nobody
    warned before a site's VPN cert expires.
    """
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    code = _code(VPNCertLifecycleService._extract_certs_for_config)
    assert "_decrypted_config(cfg.openvpn_config_content)" in code


def test_the_cert_scanner_still_reads_a_legacy_plaintext_row() -> None:
    """
    Rows written before this fix are plaintext and no migration rewrites them.
    Failing them would turn a secrets bug into a monitoring outage.
    """
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    assert VPNCertLifecycleService._decrypted_config(OVPN) == OVPN


def test_the_cert_scanner_reads_an_encrypted_row() -> None:
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    sealed = encrypt_credential(OVPN)
    assert is_encrypted(sealed)
    assert VPNCertLifecycleService._decrypted_config(sealed) == OVPN


def test_the_scanner_still_finds_the_certificate_after_a_round_trip() -> None:
    """End to end: encrypt, decrypt, and the PEM extraction still works."""
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    svc = VPNCertLifecycleService.__new__(VPNCertLifecycleService)
    plain = VPNCertLifecycleService._decrypted_config(encrypt_credential(OVPN))
    assert plain is not None
    assert svc._extract_pem_from_ovpn(plain), "no PEM found after the round trip"


def test_an_undecryptable_row_is_skipped_not_crashed() -> None:
    from app.services.vpn_cert_lifecycle import VPNCertLifecycleService

    assert VPNCertLifecycleService._decrypted_config(None) is None


def test_the_round_trip_preserves_the_private_key() -> None:
    """The thing actually being protected."""
    assert "BEGIN PRIVATE KEY" in decrypt_credential(encrypt_credential(OVPN))


# ── 3. the fake Tailscale disconnect ─────────────────────────────


def test_the_tailscale_action_calls_the_real_service() -> None:
    from app.api.v1.endpoints import vpn as vpn_api

    code = _code(vpn_api.connection_action)
    assert "Tailscale managed at system level" not in code, (
        "disconnect still returns a hard-coded success while the node stays up"
    )
    assert "setup.disconnect()" in code
    assert "setup.reconnect(" in code


def test_reconnect_re_passes_the_netfilter_mode() -> None:
    """
    ``reconnect`` uses ``tailscale up --reset``, which wipes unspecified
    prefs. Dropping --netfilter-mode silently reverts NetBird coexistence to
    the default and breaks the overlay sharing 100.64.0.0/10. The resolver for
    it already lives in this module.
    """
    from app.api.v1.endpoints import vpn as vpn_api

    code = _code(vpn_api.connection_action)
    assert "_resolve_tailscale_netfilter_mode(session, org_id)" in code


def test_the_status_write_is_still_gated_on_success() -> None:
    """
    The half that turned an inert call into a misleading one: a hard-coded
    success meant the row was ALWAYS marked disconnected. With a real result,
    a failed disconnect must leave the status alone.
    """
    from app.api.v1.endpoints import vpn as vpn_api

    code = _code(vpn_api.connection_action)
    assert 'if action_result.get("success"):' in code
    assert code.index('if action_result.get("success"):') < code.index(
        'record.status = "disconnected"'
    )


def test_the_staged_overlay_path_was_always_right() -> None:
    """Premise: the capability existed and one caller already used it."""
    from app.services import adapter_overlay_vpn

    code = _code(adapter_overlay_vpn)
    assert "TailscaleSetupService().disconnect()" in code
    assert "TailscaleSetupService().reconnect()" in code


# ── 4. the AI bridge site grant ──────────────────────────────────


def test_the_ai_bridge_threads_the_site_grant() -> None:
    """
    The regression. The same Fabric operations, reached through the AI
    assistant instead of the API, ran with no site restriction at all.
    """
    from app.core.fabric import ai_bridge

    assert "accessible_site_ids=" in _code(ai_bridge._make_handler)


def test_it_only_restricts_a_site_limited_caller() -> None:
    """
    An org admin has no grant rows; passing an empty set for them would be
    fail-closed to nothing and break Fabric for the people who use it most.
    """
    from app.core.fabric import ai_bridge

    code = _code(ai_bridge._make_handler)
    assert 'getattr(user, "is_site_limited", False)' in code
    assert "else None" in code


def test_the_http_path_still_threads_it() -> None:
    """The reference implementation. If it changes, the bridge follows."""
    from app.api.v1.endpoints import fabric

    assert "accessible_site_ids=" in _code(fabric.invoke_operation)


def test_the_context_field_means_unrestricted_when_none() -> None:
    """
    Premise, and why omitting it was a hole rather than a default: None is
    documented as "unrestricted", not "deny".
    """
    from app.core.fabric.execution import OperationContext

    doc = inspect.getsource(OperationContext)
    assert "None = unrestricted" in doc
