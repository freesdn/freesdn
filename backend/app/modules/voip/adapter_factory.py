# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — FreePBX adapter factory
=================================

Single source of truth for turning a ``voip.pbx`` row into a connected
:class:`FreePBXAdapter`. Both the VoIP module's direct-call path
(``VoIPService._adapter_from_pbx``) and the staged-write bridge
(``FreePBXServiceBase`` under ``app.services``) build their adapters
here so credential handling, the OAuth2 vs web-session selection, and
the TLS-verification acknowledgement gate can never drift between the
two paths.

Credential precedence (matches the encrypted-column migration):
  * ``*_enc`` columns (Fernet) win when set,
  * the legacy ``settings`` JSONB keys are the fallback.

TLS: ``verify_ssl`` is forced True unless the operator has explicitly
flipped ``tls_verify_disabled_acknowledged=True`` on the PBX row — the
third enforcement layer (REST + ARI + AMI-TLS) called out in the audit.

OAuth2: when ``api_client_id`` + ``api_client_secret_enc`` are present,
the adapter activates the FreePBX 16+ Admin API (OAuth2 client_credentials
→ GraphQL). Without them it falls back to web-session auth + AJAX.
"""

from __future__ import annotations

from typing import Any


def build_freepbx_adapter_from_pbx(pbx: Any) -> Any:
    """Build (but do NOT connect) a :class:`FreePBXAdapter` from a PBX row.

    The returned adapter inherits the process-wide ``ADAPTER_READ_ONLY``
    default (True in production), so writes stay gated until an operator
    both flips the env AND passes ``force=True`` through the staging
    apply path. Callers are responsible for ``await adapter.connect()``.
    """
    from app.adapters.freepbx import FreePBXAdapter

    # Lazy import to avoid an import cycle: voip.service imports this
    # factory at call time, and this factory reuses service-level
    # credential helpers. Importing them lazily keeps both module loads
    # acyclic.
    from app.modules.voip.service import (
        _decrypt_or_legacy,
        _decrypt_settings_credentials,
    )

    settings = _decrypt_settings_credentials(pbx.settings or {})
    web_password = _decrypt_or_legacy(
        getattr(pbx, "web_password_enc", None),
        settings.get("api_password") or settings.get("web_password", ""),
    )
    ami_secret = _decrypt_or_legacy(
        getattr(pbx, "ami_secret_enc", None),
        settings.get("ami_secret"),
    )
    ari_password = _decrypt_or_legacy(
        getattr(pbx, "ari_password_enc", None),
        settings.get("ari_password"),
    )
    allowed_prefixes = tuple(str(p) for p in settings.get("allowed_outbound_prefixes") or () if p)
    # verify_ssl is True unless the operator has acknowledged turning it off.
    ack = bool(getattr(pbx, "tls_verify_disabled_acknowledged", False))
    api_client_id = getattr(pbx, "api_client_id", None)
    api_client_secret = _decrypt_or_legacy(
        getattr(pbx, "api_client_secret_enc", None),
        None,
    )

    return FreePBXAdapter(
        host=pbx.ip_address,
        username=settings.get("api_username", "admin"),
        password=web_password,
        ami_username=settings.get("ami_username"),
        ami_secret=ami_secret,
        ari_username=settings.get("ari_username"),
        ari_password=ari_password,
        web_port=pbx.api_port,
        allowed_outbound_prefixes=allowed_prefixes,
        verify_ssl=not ack,
        api_client_id=api_client_id or None,
        api_client_secret=api_client_secret or None,
    )
