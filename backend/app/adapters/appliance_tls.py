# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Consistent TLS trust for TrueNAS and UniFi Protect authenticated transports.

Private CAs extend the system trust store. A configured unreadable/invalid bundle
fails closed. Existing explicit verification opt-outs remain visible warnings;
there is no retry with weaker TLS after a certificate verification failure.
"""

from __future__ import annotations

import logging
import os
import ssl

from app.adapters.exceptions import AdapterConnectionError

logger = logging.getLogger(__name__)


def appliance_tls_context(verify_ssl: bool, *, adapter_id: str) -> ssl.SSLContext:
    if not isinstance(verify_ssl, bool):
        raise AdapterConnectionError("TLS verification setting must be a boolean")
    try:
        context = ssl.create_default_context()
        bundle = os.environ.get("FREESDN_DEVICE_CA_BUNDLE", "")
        if bundle:
            context.load_verify_locations(cafile=bundle)
    except (OSError, ssl.SSLError) as exc:
        raise AdapterConnectionError(
            "Device TLS trust store could not be loaded; check the mounted CA bundle",
            adapter_id=adapter_id,
        ) from exc
    if not verify_ssl:
        logger.warning(
            "%s: TLS peer verification explicitly disabled; connection is not authenticated",
            adapter_id,
        )
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
