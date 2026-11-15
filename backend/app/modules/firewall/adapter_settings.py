# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Which keys of a gateway's ``settings`` JSON reach the adapter constructor.

``GatewayConnection.settings`` is free-form JSON an organization admin can set
through the API. Two builders splatted it into ``adapter_registry.create_adapter``
as keyword arguments: ``app.modules.gateway.adapter_helpers.build_adapter`` (the
sync, drift, distribution and passthrough paths) passed it whole, and
``GatewayService._build_adapter`` dropped only a short block-list. Every other
key became a constructor argument. A key the adapter knows changes how it
connects: ``use_ssl`` switches TLS, ``timeout`` sets how long a sync may hold a
worker, and pfSense's ``api_version`` is pasted into every request path. A key
that collides with an explicit argument (``verify_ssl``, ``port``) did not
override it but raised ``TypeError`` instead, breaking every sync of that
gateway.

Now each vendor has an explicit allow-list of the options its adapter actually
reads, each with a value check. Everything else, and every value that fails its
check, is dropped and logged (the key, never the value). Connection identity
(host, port, TLS verification, credentials) and the write gate never come from
this JSON; they come from their own columns.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["GATEWAY_ADAPTER_SETTINGS", "gateway_adapter_settings"]

_DROP = object()

#: Longest request timeout a gateway's settings may ask for, in seconds. A sync
#: and the light health poll hold a worker slot for this long per request.
MAX_TIMEOUT_SECONDS = 120

_INTERFACE_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


def _bool(value: Any) -> Any:
    return value if type(value) is bool else _DROP


def _timeout(value: Any) -> Any:
    if type(value) not in (int, float):
        return _DROP
    return value if 1 <= value <= MAX_TIMEOUT_SECONDS else _DROP


def _pfsense_api_version(value: Any) -> Any:
    # Pasted into every request path (/api/{api_version}/...), so only the two
    # versions the client implements.
    return value if value in ("v1", "v2") else _DROP


def _interface_name(value: Any) -> Any:
    return value if isinstance(value, str) and _INTERFACE_NAME.fullmatch(value) else _DROP


#: vendor -> {setting key -> value check}. Keys are matched exactly.
GATEWAY_ADAPTER_SETTINGS: dict[str, dict[str, Callable[[Any], Any]]] = {
    # OPNsense is HTTPS-only; its adapter refuses use_ssl=False with a clear
    # error, so the key is forwarded for that message.
    "opnsense": {"use_ssl": _bool, "timeout": _timeout, "parent_interface": _interface_name},
    "pfsense": {"use_ssl": _bool, "timeout": _timeout, "api_version": _pfsense_api_version},
    "mikrotik": {"use_ssl": _bool, "timeout": _timeout},
    "openwrt": {"timeout": _timeout, "parent_interface": _interface_name},
}


def gateway_adapter_settings(
    vendor: Any,
    settings: Mapping[str, Any] | None,
    *,
    gateway_id: Any = None,
) -> dict[str, Any]:
    """The constructor keyword arguments ``settings`` may supply for ``vendor``."""
    allowed = GATEWAY_ADAPTER_SETTINGS.get(str(getattr(vendor, "value", vendor)).lower(), {})
    kept: dict[str, Any] = {}
    dropped: list[str] = []
    for key, value in (settings or {}).items():
        check = allowed.get(key) if isinstance(key, str) else None
        checked = check(value) if check is not None else _DROP
        if checked is _DROP:
            dropped.append(str(key)[:64])
        else:
            kept[key] = checked
    if dropped:
        # Once per gateway and key set per process: the sync and health poll
        # build an adapter every few minutes, and the same ignored key does not
        # need a warning each time.
        memo = (str(gateway_id), str(vendor), tuple(sorted(dropped)))
        if memo not in _WARNED:
            if len(_WARNED) >= 1024:
                _WARNED.clear()
            _WARNED.add(memo)
            logger.warning(
                "Gateway %s: settings %s are not %s adapter options or have an "
                "invalid value; ignored",
                gateway_id or "(unsaved)",
                sorted(dropped),
                vendor,
            )
    return kept


_WARNED: set[tuple[str, str, tuple[str, ...]]] = set()
