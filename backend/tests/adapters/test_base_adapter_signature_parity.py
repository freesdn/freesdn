# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Every adapter override must be callable the way BaseAdapter promises.

Background
----------
``BaseAdapter`` is the vendor-neutral contract. Endpoints like the Switches PoE
toggle, the Clients block/unblock buttons and device adoption call it without
knowing or caring which vendor is behind it::

    await adapter.block_client(client.mac_address)
    await adapter.set_port_poe(device.mac_address, port_index, enabled)
    await adapter.adopt_device(device.mac_address)

UniFi's native API is site-scoped, so its methods were written site-first --
``block_client(site, client_mac)``, ``set_port_poe(site, device_mac, port_idx,
poe_mode)``, ``adopt_device(site, device_mac)``. Placed on the OVERRIDE, that
signature silently broke every one of those call sites: the MAC bound to
``site``, the real parameter went missing, Python raised TypeError, the endpoint
caught it and returned 502. Blocking a client on a UniFi network, toggling PoE
on a UniFi switch port, and adopting a UniFi device failed 100% of the time --
not intermittently, not under load, always.

Nothing caught it because the vendor-specific tests call the vendor-specific
shape, which works, and the neutral endpoints are only exercised against
adapters that happen to conform.

Omada already had the right layering and is the model: its ADAPTER conforms to
the contract and resolves the site internally, while its CLIENT takes the site.
UniFi now does the same, keeping the rich forms under ``*_on_site`` names for
the staged appliers and the /unifi/* endpoints that legitimately know the site.

The rule
--------
An override is call-compatible when every call the base signature permits is
also accepted by the override:

  * the leading positional parameters match the base's, in order and by NAME
    (name matters -- a neutral caller may pass by keyword), and
  * the override does not REQUIRE more arguments than the base supplies.

An override may add optional parameters (UniFi's ``site=`` / ``force=``
keyword-only extras are fine). It may not add required ones.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import pytest

import app.adapters as adapters_pkg
from app.adapters.base import BaseAdapter


def _adapter_classes() -> dict[str, type]:
    """Every concrete BaseAdapter subclass, found by import rather than by name.

    Discovery matters here: an earlier hand-written map of module:ClassName
    silently skipped OpenWRTAdapter because it was spelled ``OpenWrtAdapter``,
    and a skipped adapter is an unchecked adapter.
    """
    for mod in pkgutil.walk_packages(adapters_pkg.__path__, f"{adapters_pkg.__name__}."):
        if mod.name.endswith(".adapter"):
            try:
                importlib.import_module(mod.name)
            except Exception:  # pragma: no cover - optional vendor deps
                continue

    found: dict[str, type] = {}

    def _walk(cls: type) -> None:
        for sub in cls.__subclasses__():
            found[f"{sub.__module__}.{sub.__name__}"] = sub
            _walk(sub)

    _walk(BaseAdapter)
    return found


def _positional_names(fn) -> list[str] | None:
    """Positional-or-keyword parameter names, minus self, minus *args/**kwargs."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):  # pragma: no cover
        return None
    return [
        name
        for name, p in sig.parameters.items()
        if name != "self"
        and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
        and p.kind != p.KEYWORD_ONLY
    ]


def _required_count(fn) -> int:
    sig = inspect.signature(fn)
    return sum(
        1
        for name, p in sig.parameters.items()
        if name != "self"
        and p.default is p.empty
        and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD, p.KEYWORD_ONLY)
    )


_BASE_METHODS = {
    name: fn
    for name, fn in inspect.getmembers(BaseAdapter, predicate=inspect.isfunction)
    if not name.startswith("_")
}

_ADAPTERS = _adapter_classes()

# Adapters the owner has explicitly DEFERRED. They are still registered, so the
# discovery above finds them, but they are out of scope for work and it would be
# dishonest to "fix" a contract on something nobody is maintaining. Listed here
# with the reason rather than silently skipped, so the exemption is visible.
#
#   unifi_protect — deferred by the owner (2026-08-18) along with access_control:
#   "we are not ready for them yet". Its get_snapshot(channel) does not match the
#   base's (device_id, channel, stream). Remove this entry when the adapter comes
#   back into scope.
_DEFERRED_ADAPTERS = {"app.adapters.unifi_protect.adapter.UniFiProtectAdapter"}


def test_discovery_actually_found_the_adapters() -> None:
    """A parity test over an empty set passes and protects nothing."""
    assert len(_ADAPTERS) >= 10, f"only found {sorted(_ADAPTERS)}"
    names = " ".join(_ADAPTERS)
    for vendor in ("unifi", "omada", "hikvision", "opnsense", "openwrt"):
        assert vendor in names.lower(), f"{vendor} adapter was not discovered"


def test_base_contract_is_not_empty() -> None:
    assert len(_BASE_METHODS) >= 20


@pytest.mark.parametrize("adapter_name", sorted(set(_ADAPTERS) - _DEFERRED_ADAPTERS))
def test_overrides_are_call_compatible_with_base(adapter_name: str) -> None:
    adapter = _ADAPTERS[adapter_name]
    problems: list[str] = []

    for name, base_fn in _BASE_METHODS.items():
        impl = getattr(adapter, name, None)
        if impl is None or impl is base_fn:
            continue  # not overridden

        base_pos = _positional_names(base_fn)
        impl_pos = _positional_names(impl)
        if base_pos is None or impl_pos is None:
            continue

        if impl_pos[: len(base_pos)] != base_pos:
            problems.append(
                f"{name}: base takes ({', '.join(base_pos)}) but the override "
                f"takes ({', '.join(impl_pos)}) -- a vendor-neutral call binds "
                "the wrong arguments"
            )
            continue

        if _required_count(impl) > len(base_pos):
            problems.append(
                f"{name}: the override REQUIRES more arguments than the base "
                f"supplies ({', '.join(impl_pos)}); a neutral call raises TypeError"
            )

    assert not problems, (
        f"{adapter_name} breaks the BaseAdapter contract:\n  "
        + "\n  ".join(problems)
        + "\n\nKeep the vendor-shaped method under its own name (see UniFi's "
        "*_on_site methods) and make the override match the base."
    )


# ── Direct guards for the four that were actually broken ─────────


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("block_client", ("aa:bb:cc:dd:ee:ff",)),
        ("unblock_client", ("aa:bb:cc:dd:ee:ff",)),
        ("adopt_device", ("aa:bb:cc:dd:ee:ff",)),
        ("set_port_poe", ("aa:bb:cc:dd:ee:ff", 1, True)),
    ],
)
def test_unifi_accepts_the_neutral_call_shape(method: str, args: tuple) -> None:
    """
    Bind the arguments without executing, which is exactly what used to fail.
    No controller is contacted -- ``Signature.bind`` raises TypeError for the
    broken shape and returns cleanly for the fixed one.
    """
    from app.adapters.unifi.adapter import UniFiAdapter

    fn = getattr(UniFiAdapter, method)
    inspect.signature(fn).bind(object(), *args)


def test_unifi_keeps_the_site_explicit_forms() -> None:
    """
    The staged appliers and the /unifi/* endpoints legitimately know the site
    and must keep a way to say so. Losing these would have traded one breakage
    for another.
    """
    from app.adapters.unifi.adapter import UniFiAdapter

    for rich in (
        "block_client_on_site",
        "unblock_client_on_site",
        "adopt_device_on_site",
        "set_port_poe_on_site",
    ):
        fn = getattr(UniFiAdapter, rich, None)
        assert fn is not None, f"UniFiAdapter lost {rich}"
        assert _positional_names(fn)[0] == "site", f"{rich} should take site first"
