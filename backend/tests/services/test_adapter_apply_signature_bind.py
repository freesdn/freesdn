# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Staged appliers must be able to CALL the method they route to.

Background
----------
A staged write travels: stage endpoint -> ``adapter_pending_changes`` row ->
operator review -> ``build_applier`` -> vendor client/adapter method. Three of
those appliers shipped routing a feature to a method whose signature they could
never bind, so the write died with a bare ``TypeError`` -- ``apply_change``
sanitises the failure to the exception class name, so the operator's row read
``failure_reason="TypeError"`` and retrying never helped.

Nothing caught them because every existing apply-path test hands the applier a
``MagicMock``, and a ``MagicMock`` accepts any call shape. The mock WAS the bug:
it made the mismatched call look successful.

So the stub here is generated from ``inspect.signature`` of the real class. A
call the live method would reject raises ``TypeError`` here too, at the same
point, for the same reason.

Pinned here
-----------
* ``firewall.ids_ips.signatures``/create -> ``update_ids_ips_signatures``, which
  is a body-less command trigger taking only ``site_id`` while its ``update_*``
  siblings take ``(site_id, payload)``.
* ``unifi.devices.adopt``/update -> ``adopt_device_on_site``, not the neutral
  one-argument ``BaseAdapter`` wrapper ``adopt_device``.
* the ``truenas.storage.*`` alias the stage endpoint accepts, which the applier
  has to strip before it looks ``_APPLY`` up.
"""

from __future__ import annotations

import importlib
import inspect
import pathlib
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

import app.services
from app.adapters.omada.client import OmadaApiClient
from app.adapters.truenas.adapter import TrueNASAdapter
from app.adapters.unifi.adapter import UniFiAdapter
from app.api.v1.endpoints.adapter_truenas_storage import (
    _PREFIXES,
    validate_storage_operation,
)
from app.services.adapter_omada_firewall import GatewayFirewallService
from app.services.adapter_truenas_storage import (
    _APPLY as STORAGE_APPLY,
)
from app.services.adapter_truenas_storage import (
    GatewayTrueNASStorageService,
    _canonical_feature,
)
from app.services.adapter_unifi_devices import (
    _APPLY as DEVICES_APPLY,
)
from app.services.adapter_unifi_devices import GatewayUniFiDevicesService

# ── signature-faithful stub ──────────────────────────────────────────


def _bound_signature(cls: type, name: str) -> inspect.Signature:
    """``cls.name``'s signature as an *instance* sees it (``self`` dropped)."""
    sig = inspect.signature(getattr(cls, name))
    return sig.replace(parameters=list(sig.parameters.values())[1:])


class SignatureFaithfulStub:
    """A vendor client/adapter stand-in that enforces the REAL signatures.

    Attribute lookup resolves against ``cls`` first, so a name the real class
    does not carry raises ``AttributeError`` (which is what the appliers'
    ``getattr(client, name, None)`` probes expect), and every call is
    ``Signature.bind``-checked before it is recorded -- the same check CPython
    performs when the live method is invoked.
    """

    def __init__(self, cls: type, *, result: Any = None) -> None:
        self._cls = cls
        self._result: Any = {"ok": True} if result is None else result
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        getattr(self._cls, name)  # AttributeError when the class lacks it
        sig = _bound_signature(self._cls, name)

        async def _call(*args: Any, **kwargs: Any) -> Any:
            sig.bind(*args, **kwargs)  # TypeError on a shape the real method rejects
            self.calls.append((name, args, kwargs))
            return self._result

        return _call

    def call_names(self) -> list[str]:
        return [name for name, _a, _kw in self.calls]

    def write_names(self) -> list[str]:
        """Call names minus lifecycle plumbing the appliers run in ``finally``."""
        return [name for name in self.call_names() if name != "disconnect"]

    def one_call(self, name: str) -> tuple[tuple[Any, ...], dict[str, Any]]:
        matches = [(a, kw) for n, a, kw in self.calls if n == name]
        assert len(matches) == 1, f"expected exactly one {name!r} call, got {self.calls!r}"
        return matches[0]


def _change(feature: str, operation: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=kw.get("payload", {}),
        target_id=kw.get("target_id"),
        controller_id=kw.get("controller_id", uuid4()),
        organization_id=kw.get("organization_id", uuid4()),
        omada_site_id=kw.get("omada_site_id", "site-abc"),
    )


class TestStubIsHonest:
    """The stub is the whole point of this file -- prove it can fail."""

    async def test_wrong_arity_raises_typeerror(self) -> None:
        stub = SignatureFaithfulStub(OmadaApiClient)
        with pytest.raises(TypeError):
            await stub.update_ids_ips_signatures("site-abc", {"extra": 1})

    async def test_unknown_keyword_raises_typeerror(self) -> None:
        stub = SignatureFaithfulStub(UniFiAdapter)
        with pytest.raises(TypeError):
            await stub.adopt_device("aa:bb:cc:dd:ee:ff", force=True)

    async def test_missing_attribute_raises(self) -> None:
        stub = SignatureFaithfulStub(OmadaApiClient)
        with pytest.raises(AttributeError):
            stub.no_such_client_method  # noqa: B018

    async def test_correct_shape_is_accepted(self) -> None:
        stub = SignatureFaithfulStub(OmadaApiClient)
        await stub.update_ids_ips_signatures("site-abc")
        assert stub.one_call("update_ids_ips_signatures") == (("site-abc",), {})


# ── Omada gateway firewall ───────────────────────────────────────────


def _omada_firewall_service() -> tuple[GatewayFirewallService, SignatureFaithfulStub]:
    svc = GatewayFirewallService(MagicMock())
    client = SignatureFaithfulStub(OmadaApiClient)

    async def _ctrl(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _client(*_a: Any, **_kw: Any) -> Any:
        return client

    svc._get_controller = _ctrl  # type: ignore[method-assign]
    svc._get_client = _client  # type: ignore[method-assign]
    return svc, client


class TestOmadaIdsIpsSignatureRefresh:
    async def test_signature_refresh_calls_site_only_command(self) -> None:
        """``update_ids_ips_signatures(site_id)`` -- no payload.

        Mutation this catches: routing the feature through the generic
        ``create`` branch (``method(omada_site_id, payload)``), which is what
        shipped and made every staged signature refresh fail with ``TypeError``
        before it reached the controller.
        """
        svc, client = _omada_firewall_service()
        change = _change("firewall.ids_ips.signatures", "create", payload={})
        await svc.build_applier(change)(change)
        assert client.one_call("update_ids_ips_signatures") == (("site-abc",), {})

    async def test_signature_refresh_ignores_a_payload_it_cannot_send(self) -> None:
        """The controller command takes no body, so a payload must not be forwarded.

        Mutation this catches: a "fix" that passes the payload through as a
        second positional or as a keyword -- the client method has neither.
        """
        svc, client = _omada_firewall_service()
        change = _change(
            "firewall.ids_ips.signatures",
            "create",
            payload={"categories": ["botnet"]},
        )
        await svc.build_applier(change)(change)
        assert client.one_call("update_ids_ips_signatures") == (("site-abc",), {})

    async def test_ids_ips_config_update_still_takes_the_payload(self) -> None:
        """Guard against the new branch being over-broad.

        ``firewall.ids_ips``/update is a genuine config PUT and MUST keep
        sending its payload; a prefix match instead of an exact feature match
        would silently drop it.
        """
        svc, client = _omada_firewall_service()
        change = _change("firewall.ids_ips", "update", payload={"mode": "prevent"})
        await svc.build_applier(change)(change)
        assert client.one_call("update_ids_ips_config") == (
            ("site-abc", {"mode": "prevent"}),
            {},
        )

    @pytest.mark.parametrize(
        ("feature", "operation", "target_id"),
        [
            ("firewall.urlfilter.rule", "create", None),
            ("firewall.urlfilter.rule", "update", "rule-1"),
            ("firewall.urlfilter.rule", "delete", "rule-1"),
            ("firewall.port_forward", "create", None),
            ("firewall.port_forward", "update", "pf-1"),
            ("firewall.port_forward", "delete", "pf-1"),
            ("firewall.dmz", "update", None),
            ("firewall.one_to_one_nat", "create", None),
            ("firewall.upnp", "update", None),
            ("firewall.upnp.mapping", "delete", "map-1"),
            ("firewall.attack_defense", "update", None),
            ("firewall.alg", "update", None),
        ],
    )
    async def test_generic_branches_bind_against_the_real_client(
        self, feature: str, operation: str, target_id: str | None
    ) -> None:
        """Every other entry in the map must still bind after the special case."""
        svc, client = _omada_firewall_service()
        change = _change(feature, operation, payload={"k": "v"}, target_id=target_id)
        await svc.build_applier(change)(change)
        assert len(client.calls) == 1


# ── UniFi devices ────────────────────────────────────────────────────


def _unifi_devices_service() -> tuple[GatewayUniFiDevicesService, SignatureFaithfulStub]:
    svc = GatewayUniFiDevicesService(MagicMock())
    adapter = SignatureFaithfulStub(UniFiAdapter)
    ctrl = MagicMock()
    # Operator-configured allowlist -> the IDOR guard short-circuits without a
    # live sites lookup, which is the onboarded-controller path.
    ctrl.site_mappings = {"default": str(uuid4())}

    async def _resolve(*_a: Any, **_kw: Any) -> Any:
        return ctrl

    async def _get_adapter(*_a: Any, **_kw: Any) -> Any:
        return adapter

    svc._resolve_controller_or_gateway = _resolve  # type: ignore[method-assign]
    svc._get_adapter = _get_adapter  # type: ignore[method-assign]
    return svc, adapter


class TestUniFiDeviceAdopt:
    async def test_adopt_routes_to_the_site_aware_method(self) -> None:
        """Adoption must hit ``adopt_device_on_site(site, mac, force=True)``.

        Mutation this catches: pointing the map back at ``adopt_device``, the
        neutral ``BaseAdapter`` wrapper, which takes one positional and no
        ``force`` -- the shipped wiring, which made every staged adoption fail
        with ``TypeError`` before any HTTP request was made.
        """
        svc, adapter = _unifi_devices_service()
        change = _change(
            "unifi.devices.adopt",
            "update",
            payload={"site": "default"},
            target_id="aa:bb:cc:dd:ee:ff",
        )
        await svc.build_applier(change)(change)
        assert adapter.one_call("adopt_device_on_site") == (
            ("default", "aa:bb:cc:dd:ee:ff"),
            {"force": True},
        )

    async def test_adopt_does_not_call_the_default_site_wrapper(self) -> None:
        """``adopt_device`` targets ``_default_site``; a staged change names its own."""
        svc, adapter = _unifi_devices_service()
        change = _change(
            "unifi.devices.adopt",
            "update",
            payload={"site": "default"},
            target_id="aa:bb:cc:dd:ee:ff",
        )
        await svc.build_applier(change)(change)
        assert "adopt_device" not in adapter.call_names()

    @pytest.mark.parametrize(
        ("feature", "payload", "expect"),
        [
            ("unifi.devices.restart", {"site": "default"}, "restart_device"),
            ("unifi.devices.upgrade", {"site": "default"}, "upgrade_device"),
            (
                "unifi.devices.force_provision",
                {"site": "default"},
                "force_provision_device",
            ),
            (
                "unifi.devices.disable",
                {"site": "default", "disabled": True},
                "disable_device",
            ),
            (
                "unifi.devices.port_override",
                {"site": "default", "port_idx": 3, "overrides": {"name": "up"}},
                "update_switch_port",
            ),
            (
                "unifi.devices.set_port_poe",
                {"site": "default", "port_idx": 3, "mode": "auto"},
                "set_port_poe_on_site",
            ),
            (
                "unifi.devices.locate",
                {"site": "default", "enabled": True},
                "locate_device",
            ),
        ],
    )
    async def test_every_other_feature_binds_against_the_real_adapter(
        self, feature: str, payload: dict[str, Any], expect: str
    ) -> None:
        svc, adapter = _unifi_devices_service()
        change = _change(feature, "update", payload=payload, target_id="aa:bb:cc:dd:ee:ff")
        await svc.build_applier(change)(change)
        assert adapter.call_names() == [expect]

    def test_map_covers_every_feature_the_applier_branches_on(self) -> None:
        assert ("unifi.devices.adopt", "update") in DEVICES_APPLY


# ── TrueNAS storage: the vendor-qualified alias ──────────────────────


def _truenas_service() -> tuple[GatewayTrueNASStorageService, SignatureFaithfulStub]:
    svc = GatewayTrueNASStorageService(MagicMock())
    adapter = SignatureFaithfulStub(TrueNASAdapter)

    async def _ctrl(*_a: Any, **_kw: Any) -> Any:
        return MagicMock()

    async def _adapter(*_a: Any, **_kw: Any) -> Any:
        return adapter

    svc._get_controller = _ctrl  # type: ignore[method-assign]
    svc._get_truenas_adapter = _adapter  # type: ignore[method-assign]
    return svc, adapter


_ALIAS_CASES: list[tuple[str, str, dict[str, Any], str]] = [
    (
        "truenas.storage.dataset",
        "create",
        {"name": "tank/backups"},
        "create_dataset",
    ),
    (
        "truenas.storage.snapshot",
        "create",
        {"dataset": "tank/backups", "name": "nightly"},
        "create_snapshot",
    ),
    (
        "truenas.storage.snapshot",
        "delete",
        {"snapshot_id": "tank/backups@nightly"},
        "delete_snapshot",
    ),
    ("truenas.storage.scrub", "start", {"pool": "tank"}, "start_scrub"),
]


class TestTrueNASVendorPrefixAlias:
    @pytest.mark.parametrize(("feature", "operation", "payload", "expect"), _ALIAS_CASES)
    async def test_alias_reaches_the_appliance(
        self, feature: str, operation: str, payload: dict[str, Any], expect: str
    ) -> None:
        """A row staged under ``truenas.storage.*`` must apply.

        Mutation this catches: looking ``_APPLY`` up with the raw
        ``c.feature`` (the shipped code), which misses the bare-``storage.*``
        keys and 400s "no applier" forever -- after the change was reviewed and
        approved.
        """
        svc, adapter = _truenas_service()
        change = _change(feature, operation, payload=payload)
        await svc.build_applier(change)(change)
        assert adapter.write_names() == [expect]
        _args, kwargs = adapter.one_call(expect)
        assert kwargs["force"] is True

    @pytest.mark.parametrize(("feature", "operation", "payload", "expect"), _ALIAS_CASES)
    async def test_alias_and_bare_form_reach_the_same_method(
        self, feature: str, operation: str, payload: dict[str, Any], expect: str
    ) -> None:
        bare = feature.removeprefix("truenas.")
        svc_a, adapter_a = _truenas_service()
        change_a = _change(feature, operation, payload=payload)
        await svc_a.build_applier(change_a)(change_a)

        svc_b, adapter_b = _truenas_service()
        change_b = _change(bare, operation, payload=payload)
        await svc_b.build_applier(change_b)(change_b)

        assert adapter_a.calls == adapter_b.calls
        assert adapter_a.write_names() == [expect]

    async def test_bare_store_blob_still_reaches_the_blob_branch(self) -> None:
        """The management normalisation must not divert the blob path.

        Mutation this catches: routing ``storage.store_blob`` into
        ``_apply_management`` (e.g. by inverting the branch), which would reject
        every Fabric blob upload with 400 "no applier" instead of validating the
        destination.
        """
        svc, _adapter = _truenas_service()
        change = _change("storage.store_blob", "create", payload={})
        with pytest.raises(HTTPException) as exc:
            await svc.build_applier(change)(change)
        # Reached the blob branch: it complains about the dataset path, not
        # about there being no applier for the feature.
        assert exc.value.status_code == 400
        assert "dataset_path" in str(exc.value.detail)

    async def test_alias_store_blob_remains_a_known_dead_end(self) -> None:
        """``truenas.storage.store_blob`` still 400s, and that is not a regression.

        The blob branch deliberately keys on the RAW ``c.feature`` -- see the
        comment on it -- so the aliased form drops through
        ``_apply_management`` and 400s exactly as it did before the management
        aliases were normalised. Pinned so that behaviour is a decision on
        record rather than something a reader has to rediscover; nothing an
        operator can reach depends on it (Fabric stages the canonical name, and
        an HTTP-staged blob carries no ``_artifact`` and 409s regardless).
        """
        svc, adapter = _truenas_service()
        change = _change("truenas.storage.store_blob", "create", payload={})
        with pytest.raises(HTTPException) as exc:
            await svc.build_applier(change)(change)
        assert exc.value.status_code == 400
        assert adapter.write_names() == []

    async def test_withheld_destructive_alias_is_still_refused(self) -> None:
        """Normalising the lookup must not open a door the platform closed."""
        svc, adapter = _truenas_service()
        change = _change("truenas.storage.dataset", "delete", payload={"name": "tank/backups"})
        with pytest.raises(HTTPException) as exc:
            await svc.build_applier(change)(change)
        assert exc.value.status_code == 400
        assert adapter.write_names() == []

    async def test_unknown_alias_feature_still_400s(self) -> None:
        svc, adapter = _truenas_service()
        change = _change("truenas.storage.nonsense", "create", payload={})
        with pytest.raises(HTTPException) as exc:
            await svc.build_applier(change)(change)
        assert exc.value.status_code == 400
        assert "no applier" in str(exc.value.detail)
        assert adapter.write_names() == []


class TestStagePrefixesAndApplierAgree:
    """The two ends of the alias must not drift apart again.

    ``validate_storage_operation`` (endpoint) strips the vendor prefix inline;
    ``_canonical_feature`` (service) is what the applier uses. If someone adds a
    third accepted prefix to ``_PREFIXES`` without teaching the applier about
    it, every change staged under it becomes unappliable -- exactly the shape of
    the defect this file pins.
    """

    @pytest.mark.parametrize("prefix", _PREFIXES)
    def test_every_accepted_prefix_normalises_into_the_apply_keyspace(self, prefix: str) -> None:
        for feature, operation in sorted(STORAGE_APPLY):
            aliased = prefix + feature.removeprefix("storage.")
            validate_storage_operation(aliased, operation)  # accepted at stage
            assert (
                _canonical_feature(aliased),
                operation,
            ) in STORAGE_APPLY, f"{aliased!r} stages but does not normalise into _APPLY"


# ── class-wide ratchet ───────────────────────────────────────────────

# Vendor -> the classes a staged applier may dispatch on. Two entries where the
# service layer is split: several UniFi/Omada services resolve the full adapter
# (``_get_adapter``) and others the wrapped REST client (``_get_client``), and
# for the ones driven by a shared base (``GatewayUniFiServiceBase``) neither
# call appears in the service's own source, so which of the two is in play is
# not statically decidable. Accepting either keeps the check honest instead of
# guessing.
_VENDOR_TARGETS: dict[str, tuple[str, ...]] = {
    "omada": (
        "app.adapters.omada.client:OmadaApiClient",
        "app.adapters.omada.adapter:OmadaAdapter",
    ),
    "mikrotik": (
        "app.adapters.mikrotik.client:MikroTikClient",
        "app.adapters.mikrotik.adapter:MikroTikAdapter",
    ),
    "opnsense": (
        "app.adapters.opnsense.client:OPNsenseClient",
        "app.adapters.opnsense.adapter:OPNsenseAdapter",
    ),
    "pfsense": (
        "app.adapters.pfsense.client:PfSenseClient",
        "app.adapters.pfsense.adapter:PfSenseAdapter",
    ),
    "openwrt": (
        "app.adapters.openwrt.client:OpenWRTClient",
        "app.adapters.openwrt.adapter:OpenWRTAdapter",
    ),
    "unifi": ("app.adapters.unifi.adapter:UniFiAdapter", "app.adapters.unifi.client:UniFiClient"),
    "unifi_protect": ("app.adapters.unifi_protect.adapter:UniFiProtectAdapter",),
    "truenas": ("app.adapters.truenas.adapter:TrueNASAdapter",),
    "proxmox": ("app.adapters.proxmox.adapter:ProxmoxAdapter",),
    "freepbx": ("app.adapters.freepbx.adapter:FreePBXAdapter",),
    "hikvision": ("app.adapters.hikvision.adapter:HikvisionAdapter",),
    "grandstream": ("app.adapters.grandstream.adapter:GrandstreamAdapter",),
    "onvif": ("app.adapters.onvif.adapter:ONVIFAdapter",),
}


def _load(spec: str) -> type:
    module_name, _, class_name = spec.partition(":")
    return cast(type, getattr(importlib.import_module(module_name), class_name))


def _apply_map_services() -> list[tuple[str, str, dict[tuple[str, str], str]]]:
    """(module stem, controller type, _APPLY) for every staged-write service."""
    services_dir = pathlib.Path(app.services.__file__).parent
    out: list[tuple[str, str, dict[tuple[str, str], str]]] = []
    for path in sorted(services_dir.glob("adapter_*.py")):
        module = importlib.import_module(f"app.services.{path.stem}")
        apply_map = getattr(module, "_APPLY", None)
        if not isinstance(apply_map, dict) or not apply_map:
            continue
        svc = next(
            (
                obj
                for obj in vars(module).values()
                if inspect.isclass(obj)
                and obj.__module__ == module.__name__
                and getattr(obj, "SUPPORTED_CONTROLLER_TYPE", None)
            ),
            None,
        )
        vendor = getattr(svc, "SUPPORTED_CONTROLLER_TYPE", "")
        out.append((path.stem, str(vendor), apply_map))
    return out


_APPLY_SERVICES = _apply_map_services()


class TestEveryApplyMapNamesARealMethod:
    """Nothing may route a staged write to a method that does not exist.

    Narrower than the rest of this file on purpose, and worth saying plainly:
    this walks all 64 ``_APPLY`` maps but only checks that the NAME resolves. It
    would NOT have caught the UniFi adopt defect, because ``adopt_device``
    exists -- it is the wrong overload. Only the bind-checked tests above catch
    a shape mismatch, and they cover one module each.

    What it does catch: renaming or deleting a vendor method without updating
    the map that points at it, and a typo in a new map entry -- both of which
    are 501/AttributeError at apply time, after review and approval.
    """

    def test_the_sweep_actually_found_the_services(self) -> None:
        # A broken discovery helper would make every case below vacuous.
        assert len(_APPLY_SERVICES) > 50
        stems = {stem for stem, _v, _m in _APPLY_SERVICES}
        assert {"adapter_omada_firewall", "adapter_unifi_devices"} <= stems

    @pytest.mark.parametrize(
        ("stem", "vendor", "apply_map"),
        [pytest.param(*row, id=row[0]) for row in _APPLY_SERVICES],
    )
    def test_apply_map_names_resolve(
        self, stem: str, vendor: str, apply_map: dict[tuple[str, str], str]
    ) -> None:
        specs = _VENDOR_TARGETS.get(vendor)
        assert specs, f"{stem}: controller type {vendor!r} is not in _VENDOR_TARGETS"
        classes = [_load(spec) for spec in specs]
        missing = sorted(
            {name for name in apply_map.values() if not any(hasattr(c, name) for c in classes)}
        )
        assert not missing, (
            f"{stem} routes staged writes to {missing}, which "
            f"{[c.__name__ for c in classes]} do not define"
        )
