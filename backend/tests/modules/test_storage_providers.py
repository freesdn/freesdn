# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The storage module was the TrueNAS module.

``_fabric_storage_health_handler`` selected controllers with
``Controller.controller_type == "truenas"`` and called ``build_truenas_adapter``
directly. "Storage health across the org" therefore meant "health of the org's
TrueNAS boxes", and a second vendor could not be added without editing the
query and the loop -- which is the real reason storage was single-vendor, not
the absence of a second adapter.

The seam is a provider: it turns one controller into the three things
``summarize_health`` already consumes, and the handler iterates a registry
instead of naming a vendor.

**Proxmox is the second provider, and the choice was deliberate.** A Synology or
Unraid adapter would be larger, and would ship mock-tested against hardware
nobody here has -- exactly the kind of unproven surface ``maturity.py`` exists
to flag. Proxmox storage reads are already implemented and already exercised
against the maintainer's live cluster, so this is a vendor whose numbers can
actually be checked. It is read-only, which also keeps the standing rule that
Proxmox writes stay off.

The mapping is where the thought went. Proxmox reports no ZFS status word --
it has capacity plus ``active`` and ``enabled`` flags -- so the provider
translates those into the vocabulary the summariser already understands rather
than teaching the summariser a second dialect.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.modules.storage.health import summarize_health
from app.modules.storage.providers import (
    STORAGE_PROVIDERS,
    _ProxmoxProvider,
    read_controller_storage,
    storage_controller_types,
)


def _proxmox_row(**over):
    row = {
        "storage": "local-lvm",
        "type": "lvmthin",
        "total": 1000,
        "used": 100,
        "avail": 900,
        "active": True,
        "enabled": True,
        "shared": False,
    }
    row.update(over)
    return row


# ── the module is no longer one vendor ──────────────────────────


def test_storage_covers_more_than_one_vendor():
    """
    The whole point. A single-entry registry is the state this replaced.
    """
    assert len(STORAGE_PROVIDERS) >= 2
    assert "truenas" in STORAGE_PROVIDERS
    assert "proxmox" in STORAGE_PROVIDERS


def test_the_query_filter_comes_from_the_registry():
    """
    The hardcoded ``controller_type == "truenas"`` lived in the query, so a
    provider registered without the query knowing is a vendor that never gets
    read. This is the wiring that makes registration sufficient.
    """
    import inspect

    from app.modules.storage import module as mod

    src = inspect.getsource(mod._fabric_storage_health_handler)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))

    assert "storage_controller_types()" in body
    assert '== "truenas"' not in body, "the vendor is hardcoded again"


def test_the_handler_does_not_name_an_adapter():
    """
    Building a specific adapter in the handler is the other half of the
    hardcoding: the query could be generic and the loop still TrueNAS-only.
    """
    import inspect

    from app.modules.storage import module as mod

    src = inspect.getsource(mod._fabric_storage_health_handler)

    assert "build_truenas_adapter" not in src
    assert "read_controller_storage" in src


def test_registering_a_vendor_is_one_entry(monkeypatch):
    """
    A third vendor should be a class and a dict entry. If the filter is
    computed from the registry, adding one changes what the query selects
    without touching the query.
    """
    before = storage_controller_types()
    monkeypatch.setitem(STORAGE_PROVIDERS, "synology", _ProxmoxProvider())

    assert "synology" in storage_controller_types()
    assert set(before) < set(storage_controller_types())


# ── the Proxmox mapping ─────────────────────────────────────────


def test_an_enabled_active_datastore_is_online():
    pool = _ProxmoxProvider._to_pool("pve1", _proxmox_row())

    assert pool.status == "ONLINE"
    assert pool.usage.size == 1000
    assert pool.usage.allocated == 100


def test_a_disabled_datastore_reports_offline_not_healthy():
    """
    An administratively disabled storage is not a fault, but it is not holding
    anything either. Reporting it healthy is how a backup target turns out to
    have been switched off for a month.
    """
    pool = _ProxmoxProvider._to_pool("pve1", _proxmox_row(enabled=False))

    assert pool.status == "OFFLINE"


def test_an_inactive_but_enabled_datastore_reports_unavail():
    """
    Configured and not answering -- which is close to exactly what UNAVAIL
    means in ZFS, so the summariser needs no new vocabulary.
    """
    pool = _ProxmoxProvider._to_pool("pve1", _proxmox_row(active=False))

    assert pool.status == "UNAVAIL"


def test_datastores_are_namespaced_by_node():
    """
    Two nodes commonly both have ``local-lvm``. Collapsing them would report
    one node's capacity for both, and the operator would chase a full disk on
    the wrong machine.
    """
    a = _ProxmoxProvider._to_pool("pve1", _proxmox_row())
    b = _ProxmoxProvider._to_pool("pve2", _proxmox_row())

    assert a.name != b.name
    assert a.name == "pve1/local-lvm"


def test_the_mapping_reads_objects_as_well_as_dicts():
    """
    ``get_storage`` returns ``ProxmoxStorage`` models, not dicts. A mapping
    that only understood dicts would produce a rollup of empty pools and look
    like a healthy, idle cluster.
    """
    model = SimpleNamespace(storage="tank", total=500, used=250, active=True, enabled=True)

    pool = _ProxmoxProvider._to_pool("pve1", model)

    assert pool.name == "pve1/tank"
    assert pool.usage.size == 500


# ── the two vendors agree once summarised ───────────────────────


def test_a_proxmox_datastore_flows_through_the_shared_summariser():
    """
    The property that makes this one module rather than two: a Proxmox
    datastore over capacity must raise the same warning a ZFS pool would,
    through the same code.
    """
    pools = [_ProxmoxProvider._to_pool("pve1", _proxmox_row(total=1000, used=950))]

    summary = summarize_health(pools, [], {})

    assert summary["status"] == "warning"
    assert summary["over_capacity_pools"] == ["pve1/local-lvm"]


def test_an_offline_datastore_escalates_like_a_faulted_pool():
    pools = [_ProxmoxProvider._to_pool("pve1", _proxmox_row(enabled=False))]

    summary = summarize_health(pools, [], {})

    assert summary["status"] == "error"
    assert summary["degraded_pools"] == ["pve1/local-lvm"]


def test_a_healthy_datastore_is_not_flagged():
    """Guards the two tests above from passing because everything is flagged."""
    summary = summarize_health([_ProxmoxProvider._to_pool("pve1", _proxmox_row())], [], {})

    assert summary["status"] == "ok"
    assert summary["degraded_pools"] == []


def test_proxmox_reports_no_temperatures_rather_than_zero():
    """
    Proxmox exposes no per-disk SMART temperature through this path. Reporting
    0 C would be a number an operator could read as "cold and fine"; an absence
    is honest and the summariser already handles it.
    """
    import asyncio

    class _Adapter:
        async def get_nodes(self):
            return SimpleNamespace(data=[])

        async def disconnect(self):
            return None

    async def _run():
        import app.services.adapter_proxmox_vm as vm

        original = vm.build_proxmox_adapter
        vm.build_proxmox_adapter = lambda _c: _fake()
        try:
            return await _ProxmoxProvider().read(SimpleNamespace(id="x"))
        finally:
            vm.build_proxmox_adapter = original

    async def _fake():
        return _Adapter()

    reading = asyncio.run(_run())

    assert reading.disk_temps == {}
    assert reading.alerts == []
    assert summarize_health(reading.pools, reading.alerts, reading.disk_temps)["max_temp_c"] is None


# ── failure is reported, not dropped ────────────────────────────


async def test_a_controller_no_provider_claims_is_skipped():
    unknown = SimpleNamespace(id="x", controller_type="omada")

    assert await read_controller_storage(unknown) is None


async def test_an_unreachable_appliance_does_not_empty_the_rollup(monkeypatch):
    """
    One appliance failing must not take the org-wide answer with it. The
    provider swallows and returns None; the handler reports that appliance as
    unreachable and keeps going.
    """

    class _Boom:
        async def read(self, _controller):
            raise ConnectionError("appliance is down")

    monkeypatch.setitem(STORAGE_PROVIDERS, "truenas", _Boom())

    result = await read_controller_storage(SimpleNamespace(id="x", controller_type="truenas"))

    assert result is None


def test_an_unreachable_appliance_is_reported_not_omitted():
    """
    Dropping it from the list would read as an appliance with nothing wrong,
    which is the worst possible rendering of "we could not reach it".
    """
    import inspect

    from app.modules.storage import module as mod

    src = inspect.getsource(mod._fabric_storage_health_handler)

    assert '"status": "unreachable"' in src
    assert 'worst = _worse(worst, "error")' in src


def test_each_appliance_names_its_vendor():
    """
    A mixed-vendor rollup saying "one of these is degraded" is not actionable
    without knowing which box, and the vendor is the fastest way to find it.
    """
    import inspect

    from app.modules.storage import module as mod

    assert '"vendor": ctrl.controller_type' in inspect.getsource(
        mod._fabric_storage_health_handler
    )


@pytest.mark.parametrize("vendor", sorted(STORAGE_PROVIDERS))
def test_every_registered_provider_implements_the_protocol(vendor):
    provider = STORAGE_PROVIDERS[vendor]

    assert callable(getattr(provider, "read", None))


# ── the two places that must not diverge ────────────────────────


def test_no_storage_reader_hardcodes_a_vendor():
    """
    The same idea lives in two places -- the ``storage.health`` Fabric read and
    the ``storage.poll_health`` Celery sweep -- and generalising one while
    leaving the other is exactly what happened: Proxmox datastores appeared in
    an on-demand health read and were never monitored, never snapshotted and
    never emitted a transition event.

    Nothing about that is visible from either file alone, which is why this
    checks both against the registry rather than checking one and trusting.
    """
    import inspect

    from app.modules.storage import module as fabric_mod
    from app.tasks import storage as task_mod

    readers = {
        "storage.health (Fabric)": inspect.getsource(
            fabric_mod._fabric_storage_health_handler
        ),
        "storage.poll_health (Celery)": inspect.getsource(task_mod._poll_storage_health),
    }

    offenders = []
    for label, src in readers.items():
        body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
        if '"truenas"' in body or "build_truenas_adapter" in body:
            offenders.append(label)
        if "storage_controller_types()" not in body:
            offenders.append(f"{label} (does not use the registry)")

    assert not offenders, f"these still name a vendor instead of asking the registry: {offenders}"


def test_both_readers_go_through_the_same_provider_call():
    """
    Sharing the registry is not enough if one of them still builds its own
    adapter: the two would agree on WHICH controllers are storage and disagree
    on what reading one means.
    """
    import inspect

    from app.modules.storage import module as fabric_mod
    from app.tasks import storage as task_mod

    for src in (
        inspect.getsource(fabric_mod._fabric_storage_health_handler),
        inspect.getsource(task_mod._poll_storage_health),
    ):
        assert "read_controller_storage" in src


def test_both_readers_summarise_through_the_same_function():
    """
    The catalog read and the emitted events have to agree on what "degraded"
    means, which is the reason ``summarize_health`` exists as one function.
    """
    import inspect

    from app.modules.storage import module as fabric_mod
    from app.tasks import storage as task_mod

    for src in (
        inspect.getsource(fabric_mod._fabric_storage_health_handler),
        inspect.getsource(task_mod._poll_storage_health),
    ):
        assert "summarize_health(" in src
