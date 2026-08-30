# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The storage adapter could see everything and do almost nothing.

Measured across the fleet: truenas had 26 read methods against 2 writes, a ratio
of 0.08 -- the lowest of any adapter that writes at all (omada 1.08, mikrotik
1.54, opnsense 0.76, hikvision 0.51). The single write was a staged blob upload
for the Fabric ``storage.store_blob`` operation. An operator could watch a pool
fill up, watch a scrub go stale, watch snapshot coverage sit at zero -- and had
to leave FreeSDN to act on any of it.

This adds the four writes a storage operator actually performs: create a
dataset, take a snapshot, delete a snapshot, start a scrub.

**They are staged, and the blob upload's data-plane sibling is not.** That line
is the point rather than an inconsistency:

* These change what the appliance IS. Configuration, so the dual gate holds
  them: an operator reviews the pending change and applies it, exactly as for
  any device mutation.
* The backup data plane puts a file inside a dataset the operator already
  nominated as a destination. That is not configuration, and routing it through
  staging would make every scheduled backup wait for a human.

**Two operations are deliberately withheld**: snapshot rollback and dataset
delete. Both destroy data irreversibly, and "it was staged" is not sufficient
design for something whose blast radius is an entire dataset -- a reviewer
approving a rollback is not being told what it discards. They need a
confirmation flow and a dry run that names the loss. Offering them as ordinary
staged writes would let a review step imply a safety it does not provide.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.adapters.exceptions import AdapterError
from app.adapters.truenas.adapter import TrueNASAdapter
from app.services.adapter_truenas_storage import (
    _APPLY,
    _WITHHELD_OPERATIONS,
    _apply_management,
    _validate_snapshot_id,
    _validate_zfs_path,
)


class _RecordingAdapter:
    """Captures what the applier would send, without an appliance."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, name):
        async def _call(**kwargs):
            self.calls.append((name, kwargs))
            return {"ok": True}

        return _call


def _change(feature, operation):
    return SimpleNamespace(feature=feature, operation=operation)


class _BlobRefusingAdapter(_RecordingAdapter):
    """A recording adapter that also stands in for the blob upload.

    ``upload_file`` raises rather than records: a management change that leaks
    into the blob branch must be a loud failure here, not a silent extra row in
    ``calls``. ``disconnect`` is real so the applier's ``finally`` does not
    record a call of its own.
    """

    async def upload_file(self, **kwargs):
        raise AssertionError(f"a management change reached the blob upload: {kwargs}")

    async def disconnect(self):
        return None


_SNAPSHOT_PAYLOAD = {"dataset": "tank/data", "name": "nightly"}


def _blob_change(feature, operation, payload):
    """A change shaped the way the staged-apply dispatcher hands one to build_applier."""
    import uuid

    return SimpleNamespace(
        feature=feature,
        operation=operation,
        payload=payload,
        target_id=None,
        controller_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
    )


def _blobless_service():
    """``GatewayTrueNASStorageService`` wired to a recording adapter, no appliance."""
    from app.services.adapter_truenas_storage import GatewayTrueNASStorageService

    adapter = _BlobRefusingAdapter()
    svc = GatewayTrueNASStorageService(db=None)

    async def _get_controller(_cid, _org):
        return object()  # unused: the builder below ignores the controller

    async def _build(_ctrl):
        return adapter

    svc._get_controller = _get_controller
    svc._get_truenas_adapter = _build
    return svc, adapter


# ── the surface exists and is routed ────────────────────────────


def test_the_operator_writes_are_registered():
    """
    Four writes an operator performs, against the one that existed. Without the
    routing entry a staged change applies to nothing and fails at apply time
    with "no applier", after the operator has already approved it.
    """
    for key in (
        ("storage.dataset", "create"),
        ("storage.snapshot", "create"),
        ("storage.snapshot", "delete"),
        ("storage.scrub", "start"),
    ):
        assert key in _APPLY, f"{key} is not routed"


def test_the_blob_upload_still_routes():
    assert _APPLY[("storage.store_blob", "create")] == "upload_file"


@pytest.mark.parametrize(
    "feature,operation,method",
    [
        ("storage.dataset", "create", "create_dataset"),
        ("storage.snapshot", "create", "create_snapshot"),
        ("storage.snapshot", "delete", "delete_snapshot"),
        ("storage.scrub", "start", "start_scrub"),
    ],
)
def test_every_routed_method_exists_on_the_adapter(feature, operation, method):
    """
    A routing table naming a method that is not there is a staged change that
    can never apply, and nothing before apply time would say so.
    """
    assert callable(getattr(TrueNASAdapter, method, None)), f"{method} is missing"


# ── the gate ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "method,kwargs",
    [
        ("create_dataset", {"name": "tank/x"}),
        ("create_snapshot", {"dataset": "tank/x", "name": "s1"}),
        ("delete_snapshot", {"snapshot_id": "tank/x@s1"}),
        ("start_scrub", {"pool_name": "tank"}),
    ],
)
async def test_every_management_write_refuses_without_the_gate(method, kwargs):
    """
    These alter appliance configuration, so each must be unreachable except
    through the staged-apply path. One of four missing the check is the failure
    mode -- and it would not be discovered until something wrote to an
    appliance nobody approved.
    """
    adapter = TrueNASAdapter.__new__(TrueNASAdapter)

    with pytest.raises(AdapterError) as exc:
        await getattr(adapter, method)(**kwargs)

    assert "force-gate not set" in str(exc.value)


def test_the_gate_has_one_implementation():
    """
    ``upload_file`` grew its own copy of the refusal first. A second, third and
    fourth hand-written copy is how one eventually ends up missing.
    """
    import inspect

    src = inspect.getsource(TrueNASAdapter)
    assert src.count('raise AdapterError("TrueNAS write refused: staging force-gate not set")') <= 2, (
        "the refusal is being copy-pasted per method"
    )


async def test_the_applier_passes_the_gate_exactly_once_per_call():
    """
    ``force=True`` is legitimate here -- this function is reachable only from
    ``build_applier``, after the dual gate. What matters is that it is passed
    deliberately for each op rather than defaulted somewhere central.
    """
    adapter = _RecordingAdapter()

    await _apply_management(adapter, _change("storage.snapshot", "create"),
                            {"dataset": "tank/data", "name": "nightly"})

    name, kwargs = adapter.calls[0]
    assert name == "create_snapshot"
    assert kwargs["force"] is True
    assert kwargs["dataset"] == "tank/data"
    assert kwargs["name"] == "nightly"


# ── what is deliberately not offered ────────────────────────────


@pytest.mark.parametrize("key", sorted(_WITHHELD_OPERATIONS))
async def test_a_withheld_operation_is_refused_with_a_reason(key):
    """
    Refused, and the refusal says why. A bare 400 would read as a bug and
    someone would "fix" it by adding the applier.
    """
    feature, operation = key

    with pytest.raises(HTTPException) as exc:
        await _apply_management(_RecordingAdapter(), _change(feature, operation), {})

    assert exc.value.status_code == 400
    assert "destroys data irreversibly" in str(exc.value.detail)


def test_rollback_and_dataset_delete_are_the_withheld_pair():
    """
    Pins the list. Adding either of these to ``_APPLY`` without building the
    confirmation flow is the mistake this guards.
    """
    assert frozenset(
        {("storage.snapshot", "rollback"), ("storage.dataset", "delete")}
    ) == _WITHHELD_OPERATIONS
    assert not (_WITHHELD_OPERATIONS & set(_APPLY)), "a withheld op is also routed"


# ── the names that reach the appliance ──────────────────────────


@pytest.mark.parametrize(
    "value",
    ["../escape", "tank/../etc", "tank//x", "a b", "", "   ", "tank/x;rm -rf /"],
)
def test_an_unsafe_dataset_name_is_refused(value):
    with pytest.raises(HTTPException):
        _validate_zfs_path(value, field="name")


@pytest.mark.parametrize("value", ["/mnt/tank/backups", "/tank/backups", "/leading"])
def test_a_mount_path_is_refused_rather_than_normalised(value):
    """
    The likeliest reason someone types a leading slash is that they pasted the
    mountpoint shown on the Storage page. Stripping it looks forgiving and is
    the opposite: ``/mnt/tank/backups`` would quietly become
    ``mnt/tank/backups`` and create a dataset called ``mnt`` at the top of the
    pool.
    """
    with pytest.raises(HTTPException) as exc:
        _validate_zfs_path(value, field="name")

    assert "pool-relative" in str(exc.value.detail)


def test_a_normal_dataset_name_is_accepted():
    assert _validate_zfs_path("tank/backups/nightly", field="name") == "tank/backups/nightly"
    assert _validate_zfs_path("tank/backups/", field="name") == "tank/backups"


def test_a_snapshot_name_may_not_contain_a_path():
    """
    ``max_segments=1`` for the snapshot's own name: ``tank/data@a/b`` is not a
    thing, and accepting it would send the appliance something it will reject
    after the operator has approved the change.
    """
    with pytest.raises(HTTPException):
        _validate_zfs_path("a/b", field="name", max_segments=1)


@pytest.mark.parametrize("value", ["tank", "a@b@c", "tank@../x", "@name", "tank@"])
def test_a_malformed_snapshot_id_is_refused(value):
    with pytest.raises(HTTPException):
        _validate_snapshot_id(value)


@pytest.mark.parametrize("value", ["tank", "a@b@c"])
def test_a_missing_or_doubled_separator_says_what_the_field_wants(value):
    """
    The ``@`` count check is redundant for safety -- ``partition`` plus the
    name regex already refuse every one of these, and a mutation removing the
    count survived a test that only asserted "raises".

    It earns its place on the error message. Without it the operator is told
    "snapshot name is unsafe: ''" for input of ``tank``, which describes the
    parser's internal state rather than what they typed wrong. Asserting the
    message is what makes this check load-bearing instead of decorative.
    """
    with pytest.raises(HTTPException) as exc:
        _validate_snapshot_id(value)

    assert "must be dataset@name" in str(exc.value.detail)


def test_a_normal_snapshot_id_is_accepted():
    assert _validate_snapshot_id("tank/data@auto-2026-08-23") == "tank/data@auto-2026-08-23"


# ── the applier dispatches correctly ────────────────────────────


async def test_dataset_create_sends_the_validated_name():
    adapter = _RecordingAdapter()
    await _apply_management(adapter, _change("storage.dataset", "create"),
                            {"name": "tank/backups/", "comments": "freesdn"})

    name, kwargs = adapter.calls[0]
    assert name == "create_dataset"
    assert kwargs["name"] == "tank/backups"
    assert kwargs["comments"] == "freesdn"


async def test_scrub_start_sends_a_pool_not_a_dataset():
    """
    A scrub runs against a POOL. ``tank/data`` is a dataset and the appliance
    would refuse it, so it is refused here where the operator can still fix it.
    """
    adapter = _RecordingAdapter()
    await _apply_management(adapter, _change("storage.scrub", "start"), {"pool": "tank"})
    assert adapter.calls[0][1]["pool_name"] == "tank"

    with pytest.raises(HTTPException):
        await _apply_management(adapter, _change("storage.scrub", "start"), {"pool": "tank/data"})


async def test_an_unroutable_feature_is_refused():
    with pytest.raises(HTTPException) as exc:
        await _apply_management(_RecordingAdapter(), _change("storage.teleport", "create"), {})

    assert exc.value.status_code == 400


@pytest.mark.parametrize(
    ("feature", "operation", "payload", "expect"),
    [
        ("storage.snapshot", "create", _SNAPSHOT_PAYLOAD, "create_snapshot"),
        ("truenas.storage.snapshot", "create", _SNAPSHOT_PAYLOAD, "create_snapshot"),
        ("storage.dataset", "create", {"name": "tank/backups"}, "create_dataset"),
        ("truenas.storage.scrub", "start", {"pool": "tank"}, "start_scrub"),
    ],
)
async def test_a_management_change_never_looks_for_a_blob(feature, operation, payload, expect):
    """
    The blob path demands an ``_artifact`` and 409s without one. A management
    change carries no blob, so falling through to it would reject every
    snapshot an operator staged -- with an error about a missing upload.

    Asserted through ``build_applier`` -- the real entry point -- rather than by
    grepping the source of the branch that does the routing. The grep version
    pinned the literal ``c.feature != "storage.store_blob"``, which made the
    fix for the aliased-blob dead end (``truenas.storage.store_blob`` routed
    into ``_apply_management`` and 400d there) unlandable without deleting the
    assertion. This form fails for the same reason the grep did -- inverting or
    dropping the branch sends a snapshot into the blob path -- and lets the
    branch key on whatever string is correct.
    """
    svc, adapter = _blobless_service()
    change = _blob_change(feature, operation, payload)

    await svc.build_applier(change)(change)

    assert [name for name, _ in adapter.calls] == [expect]


# ── the permission tier ─────────────────────────────────────────


@pytest.mark.parametrize(
    "feature",
    ["storage.dataset", "storage.snapshot", "storage.scrub", "storage.store_blob",
     "truenas.storage.blob"],
)
def test_applying_a_storage_change_requires_the_storage_tier(feature):
    """
    Every ``storage.*`` feature fell through to the ``network:write`` default,
    which was wrong in both directions at once: a network operator could apply
    a snapshot delete or a scrub on someone's NAS, and the operator actually
    holding ``storage.write`` -- the permission the module declares and the
    Fabric operation demands to STAGE -- could not apply what they had just
    staged.

    Stage and apply must demand the same tier. When they do not, the weaker of
    the two is the real gate.
    """
    from app.api.v1.endpoints.adapter_omada_vpn import _required_apply_permission

    assert _required_apply_permission(feature) == "storage.write"


def test_the_tier_matches_what_the_module_declares():
    """
    Pinned against the manifest rather than a literal, so renaming the
    permission in one place fails here instead of silently un-gating apply.
    """
    from app.modules.storage.module import StorageModule

    codes = {p.code for p in StorageModule.get_manifest().permissions}

    assert "storage.write" in codes
    assert "storage.view" in codes


def test_other_domains_keep_their_own_tier():
    """Guards the branch from being written so broadly it swallows siblings."""
    from app.api.v1.endpoints.adapter_omada_vpn import _required_apply_permission

    assert _required_apply_permission("network.vlan") == "network:write"
    assert _required_apply_permission("proxmox.vm.destroy") == "hypervisor:write"
    assert _required_apply_permission("vpn.ipsec.policy") == "vpn:write"


# ── the route that stages them ──────────────────────────────────


def test_a_staging_route_exists_at_all():
    """
    There were eighty-one staging routes across every other vendor domain and
    none for storage, because the only storage write used to be
    ``storage.store_blob`` and Fabric staged that one itself.

    Adding four management operations left them routed in ``_APPLY``, gated,
    tested -- and reachable by nothing. No Fabric operation offered them and no
    HTTP route could stage them, so an operator had no path to any of it.
    """
    from app.main import app

    paths = set(app.openapi()["paths"])

    assert "/api/v1/gateway-storage/{controller_id}/changes/{feature}" in paths
    assert "/api/v1/gateway-storage/{controller_id}/changes" in paths


def test_staging_demands_the_same_permission_as_applying():
    """
    When stage and apply disagree, the weaker of the two is the real gate.
    """
    import inspect

    from app.api.v1.endpoints import adapter_truenas_storage as route_mod
    from app.api.v1.endpoints.adapter_omada_vpn import _required_apply_permission

    src = inspect.getsource(route_mod.stage_storage_change)

    assert 'require_permissions("storage.write")' in src
    assert _required_apply_permission("storage.snapshot") == "storage.write"


def test_listing_pending_changes_needs_only_the_read_tier():
    """
    Reviewing what is staged is not itself a write. Demanding storage.write to
    LOOK would mean the person who reviews must also be the person who can
    apply, which defeats having two gates.
    """
    import inspect

    from app.api.v1.endpoints import adapter_truenas_storage as route_mod

    src = inspect.getsource(route_mod.list_pending_storage)

    assert 'require_permissions("storage.view")' in src


@pytest.mark.parametrize("key", sorted(_WITHHELD_OPERATIONS))
def test_a_withheld_operation_is_refused_at_stage_not_only_at_apply(key):
    """
    A withheld operation that stages cleanly and dies on apply has already been
    reviewed and approved by somebody. That is the worst possible moment to
    learn the platform never intended to offer it.
    """
    from app.api.v1.endpoints.adapter_truenas_storage import validate_storage_operation

    feature, operation = key

    with pytest.raises(HTTPException) as exc:
        validate_storage_operation(feature, operation)

    assert exc.value.status_code == 400
    assert "destroys data irreversibly" in str(exc.value.detail)


def test_a_withheld_operation_is_not_reported_as_a_typo():
    """
    Order matters. A withheld operation IS a known name, so reporting it as
    unrecognised would send an operator hunting for a spelling mistake in
    something deliberately not offered.
    """
    from app.api.v1.endpoints.adapter_truenas_storage import validate_storage_operation

    with pytest.raises(HTTPException) as exc:
        validate_storage_operation("storage.snapshot", "rollback")

    assert "no storage operation" not in str(exc.value.detail)


@pytest.mark.parametrize(
    "feature,operation",
    [
        ("storage.snapshot", "creat"),
        ("storage.snapshot", "start"),
        ("storage.teleport", "create"),
        ("storage.scrub", "stop"),
    ],
)
def test_an_unknown_operation_is_refused_with_the_supported_list(feature, operation):
    """
    "no applier" at apply time names nothing an operator can act on. Refusing
    at stage, with the supported set, is the difference between a dead end and
    a correction.

    Behavioural rather than a source grep: the checks used to be inline and the
    test could only assert the message text was PRESENT, so a mutation that
    removed the ``if`` and left the ``raise`` unreachable passed.
    """
    from app.api.v1.endpoints.adapter_truenas_storage import validate_storage_operation

    with pytest.raises(HTTPException) as exc:
        validate_storage_operation(feature, operation)

    detail = str(exc.value.detail)
    assert "no storage operation" in detail
    assert "storage.snapshot/create" in detail, "the refusal does not say what IS supported"


@pytest.mark.parametrize(
    "feature,operation",
    [
        ("storage.dataset", "create"),
        ("storage.snapshot", "create"),
        ("storage.snapshot", "delete"),
        ("storage.scrub", "start"),
        ("storage.store_blob", "create"),
        ("truenas.storage.store_blob", "create"),
    ],
)
def test_a_supported_operation_passes(feature, operation):
    """Guards the refusals above from passing because everything is refused."""
    from app.api.v1.endpoints.adapter_truenas_storage import validate_storage_operation

    validate_storage_operation(feature, operation)


@pytest.mark.parametrize(
    "feature", ["firewall.rule", "network.vlan", "proxmox.vm", "", "storagex.thing"]
)
def test_a_non_storage_feature_is_refused(feature):
    """
    A staging endpoint that took any feature would let a storage.write holder
    stage a firewall change and have it applied under the storage tier.
    """
    from app.api.v1.endpoints.adapter_truenas_storage import validate_storage_operation

    with pytest.raises(HTTPException) as exc:
        validate_storage_operation(feature, "create")

    assert "only accepts storage" in str(exc.value.detail)
