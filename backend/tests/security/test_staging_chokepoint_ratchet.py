# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: no NEW endpoint may write to a device outside the staging chokepoint.

FreeSDN's core safety invariant is that every device mutation is recorded as an
``AdapterPendingChange`` and reaches the controller ONLY through
``AdapterStagingService.apply_change``, behind two gates: the
``ADAPTER_READ_ONLY`` environment gate and an explicit per-request ``force=true``.

A set of legacy endpoint families predate that invariant and still call adapter
methods directly -- ``tests/security/test_pentest_omada_write_gate.py`` documents
them. A client-layer gate was added so those calls are refused *while read-only
is engaged*; but the SHIPPED deployment default is read-WRITE
(``freesdn/docker-compose.yml:69``), and under that setting the gate is a no-op.
So on a default install these endpoints reach the live controller with no staged
row and no operator review -- which also means the pending-change ledger is not a
complete audit trail.

Authorization is NOT bypassed: these routes still enforce their permission
dependency and per-user site grants. The gap is the review/apply gate and the
audit record, not the privilege boundary.

Migrating them is a sequenced project: each family needs an ``adapter_*`` service
module exposing ``build_applier``, an endpoint rewritten to return a pending row
instead of a live result, matching frontend work, and device testing. Until that
lands, THIS TEST STOPS THE BLEEDING -- the inventory below is pinned, so a newly
written endpoint that forgets to stage fails CI.

Rules for editing ``KNOWN_DIRECT_WRITE_ENDPOINTS``:
  * REMOVING entries is always correct -- it means a family was migrated.
  * ADDING an entry is a deliberate decision that needs a reason in the PR. The
    default answer for new code is ``stage_change()``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parents[2] / "app"

#: Every root that can serve HTTP and therefore reach a device.
#:
#: This was a single ``ENDPOINTS_DIR`` pointing at app/api/v1/endpoints, scanned
#: with a NON-recursive glob. app/modules was never opened at all -- 128 files, 26
#: of them declaring their own APIRouter, which is the largest route surface in
#: the repo. So the guard on the staging chokepoint could not see the module
#: routers, and a new direct-to-device write added there would merge with no
#: signal whatsoever. The writes that are there today are deliberate and gated
#: (see the NOTE at app/modules/cameras/api.py:2665), but they were invisible to
#: the ratchet AND absent from docs/agents/STAGING-MIGRATION.md, so the tracked
#: inventory understated the real surface.
SCAN_ROOTS = [_APP / "api" / "v1" / "endpoints", _APP / "modules"]

#: Kept for the messages and for locating a pinned file.
ENDPOINTS_DIR = SCAN_ROOTS[0]

#: Receiver names that denote a vendor adapter/client. ``conn`` is deliberately
#: excluded: it is a SQLAlchemy connection (``conn.execute``), not a device.
ADAPTER_RECEIVERS = {"adapter", "client"}

#: Method-name prefixes that denote a mutation rather than a read.
MUTATING_PREFIXES = (
    "update",
    "set",
    "create",
    "delete",
    "remove",
    "add",
    "reboot",
    "adopt",
    "forget",
    "upgrade",
    "push",
    "provision",
    "restart",
    "enable",
    "disable",
    "move",
    "assign",
    "block",
    "unblock",
    "reset",
    "install",
    "start",
    "stop",
    "send",
    "clear",
    "purge",
    # ``factory_reset`` is the one DEVICE_OPERATIONS entry this prefix list did
    # not match: the list has "reset", which catches reset_* but not
    # factory_reset. So the single most destructive operation an adapter exposes
    # was invisible to the main ratchet, while the receiver-independent sweep
    # below DID list it in DEVICE_OPERATIONS -- the two classifiers disagreed,
    # and the weaker one is the one that gates new code.
    "factory",
)

#: The pinned legacy inventory: {endpoint module: {direct-write adapter methods}}
KNOWN_DIRECT_WRITE_ENDPOINTS: dict[str, set[str]] = {
    # ── app/modules/ ────────────────────────────────────────────────────
    #
    # Pinned 2026-08-26, when the scan was widened from app/api/v1/endpoints to
    # include app/modules. These are NOT newly-introduced violations: they
    # predate this pin and were simply invisible, because the scan never opened
    # this tree. They are deliberate and gated -- app/modules/cameras/api.py:2665
    # documents the reasoning (the route already required ``cameras.manage``, so
    # force=True is the contractual way to opt in) -- but "deliberate" and
    # "tracked" are different things, and until now they were only the first.
    #
    # Two of these files declare HTTP routes (cameras/api.py, 62 routes;
    # gateway/api/passthrough_api.py, 6). The rest are SERVICE layers, which is
    # where an applier legitimately calls the adapter after a staged change has
    # been applied -- the chokepoint rule is about writing from a request, not
    # about the applier. They are pinned rather than exempted so that the
    # inventory shows the true surface and a NEW name in any of them fails here.
    #
    # These belong in docs/agents/STAGING-MIGRATION.md, which currently does not
    # mention app/modules at all.
    "modules/cameras/api.py": {
        "delete_patrol",
        "reboot_device",
        "set_auto_tracking",
        "set_face_detection",
        "set_holiday_schedule",
        "set_holidays",
        "set_image_settings",
        "set_intrusion_detection",
        "set_line_crossing",
        "set_motion_detection",
        "set_patrol",
        "set_privacy_masks",
        "set_recording_schedule",
        "set_thermal_threshold",
        "start_patrol",
        "stop_patrol",
    },
    "modules/cameras/service.py": {"send_audio_data", "set_preset", "set_thermal_threshold"},
    "modules/firewall/gateway_service.py": {
        "create_alias",
        "create_backup",
        "create_dhcp_static_mapping",
        "create_dns_domain_override",
        "create_dns_override",
        "create_firewall_rule",
        "create_openvpn_instance",
        "create_port_forward",
        "create_shaper_pipe",
        "create_shaper_queue",
        "create_shaper_rule",
        "create_source_nat_rule",
        "create_static_route",
        "create_wireguard_peer",
        "create_wireguard_server",
        "delete_alias",
        "delete_backup",
        "delete_dhcp_static_mapping",
        "delete_dns_domain_override",
        "delete_dns_override",
        "delete_firewall_rule",
        "delete_openvpn_instance",
        "delete_port_forward",
        "delete_shaper_pipe",
        "delete_shaper_queue",
        "delete_shaper_rule",
        "delete_source_nat_rule",
        "delete_static_route",
        "delete_wireguard_peer",
        "delete_wireguard_server",
        "reboot_device",
        "restart_ids",
        "restart_service",
        "start_ids",
        "start_service",
        "stop_ids",
        "stop_service",
        "update_alias",
        "update_dhcp_static_mapping",
        "update_dns_domain_override",
        "update_dns_override",
        "update_firewall_rule",
        "update_ids_rules",
        "update_ids_settings",
        "update_openvpn_instance",
        "update_port_forward",
        "update_shaper_pipe",
        "update_shaper_queue",
        "update_shaper_rule",
        "update_source_nat_rule",
        "update_static_route",
        "update_wireguard_peer",
        "update_wireguard_server",
    },
    "modules/gateway/api/passthrough_api.py": {"create_backup", "restart_service"},
    "modules/hypervisor/service.py": {
        "update_guest_cloudinit",
    },
    "modules/voip/service.py": {
        # factory_reset was invisible on TWO counts: this file is under
        # app/modules (an unscanned root until 2026-08-26) and "factory_reset"
        # did not match any MUTATING_PREFIX. It is properly gated -- the route
        # requires voip.manage_phones AND an explicit ?confirm=true (409
        # otherwise,), and the service refuses while
        # ADAPTER_READ_ONLY is set -- so this is a pin, not an exemption. The
        # point is that a FUTURE ungated one now fails here.
        "factory_reset",
        "create_extension",
        "create_ring_group",
        "delete_extension",
        "delete_ring_group",
        "reboot",
        "set_config",
        "update_extension",
    },
    "modules/voip/tasks.py": {"reboot_phone"},
    "access_points.py": {
        "adopt_device",
        "forget_device",
        "reboot_device",
        "set_ap_location",
        "set_ap_mesh",
        "set_device_led",
        "update_ap_radio",
        "update_ap_ssid_override",
        "upgrade_firmware",
    },
    "actions.py": {"reboot_device"},
    "controllers.py": {
        "create_controller_backup",
        "create_vouchers",
        "delete_voucher",
        "update_captive_portal_config",
        "update_dot1x_config",
        "update_hotspot_config",
        "update_site_radio_settings",
    },
    "devices.py": {
        "adopt_device",
        "forget_device",
        "reboot_device",
        "set_device_led",
        "upgrade_firmware",
    },
    "network.py": {
        "block_client",
        "create_ssid",
        "create_vlan",
        "delete_ssid",
        "delete_vlan",
        "unblock_client",
        "update_ssid",
        "update_vlan",
    },
    "switches.py": {
        "create_poe_schedule",
        "create_port_profile",
        "create_switch_acl_rule",
        "create_switch_lag",
        "delete_poe_schedule",
        "delete_port_profile",
        "delete_switch_acl_rule",
        "delete_switch_lag",
        "set_switch_port_bandwidth",
        "set_switch_port_flow_control",
        "set_switch_port_isolation",
        "set_switch_port_lldp",
        "set_switch_port_loopback_detect",
        "set_switch_port_speed_duplex",
        "set_switch_port_storm_control",
        "update_dhcp_snooping_config",
        "update_poe_schedule",
        "update_port_profile",
        "update_qos_config",
        "update_switch_acl_rule",
        "update_switch_igmp_config",
        "update_switch_lag",
        "update_switch_mirror_config",
        "update_switch_port_overrides",
        "update_switch_stp_config",
    },
    "unifi_clients.py": {"block_client_on_site", "forget_client", "unblock_client_on_site"},
    "unifi_devices.py": {
        "disable_device",
        "restart_device",
        "set_port_poe_on_site",
        "update_port_override",
    },
    "unifi_wlans.py": {"enable_wlan", "update_wlan_password"},
}

#: Operations that are disruptive and not trivially reversible. Tracked
#: separately so the migration is ordered by consequence rather than file size.
#:
#: VERIFIED 2026-08-25 -- these are NOT unguarded, and it matters for how
#: urgently they need migrating. All ten handlers that reach one of these
#: methods enforce BOTH an authorization dependency AND an unconditional
#: explicit-intent flag:
#:
#:   * The Omada-family handlers (``access_points.py`` reboot/forget/firmware,
#:     ``devices.py`` reboot/forget/firmware, ``actions.py`` reboot) each carry a
#:     plain ``if not confirm: raise HTTPException(400)`` -- NOT conditioned on
#:     read-only -- plus ``require_permissions("network:write")`` and a site-grant
#:     check.
#:   * The UniFi handlers (``unifi_devices.py`` restart/disable,
#:     ``unifi_clients.py`` forget_client) carry
#:     ``require_min_role("site_admin")`` plus ``force=body.force``, which
#:     ``app/adapters/unifi/adapter.py::_enforce_read_only`` requires ALWAYS --
#:     explicitly "not only while ADAPTER_READ_ONLY is set". That closed the
#:     force-ignored-under-read-write gap for this family.
#:
#: So what these still lack is the staged-change LEDGER: a reviewable pending
#: row and an audit record of the write. That is an auditability gap, not an
#: unguarded destructive write, and it is why migrating them is important but
#: not an emergency.
HIGH_BLAST_RADIUS = {
    "reboot_device",
    "restart_device",
    "forget_device",
    "forget_client",
    "upgrade_firmware",
    "disable_device",
}


def _is_mutating(name: str) -> bool:
    n = name.lower().lstrip("_")
    return any(n == p or n.startswith(p + "_") for p in MUTATING_PREFIXES)


def _direct_writes(path: Path) -> set[str]:
    """Adapter mutating methods awaited directly in this module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Await):
            continue
        call = node.value
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if not isinstance(func, ast.Attribute):
            continue
        recv = func.value
        if not isinstance(recv, ast.Name) or recv.id not in ADAPTER_RECEIVERS:
            continue
        if _is_mutating(func.attr):
            found.add(func.attr)
    return found


def _iter_sources():
    """Every python file under every scan root, recursively.

    ``glob("*.py")`` was non-recursive, so anything in a subpackage was invisible
    even inside a root that WAS scanned.
    """
    for root in SCAN_ROOTS:
        if root.is_dir():
            yield from sorted(root.rglob("*.py"))


def _key(path: Path) -> str:
    """Inventory key: bare filename under endpoints, app-relative elsewhere.

    Endpoint filenames stay bare so the existing pins keep working; module files
    need their path because several are called api.py or service.py.
    """
    try:
        return path.relative_to(ENDPOINTS_DIR).as_posix()
    except ValueError:
        return path.relative_to(_APP).as_posix()


def _scan() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for p in _iter_sources():
        hits = _direct_writes(p)
        if hits:
            out[_key(p)] = hits
    return out


def test_endpoints_directory_is_readable() -> None:
    """Guard the guard: an empty scan must not read as a clean result."""
    for root in SCAN_ROOTS:
        assert root.is_dir(), f"scan root not found: {root}"
    assert len(list(_iter_sources())) > 200, (
        "the scan looks truncated -- it must cover app/api/v1/endpoints AND "
        "app/modules, recursively"
    )


def test_no_new_endpoint_writes_to_a_device_outside_staging() -> None:
    """The ratchet. A new unstaged device write must not appear."""
    new: dict[str, list[str]] = {}
    for module, methods in _scan().items():
        unexpected = methods - KNOWN_DIRECT_WRITE_ENDPOINTS.get(module, set())
        if unexpected:
            new[module] = sorted(unexpected)

    sep = chr(10) + "  "
    detail = sep.join(f"{m}: {', '.join(v)}" for m, v in sorted(new.items()))
    assert not new, (
        "New direct-to-device write(s) found outside the staging chokepoint:"
        + sep
        + detail
        + " -- device mutations must be recorded via "
        "AdapterStagingService.stage_change() and reach the controller only "
        "through apply_change(). If this is a deliberate exception, add it to "
        "KNOWN_DIRECT_WRITE_ENDPOINTS with a reason."
    )


def test_pinned_inventory_does_not_rot() -> None:
    """Entries that no longer exist must be removed, so the pin stays honest.

    Otherwise a migrated family leaves a stale allowance behind that could
    silently re-admit a future direct write under the same method name.
    """
    actual = _scan()
    stale: dict[str, list[str]] = {}
    for module, methods in KNOWN_DIRECT_WRITE_ENDPOINTS.items():
        gone = methods - actual.get(module, set())
        if gone:
            stale[module] = sorted(gone)

    detail = "\n".join(f"  {m}: {', '.join(v)}" for m, v in sorted(stale.items()))
    assert not stale, (
        "KNOWN_DIRECT_WRITE_ENDPOINTS lists entries that no longer exist "
        f"(migrated or renamed) -- remove them:\n{detail}"
    )


@pytest.mark.parametrize("module", sorted(KNOWN_DIRECT_WRITE_ENDPOINTS))
def test_known_direct_write_module_still_exists(module: str) -> None:
    """A pinned module that vanished means the inventory needs updating."""
    candidate = ENDPOINTS_DIR / module if "/" not in module else _APP / module
    assert candidate.exists(), (
        f"{module} is pinned in KNOWN_DIRECT_WRITE_ENDPOINTS but no longer exists"
    )


#: Method names that are unambiguously DEVICE operations rather than writes to
#: FreeSDN's own tables. Used by the receiver-independent sweep below.
DEVICE_OPERATIONS = {
    "reboot_device",
    "restart_device",
    "forget_device",
    "forget_client",
    "upgrade_firmware",
    "disable_device",
    "adopt_device",
    "set_device_led",
    "update_ap_radio",
    "update_ap_ssid_override",
    "set_ap_location",
    "set_ap_mesh",
    "block_client",
    "unblock_client",
    "set_port_poe",
    "set_port_enabled",
    "push_full_config",
    "factory_reset",
    "provision_device",
}


def test_no_device_operation_hides_behind_an_unexpected_receiver() -> None:
    """Catch a device write bound to a variable the main scan does not know.

    The scan above keys on receivers literally named ``adapter`` or ``client``,
    which is a good proxy but not a guarantee: ``ad.reboot_device()``,
    ``controller_adapter.update_ap_radio()`` or ``get_adapter(...).reboot_device()``
    would all evade it. Verified 2026-08-25 that there are currently NO such
    call sites -- this test exists so a rename or a new helper cannot introduce
    one silently.

    Deliberately keyed on the METHOD name, not the receiver, so it is
    receiver-independent. Service-layer writes (``svc.create_rule``) are not
    device operations and are not in scope here.
    """
    offenders: list[str] = []
    for path in sorted(ENDPOINTS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Await):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if not isinstance(func, ast.Attribute) or func.attr not in DEVICE_OPERATIONS:
                continue
            recv = func.value
            if isinstance(recv, ast.Name) and recv.id in ADAPTER_RECEIVERS:
                continue  # covered by the main inventory scan above
            shape = recv.id if isinstance(recv, ast.Name) else f"<{type(recv).__name__}>"
            offenders.append(f"{path.name}:{node.lineno} {shape}.{func.attr}")

    sep = chr(10) + "  "
    detail = sep.join(offenders)
    assert not offenders, (
        "Device operation(s) invoked on a receiver the inventory scan does not "
        "track, so they sit outside the staging ratchet entirely:"
        + sep
        + detail
        + " -- either route them through stage_change() or add the receiver "
        "name to ADAPTER_RECEIVERS so the inventory covers them."
    )


#: The high-blast-radius operations that are STILL direct writes today, written
#: out by hand rather than derived from anything above.
#:
#: That is the entire point. The assertion below used to be
#: ``set(HIGH_BLAST_RADIUS & pinned) <= HIGH_BLAST_RADIUS`` -- an intersection
#: compared against one of its own operands, so it was True for every possible
#: inventory: today's, an inventory of pure junk, an EMPTY inventory (the goal
#: state its docstring claimed it would announce), and an emptied
#: HIGH_BLAST_RADIUS. It reported green in a CI summary as one of this file's
#: six device-write checks while gating nothing at all.
#:
#: Compared as an equality against this literal it flips in both directions: an
#: operation migrated onto stage_change() drops out of ``still_direct``, and
#: gutting HIGH_BLAST_RADIUS or the inventory empties it.
UNMIGRATED_HIGH_BLAST = {
    "disable_device",
    "forget_client",
    "forget_device",
    "reboot_device",
    "restart_device",
    "upgrade_firmware",
}


def test_high_blast_radius_operations_are_tracked() -> None:
    """Announce when a disruptive operation enters or leaves the direct-write set.

    This keeps the migration ordered by consequence, so 'reboot the AP with no
    review step' is not left until last because it happens to live in a small
    file -- and it makes the finish line visible: when one of these is finally
    routed through stage_change(), this test says so instead of staying silent.
    """
    pinned = {m for methods in KNOWN_DIRECT_WRITE_ENDPOINTS.values() for m in methods}
    still_direct = HIGH_BLAST_RADIUS & pinned
    migrated = sorted(UNMIGRATED_HIGH_BLAST - still_direct)
    appeared = sorted(still_direct - UNMIGRATED_HIGH_BLAST)
    assert still_direct == UNMIGRATED_HIGH_BLAST, (
        "the high-blast-radius direct-write set changed.\n"
        f"  no longer direct: {migrated or 'none'}\n"
        f"  newly direct:     {appeared or 'none'}\n"
        "If one was migrated onto stage_change(), drop it from "
        "UNMIGRATED_HIGH_BLAST (and from HIGH_BLAST_RADIUS once nothing writes "
        "it directly). If one is NEW, it is an unreviewable device write that "
        "should have gone through staging."
    )


def test_every_device_operation_is_classified_as_mutating() -> None:
    """The two classifiers in this file must agree.

    ``_is_mutating`` (prefix-based) gates the main ratchet; ``DEVICE_OPERATIONS``
    (an explicit list) gates the receiver-independent sweep. They disagreed on
    ``factory_reset``: the prefix list had "reset", which matches reset_* but not
    factory_reset, so a new direct factory_reset call was invisible to the ratchet
    that actually blocks new code. Any future addition to DEVICE_OPERATIONS that
    the prefix list cannot see fails here instead of silently going unguarded.
    """
    unseen = sorted(op for op in DEVICE_OPERATIONS if not _is_mutating(op))
    assert not unseen, (
        "these device operations are listed in DEVICE_OPERATIONS but "
        f"_is_mutating() does not recognise them: {unseen}. Add a matching "
        "prefix to MUTATING_PREFIXES, or the main ratchet cannot see a new "
        "direct call to them."
    )
