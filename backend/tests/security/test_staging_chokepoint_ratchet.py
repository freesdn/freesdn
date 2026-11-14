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
    # Added 2026-11-12 (26.12.0). The list above had no entry for these verbs,
    # so direct writes named this way were invisible: the shared Switches/PoE
    # port controls (configure_switch_port, cycle_poe_port), SSID and firewall
    # rule toggles, batch reboot/firmware, Proxmox cloud-init regenerate and
    # backup restore, config revert, VPN session kill. Verbs with no hit today
    # are here so the next write named that way is caught on arrival.
    "configure",
    "toggle",
    "cycle",
    "batch",
    "regenerate",
    "restore",
    "rollback",
    "revert",
    "clone",
    "migrate",
    "resize",
    "shutdown",
    "power",
    "rename",
    "apply",
    "save",
    "import",
    "rotate",
    "flush",
    "kill",
    "suspend",
    "resume",
    "reconnect",
    "approve",
    "authorize",
    "deauthorize",
    "kick",
    "trigger",
    "commit",
    "replace",
    # Added 2026-11-13 with the firewall gateway API conversion: the gateway
    # writes named this way (power off, clear the IDS alert log, bring an IPsec
    # tunnel up or down, install firmware) were invisible to the classifier.
    # ``connect``/``disconnect`` alone would match every adapter session.
    "halt",
    "drop",
    "connect_ipsec",
    "disconnect_ipsec",
    "firmware_update",
)

#: Names that match a mutating prefix but change nothing on a device. Each needs
#: a reason; keep this short, since every entry is a name the ratchet ignores.
NON_MUTATING_NAMES: dict[str, str] = {
    "batch_firmware_check": "reads firmware availability for several devices",
    "set_active_site": "Omada adapter: sets which site later calls address (in memory)",
    "add_phone": "Grandstream adapter: registers a phone in its in-memory table",
    # One audio chunk of a two-way audio session the operator opened; it changes
    # no device state, and an audit record per chunk would be one per 20 ms.
    "send_audio_data": "Hikvision two-way audio: streams a chunk into an open session",
    # The controller health probe (66b65e83) checks whether the Omada session
    # it kept is still logged in (GET loginStatus); it changes nothing.
    "resume_session": "Omada adapter: checks a kept session is still logged in",
}

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
    # None left (2026-11-13): the firewall gateway API, the VoIP service and
    # the hypervisor service, the last three files pinned here, write through
    # the staging envelopes below. A new direct write in app/modules or the
    # endpoints fails test_no_new_endpoint_writes_to_a_device_outside_staging.
}

#: Pinned 2026-11-12 (26.12.0), when the classifier learned the verbs above and
#: started counting adapter calls that are wrapped (``asyncio.wait_for(...)``)
#: rather than awaited directly. NOT new code: every entry predates this pin and
#: was invisible until now. They reach the device with no staged row.
_FOUND_BY_WIDER_CLASSIFIER_2026_11: dict[str, set[str]] = {
    # None left (2026-11-13): the gateway and hypervisor writes found then are
    # staged or audited now, and the unreachable direct backup restore is gone.
}
for _module, _names in _FOUND_BY_WIDER_CLASSIFIER_2026_11.items():
    KNOWN_DIRECT_WRITE_ENDPOINTS.setdefault(_module, set()).update(_names)

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


#: Calls whose function argument is the device write of a change that goes
#: through the staging chokepoint. ``AdapterStagingService.apply_now`` stages the
#: change and applies it, in the same request, through ``apply_change``: read-only
#: mode refuses it, ``force`` is required, and the ledger records who, what, when
#: and the result. A device call written inside the function passed as one of
#: these keyword arguments IS staged, so it is not a direct write.
#:
#: Every entry other than ``apply_now`` must forward that argument to
#: ``apply_now`` unchanged (checked by
#: test_every_staging_envelope_reaches_apply_now), so the list cannot become a
#: way to label a direct write as staged.
STAGED_ENVELOPES: dict[str, frozenset[str]] = {
    "apply_now": frozenset({"perform"}),
    # ZTP: AdoptionOrchestrator._device_write (adopt, firmware, provisioning)
    "_device_write": frozenset({"perform"}),
    # app/services/device_writes.py: the endpoint-facing forms of apply_now
    "write_through_staging": frozenset({"perform"}),
    "write_device_config": frozenset({"perform"}),
    "write_controller_config": frozenset({"perform"}),
    # services/device_control.py: DeviceControlService's configuration actions
    "_staged_device_write": frozenset({"perform"}),
    # cameras/config_write.py: every camera config write and its rollback
    "staged_camera_write": frozenset({"apply", "rollback"}),
    # modules/firewall/gateway_service.py: every firewall gateway API write
    "_gateway_write": frozenset({"perform"}),
    # modules/voip/service.py: PBX extension and ring-group writes
    "_pbx_write": frozenset({"perform"}),
    # One member of a change group (AdapterStagingService.apply_group_now).
    # A dataclass, not a function: test_group_member_bodies_only_run_in_a_group
    # checks that only apply_group_now runs them.
    "GroupMember": frozenset({"perform", "compensate"}),
}

#: Operational actions (STAGING-MIGRATION option 3): not staged, audited. A call
#: inside the function passed to ``audited_device_action(perform=...)`` writes
#: an audit record once the device accepts it. Only the method names below may
#: run there; any other adapter mutation inside the envelope still counts as a
#: direct write, so a configuration change cannot be filed as an "action".
AUDITED_ENVELOPES: dict[str, frozenset[str]] = {
    "audited_device_action": frozenset({"perform"}),
    # app/services/device_writes.py: the same, for one device row or controller
    "device_action": frozenset({"perform"}),
    "controller_action": frozenset({"perform"}),
    # services/device_control.py: DeviceControlService's operational actions
    "_audited_device_action": frozenset({"perform"}),
    # modules/firewall/gateway_service.py: the gateway API's operational actions
    "_gateway_action": frozenset({"perform"}),
    # modules/voip/service.py: phone reboot and factory reset
    "_phone_action": frozenset({"perform"}),
}

OPERATIONAL_ACTIONS: dict[str, str] = {
    "reboot_device": "restarts the device; no configuration changes",
    "restart_device": "restarts the device; no configuration changes",
    "reboot": "restarts a phone; no configuration changes",
    "reboot_phone": "restarts a phone; no configuration changes",
    "batch_reboot": "restarts several devices",
    "cycle_poe_port": "power-cycles one PoE port; its configuration is unchanged",
    "power_cycle_port": "power-cycles one PoE port; its configuration is unchanged",
    "start_patrol": "starts a saved PTZ patrol (live camera control)",
    "stop_patrol": "stops a PTZ patrol (live camera control)",
    "kick_client": "disconnects a wireless client; it may reconnect at once",
    "restart_service": "restarts a service on the gateway",
    "start_service": "starts a service on the gateway",
    "stop_service": "stops a service on the gateway",
    "start_ids": "starts the gateway's IDS service",
    "stop_ids": "stops the gateway's IDS service",
    "restart_ids": "restarts the gateway's IDS service",
    "flush_arp": "clears the gateway's ARP cache",
    "kill_openvpn_session": "disconnects one VPN session; the user may reconnect",
    "connect_ipsec_tunnel": "brings a configured IPsec tunnel up; its configuration is unchanged",
    "disconnect_ipsec_tunnel": "takes an IPsec tunnel down; its configuration is unchanged",
    "halt_device": "powers the gateway off; kept behind its own confirmation",
    "drop_ids_alert_log": "clears the gateway's IDS alert log",
    "create_backup": "the device writes a backup of its own configuration",
    "create_controller_backup": "the controller writes a backup of its own configuration",
    "factory_reset": "erases the device; kept behind its own confirmation",
}


def _call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _scoped_defs(tree: ast.AST) -> dict[tuple[int, str], list[ast.AST]]:
    """Nested function definitions keyed by (id of enclosing scope, name)."""
    out: dict[tuple[int, str], list[ast.AST]] = {}

    def visit(node: ast.AST, scope: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault((id(scope), child.name), []).append(child)
                visit(child, child)
            elif isinstance(child, (ast.Lambda, ast.ClassDef)):
                visit(child, child)
            else:
                visit(child, scope)

    visit(tree, tree)
    return out


def _envelope_bodies(tree: ast.AST, envelopes: dict[str, frozenset[str]]) -> list[ast.AST]:
    """The functions and lambdas passed as an envelope's body argument."""
    defs = _scoped_defs(tree)
    bodies: list[ast.AST] = []

    def visit(node: ast.AST, scope: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call):
                kws = envelopes.get(_call_name(child.func) or "")
                if kws:
                    for kw in child.keywords:
                        if kw.arg not in kws:
                            continue
                        if isinstance(kw.value, ast.Lambda):
                            bodies.append(kw.value)
                        elif isinstance(kw.value, ast.Name):
                            bodies.extend(defs.get((id(scope), kw.value.id), []))
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                visit(child, child)
            else:
                visit(child, scope)

    visit(tree, tree)
    return bodies


def _calls_inside(bodies: list[ast.AST]) -> set[int]:
    return {id(n) for body in bodies for n in ast.walk(body) if isinstance(n, ast.Call)}


def _is_mutating(name: str) -> bool:
    if name in NON_MUTATING_NAMES:
        return False
    n = name.lower().lstrip("_")
    return any(n == p or n.startswith(p + "_") for p in MUTATING_PREFIXES)


def _direct_writes(path: Path) -> set[str]:
    """Adapter mutating methods called in this module.

    Every call counts, not only ``await adapter.x()``: until 26.12.0 a call
    wrapped in another (``await asyncio.wait_for(adapter.create_vlan(...))``)
    was invisible, because the awaited expression is ``wait_for``.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    staged = _calls_inside(_envelope_bodies(tree, STAGED_ENVELOPES))
    audited = _calls_inside(_envelope_bodies(tree, AUDITED_ENVELOPES))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in staged:
            continue
        call = node
        func = call.func
        if not isinstance(func, ast.Attribute):
            continue
        recv = func.value
        if not isinstance(recv, ast.Name) or recv.id not in ADAPTER_RECEIVERS:
            continue
        if id(node) in audited and func.attr in OPERATIONAL_ACTIONS:
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
#: None left. 2026-11-13: forget, firmware upgrade and disable go through
#: staging (STAGING-MIGRATION option 2); the access point, device, UniFi and
#: camera reboots/restarts are audited actions (option 3), and so, since the
#: gateway API conversion, is the firewall gateway reboot. An audited action is
#: not debt, so this set is empty: pinning a new direct one fails below.
UNMIGRATED_HIGH_BLAST: set[str] = set()


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


#: Request-path files that call an adapter method chosen at runtime
#: (``getattr(adapter, name)(...)``). No name-based check can see what such a
#: call does, so each file is pinned with its count and a new one fails here.
#: Added 2026-11-12 (26.12.0). The staged appliers under app/services dispatch
#: the same way legitimately (they run only inside apply_change) and are outside
#: SCAN_ROOTS.
KNOWN_DYNAMIC_DISPATCH: dict[str, int] = {
    # bulk device actions (reboot / forget / ...) chosen by the request body
    "devices.py": 1,
    # _read_live_aggregate and _read_trust_inventory: both dispatch READS
    "modules/firewall/gateway_service.py": 2,
    # SyncService._read_device walks _SECTIONS, a constant tuple of get_* READ
    # methods (pinned to reads by test_gateway_sync_sections_are_reads below)
    "modules/gateway/services/sync_service.py": 1,
}


def test_gateway_sync_sections_are_reads() -> None:
    """The gateway sync's dynamic dispatch can only ever reach read methods."""
    from app.modules.gateway.services.sync_service import _SECTIONS

    methods = [method for _, method in _SECTIONS]
    assert methods, "the gateway sync reads no sections"
    for method in methods:
        assert method.startswith("get_"), (
            f"{method} in the gateway sync's _SECTIONS is not a read; a write "
            "there would reach the device on every periodic sync without staging"
        )


def _dynamic_dispatch_count(path: Path) -> int:
    count = 0
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in ADAPTER_RECEIVERS
            and not isinstance(node.args[1], ast.Constant)
        ):
            count += 1
    return count


def test_dynamic_adapter_dispatch_in_request_paths_is_pinned() -> None:
    """A runtime-chosen adapter call in a request path must be deliberate."""
    actual: dict[str, int] = {}
    for path in _iter_sources():
        n = _dynamic_dispatch_count(path)
        if n:
            actual[_key(path)] = n
    assert actual == KNOWN_DYNAMIC_DISPATCH, (
        "getattr(adapter|client, <name>) dispatch in a request path changed. "
        f"Found {actual}, pinned {KNOWN_DYNAMIC_DISPATCH}. A new dispatch can "
        "reach any adapter method, including writes, without staging: call the "
        "method by name (so the main ratchet sees it) or pin it here with a "
        "reason. A removed one should be unpinned."
    )


def test_non_mutating_exceptions_are_real_adapter_methods() -> None:
    """An exception for a name no adapter defines would be a silent hole."""
    sources = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted((_APP / "adapters").rglob("*.py"))
    )
    for name in NON_MUTATING_NAMES:
        assert f"def {name}(" in sources, f"{name} is not defined by any adapter"


# ── app/services and app/tasks ──────────────────────────────────────────────
#
# SCAN_ROOTS covers the HTTP surface, but endpoints, the automation engine and
# ZTP hand device writes to app/services, Celery runs others from app/tasks,
# and a write placed there reaches the controller exactly as one in an
# endpoint would. The site-to-site tunnel push
# (VPNKeyExchangeService.push_config_to_gateway) is one: it writes to both
# gateways outside staging and no ratchet could see it. Added 2026-11-13.
#
# The services tree also holds the staged appliers, which legitimately call
# adapters directly (they run only inside AdapterStagingService.apply_change).
# So this inventory is pinned separately, grouped by WHY each write is there.
# ``read_only_refuses_write`` in the adapter clients still refuses every KNOWN
# BYPASS while ADAPTER_READ_ONLY is on; what they skip is staging review and the
# pending-change record. Same editing rules as above: removing an entry is
# always right; adding one needs a reason.
BACKGROUND_ROOTS = [_APP / "services", _APP / "tasks"]

KNOWN_SERVICE_DIRECT_WRITES: dict[str, set[str]] = {
    # ── Staged appliers: called only from build_applier() inside apply_change ──
    "services/adapter_freepbx_extensions.py": {
        "create_extension",
        "update_extension",
        "delete_extension",
    },
    "services/adapter_freepbx_trunks.py": {"create_trunk", "update_trunk", "delete_trunk"},
    "services/adapter_omada_switch_ports.py": {"update_switch_port"},
    "services/adapter_pfsense_firewall.py": {"apply_firewall_changes"},
    "services/adapter_truenas_storage.py": {
        "create_dataset",
        "create_snapshot",
        "delete_snapshot",
        "start_scrub",
    },
    "services/adapter_unifi_hotspot.py": {
        "create_hotspot_operator",
        "delete_hotspot_operator",
        "create_voucher",
    },
    "services/adapter_unifi_networks.py": {"update_network", "delete_network"},
    "services/adapter_unifi_radios.py": {"update_radio"},
    "services/adapter_unifi_switch.py": {
        "update_switch_port",
        "set_port_poe_on_site",
        "update_port_override",
        "power_cycle_port",
    },
    # Proxmox apply_* helpers, each dispatched from an adapter_proxmox_* applier
    "services/hypervisor_backup_jobs.py": {"apply_reviewed_backup_job"},
    "services/hypervisor_certificates.py": {"delete_custom_certificate"},
    "services/hypervisor_cluster_operations.py": {
        "create_ha_resource",
        "delete_ha_resource",
        "create_ha_group",
        "delete_ha_group",
    },
    "services/hypervisor_deletion.py": {"delete_vm"},
    "services/hypervisor_firewall_operations.py": {"apply_firewall_operation"},
    "services/hypervisor_storage_operations.py": {"delete_storage_volume"},
    "services/hypervisor_task_control.py": {"stop_task"},
    # ── Not device writes: backup storage transports (SFTP/FTP client, the
    #    TrueNAS backup data plane) and a Valkey lock ──
    "services/backup.py": {"rename", "remove", "delete", "remove_backup_dataset"},
    "services/discovery_jobs.py": {"set"},
    "tasks/discovery.py": {"set"},
    # ── KNOWN BYPASSES: device writes outside staging ──
    # None left (2026-11-13): config-version rollback, drift auto-remediation,
    # the 802.1X and roaming pushes and the Celery bulk operations are staged
    # (or, for the bulk reboot, audited) where they run.
}


def _scan_services() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for root in BACKGROUND_ROOTS:
        for p in sorted(root.rglob("*.py")):
            hits = _direct_writes(p)
            if hits:
                out[p.relative_to(_APP).as_posix()] = hits
    return out


def test_background_directories_are_readable() -> None:
    """Guard the guard: an empty services/tasks scan must not read as clean."""
    services, tasks = BACKGROUND_ROOTS
    assert services.is_dir(), f"scan root not found: {services}"
    assert tasks.is_dir(), f"scan root not found: {tasks}"
    assert len(list(services.rglob("*.py"))) > 100, "the services scan looks truncated"
    assert len(list(tasks.rglob("*.py"))) > 20, "the tasks scan looks truncated"


def test_no_new_service_layer_device_write() -> None:
    """A new direct device write in app/services or app/tasks needs a pin and a reason."""
    new: dict[str, list[str]] = {}
    for module, methods in _scan_services().items():
        unexpected = methods - KNOWN_SERVICE_DIRECT_WRITES.get(module, set())
        if unexpected:
            new[module] = sorted(unexpected)

    detail = "\n".join(f"  {m}: {', '.join(v)}" for m, v in sorted(new.items()))
    assert not new, (
        "New direct-to-device write(s) in app/services or app/tasks:\n"
        + detail
        + "\nA device mutation must be staged with stage_change() and applied by a "
        "build_applier(). If this one IS a staged applier, or a deliberate "
        "exception, pin it in KNOWN_SERVICE_DIRECT_WRITES under the right heading."
    )


def test_service_inventory_does_not_rot() -> None:
    """Migrated or renamed service writes must be unpinned."""
    actual = _scan_services()
    stale: dict[str, list[str]] = {}
    for module, methods in KNOWN_SERVICE_DIRECT_WRITES.items():
        gone = methods - actual.get(module, set())
        if gone:
            stale[module] = sorted(gone)

    detail = "\n".join(f"  {m}: {', '.join(v)}" for m, v in sorted(stale.items()))
    assert not stale, (
        f"KNOWN_SERVICE_DIRECT_WRITES lists entries that no longer exist -- remove them:\n{detail}"
    )


# ── Staging envelopes ───────────────────────────────────────────────────────


def _all_app_sources() -> list[Path]:
    return sorted(_APP.rglob("*.py"))


@pytest.mark.parametrize(
    ("envelopes", "root"),
    [(STAGED_ENVELOPES, "apply_now"), (AUDITED_ENVELOPES, "audited_device_action")],
)
def test_every_staging_envelope_reaches_apply_now(envelopes, root) -> None:
    """An envelope must hand its body, unchanged, to another envelope of its kind.

    Each one is checked, so every chain ends at apply_now (staged) or at
    audited_device_action (audited). Otherwise adding a name to an envelope
    list would hide a direct write.
    """
    for name, kws in envelopes.items():
        if name in (root, "GroupMember"):
            continue
        definitions = [
            node
            for path in _all_app_sources()
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
        ]
        assert definitions, f"STAGED_ENVELOPES names {name!r}, which nothing defines"
        for definition in definitions:
            for kw in kws:
                bodies = _envelope_bodies(definition, envelopes)
                forwarded = any(
                    isinstance(n, ast.Call)
                    and _call_name(n.func) in envelopes
                    and _call_name(n.func) != name
                    and any(
                        k.arg in envelopes[_call_name(n.func) or ""]
                        and isinstance(k.value, ast.Name)
                        and k.value.id == kw
                        for k in n.keywords
                    )
                    for n in ast.walk(definition)
                ) or any(
                    isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == kw
                    for body in bodies
                    for n in ast.walk(body)
                )
                assert forwarded, (
                    f"{name}() must pass its {kw!r} argument to {root} (or another "
                    f"envelope of its kind) as {kw}={kw}; otherwise what it runs is "
                    "not what the envelope says"
                )


def test_an_envelope_body_is_only_run_by_its_envelope() -> None:
    """A function passed to an envelope must not also be called directly."""
    offenders: list[str] = []
    for path in [*_iter_sources(), *(p for r in BACKGROUND_ROOTS for p in sorted(r.rglob("*.py")))]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            b.name
            for b in _envelope_bodies(tree, {**STAGED_ENVELOPES, **AUDITED_ENVELOPES})
            if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in names
            ):
                offenders.append(f"{path.relative_to(_APP)}:{node.lineno} {node.func.id}()")
    assert not offenders, (
        "these staged write bodies are also called outside their envelope: " + ", ".join(offenders)
    )


def test_the_envelope_scan_sees_through_closures_and_lambdas() -> None:
    """Guard the guard: the exclusion is lexical, and only for the envelope argument."""
    src = """
async def endpoint(adapter, staging):
    async def _write():
        return await adapter.reboot_device("x")

    await staging.apply_now(perform=_write)
    await staging.apply_now(perform=lambda: adapter.update_vlan(1))
    await staging.apply_now(payload=adapter.delete_vlan(2), perform=_write)
    await adapter.create_vlan(3)
"""
    tree = ast.parse(src)
    staged = _calls_inside(_envelope_bodies(tree, STAGED_ENVELOPES))
    direct = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "adapter"
        and id(n) not in staged
    }
    assert direct == {"delete_vlan", "create_vlan"}


def test_the_audited_envelope_records_actions_and_nothing_else() -> None:
    """A configuration write inside audited_device_action is still a direct write."""
    src = """
async def endpoint(adapter, db):
    async def _act():
        return await adapter.reboot_device("x")

    await audited_device_action(db, perform=_act)
    await audited_device_action(db, perform=lambda: adapter.update_vlan(1))
"""
    tree = ast.parse(src)
    audited = _calls_inside(_envelope_bodies(tree, AUDITED_ENVELOPES))
    still_direct = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "adapter"
        and _is_mutating(n.func.attr)
        and not (id(n) in audited and n.func.attr in OPERATIONAL_ACTIONS)
    }
    assert still_direct == {"update_vlan"}


def test_operational_actions_are_real_adapter_methods() -> None:
    """An exemption for a name no adapter defines would be a silent hole."""
    sources = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted((_APP / "adapters").rglob("*.py"))
    )
    missing = [name for name in OPERATIONAL_ACTIONS if f"def {name}(" not in sources]
    assert not missing, f"not defined by any adapter: {missing}"


def test_audited_device_action_records_only_accepted_actions() -> None:
    """Guard the helper: a refused action is returned but not recorded."""
    import asyncio

    from app.adapters.base import AdapterResult
    from app.services import device_writes

    logged: list[dict] = []

    class _Audit:
        def __init__(self, _db: object) -> None:
            pass

        async def log(self, **kwargs: object) -> None:
            logged.append(kwargs)

    class _Db:
        async def commit(self) -> None:
            pass

        async def rollback(self) -> None:
            pass

    import app.services.audit as audit_module

    original = audit_module.AuditService
    audit_module.AuditService = _Audit  # type: ignore[misc,assignment]
    try:

        async def run(result: object) -> object:
            async def _perform() -> object:
                return result

            return await device_writes.audited_device_action(
                _Db(),  # type: ignore[arg-type]
                action="reboot",
                target_type="device",
                target_id="aa",
                target_name="ap1",
                organization_id=None,
                actor_id=None,
                parameters={"port": 3, "password": "hunter2"},
                perform=_perform,
            )

        refused = AdapterResult.fail("busy")
        assert asyncio.run(run(refused)) is refused
        assert logged == []
        assert asyncio.run(run(AdapterResult.ok({"done": True}))).success
    finally:
        audit_module.AuditService = original  # type: ignore[misc]
    (entry,) = logged
    assert entry["action"] == "device_action:reboot"
    assert entry["new_state"]["parameters"]["port"] == 3  # type: ignore[index]
    assert entry["new_state"]["parameters"]["password"] != "hunter2"  # type: ignore[index]


def test_group_member_bodies_only_run_in_a_group() -> None:
    """GroupMember.perform/compensate run only inside apply_group_now's apply_change."""
    src = (_APP / "services" / "adapter_staging.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    service = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AdapterStagingService"
    )
    runners = {
        node.name
        for node in service.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(n, ast.Attribute)
            and n.attr in ("perform", "compensate")
            and isinstance(n.value, ast.Name)
            and n.value.id == "member"
            for n in ast.walk(node)
        )
    }
    # Nothing outside the service touches a member's write either.
    outside = [
        n.lineno
        for top in tree.body
        if not (isinstance(top, ast.ClassDef) and top.name == "AdapterStagingService")
        for n in ast.walk(top)
        if isinstance(n, ast.Attribute)
        and n.attr in ("perform", "compensate")
        and isinstance(n.value, ast.Name)
        and n.value.id == "member"
    ]
    assert not outside, outside
    assert runners <= {"apply_group_now", "_apply_member"}, runners
    member = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_apply_member"
    )
    assert any(
        isinstance(n, ast.Call) and _call_name(n.func) == "apply_change" for n in ast.walk(member)
    ), "_apply_member must apply through apply_change"
