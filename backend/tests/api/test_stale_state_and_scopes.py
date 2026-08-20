# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Five defects where the state FreeSDN reported had come apart from reality.

1. AN API KEY KEPT ITS OLD ROLE'S POWERS AFTER A DEMOTE
   A key's ``scopes`` were used verbatim as its permissions. Demoting a user
   bumps ``token_version``, which kills their JWTs -- and does nothing to their
   API keys. So the documented way to strip somebody's access left their
   long-lived credential holding an org_admin's powers indefinitely.

   The scopes are now intersected with whatever the owner can do TODAY. The
   intersection has to use the same wildcard rules ``has_permission`` uses:
   role permissions are written ``network:*`` / ``organization:*``, so a plain
   set-membership test would drop a scope of ``network:read`` from an admin and
   break every working key -- a worse outcome than the bug.

2. REORDERING FIREWALL RULES ALWAYS RETURNED 500
   ``list_rules`` is annotated ``-> list[Any]`` and actually returns
   ``(rows, total)``. ``reorder_rules`` returned that tuple whole, and the
   endpoint does ``[FirewallRuleResponse.model_validate(r) for r in rules]`` --
   iterating a 2-tuple yields the LIST and then the int, so validating a list
   against a rule model raised.

   The rule_order writes were committed before the response was built, so the
   reorder took effect and only the reply failed: the UI shows an error toast
   and then refetches into the new order. That is exactly the shape that gets a
   bug written off as cosmetic.

3. SMART HEALTH WAS UNREACHABLE FOR EVERY NVMe DISK
   ``^/dev/[a-z]+[0-9]*$`` cannot match ``/dev/nvme0n1``: after ``nvme``
   (letters) comes ``0`` (digits) and then ``n`` (a letter again), and the
   pattern allows no letters after digits. SATA matched, so the feature looked
   fine on older hardware and failed on every modern Proxmox host.

4. A CONTROLLER SYNC ERASED THE OPERATOR'S CLIENT BLOCKS
   ``POST /network/clients/{id}/block`` pushes to the controller, checks the
   AdapterResult, then records ``client_metadata["blocked"] = True``. The sync
   did ``dc.client_metadata = _safe_meta(c)`` -- a wholesale replacement with a
   controller payload that has no such key. Minutes later the flag was gone.

   The client stayed blocked on the controller, which is what matters and
   always worked. What broke was FreeSDN's memory of it: the Clients page
   showed the client as normal, the "blocked" filter matched nothing, and the
   stats card counted zero. An operator looking for who they had blocked found
   no one.

5. CHANGING AN SSID'S VLAN REPORTED SUCCESS AND CHANGED NOTHING
   The ``create`` branch sent ``vlanEnable``/``vlanId``; the ``update`` branch
   never did. So moving an existing SSID onto a different VLAN saved the new id
   locally, returned ``controller_synced: true``, and left the controller on
   the old VLAN. That is a segmentation failure, not a display one: an operator
   moving a guest SSID onto the guest VLAN got a success message while guests
   kept landing wherever they were before.
"""

from __future__ import annotations

import inspect
import re

import pytest

from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, _permission_granted_by


def _code(obj) -> str:
    """Source with comments stripped -- the fixes quote the old code in comments."""
    src = inspect.getsource(obj)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))


# ── 1. API key scopes are a ceiling, not a grant ─────────────────


def _effective(scopes: list[str], role: str) -> list[str]:
    """The intersection the API-key auth path performs."""
    granted = DEFAULT_ROLE_PERMISSIONS.get(role, DEFAULT_ROLE_PERMISSIONS["viewer"])
    return [s for s in scopes if _permission_granted_by(s, granted)]


def test_a_demoted_owner_loses_their_keys_elevated_scopes() -> None:
    """
    The regression. A key minted while its owner was an org_admin kept those
    powers after the demote, because scopes were used verbatim.
    """
    scopes = ["user:write", "controller:admin"]
    assert _effective(scopes, "org_admin") != []
    assert _effective(scopes, "viewer") == [], "a viewer's key still carries org_admin scopes"


def test_a_key_still_works_for_what_its_owner_can_still_do() -> None:
    """Intersecting must not revoke everything -- only what the role lost."""
    effective = _effective(["network:read", "user:write"], "viewer")
    assert "user:write" not in effective
    # Whatever a viewer legitimately keeps stays.
    viewer = DEFAULT_ROLE_PERMISSIONS["viewer"]
    for scope in effective:
        assert _permission_granted_by(scope, viewer)


def test_a_wildcard_role_permission_still_covers_a_narrow_scope() -> None:
    """
    The trap. Role lists are written ``network:*``; a plain set intersection
    would drop ``network:read`` from an admin and break every working key --
    a regression worse than the bug being fixed.
    """
    assert _permission_granted_by("network:read", ["network:*"]) is True
    assert _permission_granted_by("cameras.view", ["cameras.*"]) is True
    assert _permission_granted_by("anything:at:all", ["*"]) is True


def test_the_matcher_agrees_with_has_permission() -> None:
    """
    Two implementations of the same rule is how they drift. Pin the cases that
    matter against the real thing.
    """
    from app.core.dependencies import CurrentUser

    for permission, granted in [
        ("network:read", ["network:*"]),
        ("cameras.view", ["cameras.*"]),
        ("user:write", ["network:*"]),
        ("device:reboot", ["device:reboot"]),
        ("a:b", []),
    ]:
        principal = CurrentUser.__new__(CurrentUser)
        principal.permissions = granted
        principal._scoped = True  # evaluate against the list only
        assert principal.has_permission(permission) == _permission_granted_by(
            permission, granted
        ), f"{permission} vs {granted}"


def test_an_unscoped_key_still_inherits_the_role() -> None:
    """A key with no scopes was never the problem and must keep working."""
    assert _effective([], "org_admin") == []
    src = _code(inspect.getmodule(_permission_granted_by))
    assert "permissions = user_permissions" in src


def test_the_auth_path_actually_performs_the_intersection() -> None:
    """
    Anchor the tests above to production.

    ``_effective`` in this file models what the API-key branch of
    ``get_current_user`` does; the branch itself needs a database, a hashed
    key and a live session to drive. This asserts the real code does the same
    thing, and it is one of the tests that fails against pristine HEAD -- so
    the modelling above is not free-floating.
    """
    import app.core.dependencies as deps

    src = inspect.getsource(deps)
    assert "_permission_granted_by(s, user_permissions)" in src, (
        "the API-key path no longer intersects scopes with the owner's role"
    )
    assert "list(db_key.scopes)" + chr(10) not in src, (
        "the verbatim scope list is back; a demoted owner's key keeps its old powers"
    )


def test_a_super_admin_owner_keeps_their_narrow_key_narrow() -> None:
    """
    audit #8: a read-only key minted by a super_admin must STAY read-only. The
    intersection must not widen a scope list just because the owner holds "*".
    """
    effective = _effective(["network:read"], "super_admin")
    assert effective == ["network:read"]


# ── 2. the firewall reorder 500 ──────────────────────────────────


def test_list_rules_declares_the_tuple_it_returns() -> None:
    """The lie that caused it: the annotation said list, the body said tuple."""
    from app.modules.firewall.service import FirewallService

    sig = inspect.signature(FirewallService.list_rules)
    assert "tuple" in str(sig.return_annotation)


def test_reorder_unpacks_instead_of_returning_the_tuple() -> None:
    from app.modules.firewall.service import FirewallService

    code = _code(FirewallService.reorder_rules)
    assert "return await self.list_rules" not in code, (
        "reorder still hands the endpoint a (rows, total) tuple"
    )
    assert "rows, _total = await self.list_rules" in code


def test_reorder_is_not_truncated_by_the_default_page_size() -> None:
    """
    ``list_rules`` defaults to limit=100. Reordering is the one operation where
    returning a truncated list would tell the operator their rules had been
    reordered into a shorter set.
    """
    from app.modules.firewall.service import FirewallService

    assert "limit=max(len(rule_ids), 100)" in _code(FirewallService.reorder_rules)


def test_the_endpoint_iterates_what_it_is_given() -> None:
    """
    Premise. If the endpoint ever stopped iterating, the tuple would have been
    harmless and this fix would be pointless.
    """
    from app.modules.firewall.api import reorder_rules

    assert "for r in rules" in _code(reorder_rules)


# ── 3. the NVMe disk path ────────────────────────────────────────


@pytest.mark.parametrize(
    "disk",
    [
        "/dev/sda",
        "/dev/sdb",
        "/dev/vda",
        "/dev/hda",
        "/dev/xvda",
        "/dev/nvme0n1",
        "/dev/nvme1n2",
        "/dev/mmcblk0",
        "/dev/sg0",
    ],
)
def test_every_real_disk_shape_is_accepted(disk: str) -> None:
    from app.modules.hypervisor.api import _RE_DISK

    assert _RE_DISK.match(disk), f"{disk} rejected"


def test_the_old_pattern_really_did_reject_nvme() -> None:
    """Negative control: the exact regex that shipped, against the exact path."""
    old = re.compile(r"^/dev/[a-z]+[0-9]*$")
    assert old.match("/dev/sda")
    assert not old.match("/dev/nvme0n1")


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/dev/../etc/shadow",
        "/dev/sda; rm -rf /",
        "/dev/sda\n/dev/sdb",
        "",
        "/dev/",
        "../../dev/sda",
    ],
)
def test_the_guard_is_still_a_strict_allowlist(path: str) -> None:
    """
    This value is a device path handed to the hypervisor. Widening it to
    ``[a-z0-9]+`` would have fixed NVMe and weakened the check; the point was
    to enumerate the shapes Linux actually uses.
    """
    from app.modules.hypervisor.api import _RE_DISK

    assert not _RE_DISK.match(path)


# ── 4. the erased client block ───────────────────────────────────


def test_the_client_sync_merges_rather_than_replaces() -> None:
    from app.services import controller_sync

    code = _code(controller_sync._sync_clients)
    assert "dc.client_metadata = _safe_meta(c)" not in code, (
        "the sync still overwrites FreeSDN-owned client state"
    )
    assert "merged.update(incoming)" in code


def test_a_controller_that_reports_block_state_still_wins() -> None:
    """
    Omada does report it. The controller is the authority when it speaks; the
    merge only fills in when it says nothing.
    """
    from app.services import controller_sync

    code = _code(controller_sync._sync_clients)
    assert 'if "blocked" not in incoming' in code


def test_the_block_endpoint_is_what_writes_the_flag() -> None:
    """Premise: the key is FreeSDN-owned, which is why a blind overwrite lost it."""
    from app.api.v1.endpoints.network import block_client

    assert 'meta["blocked"] = True' in _code(block_client)


def test_the_blocked_filter_reads_that_same_key() -> None:
    """The user-visible consequence: the filter matched nothing after a sync."""
    from app.modules.network.service import NetworkClientService

    assert 'client_metadata["blocked"]' in _code(NetworkClientService.list)


# ── 5. the SSID VLAN that never left ─────────────────────────────


def test_the_ssid_update_sends_the_vlan() -> None:
    from app.api.v1.endpoints import network

    code = _code(network._push_wifi_to_controller)
    update_branch = code[
        code.index('elif action == "update":') : code.index('elif action == "delete":')
    ]
    assert '"vlanId"' in update_branch, "changing an SSID's VLAN still never reaches the controller"
    assert '"vlanEnable"' in update_branch


def test_clearing_the_vlan_is_sent_too() -> None:
    """
    Omitting the keys when vlan_id is empty would make "remove the VLAN tag"
    the one edit that still silently does nothing.
    """
    from app.api.v1.endpoints import network

    code = _code(network._push_wifi_to_controller)
    update_branch = code[
        code.index('elif action == "update":') : code.index('elif action == "delete":')
    ]
    assert 'config["vlanEnable"] = False' in update_branch


def test_create_still_sends_it() -> None:
    """The branch that always worked, and the reason the gap was invisible."""
    from app.api.v1.endpoints import network

    code = _code(network._push_wifi_to_controller)
    create_branch = code[
        code.index('if action == "create":') : code.index('elif action == "update":')
    ]
    assert '"vlanId"' in create_branch
