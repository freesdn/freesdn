# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ratchet: the number of hand-rolled ``.organization_id ==`` comparisons can only go down.

``tests/security/test_tenancy_registry.py`` gates CLASSIFICATION: no mapped model
can merge without a decision about how it is scoped. It does not gate ADOPTION.
``app.core.tenancy.tenant_filter`` is the target state for scoping a query (org,
per-user site grants and the scoped-key fail-closed rule, all in one place), but
most queries still hand-roll ``Model.organization_id == org``, and a newly
written query that forgets the comparison, or gets the site grant wrong, merges
as easily as one that does not. Owner decision 2026-11-13: CI ratchet only, the
raw count can only go down.

WHAT COUNTS
-----------
One count per ``==`` operator in ``backend/app`` (parsed with ``ast``, so
comments, docstrings and strings never count) where either operand is an
attribute named ``organization_id``, whatever it is an attribute of:

* ``Device.organization_id == org`` and ``table.c.organization_id == org``
  (query filters, the thing ``tenant_filter`` replaces);
* ``alias.organization_id == org`` inside a query, which cannot be told apart
  from the next case without type information;
* ``device.organization_id == user.organization_id`` as a plain Python check
  after a fetch. These count too: statically they look exactly like an aliased
  query filter, and a post-fetch check is itself the pattern ``tenant_filter``
  exists to move into the query.

Not counted: ``!=``, ``.is_(...)``, ``.in_(...)``, and the comparison inside
``tenant_filter`` itself (``getattr(model, org_attr) == org`` has no attribute
named ``organization_id``).

RULES FOR EDITING ``BASELINE``
------------------------------
* A file's count went DOWN (a query moved to ``tenant_filter``, or code was
  deleted): lower its entry, or delete it at zero. ``test_the_baseline_is_tight``
  fails until you do, so every migration tightens the ratchet and the gain
  cannot be quietly spent again later.
* A file's count went UP, or a new file appears: use
  ``tenant_filter(Model, current_user)`` instead. Raising an entry is a reviewed
  decision with its reason in the commit message, never a way to make CI green.

Measured on 2026-11-13: 835 comparisons in 158 files, against 55 ``tenant_filter``
call sites.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
_APP = _BACKEND / "app"

#: Measured debt. Path (posix, relative to backend/) -> count. See the module
#: docstring for what counts and how to edit this.
BASELINE: dict[str, int] = {
    "app/api/v1/endpoints/access_points.py": 1,
    "app/api/v1/endpoints/actions.py": 3,
    "app/api/v1/endpoints/adapter_omada_vpn.py": 1,
    "app/api/v1/endpoints/agent_downloads.py": 2,
    "app/api/v1/endpoints/agent_release_upload.py": 2,
    "app/api/v1/endpoints/agents.py": 10,
    "app/api/v1/endpoints/alert_rules.py": 2,
    "app/api/v1/endpoints/analytics.py": 14,
    "app/api/v1/endpoints/automation.py": 12,
    "app/api/v1/endpoints/backups.py": 1,
    "app/api/v1/endpoints/config_versions.py": 2,
    "app/api/v1/endpoints/controllers.py": 5,
    "app/api/v1/endpoints/correlation.py": 2,
    "app/api/v1/endpoints/credentials.py": 8,
    "app/api/v1/endpoints/dashboard.py": 4,
    "app/api/v1/endpoints/data.py": 10,
    "app/api/v1/endpoints/devices.py": 1,
    "app/api/v1/endpoints/discovery.py": 10,
    "app/api/v1/endpoints/dpi.py": 8,
    "app/api/v1/endpoints/enterprise.py": 36,
    "app/api/v1/endpoints/firmware.py": 4,
    "app/api/v1/endpoints/integrations.py": 8,
    "app/api/v1/endpoints/logs.py": 13,
    "app/api/v1/endpoints/network.py": 4,
    "app/api/v1/endpoints/organizations.py": 13,
    "app/api/v1/endpoints/plugins.py": 5,
    "app/api/v1/endpoints/poe.py": 10,
    "app/api/v1/endpoints/radius.py": 10,
    "app/api/v1/endpoints/security.py": 1,
    "app/api/v1/endpoints/sites.py": 3,
    "app/api/v1/endpoints/sla.py": 6,
    "app/api/v1/endpoints/sla_reports.py": 3,
    "app/api/v1/endpoints/switches.py": 4,
    "app/api/v1/endpoints/topology.py": 5,
    "app/api/v1/endpoints/users.py": 2,
    "app/api/v1/endpoints/vpn.py": 27,
    "app/api/v1/endpoints/vpn_orchestration.py": 5,
    "app/api/v1/endpoints/webhooks.py": 3,
    "app/api/v1/endpoints/websocket.py": 1,
    "app/api/v1/endpoints/ztp.py": 27,
    "app/core/dependencies.py": 1,
    "app/core/fabric/executor.py": 2,
    "app/core/tenancy.py": 1,
    "app/modules/access_control/service.py": 3,
    "app/modules/ai/api.py": 10,
    "app/modules/ai/governance.py": 3,
    "app/modules/ai/service.py": 2,
    "app/modules/ai/tools/automation.py": 2,
    "app/modules/ai/tools/collector.py": 4,
    "app/modules/ai/tools/diagnostics.py": 2,
    "app/modules/ai/tools/estate.py": 3,
    "app/modules/ai/tools/network.py": 5,
    "app/modules/cameras/api.py": 36,
    "app/modules/cameras/backup.py": 8,
    "app/modules/cameras/push_service.py": 5,
    "app/modules/cameras/service.py": 48,
    "app/modules/collector/api.py": 14,
    "app/modules/collector/module.py": 1,
    "app/modules/collector/services/classifier.py": 1,
    "app/modules/enablement.py": 1,
    "app/modules/firewall/backup.py": 3,
    "app/modules/firewall/gateway_service.py": 3,
    "app/modules/firewall/service.py": 1,
    "app/modules/gateway/adapter_helpers.py": 1,
    "app/modules/gateway/api/dashboard_api.py": 10,
    "app/modules/gateway/api/import_api.py": 1,
    "app/modules/gateway/services/canonical_service.py": 12,
    "app/modules/gateway/services/distribution_service.py": 3,
    "app/modules/gateway/services/drift_service.py": 8,
    "app/modules/gateway/services/import_service.py": 5,
    "app/modules/gateway/services/reconciliation_service.py": 3,
    "app/modules/gateway/services/role_map_service.py": 2,
    "app/modules/gateway/services/suppression_service.py": 3,
    "app/modules/gateway/services/template_service.py": 4,
    "app/modules/hypervisor/api.py": 1,
    "app/modules/network/api.py": 2,
    "app/modules/network/backup.py": 1,
    "app/modules/network/service.py": 1,
    # Correlated EXISTS (OrganizationModule row of the polled row's org) in a
    # background poller: there is no principal for tenant_filter to scope.
    "app/modules/poll_gate.py": 1,
    "app/modules/service.py": 5,
    "app/modules/storage/module.py": 1,
    "app/modules/voip/api.py": 3,
    "app/modules/voip/backup.py": 4,
    "app/modules/voip/provisioning.py": 1,
    "app/modules/voip/service.py": 2,
    "app/plugins/public_auth.py": 2,
    "app/plugins/scheduler.py": 1,
    "app/plugins/sdk.py": 17,
    "app/services/adapter_base.py": 2,
    "app/services/adapter_freepbx_base.py": 1,
    "app/services/adapter_omada_switch_ports.py": 1,
    "app/services/adapter_overlay_vpn.py": 1,
    "app/services/adapter_staging.py": 3,
    "app/services/agent_release_catalogue.py": 1,
    "app/services/agent_release_delete_request.py": 1,
    "app/services/agent_release_promotion.py": 1,
    "app/services/agent_release_reservation.py": 1,
    "app/services/alert_rules.py": 10,
    "app/services/analytics.py": 12,
    "app/services/audit.py": 4,
    "app/services/auto_backup.py": 1,
    "app/services/automation.py": 11,
    "app/services/backup.py": 18,
    "app/services/backup_contributors/account_security.py": 4,
    "app/services/backup_download_authority.py": 1,
    "app/services/brain_vpn.py": 5,
    "app/services/correlation.py": 12,
    "app/services/custom_roles.py": 3,
    "app/services/device_config_backup.py": 1,
    "app/services/device_migration.py": 2,
    "app/services/discovered_hosts.py": 5,
    "app/services/discovery.py": 1,
    "app/services/enterprise.py": 2,
    "app/services/event_service.py": 7,
    "app/services/fabric_connections.py": 4,
    "app/services/firmware.py": 12,
    "app/services/hypervisor_backup_jobs.py": 1,
    "app/services/hypervisor_certificates.py": 1,
    "app/services/hypervisor_cluster_operations.py": 2,
    "app/services/hypervisor_firewall_operations.py": 1,
    "app/services/hypervisor_guest_changes.py": 1,
    "app/services/hypervisor_storage_operations.py": 1,
    "app/services/hypervisor_task_control.py": 1,
    "app/services/import_export.py": 12,
    "app/services/notification.py": 7,
    "app/services/notification_helpers.py": 1,
    "app/services/notification_outbox.py": 3,
    "app/services/organization.py": 13,
    "app/services/radius.py": 2,
    "app/services/remote_agent.py": 3,
    "app/services/remote_write_coordination.py": 1,
    "app/services/remote_write_journal.py": 2,
    "app/services/roaming.py": 5,
    "app/services/security_audit.py": 21,
    "app/services/sla.py": 13,
    "app/services/sla_report_delivery.py": 6,
    "app/services/sla_reports.py": 6,
    "app/services/sla_schedule_authorization.py": 2,
    "app/services/sso.py": 2,
    "app/services/topology.py": 1,
    "app/services/vault_export_operation_state.py": 1,
    "app/services/vpn_cert_lifecycle.py": 2,
    "app/services/vpn_integration.py": 2,
    "app/services/vpn_key_exchange.py": 1,
    "app/services/vpn_orchestration.py": 10,
    "app/services/vpn_preflight.py": 3,
    "app/services/vpn_reconnect.py": 1,
    "app/services/vpn_route_conflicts.py": 3,
    "app/services/webhooks.py": 4,
    "app/services/ztp.py": 3,
    "app/setup/service.py": 1,
    "app/tasks/agents.py": 6,
    "app/tasks/backup.py": 1,
    "app/tasks/bulk_operations.py": 5,
    "app/tasks/cameras.py": 8,
    "app/tasks/discovery.py": 5,
    "app/tasks/notification_retry.py": 2,
    "app/tasks/poe.py": 1,
    "app/tasks/sync.py": 1,
}


def _is_org_attr(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "organization_id"


def _count(source: str) -> int:
    count = 0
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for i, op in enumerate(node.ops):
            if isinstance(op, ast.Eq) and (
                _is_org_attr(operands[i]) or _is_org_attr(operands[i + 1])
            ):
                count += 1
    return count


def _measure() -> Counter[str]:
    counts: Counter[str] = Counter()
    for path in sorted(_APP.rglob("*.py")):
        n = _count(path.read_text(encoding="utf-8"))
        if n:
            counts[path.relative_to(_BACKEND).as_posix()] = n
    return counts


_SAMPLE = '''
# Device.organization_id == org  (a comment)
"""Device.organization_id == org (a docstring)"""
q = select(Device).where(Device.organization_id == org)
q = q.where(org == Alert.organization_id, Alert.site_id == site)
t = table.c.organization_id == org
ok = device.organization_id == user.organization_id
chained = a == b.organization_id == c
not_counted = Device.organization_id != org
not_counted_2 = Device.organization_id.is_(None)
'''


def test_the_counter_counts_what_the_docstring_says() -> None:
    # Device, Alert, table.c, device (one per ==), and both == of the chain.
    assert _count(_SAMPLE) == 6


def test_the_scan_sees_the_code_it_ratchets() -> None:
    """Guards against a path change that would make the scan find nothing."""
    assert sum(_measure().values()) >= 500


def test_no_file_gained_a_raw_organization_comparison() -> None:
    measured = _measure()
    grown = {
        path: (BASELINE.get(path, 0), n)
        for path, n in measured.items()
        if n > BASELINE.get(path, 0)
    }
    assert not grown, (
        "New hand-rolled .organization_id == comparisons (path: (baseline, now)): "
        f"{grown}. Scope the query with tenant_filter(Model, current_user) from "
        "app.core.tenancy instead; see this file's docstring."
    )


def test_the_baseline_is_tight() -> None:
    """A count that went down must be lowered here, so it cannot grow back."""
    measured = _measure()
    slack = {
        path: (n, measured.get(path, 0))
        for path, n in BASELINE.items()
        if measured.get(path, 0) < n
    }
    assert not slack, (
        "These files now have fewer raw .organization_id == comparisons than "
        f"BASELINE records (path: (baseline, now)): {slack}. Lower (or delete) "
        "their entries so the ratchet keeps the gain."
    )
