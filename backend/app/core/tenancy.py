# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Canonical application-layer tenant scoping.

FreeSDN enforces multi-tenant isolation in the APPLICATION layer (it deliberately
does NOT use PostgreSQL Row-Level Security).
Historically that enforcement was hand-rolled per endpoint (~120 copies of the same
``where(Model.organization_id == ...)`` / ``is_unscoped_superuser`` idiom), and a
forgotten copy was the root cause of repeated cross-tenant findings.

``tenant_filter(model, user)`` is the ONE place that decides how a collection query
on a given model is scoped to the rows a principal may see. It delegates to the
already-hardened primitives (``is_unscoped_superuser`` / ``site_scope_filter``) and
classifies the model by COLUMN INTROSPECTION (immune to ``Mapped[]`` vs ``Column()``
declaration style), with an explicit ``TENANT_EXEMPT`` allow-list for the models that
carry no ``organization_id`` / ``site_id`` column.

A model that declares neither column and is not in ``TENANT_EXEMPT`` raises
``UnregisteredTenantModel`` — and the CI meta-test (``test_tenancy_registry``) fails
the build, so a new tenant-ambiguous table cannot merge unclassified. That gate is
what turns "forgot to scope → silent cross-tenant leak" into "forgot to classify →
red CI".
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, false, select, true

from app.core.dependencies import is_unscoped_superuser
from app.core.site_access import site_scope_filter

# ---------------------------------------------------------------------------
# Exempt models: declare NO organization_id / site_id column and are
# INTENTIONALLY not directly tenant-filtered. Two kinds, both -> true():
#   - global   : genuinely platform-wide / cross-org / user-scoped (org via owner)
#   - viaparent: child rows reached through a parent FK; scoped transitively by the
#                parent query, never queried directly with a tenant filter.
# Keyed by "module:ClassName" (table names are NOT unique across schemas).
# Keep this list HONEST — the meta-test rejects stale entries (a listed model that
# has since gained an org/site column) and unclassified new models.
# ---------------------------------------------------------------------------
TENANT_EXEMPT: dict[str, str] = {
    # --- genuinely platform-global / cross-org ---
    "app.models.core:Organization": "global: the tenant root itself",
    "app.models.security_audit:FailedLoginRecord": "global: platform brute-force tracking (no org column)",
    "app.models.security_audit:IPBlockRecord": "global: platform IP block list (no org column)",
    "app.models.sync_lock:DeviceSyncLock": "global: process concurrency lock",
    "app.models.analytics:MetricDefinitionRecord": "global: shared metric catalog",
    "app.models.marketplace:MarketplacePlugin": "global: marketplace catalog (cross-org by design)",
    "app.models.marketplace:MarketplacePluginVersion": "global: marketplace catalog versions",
    "app.models.marketplace:PluginReview": "global: cross-org plugin reviews",
    "app.models.plugins:InstalledPlugin": "global: plugin registry (per-org state in PluginOrganizationState)",
    # --- user-scoped (org reached via the owning user) ---
    "app.models.api_keys:APIKey": "user-scoped: org via owning user",
    "app.models.core:UserSession": "user-scoped: org via owning user",
    "app.models.sso:SSOSession": "user-scoped: org via owning user",
    "app.models.notification:NotificationPreference": "user-scoped: org via owning user",
    "app.models.oauth2:OAuth2AuthorizationCode": "user-scoped: short-lived OAuth code",
    "app.models.oauth2:OAuth2Token": "user-scoped: OAuth token",
    # --- child rows scoped via a parent FK ---
    "app.models.agents:AgentScheduleRun": "viaparent: AgentSchedule",
    "app.models.agents:AgentTask": "viaparent: RemoteAgent",
    "app.models.agents:AgentHeartbeat": "viaparent: RemoteAgent (LogDB)",
    "app.models.correlation:IncidentEvent": "viaparent: Incident",
    "app.models.devices:DeviceClient": "viaparent: Device",
    "app.models.devices:DevicePort": "viaparent: Device",
    "app.models.enterprise:DeviceGroupMembership": "viaparent: DeviceGroup",
    "app.models.enterprise:DeviceTag": "viaparent: Device",
    "app.models.radius:Dot1xPortConfig": "viaparent: DevicePort / Device",
    "app.models.sla:SLASnapshot": "viaparent: SLAPolicy",
    "app.models.vpn:VPNReconnectState": "viaparent: VPNConnection",
    "app.models.webhooks:WebhookDelivery": "viaparent: Webhook",
    "app.modules.ai.models:AIMessage": "viaparent: AIConversation",
    "app.modules.backup.models:RestoreJob": "viaparent: Backup",
    "app.modules.cameras.models:CameraGroupMember": "viaparent: CameraGroup",
    "app.modules.network.models:LinkAggregationGroup": "viaparent: Device / site",
    "app.modules.network.models:TopologyLink": "viaparent: site",
    # --- module child rows (register only when the module imports) ---
    "app.modules.firewall.models:FirewallRule": "viaparent: Device -> Site -> org",
    "app.modules.firewall.models:NATRule": "viaparent: Device -> Site -> org",
    "app.modules.firewall.models:FirewallLog": "viaparent: Device -> Site -> org",
    "app.modules.firewall.models:IDSAlert": "viaparent: Device -> Site -> org",
    "app.modules.firewall.models:VPNTunnel": "viaparent: Device -> Site -> org",
    "app.modules.firewall.models:GatewaySyncLog": "viaparent: gateway",
    "app.modules.gateway.models:SiteRoleAssignment": "viaparent: gateway role map -> site",
    "app.modules.voip.models:CallLog": "viaparent: PBX -> Site -> org",
    "app.modules.voip.models:Extension": "viaparent: PBX -> Site -> org",
    "app.modules.voip.models:RingGroup": "viaparent: PBX -> Site -> org",
    "app.modules.voip.models:VoicemailMessage": "viaparent: PBX -> Site -> org",
    "app.modules.access_control.models:Reader": "viaparent: Door / Controller -> Site",
    "app.modules.access_control.models:AccessCredential": "viaparent: Cardholder -> Site",
    "app.modules.access_control.models:AccessEvent": "viaparent: Door / Cardholder -> Site",
}


# Models whose per-user SITE grant is keyed on their PRIMARY KEY rather than a
# ``site_id`` column — i.e. the model IS a site. ``Site`` has an organization_id
# column (so column-introspection treats it as direct_org) but its grant predicate
# must be ``Site.id IN (granted)``, not a (non-existent) ``Site.site_id``. Without
# this special case tenant_filter(Site, site_limited_user) would silently drop the
# grant and show sibling sites.
#
# FORWARD-LOOKING: if you ever add another model that IS a site-like root (its
# primary key is what the per-user site grant is keyed on, and it has no separate
# ``site_id`` column), add its "module:ClassName" qual here too — otherwise
# tenant_filter would scope it by org only and a site-limited caller would see
# every sibling. There is no automatic detector for "this PK is a site"; this is a
# deliberate, reviewed allow-list of exactly one model today.
_SITE_PK_GRANT: frozenset[str] = frozenset({"app.models.core:Site"})


class UnregisteredTenantModel(RuntimeError):
    """A model with no organization_id/site_id column was passed to
    ``tenant_filter`` but is not classified in ``TENANT_EXEMPT``."""


def _qual(model: Any) -> str:
    return f"{model.__module__}:{model.__name__}"


def _columns(model: Any) -> set[str]:
    return {c.name for c in model.__table__.columns}


def tenant_filter(model: Any, user: Any) -> Any:
    """Return a SQLAlchemy predicate scoping a query on ``model`` to the rows
    ``user`` may see. ``AND`` it into the WHERE clause of any collection query::

        stmt = select(Alert).where(tenant_filter(Alert, current_user))

    Principal handling (identical to the per-endpoint helpers it replaces):
      - UNSCOPED super_admin            -> ``true()``  (platform-wide, no filter)
      - org user / site-limited user    -> org and/or per-user-site-grant predicate
      - SCOPED super_admin key (no org) -> ``false()`` (fail closed, matches no rows)

    Shape (by column introspection):
      - has organization_id : ``organization_id == <org>``  (+ site grant if it also has site_id)
      - site_id only        : ``site_id IN (sites in <org>)``  + site grant  (reach org via Site)
      - neither column      : ``true()`` if in TENANT_EXEMPT, else raise
    """
    cols = _columns(model)
    has_org = "organization_id" in cols
    has_site = "site_id" in cols

    if not has_org and not has_site:
        if _qual(model) in TENANT_EXEMPT:
            return true()
        raise UnregisteredTenantModel(
            f"{_qual(model)} declares no organization_id/site_id column and is not "
            f"classified in app.core.tenancy.TENANT_EXEMPT. Classify it (global / "
            f"user-scoped / viaparent) before scoping a query with tenant_filter."
        )

    # Resolve the org WITHOUT raising (this is a predicate builder, not a gate):
    # unscoped super -> None (platform-wide); a non-unscoped principal with no org
    # is a scoped/no-org key -> fail closed.
    unscoped = is_unscoped_superuser(user)
    org = None if unscoped else getattr(user, "organization_id", None)
    if not unscoped and org is None:
        return false()  # scoped/no-org principal: see nothing (fail closed)

    preds: list[Any] = []
    if has_org:
        if org is not None:
            preds.append(model.organization_id == org)
    elif has_site:
        # via_site: reach the org through the Site join.
        if org is not None:
            from app.models.core import Site

            preds.append(
                model.site_id.in_(
                    select(Site.id).where(Site.organization_id == org, Site.deleted_at.is_(None))
                )
            )

    if has_site:
        # Per-user site grant: no-op (true()) for non-site-limited principals,
        # ``site_id IN (granted)`` for a site-limited caller, fail-closed empty IN
        # for a site-limited caller with no grants.
        preds.append(site_scope_filter(user, model.site_id))
    elif _qual(model) in _SITE_PK_GRANT:
        # The model IS a site — apply the grant on its primary key.
        preds.append(site_scope_filter(user, model.id))

    if not preds:
        return true()
    return and_(*preds)
