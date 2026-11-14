// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Page identity for MainLayout's route transition.
 *
 * MainLayout animates (and, through the animation's React `key`, remounts) the
 * page whenever this key changes. It used to be `location.pathname`, so every
 * URL-driven tab (`/sites/:siteId/network`, `/switches/:id/ports`,
 * `/devices/list`, `/vpn/tunnels`, ...) tore the whole page down: a fade out and
 * in, a refetch flash, and the loss of every filter, search box, selection and
 * scroll position on the page. A tab is a view of the same page, not a new one.
 *
 * The key is therefore the pathname with a trailing `:tab` segment removed when
 * the best-ranked route for the path is a tabbed route. Everything else keeps
 * the old behaviour: a different page, or the same detail page for a different
 * entity (`/devices/a` to `/devices/b`), still gets a fresh mount.
 */
import { matchRoutes, type RouteObject } from 'react-router-dom';
import { moduleManifests } from '@/modules';

/**
 * Tabbed routes declared statically in App.tsx, plus their tab-less siblings
 * so route ranking picks the same winner React Router does. A guard test
 * (`route-transition-key.test.ts`) fails if App.tsx gains a `:tab` route that
 * is missing here.
 */
export const STATIC_TABBED_ROUTES = [
  '/sites/:siteId',
  '/sites/:siteId/:tab',
  '/controllers/:id/:tab?',
  '/devices/list',
  '/devices/:deviceId',
  '/devices/:deviceId/:tab',
  '/organizations/:orgId',
  '/organizations/:orgId/:tab',
  '/discovery/:tab',
  '/settings/:tab',
  '/settings/modules/:moduleId',
  '/settings/modules/:moduleId/:tab',
  '/analytics/sites-comparison',
  '/analytics/:tab',
  '/logs/:tab',
  '/alerts/:tab',
  '/automation/:tab',
  '/firmware/:tab',
  '/health/:tab',
  '/groups/:tab',
  '/incidents/:tab',
  '/sla/:tab',
  '/alert-rules/:tab',
  '/notification-providers/:tab',
  '/security/:tab',
  '/roles/:tab',
  '/agents/downloads',
  '/agents/releases',
  '/agents/:id',
  '/marketplace/:slug',
];

/**
 * Static paths that are a tab of a sibling page rather than a page: the
 * Devices and Cameras list tabs, and FirewallPage's tabs, which it resolves
 * from its `/firewall/*` splat rather than a `:tab` param.
 */
const TAB_ALIASES: Record<string, string> = {
  '/devices/list': '/devices',
  '/cameras/list': '/cameras',
  '/firewall/gateways': '/firewall',
  '/firewall/rules': '/firewall',
  '/firewall/nat-rules': '/firewall',
  '/firewall/vpn': '/firewall',
  '/firewall/ids': '/firewall',
  '/firewall/logs': '/firewall',
};

let cachedRoutes: RouteObject[] | null = null;

function knownRoutes(): RouteObject[] {
  if (!cachedRoutes) {
    const paths = new Set<string>(STATIC_TABBED_ROUTES);
    for (const mod of moduleManifests) {
      for (const route of mod.routes) paths.add(route.path);
    }
    cachedRoutes = [...paths].map((path) => ({ path }));
  }
  return cachedRoutes;
}

export function routeTransitionKey(pathname: string): string {
  const clean = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  const alias = TAB_ALIASES[clean];
  if (alias) return alias;

  const matches = matchRoutes(knownRoutes(), clean);
  const leaf = matches?.[matches.length - 1];
  const tab = leaf?.params.tab;
  if (!tab) return clean;

  const suffix = `/${tab}`;
  return clean.endsWith(suffix) ? clean.slice(0, -suffix.length) || '/' : clean;
}
