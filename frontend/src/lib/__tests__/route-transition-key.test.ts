// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MainLayout keys its page transition on `routeTransitionKey(pathname)`. When
 * the key was the raw pathname, every URL-driven tab remounted the whole page:
 * clicking "Ports" on a switch faded the page out and in, refetched, and threw
 * away filters, selections and scroll. These tests pin the two halves of the
 * contract: a tab keeps the page's key, a different page or entity changes it.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { routeTransitionKey, STATIC_TABBED_ROUTES } from '@/lib/route-transition-key';

describe('routeTransitionKey: a tab is the same page', () => {
  it.each([
    ['/sites/abc', '/sites/abc/network'],
    ['/controllers/abc', '/controllers/abc/firmware'],
    ['/devices', '/devices/list'],
    ['/devices/dev-1', '/devices/dev-1/ports'],
    ['/switches/sw-1', '/switches/sw-1/ports'],
    ['/access-points/ap-1', '/access-points/ap-1/clients'],
    ['/vpn', '/vpn/tunnels'],
    ['/poe', '/poe/schedules'],
    ['/discovery', '/discovery/agents'],
    ['/firewall/gateways/gw-1', '/firewall/gateways/gw-1/rules'],
    ['/firewall', '/firewall/rules'],
    ['/firewall', '/firewall/ids'],
    ['/firewall/orchestration', '/firewall/orchestration/drift'],
    ['/settings', '/settings/security'],
    ['/cameras', '/cameras/list'],
    ['/cameras/c-1', '/cameras/c-1/ptz'],
    ['/cameras/nvrs/n-1', '/cameras/nvrs/n-1/channels'],
    ['/hypervisor', '/hypervisor/vms'],
    ['/backups', '/backups/schedules'],
    ['/voip/phones/p-1', '/voip/phones/p-1/config'],
    ['/voip/pbx/x-1', '/voip/pbx/x-1/trunks'],
    ['/voip/extensions', '/voip/extensions/ringgroups'],
  ])('%s and %s share a key', (base, tabbed) => {
    expect(routeTransitionKey(tabbed)).toBe(routeTransitionKey(base));
  });

  it('ignores a trailing slash', () => {
    expect(routeTransitionKey('/sites/abc/network/')).toBe('/sites/abc');
  });
});

describe('routeTransitionKey: a different page or entity still remounts', () => {
  it.each([
    ['/devices/dev-1', '/devices/dev-2'],
    ['/switches/sw-1', '/switches/sw-2'],
    ['/sites/abc', '/sites/def'],
    ['/cameras/nvrs/n-1', '/cameras/nvrs/n-2'],
    ['/devices', '/switches'],
    ['/firewall', '/firewall/gateways/gw-1'],
  ])('%s and %s differ', (a, b) => {
    expect(routeTransitionKey(a)).not.toBe(routeTransitionKey(b));
  });

  it('leaves untabbed paths untouched', () => {
    expect(routeTransitionKey('/dashboard')).toBe('/dashboard');
    expect(routeTransitionKey('/')).toBe('/');
  });
});

describe('STATIC_TABBED_ROUTES covers App.tsx', () => {
  it('lists every :tab route declared in App.tsx', () => {
    const source = readFileSync(resolve(__dirname, '../../App.tsx'), 'utf8');
    const tabbed = [...source.matchAll(/path="([^"]*:tab[^"]*)"/g)].map((m) => m[1]);
    expect(tabbed.length).toBeGreaterThan(10);
    for (const path of tabbed) {
      expect(STATIC_TABBED_ROUTES).toContain(path);
    }
  });
});
