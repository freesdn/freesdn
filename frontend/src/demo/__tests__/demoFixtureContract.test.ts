// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The demo fixtures are a stand-in for real API responses, so their field
 * names are a contract with the components that read them. Nothing enforced
 * that contract, and demo.freesdn.org is the first thing most people see.
 *
 * Two defects shipped because of it, both on the dashboard, the landing screen:
 *
 * 1. "Devices 0/8 Online" with seven of eight devices up.
 *    `dashboardSummary` exposed online_devices / offline_devices /
 *    warning_devices. The backend's DashboardSummaryResponse
 *    (app/schemas/analytics.py) calls them devices_online / devices_offline /
 *    devices_warning, and that is what DashboardPage reads. Every lookup missed
 *    and fell back to `?? 0`.
 *
 * 2. Every site painted red, and "/42 devices online" with no numerator.
 *    The site fixtures had device_count but no online_device_count. The health
 *    chain computed `undefined / 42` = NaN, and NaN fails both `>= 1` and
 *    `>= 0.5`, so all three sites fell through to 'critical'.
 *
 * The `?? 0` fallbacks are why neither failed loudly: a missing field renders
 * as a confident zero.
 */

import { describe, expect, it } from 'vitest';

import { dashboardSummary, devices, sites } from '../fixtures';

describe('demo dashboard summary matches the backend field names', () => {
  // Mirrors DashboardSummaryResponse in app/schemas/analytics.py. If the
  // backend renames one of these, this test should be updated with it -- that
  // is the point of pinning them.
  const REQUIRED = [
    'total_devices',
    'devices_online',
    'devices_offline',
    'devices_warning',
    'total_sites',
  ] as const;

  it.each(REQUIRED)('exposes %s', (field) => {
    expect(dashboardSummary).toHaveProperty(field);
    expect(typeof (dashboardSummary as Record<string, unknown>)[field]).toBe('number');
  });

  it('does not carry the old reversed names', () => {
    // The exact shape that produced "0/8 Online".
    for (const stale of ['online_devices', 'offline_devices', 'warning_devices']) {
      expect(dashboardSummary).not.toHaveProperty(stale);
    }
  });

  it('reports the online count the device list actually supports', () => {
    const online = devices.filter((d) => d.status === 'online').length;
    expect(dashboardSummary.devices_online).toBe(online);
    // Guard the regression directly: the bug rendered 0 while devices were up.
    expect(dashboardSummary.devices_online).toBeGreaterThan(0);
    expect(dashboardSummary.total_devices).toBe(devices.length);
  });
});

describe('demo sites can be scored for health', () => {
  it('every site reports how many of its devices are online', () => {
    expect(sites.length).toBeGreaterThan(0);
    for (const site of sites) {
      expect(
        typeof (site as { online_device_count?: number }).online_device_count,
        `${site.name} has no online_device_count, so its health scores as NaN`,
      ).toBe('number');
    }
  });

  it('the online count never exceeds the device count', () => {
    for (const site of sites) {
      const s = site as { name: string; device_count: number; online_device_count: number };
      expect(s.online_device_count).toBeLessThanOrEqual(s.device_count);
      expect(s.online_device_count).toBeGreaterThanOrEqual(0);
    }
  });

  it('scores as healthy or degraded, never critical, on the demo data', () => {
    /**
     * The exact chain DashboardPage runs. Reproduced rather than imported
     * because it is inline in the component; if it moves to a helper, import
     * it here instead.
     */
    const score = (deviceCount: number, onlineCount: number | undefined) => {
      const hasCount = typeof onlineCount === 'number' && Number.isFinite(onlineCount);
      const ratio = hasCount && deviceCount > 0 ? onlineCount / deviceCount : NaN;
      if (deviceCount === 0 || !hasCount) return 'unknown';
      return ratio >= 1 ? 'healthy' : ratio >= 0.5 ? 'degraded' : 'critical';
    };

    for (const site of sites) {
      const s = site as { name: string; device_count: number; online_device_count: number };
      expect(score(s.device_count, s.online_device_count), s.name).not.toBe('critical');
      expect(score(s.device_count, s.online_device_count), s.name).not.toBe('unknown');
    }
  });

  it('an absent count scores unknown, not critical', () => {
    // The fix that matters beyond the demo: a real API response missing the
    // field must not paint a healthy site red. Unknown is not critical.
    const score = (deviceCount: number, onlineCount: number | undefined) => {
      const hasCount = typeof onlineCount === 'number' && Number.isFinite(onlineCount);
      const ratio = hasCount && deviceCount > 0 ? onlineCount / deviceCount : NaN;
      if (deviceCount === 0 || !hasCount) return 'unknown';
      return ratio >= 1 ? 'healthy' : ratio >= 0.5 ? 'degraded' : 'critical';
    };

    expect(score(42, undefined)).toBe('unknown');
    expect(score(42, NaN)).toBe('unknown');
    expect(score(42, 42)).toBe('healthy');
    expect(score(42, 30)).toBe('degraded');
    expect(score(42, 3)).toBe('critical');
  });
});
