// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { buildSections, flattenItems } from '../nav-data';

describe('buildSections', () => {
  it('returns at least the 8 known sections', () => {
    const sections = buildSections();
    const ids = sections.map((s) => s.id);
    // Sidebar store declares these 8 SectionIds · every one must have a section
    expect(ids).toContain('overview');
    expect(ids).toContain('network');
    expect(ids).toContain('cameras');
    expect(ids).toContain('voip');
    expect(ids).toContain('infrastructure');
    expect(ids).toContain('operations');
    expect(ids).toContain('automation');
    expect(ids).toContain('administration');
  });

  it('every section has an icon, title, and at least 1 item', () => {
    buildSections().forEach((section) => {
      expect(section.title).toBeTruthy();
      expect(section.icon).toBeTruthy();
      expect(section.items.length).toBeGreaterThan(0);
    });
  });

  it('every nav item has a name, href, and icon', () => {
    const sections = buildSections();
    for (const section of sections) {
      for (const item of section.items) {
        expect(item.name).toBeTruthy();
        expect(item.href).toBeTruthy();
        expect(item.href.startsWith('/')).toBe(true);
        expect(item.icon).toBeTruthy();
      }
    }
  });

  it('all hrefs are unique across the entire nav', () => {
    const allItems = flattenItems(buildSections());
    const hrefs = allItems.map((i) => i.href);
    const unique = new Set(hrefs);
    expect(unique.size).toBe(hrefs.length);
  });

  it('passing an alertCount surfaces it on the alerts item', () => {
    const sections = buildSections(7);
    const allItems = flattenItems(sections);
    const alertsItem = allItems.find((i) => i.href === '/alerts');
    expect(alertsItem).toBeTruthy();
    expect(alertsItem?.badge).toBe(7);
  });

  it('zero alertCount means no badge on alerts item', () => {
    const sections = buildSections(0);
    const allItems = flattenItems(sections);
    const alertsItem = allItems.find((i) => i.href === '/alerts');
    expect(alertsItem?.badge).toBeFalsy();
  });
});

describe('flattenItems', () => {
  it('returns a flat list with sectionId and sectionTitle attached to each item', () => {
    const sections = buildSections();
    const flat = flattenItems(sections);

    // Sample check: dashboard should be in overview section
    const dashboard = flat.find((i) => i.href === '/');
    expect(dashboard).toBeTruthy();
    expect(dashboard?.sectionId).toBe('overview');
    expect(dashboard?.sectionTitle).toBe('Overview');
  });

  it('preserves item count exactly (no duplicates, no drops)', () => {
    const sections = buildSections();
    const totalFromSections = sections.reduce((sum, s) => sum + s.items.length, 0);
    const flatCount = flattenItems(sections).length;
    expect(flatCount).toBe(totalFromSections);
  });

  it('every flattened item has its sectionId set', () => {
    flattenItems(buildSections()).forEach((item) => {
      expect(item.sectionId).toBeTruthy();
      expect(item.sectionTitle).toBeTruthy();
    });
  });
});
