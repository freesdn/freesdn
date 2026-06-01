// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, beforeEach } from 'vitest';
import {
  useSidebarStore,
  useUIPaletteStore,
  RECENT_VISIBILITY_THRESHOLD,
  type SectionId,
} from '../sidebarStore';

describe('useSidebarStore', () => {
  beforeEach(() => {
    // Reset store to defaults · must also clear the internal `recentRoutesV2`
    // field that trackVisit() reads from, not just the public `recentRoutes`.
    useSidebarStore.setState({
      sections: {
        overview: true,
        network: true,
        cameras: true,
        voip: true,
        infrastructure: true,
        operations: true,
        automation: true,
        administration: true,
      },
      recentRoutes: [],
      // @ts-expect-error · internal field not in public type
      recentRoutesV2: [],
    });
  });

  it('starts with all sections expanded by default', () => {
    const sections = useSidebarStore.getState().sections;
    Object.values(sections).forEach((v) => expect(v).toBe(true));
  });

  it('toggleSection() flips a single section', () => {
    useSidebarStore.getState().toggleSection('network');
    expect(useSidebarStore.getState().sections.network).toBe(false);
    useSidebarStore.getState().toggleSection('network');
    expect(useSidebarStore.getState().sections.network).toBe(true);
  });

  it('toggleSection() leaves other sections untouched', () => {
    useSidebarStore.getState().toggleSection('cameras');
    expect(useSidebarStore.getState().sections.cameras).toBe(false);
    expect(useSidebarStore.getState().sections.network).toBe(true);
    expect(useSidebarStore.getState().sections.voip).toBe(true);
  });

  it('expandSection() forces a section open', () => {
    useSidebarStore.getState().toggleSection('voip'); // close it
    expect(useSidebarStore.getState().sections.voip).toBe(false);
    useSidebarStore.getState().expandSection('voip');
    expect(useSidebarStore.getState().sections.voip).toBe(true);
    // Idempotent
    useSidebarStore.getState().expandSection('voip');
    expect(useSidebarStore.getState().sections.voip).toBe(true);
  });

  it('setAllSections(false) collapses everything', () => {
    useSidebarStore.getState().setAllSections(false);
    Object.values(useSidebarStore.getState().sections).forEach((v) => expect(v).toBe(false));
  });

  it('setAllSections(true) re-expands everything', () => {
    useSidebarStore.getState().setAllSections(false);
    useSidebarStore.getState().setAllSections(true);
    Object.values(useSidebarStore.getState().sections).forEach((v) => expect(v).toBe(true));
  });

  it('trackVisit() records routes most-recent-first', () => {
    useSidebarStore.getState().trackVisit('/devices', 'Devices');
    useSidebarStore.getState().trackVisit('/cameras', 'Cameras');
    expect(useSidebarStore.getState().recentRoutes).toEqual(['/cameras', '/devices']);
  });

  it('trackVisit() de-duplicates: revisiting moves to front', () => {
    useSidebarStore.getState().trackVisit('/a', 'A');
    useSidebarStore.getState().trackVisit('/b', 'B');
    useSidebarStore.getState().trackVisit('/a', 'A');
    expect(useSidebarStore.getState().recentRoutes).toEqual(['/a', '/b']);
  });

  it('trackVisit() caps history at 10 entries', () => {
    for (let i = 0; i < 15; i++) {
      useSidebarStore.getState().trackVisit(`/route-${i}`, `Route ${i}`);
    }
    expect(useSidebarStore.getState().recentRoutes).toHaveLength(10);
    expect(useSidebarStore.getState().recentRoutes[0]).toBe('/route-14');
  });

  it('exposes RECENT_VISIBILITY_THRESHOLD constant', () => {
    expect(RECENT_VISIBILITY_THRESHOLD).toBeGreaterThan(0);
  });

  it('handles all 8 section ids without throwing', () => {
    const ids: SectionId[] = [
      'overview', 'network', 'cameras', 'voip',
      'infrastructure', 'operations', 'automation', 'administration',
    ];
    ids.forEach((id) => {
      useSidebarStore.getState().toggleSection(id);
      expect(useSidebarStore.getState().sections[id]).toBe(false);
    });
  });
});

describe('useUIPaletteStore', () => {
  beforeEach(() => {
    useUIPaletteStore.setState({ commandPaletteOpen: false, shortcutsOpen: false });
  });

  it('command palette starts closed', () => {
    expect(useUIPaletteStore.getState().commandPaletteOpen).toBe(false);
  });

  it('toggleCommandPalette() flips open/closed', () => {
    useUIPaletteStore.getState().toggleCommandPalette();
    expect(useUIPaletteStore.getState().commandPaletteOpen).toBe(true);
    useUIPaletteStore.getState().toggleCommandPalette();
    expect(useUIPaletteStore.getState().commandPaletteOpen).toBe(false);
  });

  it('setCommandPaletteOpen() sets explicit state', () => {
    useUIPaletteStore.getState().setCommandPaletteOpen(true);
    expect(useUIPaletteStore.getState().commandPaletteOpen).toBe(true);
    useUIPaletteStore.getState().setCommandPaletteOpen(false);
    expect(useUIPaletteStore.getState().commandPaletteOpen).toBe(false);
  });

  it('openShortcuts() opens the shortcuts dialog', () => {
    useUIPaletteStore.getState().openShortcuts();
    expect(useUIPaletteStore.getState().shortcutsOpen).toBe(true);
  });

  it('shortcuts and command palette are independent', () => {
    useUIPaletteStore.getState().toggleCommandPalette();
    useUIPaletteStore.getState().openShortcuts();
    expect(useUIPaletteStore.getState().commandPaletteOpen).toBe(true);
    expect(useUIPaletteStore.getState().shortcutsOpen).toBe(true);
  });
});
