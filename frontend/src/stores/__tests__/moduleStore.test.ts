// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, beforeEach } from 'vitest';
import { useModuleStore, type ModuleManifest, type OrgModule } from '../moduleStore';

const mkManifest = (id: string, category = 'network'): ModuleManifest => ({
  id,
  name: id,
  version: '1.0.0',
  description: `${id} module`,
  category,
  icon: 'box',
  color: '#000',
  is_core: false,
  is_beta: false,
  is_premium: false,
  capabilities: [],
  device_types: [],
  dependencies: [],
  permissions: [],
  nav_items: [],
  widgets: [],
  author: 'test',
  license: 'MIT',
});

describe('useModuleStore', () => {
  beforeEach(() => {
    useModuleStore.setState({
      modules: [],
      moduleStates: [],
      enabledModules: [],
      orgModules: [],
      navigationItems: [],
      isLoaded: false,
      isLoading: false,
      error: null,
    });
  });

  it('starts empty', () => {
    const s = useModuleStore.getState();
    expect(s.modules).toEqual([]);
    expect(s.enabledModules).toEqual([]);
    expect(s.isLoaded).toBe(false);
  });

  it('setModules() stores manifests', () => {
    const m = [mkManifest('cameras'), mkManifest('voip')];
    useModuleStore.getState().setModules(m);
    expect(useModuleStore.getState().modules).toHaveLength(2);
  });

  it('setOrgModules() derives enabledModules from is_enabled flag', () => {
    const orgModules: OrgModule[] = [
      { module_id: 'cameras', is_enabled: true, settings: {} },
      { module_id: 'voip', is_enabled: false, settings: {} },
      { module_id: 'firewall', is_enabled: true, settings: {} },
    ];
    useModuleStore.getState().setOrgModules(orgModules);
    expect(useModuleStore.getState().enabledModules).toEqual(['cameras', 'firewall']);
  });

  it('isModuleEnabled() reflects current enabled set', () => {
    useModuleStore.getState().setEnabledModules(['cameras']);
    expect(useModuleStore.getState().isModuleEnabled('cameras')).toBe(true);
    expect(useModuleStore.getState().isModuleEnabled('voip')).toBe(false);
  });

  it('getModule() returns the matching manifest', () => {
    useModuleStore.getState().setModules([mkManifest('cameras'), mkManifest('voip')]);
    expect(useModuleStore.getState().getModule('voip')?.id).toBe('voip');
    expect(useModuleStore.getState().getModule('does-not-exist')).toBeUndefined();
  });

  it('getEnabledModuleManifests() intersects modules + enabled', () => {
    useModuleStore.getState().setModules([
      mkManifest('cameras'),
      mkManifest('voip'),
      mkManifest('firewall'),
    ]);
    useModuleStore.getState().setEnabledModules(['cameras', 'firewall']);
    const enabled = useModuleStore.getState().getEnabledModuleManifests();
    expect(enabled).toHaveLength(2);
    expect(enabled.map((m) => m.id).sort()).toEqual(['cameras', 'firewall']);
  });

  it('getModulesByCategory() groups by category, defaulting to "other"', () => {
    useModuleStore.getState().setModules([
      mkManifest('cameras', 'video'),
      mkManifest('nvr', 'video'),
      mkManifest('voip', 'comms'),
      { ...mkManifest('weird'), category: '' as unknown as string }, // missing → 'other'
    ]);
    const grouped = useModuleStore.getState().getModulesByCategory();
    expect(grouped.video).toHaveLength(2);
    expect(grouped.comms).toHaveLength(1);
    expect(grouped.other).toHaveLength(1);
  });

  it('markLoaded() flips isLoaded + isLoading', () => {
    useModuleStore.getState().setLoading(true);
    expect(useModuleStore.getState().isLoading).toBe(true);
    useModuleStore.getState().markLoaded();
    expect(useModuleStore.getState().isLoaded).toBe(true);
    expect(useModuleStore.getState().isLoading).toBe(false);
  });

  it('setError() persists an error message', () => {
    useModuleStore.getState().setError('Module load failed');
    expect(useModuleStore.getState().error).toBe('Module load failed');
    useModuleStore.getState().setError(null);
    expect(useModuleStore.getState().error).toBeNull();
  });
});
