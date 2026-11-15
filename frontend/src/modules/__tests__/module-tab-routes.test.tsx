// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A tab that lives in the URL must not remount its page.
 *
 * The Cameras, VoIP, Hypervisor and Backup manifests declared a separate
 * `lazy()` for every route of the same page (`/hypervisor` and
 * `/hypervisor/:tab`, `/cameras` and `/cameras/list`, ...). Each `lazy()` is
 * its own component type, so a tab click tore the page down and rebuilt it:
 * a refetch, a loading flash, and lost filters, selection and scroll.
 *
 * These tests render the real module routes (`renderModuleRoutes`) with the
 * page modules replaced by a probe that counts its mounts, and a layout stand
 * in that keys its children the way MainLayout does. A tab change must keep a
 * single mount; a different entity must still get a fresh one.
 */
import { Suspense, useEffect, type ReactNode } from 'react';
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, useLocation, useNavigate, type NavigateFunction } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const probe = vi.hoisted(() => ({
  mounts: {} as Record<string, number>,
  navigate: null as null | ((to: string) => void),
}));

vi.mock('@/components/auth', () => ({
  ProtectedRoute: ({ children }: { children: ReactNode }) => children,
  ModuleGuard: ({ children }: { children: ReactNode }) => children,
}));

vi.mock('@/components/layout', async () => {
  const { useLocation: useLoc } = await import('react-router-dom');
  const { routeTransitionKey } = await import('@/lib/route-transition-key');
  // MainLayout keys the page on routeTransitionKey(pathname); keep that half.
  function MainLayout({ children }: { children: ReactNode }) {
    const location = useLoc();
    return <div key={routeTransitionKey(location.pathname)}>{children}</div>;
  }
  return { MainLayout };
});

function makePage(name: string) {
  return {
    default: function ProbePage() {
      const location = useLocation();
      useEffect(() => {
        probe.mounts[name] = (probe.mounts[name] ?? 0) + 1;
      }, []);
      return <p data-testid="page">{`${name} at ${location.pathname}`}</p>;
    },
  };
}

vi.mock('@/pages/hypervisor/HypervisorPage', () => makePage('hypervisor'));
vi.mock('@/pages/backups/BackupsPage', () => makePage('backups'));
vi.mock('@/pages/cameras/CamerasPage', () => makePage('cameras'));
vi.mock('@/pages/cameras/CameraDetailPage', () => makePage('camera-detail'));
vi.mock('@/pages/cameras/NVRDetailPage', () => makePage('nvr-detail'));
vi.mock('@/pages/voip/PhoneDetailPage', () => makePage('phone-detail'));
vi.mock('@/pages/voip/PBXDetailPage', () => makePage('pbx-detail'));
vi.mock('@/pages/voip/ExtensionsPage', () => makePage('extensions'));

import { renderModuleRoutes } from '../ModuleRoutes';

function NavigateProbe() {
  const navigate: NavigateFunction = useNavigate();
  probe.navigate = (to: string) => {
    void navigate(to, { replace: true });
  };
  return null;
}

async function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <NavigateProbe />
      <Suspense fallback={null}>
        <Routes>{renderModuleRoutes()}</Routes>
      </Suspense>
    </MemoryRouter>,
  );
  await screen.findByText(new RegExp(` at ${path}$`));
}

async function go(path: string) {
  await act(async () => {
    probe.navigate?.(path);
  });
  await screen.findByText(new RegExp(` at ${path}$`));
}

beforeEach(() => {
  probe.mounts = {};
  probe.navigate = null;
});

describe('module tab routes keep the page mounted', () => {
  it.each([
    ['hypervisor', ['/hypervisor', '/hypervisor/vms', '/hypervisor/storage', '/hypervisor']],
    ['backups', ['/backups', '/backups/schedules', '/backups/history', '/backups']],
    ['cameras', ['/cameras', '/cameras/list', '/cameras']],
    ['camera-detail', ['/cameras/c-1', '/cameras/c-1/ptz', '/cameras/c-1/stream', '/cameras/c-1']],
    ['nvr-detail', ['/cameras/nvrs/n-1', '/cameras/nvrs/n-1/channels', '/cameras/nvrs/n-1']],
    ['phone-detail', ['/voip/phones/p-1', '/voip/phones/p-1/config', '/voip/phones/p-1']],
    ['pbx-detail', ['/voip/pbx/x-1', '/voip/pbx/x-1/trunks', '/voip/pbx/x-1']],
    ['extensions', ['/voip/extensions', '/voip/extensions/ringgroups', '/voip/extensions']],
  ])('%s mounts once across its tabs', async (page, paths) => {
    const [first, ...rest] = paths;
    await renderAt(first);
    for (const path of rest) await go(path);
    expect(probe.mounts[page]).toBe(1);
  });

  it('still remounts for a different entity', async () => {
    await renderAt('/cameras/c-1/ptz');
    await go('/cameras/c-2/ptz');
    expect(probe.mounts['camera-detail']).toBe(2);
  });
});
