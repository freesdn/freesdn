// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * `/gateway` has sub-pages (`/gateway/vpn`, `/gateway/pending`, ...) but no
 * page of its own, so it fell through to the catch-all and showed the
 * Dashboard. It now redirects to the firewall gateways page, the way
 * `/devices/new` redirects to Discovery. The real App routes; auth, modules
 * and pages are stand-ins.
 */
import type { ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@/stores/authStore', async () => {
  const actual = await vi.importActual<typeof import('@/stores/authStore')>('@/stores/authStore');
  return { ...actual, useInitAuth: () => ({ initAuth: () => {} }) };
});
vi.mock('@/hooks/useWebSocket', () => ({ useWebSocket: () => {} }));
vi.mock('@/hooks/useModules', () => ({ useModulesInit: () => {} }));
vi.mock('@/components/auth', () => {
  const Stub = () => null;
  return {
    ProtectedRoute: ({ children }: { children: ReactNode }) => children,
    LoginPage: Stub, RegisterPage: Stub, ForgotPasswordPage: Stub, UnauthorizedPage: Stub,
  };
});
vi.mock('@/components/layout', () => ({ MainLayout: ({ children }: { children: ReactNode }) => children }));
vi.mock('@/pages/dashboard/DashboardPage', () => ({ default: () => <p>Dashboard page</p> }));
vi.mock('@/modules/ModuleRoutes', async () => {
  const { Route } = await import('react-router-dom');
  return { renderModuleRoutes: () => [<Route key="fw" path="/firewall/*" element={<p>Firewall page</p>} />] };
});

import App from '@/App';

function Where() {
  return <output aria-label="location">{useLocation().pathname}</output>;
}

describe('/gateway', () => {
  it('redirects to the firewall gateways page, not the Dashboard', async () => {
    render(
      <MemoryRouter initialEntries={['/gateway']}>
        <App />
        <Where />
      </MemoryRouter>,
    );

    expect(await screen.findByText('Firewall page')).toBeInTheDocument();
    expect(screen.getByLabelText('location')).toHaveTextContent('/firewall/gateways');
    expect(screen.queryByText('Dashboard page')).toBeNull();
  });
});
