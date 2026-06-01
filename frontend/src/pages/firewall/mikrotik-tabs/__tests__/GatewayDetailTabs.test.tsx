// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 *, tab-click navigation regression test.
 *
 * The MikroTik gateway detail page uses Radix `<Tabs>` and binds the
 * `value` prop to a `useParams()` segment. Radix only fires
 * `onValueChange` for pointer events its primitive handles internally,
 * so a JS-synthesized `MouseEvent` on a `<TabsTrigger>` does NOT cause
 * `onValueChange` to fire, meaning the URL never updates and the tab
 * content never swaps. The fix attaches an explicit `onClick` on each
 * trigger that calls `navigate(...)` directly, providing a
 * deterministic path for both pointer events and synthesized clicks.
 *
 * This test recreates the same wiring with a minimal component so the
 * behaviour can be exercised without mocking the 100+ API calls the
 * real page makes. The component shape mirrors GatewayDetailPage's
 * MikroTik branch (Tabs value=URL · TabsTrigger with onClick that
 * calls navigate · data-testid="tab-<value>").
 */
import { describe, it, expect } from 'vitest';
import { type MouseEvent, useCallback } from 'react';
import { act, render, screen } from '@testing-library/react';
import {
  MemoryRouter,
  Route,
  Routes,
  useNavigate,
  useParams,
  useLocation,
} from 'react-router-dom';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

function MikroTikTabsHarness() {
  const { id, tab } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const VALID = new Set(['system', 'interfaces', 'ip', 'dhcp', 'firewall']);
  const activeTab = tab && VALID.has(tab) ? tab : 'system';
  const setActiveTab = useCallback(
    (value: string) => navigate(`/firewall/gateways/${id}/${value}`, { replace: true }),
    [id, navigate],
  );
  const tabClick = useCallback(
    (value: string) => (event: MouseEvent<HTMLButtonElement>) => {
      if (event.defaultPrevented) return;
      setActiveTab(value);
    },
    [setActiveTab],
  );
  return (
    <Tabs value={activeTab} onValueChange={setActiveTab}>
      <TabsList>
        <TabsTrigger value="system" data-testid="tab-system" onClick={tabClick('system')}>
          System
        </TabsTrigger>
        <TabsTrigger value="interfaces" data-testid="tab-interfaces" onClick={tabClick('interfaces')}>
          Interfaces
        </TabsTrigger>
        <TabsTrigger value="firewall" data-testid="tab-firewall" onClick={tabClick('firewall')}>
          Firewall
        </TabsTrigger>
      </TabsList>
      <TabsContent value="system">system-content</TabsContent>
      <TabsContent value="interfaces">interfaces-content</TabsContent>
      <TabsContent value="firewall">firewall-content</TabsContent>
    </Tabs>
  );
}

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="loc-pathname">{loc.pathname}</div>;
}

function renderHarness(initialPath: string) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route
          path="/firewall/gateways/:id/:tab?"
          element={
            <>
              <MikroTikTabsHarness />
              <LocationProbe />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe('MikroTik tab click via synthesized MouseEvent', () => {
  it('initial render shows the URL-selected tab content', () => {
    renderHarness('/firewall/gateways/abc/system');
    expect(screen.getByText('system-content')).toBeInTheDocument();
    expect(screen.getByTestId('loc-pathname').textContent).toBe(
      '/firewall/gateways/abc/system',
    );
  });

  it('a JS-synthesized MouseEvent click on a TabsTrigger updates the URL and tab content', () => {
    renderHarness('/firewall/gateways/abc/system');
    // dispatchEvent + MouseEvent, the regression case Radix used to swallow.
    // Wrap in act() because the resulting React state update happens
    // synchronously inside the dispatched listener but must be flushed
    // before we assert.
    const interfacesTab = screen.getByTestId('tab-interfaces');
    act(() => {
      interfacesTab.dispatchEvent(
        new MouseEvent('click', { bubbles: true, cancelable: true }),
      );
    });
    expect(screen.getByTestId('loc-pathname').textContent).toBe(
      '/firewall/gateways/abc/interfaces',
    );
    expect(screen.getByText('interfaces-content')).toBeInTheDocument();
  });

  it('every tab trigger exposes a data-testid for test automation', () => {
    renderHarness('/firewall/gateways/abc/system');
    expect(screen.getByTestId('tab-system')).toBeInTheDocument();
    expect(screen.getByTestId('tab-interfaces')).toBeInTheDocument();
    expect(screen.getByTestId('tab-firewall')).toBeInTheDocument();
  });

  it('a second synthesized click navigates to a third tab', () => {
    renderHarness('/firewall/gateways/abc/system');
    act(() => {
      screen
        .getByTestId('tab-interfaces')
        .dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    });
    act(() => {
      screen
        .getByTestId('tab-firewall')
        .dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    });
    expect(screen.getByTestId('loc-pathname').textContent).toBe(
      '/firewall/gateways/abc/firewall',
    );
    expect(screen.getByText('firewall-content')).toBeInTheDocument();
  });
});
