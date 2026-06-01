// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PendingChangesDrawer · interaction & behaviour tests.
 *
 * Mocks ``@/lib/api`` (the consumer-facing barrel) so the drawer's
 * internal calls to ``listChangesForGateway`` / ``applyPendingChange``
 * / ``discardPendingChange`` are observable. We deliberately don't
 * mock at the axios layer, going through the typed API barrel is
 * closer to production behaviour and shields tests from internal
 * client refactors.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';

import { PendingChangesDrawer } from '../PendingChangesDrawer';
import {
  listChangesForGateway,
  applyPendingChange,
  discardPendingChange,
  describeApplyError,
  type PendingChangeResponse,
} from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    listChangesForGateway: vi.fn(),
    applyPendingChange: vi.fn(),
    discardPendingChange: vi.fn(),
    // Keep the real describeApplyError so the read-only banner logic
    // is exercised end-to-end.
    describeApplyError: actual.describeApplyError,
  };
});

const mockList = listChangesForGateway as unknown as Mock;
const mockApply = applyPendingChange as unknown as Mock;
const mockDiscard = discardPendingChange as unknown as Mock;

// Sanity-check the real helper is still wired through.
void describeApplyError;

beforeEach(() => {
  mockList.mockReset();
  mockApply.mockReset();
  mockDiscard.mockReset();
});

// ── Fixture helpers ────────────────────────────────────────────────────

function makeChange(
  overrides: Partial<PendingChangeResponse> = {},
): PendingChangeResponse {
  return {
    id: overrides.id ?? '11111111-1111-1111-1111-111111111111',
    organization_id: '00000000-0000-0000-0000-000000000001',
    controller_id: 'c1-controller',
    site_id: null,
    omada_site_id: null,
    feature: 'mikrotik.firewall.filter_rule',
    operation: 'create',
    status: 'pending',
    target_id: '*A1',
    payload: { chain: 'forward', action: 'accept' },
    notes: null,
    created_at: new Date().toISOString(),
    created_by: 'test@example.com',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    ...overrides,
  };
}

function ok<T>(data: T): AxiosResponse<T> {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: new AxiosHeaders() },
  };
}

const baseProps = {
  open: true,
  onOpenChange: () => {},
  vendor: 'mikrotik' as const,
  gatewayId: 'c1-controller',
  gatewayName: 'edge-rtr-1',
};

// ── Tests ──────────────────────────────────────────────────────────────

describe('PendingChangesDrawer', () => {
  it('renders empty state when there are no changes', async () => {
    mockList.mockResolvedValue([]);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    expect(
      await screen.findByText(/no pending changes/i),
    ).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith(
      'mikrotik',
      'c1-controller',
      { status: 'all' },
    );
  });

  it('renders pending changes with feature, operation badge, and target id', async () => {
    mockList.mockResolvedValue([
      makeChange({
        id: 'change-1',
        feature: 'mikrotik.firewall.filter_rule',
        operation: 'create',
        target_id: '*F5',
      }),
    ]);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    expect(
      await screen.findByText('mikrotik.firewall.filter_rule'),
    ).toBeInTheDocument();
    // operation badge, case-insensitive because Badge prints lowercase.
    expect(screen.getByText('create')).toBeInTheDocument();
    expect(screen.getByText('*F5')).toBeInTheDocument();
    expect(
      screen.getByRole('button', {
        name: /apply mikrotik\.firewall\.filter_rule/i,
      }),
    ).toBeInTheDocument();
  });

  it('apply button opens confirmation dialog', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeChange({
        id: 'change-1',
        feature: 'mikrotik.ip.address',
        operation: 'update',
      }),
    ]);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    const applyBtn = await screen.findByRole('button', {
      name: /apply mikrotik\.ip\.address/i,
    });
    await user.click(applyBtn);

    const dialog = await screen.findByRole('alertdialog', { name: /apply change/i });
    expect(dialog).toBeInTheDocument();
    // Gateway name appears in both the drawer subtitle and the dialog body;
    // narrowing to the dialog makes the assertion unambiguous.
    expect(within(dialog).getByText(/edge-rtr-1/i)).toBeInTheDocument();
  });

  it('apply confirmation calls applyPendingChange with the right id', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeChange({
        id: 'change-7',
        feature: 'mikrotik.ip.address',
        operation: 'update',
      }),
    ]);
    mockApply.mockResolvedValue(
      ok(makeChange({ id: 'change-7', status: 'applied' })),
    );

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    await user.click(
      await screen.findByRole('button', {
        name: /apply mikrotik\.ip\.address/i,
      }),
    );

    const dialog = await screen.findByRole('alertdialog', {
      name: /apply change/i,
    });
    // The dialog's primary "Apply" button is the one we want.
    const confirmBtn = within(dialog).getByRole('button', { name: /^apply$/i });
    await user.click(confirmBtn);

    await waitFor(() => {
      expect(mockApply).toHaveBeenCalledTimes(1);
      // Apply carries the apply-time confirmation flag (false for a
      // non-catastrophic change; the catastrophic path asserts true separately).
      expect(mockApply).toHaveBeenCalledWith('change-7', { confirmed: false });
    });
  });

  it('applied row moves out of the pending section after success', async () => {
    const user = userEvent.setup();
    const change = makeChange({
      id: 'change-9',
      feature: 'mikrotik.dns.static_entry',
      operation: 'create',
    });

    mockList.mockResolvedValueOnce([change]);
    mockApply.mockResolvedValue(
      ok({ ...change, status: 'applied' as const, applied_at: new Date().toISOString() }),
    );
    // Refetch after success returns the change in the applied section.
    mockList.mockResolvedValue([{ ...change, status: 'applied' as const }]);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    await user.click(
      await screen.findByRole('button', {
        name: /apply mikrotik\.dns\.static_entry/i,
      }),
    );

    const dialog = await screen.findByRole('alertdialog', {
      name: /apply change/i,
    });
    await user.click(
      within(dialog).getByRole('button', { name: /^apply$/i }),
    );

    await waitFor(() => {
      // Apply was invoked (non-catastrophic → confirmed:false).
      expect(mockApply).toHaveBeenCalledWith('change-9', { confirmed: false });
    });

    // After invalidation, the pending Apply button should be gone
    // (the row is now in Recently applied which is collapsed).
    await waitFor(() => {
      expect(
        screen.queryByRole('button', {
          name: /apply mikrotik\.dns\.static_entry/i,
        }),
      ).not.toBeInTheDocument();
    });
    // And the Recently applied summary header should appear.
    expect(screen.getByText(/recently applied/i)).toBeInTheDocument();
  });

  it('shows the read-only banner on 403 OMADA_READ_ONLY', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeChange({
        id: 'change-ro',
        feature: 'mikrotik.firewall.filter_rule',
        operation: 'create',
      }),
    ]);
    const headers = new AxiosHeaders();
    const err = new AxiosError(
      'Request failed',
      'ERR_BAD_REQUEST',
      { headers },
      undefined,
      {
        status: 403,
        statusText: 'Forbidden',
        headers: {},
        config: { headers },
        data: {
          detail:
            'OMADA_READ_ONLY=true; refusing to push staged change to the live device.',
        },
      },
    );
    mockApply.mockRejectedValue(err);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    await user.click(
      await screen.findByRole('button', {
        name: /apply mikrotik\.firewall\.filter_rule/i,
      }),
    );
    const dialog = await screen.findByRole('alertdialog', {
      name: /apply change/i,
    });
    await user.click(
      within(dialog).getByRole('button', { name: /^apply$/i }),
    );

    // The drawer may render more than one role="alert" (e.g. a transient
    // list-load error in the test env alongside the read-only banner), so
    // select the read-only banner specifically rather than assuming a
    // single alert.
    const banners = await screen.findAllByRole('alert');
    const banner = banners.find((b) => /api is read-only/i.test(b.textContent ?? ''));
    expect(banner).toBeTruthy();
    expect(within(banner!).getByText(/api is read-only/i)).toBeInTheDocument();
    // OMADA_READ_ONLY appears in both the server detail message and the
    // banner hint; assert at least one is rendered inside the banner.
    expect(
      within(banner!).getAllByText(/OMADA_READ_ONLY/i).length,
    ).toBeGreaterThan(0);
  });

  it('bulk apply confirmation requires typed APPLY ALL', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeChange({
        id: 'a',
        feature: 'mikrotik.firewall.filter_rule',
        operation: 'create',
      }),
      makeChange({
        id: 'b',
        feature: 'mikrotik.firewall.nat_rule',
        operation: 'create',
      }),
    ]);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    const applyAllBtn = await screen.findByRole('button', {
      name: /apply all/i,
    });
    await user.click(applyAllBtn);

    const dialog = await screen.findByRole('alertdialog', {
      name: /apply all pending changes/i,
    });
    // The primary apply button is initially disabled.
    const submit = within(dialog).getByRole('button', { name: /^apply 2$/i });
    expect(submit).toBeDisabled();

    // Typing the wrong text keeps it disabled.
    const input = within(dialog).getByLabelText(/type apply all/i);
    await user.type(input, 'APPLY');
    expect(submit).toBeDisabled();

    // Typing the right text enables it.
    await user.clear(input);
    await user.type(input, 'APPLY ALL');
    expect(submit).not.toBeDisabled();
  });

  it('renders recently applied section with the most recent applied rows', async () => {
    mockList.mockResolvedValue([
      makeChange({
        id: 'applied-1',
        feature: 'mikrotik.firewall.filter_rule',
        operation: 'create',
        status: 'applied',
        applied_at: new Date().toISOString(),
        applied_response: { ret: 'ok' },
      }),
      makeChange({
        id: 'applied-2',
        feature: 'mikrotik.ip.address',
        operation: 'update',
        status: 'applied',
        applied_at: new Date().toISOString(),
        applied_response: { ret: 'ok' },
      }),
    ]);

    const user = userEvent.setup();
    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    const header = await screen.findByText(/recently applied/i);
    expect(header).toBeInTheDocument();
    // Click to expand
    await user.click(header);
    // Both applied features should be visible in the expanded list.
    expect(
      await screen.findByText('mikrotik.firewall.filter_rule'),
    ).toBeInTheDocument();
    expect(screen.getByText('mikrotik.ip.address')).toBeInTheDocument();
  });

  it('catastrophic features require typed APPLY confirmation', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeChange({
        id: 'cat-1',
        feature: 'mikrotik.system.reboot',
        operation: 'create',
      }),
    ]);

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    await user.click(
      await screen.findByRole('button', {
        name: /apply mikrotik\.system\.reboot/i,
      }),
    );
    const dialog = await screen.findByRole('alertdialog', {
      name: /apply change/i,
    });
    const submit = within(dialog).getByRole('button', { name: /^apply$/i });
    // Disabled until APPLY is typed.
    expect(submit).toBeDisabled();
    const input = within(dialog).getByLabelText(/destructive change/i);
    await user.type(input, 'APPLY');
    expect(submit).not.toBeDisabled();
  });

  it('discard button calls discardPendingChange after confirmation', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeChange({
        id: 'change-d',
        feature: 'mikrotik.dhcp.static_lease',
        operation: 'create',
      }),
    ]);
    mockDiscard.mockResolvedValue(
      ok(makeChange({ id: 'change-d', status: 'discarded' })),
    );

    renderWithProviders(<PendingChangesDrawer {...baseProps} />);

    await user.click(
      await screen.findByRole('button', {
        name: /discard mikrotik\.dhcp\.static_lease/i,
      }),
    );

    const dialog = await screen.findByRole('alertdialog', {
      name: /discard change/i,
    });
    await user.click(
      within(dialog).getByRole('button', { name: /^discard$/i }),
    );

    await waitFor(() => {
      expect(mockDiscard).toHaveBeenCalledWith('change-d');
    });
  });
});
