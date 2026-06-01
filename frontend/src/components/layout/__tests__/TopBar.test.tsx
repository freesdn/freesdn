// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { TopBar } from '../TopBar';

// Stub the API layer so the notifications query doesn't hit the network.
// This file exists only to verify a11y attributes · we don't care about data.
vi.mock('../../../lib/api', () => ({
  api: { get: vi.fn().mockResolvedValue({ data: { notifications: [] } }) },
  notificationApi: {
    list: vi.fn().mockResolvedValue({ data: { items: [], total: 0, unread_count: 0 } }),
    markAllRead: vi.fn().mockResolvedValue({}),
    markRead: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({}),
  },
}));

// Stub the auth store so user menu renders
vi.mock('../../../stores/authStore', () => ({
  useAuthStore: () => ({
    user: { id: 'u1', name: 'Test User', email: 'test@example.com' },
    logout: vi.fn(),
  }),
}));

const renderTopBar = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TopBar connectionStatus="online" />
      </MemoryRouter>
    </QueryClientProvider>
  );
};

describe('TopBar · accessibility', () => {
  beforeEach(() => vi.clearAllMocks());

  it('mobile menu button has aria-label "Open menu"', () => {
    renderTopBar();
    expect(screen.getByLabelText('Open menu')).toBeInTheDocument();
  });

  it('command palette trigger has aria-label "Open command palette"', () => {
    renderTopBar();
    expect(screen.getByLabelText('Open command palette')).toBeInTheDocument();
  });

  it('notifications button has aria-label that includes count', () => {
    renderTopBar();
    // 0 unread → aria-label is just "Notifications"
    expect(screen.getByLabelText('Notifications')).toBeInTheDocument();
  });

  it('user menu trigger has aria-label "User menu"', () => {
    renderTopBar();
    expect(screen.getByLabelText('User menu')).toBeInTheDocument();
  });

  it('connection status indicator has aria-label reflecting state', () => {
    renderTopBar();
    expect(screen.getByLabelText(/connection status: online/i)).toBeInTheDocument();
  });
});
