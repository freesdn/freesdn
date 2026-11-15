// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The account dialogs in the top bar show the backend's own reason.
 *
 * They read ``response.data.detail``, but the backend wraps HTTPException in
 * { error: { message } } (backend/app/core/middleware.py), so an operator who
 * typed the wrong current password saw only "Failed to change password".
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { TopBar } from '../TopBar';

const postCalls = vi.fn();
// A plain closure rather than vi.fn().mockRejectedValue: the rejection must
// be the component's to handle, and nothing else may observe it.
let postResult: () => Promise<unknown> = async () => undefined;

vi.mock('../../../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { notifications: [] } }),
    post: (...args: unknown[]) => {
      postCalls(...args);
      return postResult();
    },
  },
  notificationApi: {
    list: vi.fn().mockResolvedValue({ data: { items: [], total: 0, unread_count: 0 } }),
    markAllRead: vi.fn().mockResolvedValue({}),
    markRead: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock('../../../stores/authStore', () => ({
  useAuthStore: () => ({
    user: { id: 'u1', name: 'Test User', email: 'test@example.com' },
    logout: vi.fn(),
  }),
}));

function renderTopBar() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TopBar connectionStatus="online" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function submitPasswordChange() {
  const user = userEvent.setup();
  renderTopBar();
  await user.click(screen.getByLabelText('User menu'));
  await user.click(await screen.findByText('Change Password'));
  await user.type(screen.getByLabelText('Current Password'), 'old-password');
  await user.type(screen.getByLabelText('New Password'), 'new-password-1');
  await user.type(screen.getByLabelText('Confirm New Password'), 'new-password-1');
  await user.click(screen.getByRole('button', { name: /change password/i }));
}

function rejectWith(response: unknown) {
  postResult = async () => {
    throw Object.assign(new Error('Request failed'), { response });
  };
}

describe('TopBar account dialogs: server errors', () => {
  beforeEach(() => {
    postCalls.mockReset();
    postResult = async () => undefined;
  });

  it("shows the backend's envelope message", async () => {
    rejectWith({
      status: 400,
      data: { error: { code: 400, message: 'Current password is incorrect', request_id: 'req-1' } },
    });
    await submitPasswordChange();
    expect(await screen.findByText('Current password is incorrect')).toBeInTheDocument();
    expect(screen.queryByText('Failed to change password')).not.toBeInTheDocument();
    expect(postCalls).toHaveBeenCalledWith('/auth/password', {
      current_password: 'old-password',
      new_password: 'new-password-1',
    });
  });

  it('keeps the dialog fallback when the body carries no message', async () => {
    rejectWith({ status: 500, data: {} });
    await submitPasswordChange();
    expect(await screen.findByText('Failed to change password')).toBeInTheDocument();
  });
});
