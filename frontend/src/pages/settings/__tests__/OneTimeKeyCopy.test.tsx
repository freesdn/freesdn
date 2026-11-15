// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A new API key is shown once. The copy button must say "Copied" only when
 * the clipboard really took the key; when it did not (plain-HTTP origin,
 * permission refused) the dialog says so and keeps saying so, because the
 * key cannot be shown again. The old handler awaited an unchecked
 * navigator.clipboard.writeText, which on plain HTTP threw (no clipboard
 * API at all) and left the operator with no message.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { APIKeysTab } from '../APIKeysTab';
import { api } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() } };
});

const KEY = 'fsdn_live_0123456789abcdef';

const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
const originalSecure = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
const originalExec = Object.getOwnPropertyDescriptor(document, 'execCommand');

function setClipboard(writeText: ((text: string) => Promise<void>) | undefined) {
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: writeText ? { writeText } : undefined,
  });
}

function restore(target: object, key: string, descriptor: PropertyDescriptor | undefined) {
  if (descriptor) Object.defineProperty(target, key, descriptor);
  else delete (target as Record<string, unknown>)[key];
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.get).mockResolvedValue({ data: [] } as never);
  vi.mocked(api.post).mockResolvedValue({
    data: {
      id: 'k-1',
      name: 'CI pipeline',
      key_prefix: 'fsdn_live_01',
      description: null,
      scopes: [],
      last_used: null,
      expires_at: null,
      is_active: true,
      created_at: '2026-11-13T00:00:00Z',
      key: KEY,
    },
  } as never);
  Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true });
  Object.defineProperty(document, 'execCommand', { configurable: true, writable: true, value: undefined });
});

afterEach(() => {
  restore(navigator, 'clipboard', originalClipboard);
  restore(window, 'isSecureContext', originalSecure);
  restore(document, 'execCommand', originalExec);
});

async function createKey(user: ReturnType<typeof userEvent.setup>) {
  renderWithProviders(<APIKeysTab />);
  await user.click(await screen.findByRole('button', { name: 'New API Key' }));
  await user.type(await screen.findByLabelText(/Name/), 'CI pipeline');
  await user.click(screen.getByRole('button', { name: 'Create Key' }));
  await screen.findByText('API Key Created');
  return screen.getByRole('dialog');
}

describe('APIKeysTab one-time key copy', () => {
  it('says the copy failed, keeps the warning up and selects the key, never "Copied"', async () => {
    const user = userEvent.setup();
    const dialog = await createKey(user);
    // userEvent.setup() installs its own clipboard stub; replace it after.
    setClipboard(async () => {
      throw new DOMException('Write permission denied.', 'NotAllowedError');
    });
    Object.defineProperty(document, 'execCommand', { configurable: true, writable: true, value: () => false });

    await user.click(within(dialog).getByRole('button', { name: 'Copy API key' }));

    expect(await within(dialog).findByRole('button', { name: 'Copy failed' })).toBeInTheDocument();
    const warning = within(dialog).getByText(/The key could not be copied to the clipboard\./);
    expect(warning).toHaveAttribute('role', 'alert');
    expect(warning).toHaveTextContent('It cannot be shown again.');
    expect(within(dialog).queryByText('Copied')).not.toBeInTheDocument();
    // The key is focused so Ctrl+C copies it by hand.
    expect(document.activeElement).toBe(within(dialog).getByLabelText('Your new API key'));

    // The button itself resets after a few seconds; the warning must not.
    await waitFor(
      () => expect(within(dialog).getByRole('button', { name: 'Copy API key' })).toBeInTheDocument(),
      { timeout: 5000 },
    );
    expect(within(dialog).getByText(/The key could not be copied/)).toBeInTheDocument();
  }, 10_000);

  it('says Copied only after the clipboard accepted the key, with no warning', async () => {
    const user = userEvent.setup();
    const dialog = await createKey(user);
    const writeText = vi.fn(async () => {});
    setClipboard(writeText);

    await user.click(within(dialog).getByRole('button', { name: 'Copy API key' }));

    expect(await within(dialog).findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith(KEY);
    expect(within(dialog).queryByText(/could not be copied/)).not.toBeInTheDocument();
  });
});
