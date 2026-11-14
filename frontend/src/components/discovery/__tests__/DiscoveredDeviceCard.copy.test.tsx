// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * "Copy IP" in a discovered device's menu reports the real result: a success
 * toast only when the clipboard took the address, an error toast (and no
 * success) when it did not. It used to call navigator.clipboard.writeText
 * without checking it, which on a plain-HTTP FreeSDN does nothing at all.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import DiscoveredDeviceCard from '../DiscoveredDeviceCard';
import { renderWithProviders } from '@/test-utils';

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
  Object.defineProperty(document, 'execCommand', { configurable: true, writable: true, value: undefined });
});

afterEach(() => {
  restore(navigator, 'clipboard', originalClipboard);
  restore(window, 'isSecureContext', originalSecure);
  restore(document, 'execCommand', originalExec);
});

async function copyIpFromMenu(user: ReturnType<typeof userEvent.setup>, container: HTMLElement) {
  const trigger = container.querySelector<HTMLButtonElement>('button[aria-haspopup="menu"]');
  if (!trigger) throw new Error('menu trigger not found');
  await user.click(trigger);
  await user.click(await screen.findByRole('menuitem', { name: 'Copy IP' }));
}

describe('DiscoveredDeviceCard Copy IP', () => {
  it('toasts success only after the clipboard accepted the address', async () => {
    const user = userEvent.setup();
    const { container } = renderWithProviders(<DiscoveredDeviceCard device={{ ip: '10.20.30.40' }} />);
    const writeText = vi.fn(async () => {});
    setClipboard(writeText);

    await copyIpFromMenu(user, container);

    expect(await screen.findByText('IP address copied')).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith('10.20.30.40');
    expect(screen.queryByText('Copy failed')).not.toBeInTheDocument();
  });

  it('shows an error, never a success, on a plain-HTTP origin with no clipboard', async () => {
    const user = userEvent.setup();
    const { container } = renderWithProviders(<DiscoveredDeviceCard device={{ ip: '10.20.30.40' }} />);
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: false });
    setClipboard(undefined);

    await copyIpFromMenu(user, container);

    expect(await screen.findByText('Copy failed')).toBeInTheDocument();
    expect(
      screen.getByText('Could not copy to the clipboard. Select the text and copy it manually.'),
    ).toBeInTheDocument();
    expect(screen.queryByText('IP address copied')).not.toBeInTheDocument();
  });
});
