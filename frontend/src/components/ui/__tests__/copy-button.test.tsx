// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * "Copied" only when the clipboard really took the text.
 *
 * navigator.clipboard is undefined outside a secure context (a FreeSDN opened
 * over plain HTTP on the LAN) and its writeText can be refused. The call
 * sites showed "Copied" without checking either.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CopyButton } from '../copy-button';
import { copyText } from '@/lib/clipboard';

const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
const originalSecure = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
const originalExec = Object.getOwnPropertyDescriptor(document, 'execCommand');

function setClipboard(writeText: ((text: string) => Promise<void>) | undefined) {
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: writeText ? { writeText } : undefined,
  });
}

function setSecure(secure: boolean) {
  Object.defineProperty(window, 'isSecureContext', { configurable: true, value: secure });
}

function setExecCommand(impl: ((command: string) => boolean) | undefined) {
  Object.defineProperty(document, 'execCommand', { configurable: true, writable: true, value: impl });
}

function restore(target: object, key: string, descriptor: PropertyDescriptor | undefined) {
  if (descriptor) Object.defineProperty(target, key, descriptor);
  else delete (target as Record<string, unknown>)[key];
}

beforeEach(() => {
  setSecure(true);
  setExecCommand(undefined);
});

afterEach(() => {
  restore(navigator, 'clipboard', originalClipboard);
  restore(window, 'isSecureContext', originalSecure);
  restore(document, 'execCommand', originalExec);
  vi.useRealTimers();
});

describe('copyText', () => {
  it('uses the Clipboard API when it accepts the text', async () => {
    const writeText = vi.fn(async () => {});
    setClipboard(writeText);
    await expect(copyText('fsdn_key_123')).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('fsdn_key_123');
  });

  it('falls back to execCommand on a plain-HTTP origin', async () => {
    setSecure(false);
    setClipboard(undefined);
    let copied: string | null = null;
    setExecCommand((command) => {
      // What is selected at the moment of the copy is what lands on the clipboard.
      copied = command === 'copy' ? (document.activeElement as HTMLTextAreaElement).value : null;
      return true;
    });
    await expect(copyText('tailscale up --auth-key=tskey-abc')).resolves.toBe(true);
    expect(copied).toBe('tailscale up --auth-key=tskey-abc');
    expect(document.querySelector('textarea')).toBeNull();
  });

  it('falls back when the Clipboard API refuses', async () => {
    setClipboard(async () => {
      throw new DOMException('Write permission denied.', 'NotAllowedError');
    });
    const exec = vi.fn(() => true);
    setExecCommand(exec);
    await expect(copyText('x')).resolves.toBe(true);
    expect(exec).toHaveBeenCalledWith('copy');
  });

  it('reports failure when nothing could copy', async () => {
    setClipboard(async () => {
      throw new DOMException('Write permission denied.', 'NotAllowedError');
    });
    setExecCommand(() => false);
    await expect(copyText('x')).resolves.toBe(false);
  });

  it('reports failure when no clipboard path exists at all', async () => {
    setSecure(false);
    setClipboard(undefined);
    await expect(copyText('x')).resolves.toBe(false);
  });
});

describe('CopyButton', () => {
  // userEvent.setup() installs its own clipboard stub, so each test sets the
  // clipboard after it.
  it('says Copied after a successful write, then resets', async () => {
    const user = userEvent.setup();
    setClipboard(async () => {});
    render(<CopyButton value="fsdn_key_123" />);
    const button = screen.getByRole('button', { name: 'Copy' });
    await user.click(button);
    await waitFor(() => expect(button).toHaveAccessibleName('Copied'));
    expect(button).toHaveAttribute('data-copy-state', 'copied');
    expect(screen.getByRole('status')).toHaveTextContent('Copied');
    await waitFor(() => expect(button).toHaveAccessibleName('Copy'), { timeout: 3000 });
  });

  it('says Copy failed, never Copied, when the write is refused', async () => {
    const user = userEvent.setup();
    setClipboard(async () => {
      throw new DOMException('Write permission denied.', 'NotAllowedError');
    });
    const onCopyResult = vi.fn();
    render(<CopyButton value="secret" label="Copy key" onCopyResult={onCopyResult} />);
    await user.click(screen.getByRole('button', { name: 'Copy key' }));
    const button = await screen.findByRole('button', { name: 'Copy failed' });
    expect(button).toHaveAttribute('data-copy-state', 'failed');
    expect(button).toHaveAttribute(
      'title',
      'Could not copy to the clipboard. Select the text and copy it manually.',
    );
    expect(screen.getByRole('status')).toHaveTextContent('Select the text and copy it manually.');
    expect(screen.queryByText('Copied')).not.toBeInTheDocument();
    expect(onCopyResult).toHaveBeenCalledWith(false);
  });

  it('does not trigger a row click underneath it', async () => {
    const user = userEvent.setup();
    setClipboard(async () => {});
    const onRow = vi.fn();
    render(
      <div onClick={onRow}>
        <CopyButton value="aa:bb:cc:dd:ee:ff" />
      </div>,
    );
    await act(async () => {
      await user.click(screen.getByRole('button', { name: 'Copy' }));
    });
    expect(onRow).not.toHaveBeenCalled();
  });
});
