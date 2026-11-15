// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConfirmProvider, useConfirm, type ConfirmOptions } from '../confirm-dialog';

function Harness({ options, second }: { options: ConfirmOptions; second?: ConfirmOptions }) {
  const confirm = useConfirm();
  const [results, setResults] = useState<string[]>([]);
  const ask = (opts: ConfirmOptions, tag: string) => {
    void confirm(opts).then((ok) => setResults((r) => [...r, `${tag}:${ok}`]));
  };
  return (
    <>
      <button type="button" onClick={() => ask(options, 'first')}>
        ask
      </button>
      {second && (
        <button type="button" onClick={() => ask(second, 'second')}>
          ask again
        </button>
      )}
      <output data-testid="results">{results.join(',')}</output>
    </>
  );
}

function renderWithProvider(options: ConfirmOptions, second?: ConfirmOptions) {
  return render(
    <ConfirmProvider>
      <Harness options={options} second={second} />
    </ConfirmProvider>,
  );
}

const results = () => screen.getByTestId('results').textContent;

const bulkDelete: ConfirmOptions = {
  title: 'Delete VLANs',
  description: 'They are removed from every switch at this site.',
  count: 7,
  items: ['10 mgmt', '20 voice', '30 cameras', '40 guests', '50 iot', '60 lab', '70 dmz'],
  confirmLabel: 'Delete VLANs',
  destructive: true,
};

describe('useConfirm with ConfirmProvider', () => {
  it('says what will happen, how many items it affects and which', async () => {
    const user = userEvent.setup();
    renderWithProvider(bulkDelete);
    await user.click(screen.getByRole('button', { name: 'ask' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Delete VLANs', { selector: 'h2' })).toBeInTheDocument();
    expect(within(dialog).getByText('They are removed from every switch at this site.')).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 7 items.')).toBeInTheDocument();
    const list = within(dialog).getByRole('list', { name: 'Affected items' });
    expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      '10 mgmt',
      '20 voice',
      '30 cameras',
      '40 guests',
      '50 iot',
    ]);
    expect(within(dialog).getByText('and 2 more')).toBeInTheDocument();
  });

  it('uses the singular for one item', async () => {
    const user = userEvent.setup();
    renderWithProvider({ title: 'Delete VLAN', count: 1, destructive: true });
    await user.click(screen.getByRole('button', { name: 'ask' }));
    expect(await screen.findByText('This affects 1 item.')).toBeInTheDocument();
  });

  it('styles a destructive action and focuses Cancel first', async () => {
    const user = userEvent.setup();
    renderWithProvider(bulkDelete);
    await user.click(screen.getByRole('button', { name: 'ask' }));
    const dialog = await screen.findByRole('alertdialog');
    const action = within(dialog).getByRole('button', { name: 'Delete VLANs' });
    expect(action.className).toMatch(/bg-destructive/);
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Cancel' })).toHaveFocus());
  });

  it('uses the primary style for a non-destructive action', async () => {
    const user = userEvent.setup();
    renderWithProvider({ title: 'Approve agent', confirmLabel: 'Approve' });
    await user.click(screen.getByRole('button', { name: 'ask' }));
    const action = await screen.findByRole('button', { name: 'Approve' });
    expect(action.className).toMatch(/bg-primary/);
    expect(action.className).not.toMatch(/bg-destructive/);
  });

  it('resolves true on confirm and false on cancel', async () => {
    const user = userEvent.setup();
    renderWithProvider(bulkDelete);
    await user.click(screen.getByRole('button', { name: 'ask' }));
    await user.click(await screen.findByRole('button', { name: 'Delete VLANs' }));
    await waitFor(() => expect(results()).toBe('first:true'));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'ask' }));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(results()).toBe('first:true,first:false'));
  });

  it('resolves false on Escape', async () => {
    const user = userEvent.setup();
    renderWithProvider(bulkDelete);
    await user.click(screen.getByRole('button', { name: 'ask' }));
    await screen.findByRole('alertdialog');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(results()).toBe('first:false'));
  });

  it('keeps confirm disabled until the confirmation text is typed', async () => {
    const user = userEvent.setup();
    renderWithProvider({
      title: 'Delete organization',
      description: 'Every site, device and user in it is removed.',
      confirmLabel: 'Delete organization',
      destructive: true,
      confirmationText: 'acme-west',
    });
    await user.click(screen.getByRole('button', { name: 'ask' }));
    const action = await screen.findByRole('button', { name: 'Delete organization' });
    expect(action).toBeDisabled();
    const field = screen.getByLabelText('Type acme-west to confirm');
    await waitFor(() => expect(field).toHaveFocus());
    await user.type(field, 'acme-wes');
    expect(action).toBeDisabled();
    await user.type(field, 't');
    expect(action).toBeEnabled();
    await user.click(action);
    await waitFor(() => expect(results()).toBe('first:true'));
  });

  it('answers an open request with false when a newer one replaces it', async () => {
    const user = userEvent.setup();
    renderWithProvider(bulkDelete, { title: 'Reboot switch', confirmLabel: 'Reboot', destructive: true });
    await user.click(screen.getByRole('button', { name: 'ask' }));
    await screen.findByRole('alertdialog');
    // The trigger sits behind the modal; fire it directly.
    screen.getByRole('button', { name: 'ask again', hidden: true }).click();
    await waitFor(() => expect(results()).toBe('first:false'));
    await user.click(await screen.findByRole('button', { name: 'Reboot' }));
    await waitFor(() => expect(results()).toBe('first:false,second:true'));
  });
});

describe('useConfirm without a provider', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('falls back to the native prompt with the same information', async () => {
    const native = vi.fn(() => true);
    vi.stubGlobal('confirm', native);
    const user = userEvent.setup();
    render(<Harness options={{ ...bulkDelete, items: ['10 mgmt', '20 voice'] }} />);
    await user.click(screen.getByRole('button', { name: 'ask' }));
    await waitFor(() => expect(results()).toBe('first:true'));
    expect(native).toHaveBeenCalledWith(
      'Delete VLANs\n\nThey are removed from every switch at this site.\n\nThis affects 7 items.\n\n10 mgmt, 20 voice',
    );
  });

  it('passes the native answer through', async () => {
    vi.stubGlobal('confirm', vi.fn(() => false));
    const user = userEvent.setup();
    render(<Harness options={bulkDelete} />);
    await user.click(screen.getByRole('button', { name: 'ask' }));
    await waitFor(() => expect(results()).toBe('first:false'));
  });

  it('answers no when there is no prompt at all', async () => {
    vi.stubGlobal('confirm', undefined);
    const user = userEvent.setup();
    render(<Harness options={bulkDelete} />);
    await user.click(screen.getByRole('button', { name: 'ask' }));
    await waitFor(() => expect(results()).toBe('first:false'));
  });
});
