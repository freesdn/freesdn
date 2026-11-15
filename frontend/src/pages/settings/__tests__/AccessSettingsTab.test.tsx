// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '@/test-utils';
import { useUIStore } from '@/stores';
import { AccessSettingsTab } from '../AccessSettingsTab';

const mock = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    systemApi: { getAdapterReadOnly: mock.get, setAdapterReadOnly: mock.put },
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  useUIStore.setState({ readOnlyMode: false });
});

describe('Settings > Read-only / Write access', () => {
  it('does not claim write access when the server mode cannot be read', async () => {
    mock.get.mockRejectedValue(new Error('403'));
    renderWithProviders(<AccessSettingsTab />);
    // "Current mode unknown" is also the loading label; wait for the error.
    expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.getByText('Current mode unknown')).toBeInTheDocument();
    expect(screen.queryByText(/Write access is ON/)).not.toBeInTheDocument();
    expect(screen.getByRole('switch')).toBeDisabled();
  });

  it('shows the mode the server reports, not the store default', async () => {
    mock.get.mockResolvedValue({ data: { read_only: true } });
    renderWithProviders(<AccessSettingsTab />);
    expect(await screen.findByText(/Read-only mode is ON/)).toBeInTheDocument();
    expect(screen.getByRole('switch')).toBeChecked();
    await waitFor(() => expect(useUIStore.getState().readOnlyMode).toBe(true));
  });

  it('asks before turning device writes on', async () => {
    mock.get.mockResolvedValue({ data: { read_only: true } });
    mock.put.mockResolvedValue({ data: { read_only: false } });
    renderWithProviders(<AccessSettingsTab />);
    fireEvent.click(await screen.findByRole('switch'));
    expect(
      await screen.findByText('Allow FreeSDN to write to devices?'),
    ).toBeInTheDocument();
    expect(mock.put).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Enable write access' }));
    await waitFor(() => expect(mock.put).toHaveBeenCalledWith(false));
    expect(await screen.findByText(/Write access is ON/)).toBeInTheDocument();
  });

  it('shows both sources and which one is in force', async () => {
    mock.get.mockResolvedValue({
      data: {
        read_only: true,
        env_read_only: false,
        setting_read_only: true,
        enforced_by: 'setting',
        can_disable: true,
      },
    });
    renderWithProviders(<AccessSettingsTab />);
    expect(await screen.findByTestId('read-only-source-env')).toHaveTextContent('Not enforced');
    expect(screen.getByTestId('read-only-source-setting')).toHaveTextContent('Read-only');
    expect(screen.getByTestId('read-only-enforced-by')).toHaveTextContent(
      'Read-only, set by the Settings switch',
    );
    expect(screen.getByRole('switch')).toBeEnabled();
  });

  it('cannot turn off a read-only mode the server environment enforces', async () => {
    mock.get.mockResolvedValue({
      data: {
        read_only: true,
        env_read_only: true,
        setting_read_only: false,
        enforced_by: 'environment',
        can_disable: false,
      },
    });
    renderWithProviders(<AccessSettingsTab />);
    expect(await screen.findByText(/cannot be turned off here/)).toBeInTheDocument();
    expect(screen.getByRole('switch')).toBeChecked();
    expect(screen.getByRole('switch')).toBeDisabled();
    expect(screen.getByTestId('read-only-source-env')).toHaveTextContent('Read-only');
    expect(screen.getByTestId('read-only-source-setting')).toHaveTextContent('Off');
    fireEvent.click(screen.getByRole('switch'));
    expect(screen.queryByText('Allow FreeSDN to write to devices?')).not.toBeInTheDocument();
    expect(mock.put).not.toHaveBeenCalled();
  });

  it('says when the stored switch could not be read', async () => {
    mock.get.mockResolvedValue({
      data: {
        read_only: true,
        env_read_only: false,
        setting_read_only: null,
        enforced_by: 'unverified',
        can_disable: true,
      },
    });
    renderWithProviders(<AccessSettingsTab />);
    expect(await screen.findByTestId('read-only-source-setting')).toHaveTextContent(
      'Could not be read',
    );
    expect(screen.getByText(/could not be read, so device writes are refused/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('says so when the server keeps read-only on', async () => {
    mock.get.mockResolvedValue({ data: { read_only: true } });
    mock.put.mockResolvedValue({ data: { read_only: true } });
    renderWithProviders(<AccessSettingsTab />);
    fireEvent.click(await screen.findByRole('switch'));
    fireEvent.click(await screen.findByRole('button', { name: 'Enable write access' }));
    expect(await screen.findByText('Mode not changed')).toBeInTheDocument();
    expect(screen.getByText(/Read-only mode is ON/)).toBeInTheDocument();
  });
});
