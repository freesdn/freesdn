// SPDX-License-Identifier: AGPL-3.0-only
/** Correction-specific interaction controls; API transport only is doubled. */
import { AxiosHeaders } from 'axios';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { PluginSettingsForm } from '../PluginSettingsForm';
import { api } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), put: vi.fn() },
  getApiErrorMessage: () => 'Owned server refusal',
}));

type Value = string | number | boolean | null;
const get = vi.mocked(api.get);
const put = vi.mocked(api.put);
function response(data: Record<string, unknown>) {
  return { data, status: 200, statusText: 'OK', headers: {}, config: { headers: new AxiosHeaders() } };
}
beforeEach(() => {
  get.mockReset();
  put.mockReset();
  put.mockResolvedValue(response({}));
});
async function open(spec: Record<string, unknown>, initial: Record<string, Value> = {}) {
  get.mockResolvedValue(response({ settings: initial }));
  renderWithProviders(<PluginSettingsForm pluginId="owned-choice-controls" manifest={{ settings_schema: { properties: { choice: { title: 'Choice', ...spec } } } }} />);
  await waitFor(() => expect(get).toHaveBeenCalledOnce());
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save settings' })).not.toBeDisabled());
  return userEvent.setup();
}
async function save(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Save settings' }));
  await waitFor(() => expect(put).toHaveBeenCalledOnce());
  expect(put.mock.calls[0][0]).toBe('/plugins/owned-choice-controls/settings');
  return put.mock.calls[0][1] as { settings: Record<string, Value> };
}

describe('Readable plugin choices and save outcomes', () => {
  it.each([
    { value: 1, label: '1 (number)' },
    { value: '1', label: '1 (text)' },
    { value: true, label: 'true (boolean)' },
    { value: 'true', label: 'true (text)' },
  ])('lets the operator distinguish and select $label', async ({ value, label }) => {
    const user = await open({ enum: [1, '1', true, 'true', 'initial'] }, { choice: 'initial' });
    await user.click(screen.getByRole('combobox', { name: 'Choice' }));
    await user.click(await screen.findByRole('option', { name: label }));
    expect(screen.getByRole('combobox')).toHaveTextContent(label);
    expect((await save(user)).settings.choice).toBe(value);
  });

  it.each([
    { value: 0, label: '0' },
    { value: false, label: 'false' },
    { value: null, label: 'null' },
    { value: '', label: 'Empty string' },
  ])('visibly retains an existing falsy choice $label', async ({ value, label }) => {
    const user = await open({ enum: [value, 'fallback'], default: 'fallback' }, { choice: value });
    expect(screen.getByRole('combobox')).toHaveTextContent(label);
    expect((await save(user)).settings.choice).toBe(value);
  });

  it.each([{ secret: true }, { format: 'password' }])('shows configured secret state without exposing the mask for %j', async (declaration) => {
    const user = await open({ ...declaration, enum: ['first', 'second'] }, { choice: '***' });
    expect(screen.getByRole('combobox')).toHaveTextContent('Configured. Select an option to replace it.');
    expect(screen.queryByText('***')).not.toBeInTheDocument();
    expect((await save(user)).settings).not.toHaveProperty('choice');
  });

  it('uses an explicit null default for an absent scalar', async () => {
    const user = await open({ default: null });
    expect((await save(user)).settings.choice).toBeNull();
  });

  it('shows a server refusal for a retained legacy choice and allows explicit correction', async () => {
    put.mockRejectedValueOnce({ response: { status: 400, data: { message: 'Owned invalid legacy value' } } });
    const user = await open({ enum: ['warning', 'info'] }, { choice: 'high' });
    expect(screen.getByRole('combobox')).toHaveTextContent('high (saved value)');
    expect(screen.getByText('This saved value is not in the current options. Select an option to change it.')).toBeInTheDocument();
    expect((await save(user)).settings.choice).toBe('high');
    expect(await screen.findByText('Owned server refusal')).toBeInTheDocument();
    expect(screen.queryByText('Saved.')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox')).toHaveTextContent('high (saved value)');
    await user.click(screen.getByRole('combobox', { name: 'Choice' }));
    expect(await screen.findByRole('option', { name: 'high (saved value)' })).toHaveAttribute('aria-disabled', 'true');
    await user.click(screen.getByRole('option', { name: 'warning' }));
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
    expect(put.mock.calls[1][1]).toEqual({ settings: { choice: 'warning' } });
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
    expect(screen.queryByText('Owned server refusal')).not.toBeInTheDocument();
  });

  it('displays an advisory warning after a successful save', async () => {
    put.mockResolvedValueOnce(response({ warning: 'Owned remote check unavailable' }));
    const user = await open({ enum: ['info', 'warning'] }, { choice: 'info' });
    expect((await save(user)).settings.choice).toBe('info');
    expect(await screen.findByText('Saved, with something to check')).toBeInTheDocument();
    expect(screen.getByText('Owned remote check unavailable')).toBeInTheDocument();
    expect(screen.queryByText('Owned server refusal')).not.toBeInTheDocument();
  });

  it('lets the operator deliberately choose a readable empty string', async () => {
    const user = await open({ enum: ['', 'initial'] }, { choice: 'initial' });
    await user.click(screen.getByRole('combobox', { name: 'Choice' }));
    await user.click(await screen.findByRole('option', { name: 'Empty string' }));
    expect(screen.getByRole('combobox')).toHaveTextContent('Empty string');
    expect((await save(user)).settings.choice).toBe('');
  });
});
