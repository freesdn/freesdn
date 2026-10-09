// SPDX-License-Identifier: AGPL-3.0-only
/** Real form/Radix interactions; HTTP is a double, not server or browser acceptance. */
import { Component, type ReactNode } from 'react';
import { AxiosHeaders } from 'axios';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { PluginSettingsForm } from '../PluginSettingsForm';
import { api } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), put: vi.fn() },
  getApiErrorMessage: () => 'Owned request failed',
}));

type Value = string | number | boolean | null;
const pluginId = 'owned-settings-form';
const get = vi.mocked(api.get);
const put = vi.mocked(api.put);
const stringOptions = ['critical', 'error', 'warning', 'info'];
const secretDeclarations = [{ secret: true }, { format: 'password' }] as const;

class ObservationBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <p role="alert">Owned form render failed</p> : this.props.children;
  }
}

function reply(settings: Record<string, Value>) {
  return { data: { settings }, status: 200, statusText: 'OK', headers: {}, config: { headers: new AxiosHeaders() } };
}

beforeEach(() => {
  vi.clearAllMocks();
  get.mockReset();
  put.mockReset();
  put.mockResolvedValue(reply({}));
});

async function open(spec: Record<string, unknown>, initial: Record<string, Value> = {}) {
  get.mockResolvedValue(reply(initial));
  const manifest = { settings_schema: { properties: { choice: { title: 'Choice', ...spec } } } };
  renderWithProviders(<ObservationBoundary><PluginSettingsForm pluginId={pluginId} manifest={manifest} /></ObservationBoundary>);
  await waitFor(() => expect(get).toHaveBeenCalledOnce());
  await waitFor(() => {
    expect(screen.queryByText('Owned form render failed')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save settings' })).not.toBeDisabled();
  });
  return userEvent.setup();
}

async function save(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Save settings' }));
  await waitFor(() => expect(put).toHaveBeenCalledOnce());
  expect(put.mock.calls[0][0]).toBe(`/plugins/${pluginId}/settings`);
  return put.mock.calls[0][1] as { settings: Record<string, Value> };
}

async function choose(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(screen.getByRole('combobox', { name: 'Choice' }));
  await user.click(await screen.findByRole('option', { name }));
}

describe('Plugin settings retain operator value and type', () => {
  it('shows and preserves an existing supported string choice', async () => {
    const user = await open({ type: 'string', enum: stringOptions }, { choice: 'error' });
    expect(screen.getByRole('combobox')).toHaveTextContent('error');
    expect((await save(user)).settings.choice).toBe('error');
  });

  it('shows the retained legacy value without silently replacing it on save', async () => {
    const user = await open({ type: 'string', enum: stringOptions, default: 'warning' }, { choice: 'high' });
    const visible = screen.getByRole('combobox').textContent;
    const submitted = await save(user);
    console.info('owned-plugin-legacy-observation', { visible, submitted });
    expect(visible).toContain('high');
    expect(submitted.settings.choice).toBe('high');
  });

  it('lets the operator explicitly replace a retained legacy choice', async () => {
    const user = await open({ type: 'string', enum: stringOptions }, { choice: 'high' });
    await choose(user, 'warning');
    expect((await save(user)).settings.choice).toBe('warning');
  });

  it('uses a declared default only for an absent value', async () => {
    const user = await open({ type: 'string', enum: stringOptions, default: 'warning' });
    expect(screen.getByRole('combobox')).toHaveTextContent('warning');
    expect((await save(user)).settings.choice).toBe('warning');
  });

  it.each([2, 0, true, false, null] as const)('keeps selected enum primitive %j instead of its display string', async (value) => {
    const user = await open({ enum: ['initial', value] }, { choice: 'initial' });
    await choose(user, String(value));
    const submitted = await save(user);
    console.info('owned-plugin-typed-selection', { selected: value, submitted });
    expect(submitted.settings.choice).toBe(value);
  });

  it.each([{ value: 1, index: 0 }, { value: '1', index: 1 }, { value: true, index: 2 }, { value: 'true', index: 3 }])(
    'keeps the identity of mixed enum option $index', async ({ value, index }) => {
      const user = await open({ enum: [1, '1', true, 'true', 'initial'] }, { choice: 'initial' });
      await user.click(screen.getByRole('combobox', { name: 'Choice' }));
      const options = await screen.findAllByRole('option');
      expect(options).toHaveLength(5);
      await user.click(options[index]);
      const submitted = await save(user);
      console.info('owned-plugin-mixed-selection', { selected: value, index, submitted });
      expect(submitted.settings.choice).toBe(value);
    },
  );

  it('preserves explicit null without replacing it with the scalar default', async () => {
    const user = await open({ default: 'fallback' }, { choice: null });
    expect((await save(user)).settings.choice).toBeNull();
  });

  it('preserves an existing null enum choice without replacing it with the default', async () => {
    const user = await open({ enum: [null, 'fallback'], default: 'fallback' }, { choice: null });
    expect((await save(user)).settings.choice).toBeNull();
  });

  it('supports an empty string enum option without a render failure', async () => {
    const user = await open({ type: 'string', enum: ['', 'initial'] }, { choice: 'initial' });
    await user.click(screen.getByRole('combobox', { name: 'Choice' }));
    const options = await screen.findAllByRole('option');
    expect(options).toHaveLength(2);
    await user.click(options[0]);
    expect((await save(user)).settings.choice).toBe('');
  });

  it('keeps an ordinary integer input numeric', async () => {
    const user = await open({ type: 'integer' }, { choice: 3 });
    await user.clear(screen.getByLabelText('Choice'));
    await user.type(screen.getByLabelText('Choice'), '7');
    expect((await save(user)).settings.choice).toBe(7);
  });

  it('keeps a switched boolean value boolean', async () => {
    const user = await open({ type: 'boolean' }, { choice: true });
    await user.click(screen.getByRole('switch', { name: 'Choice' }));
    expect((await save(user)).settings.choice).toBe(false);
  });
});

describe.each(secretDeclarations)('Plugin secret intent for %j', (declaration) => {
  it('omits an untouched configured credential', async () => {
    const user = await open({ type: 'string', ...declaration }, { choice: '***' });
    expect(screen.getByLabelText('Choice')).toHaveValue('');
    expect((await save(user)).settings).not.toHaveProperty('choice');
  });

  it('submits a deliberately typed replacement', async () => {
    const user = await open({ type: 'string', ...declaration }, { choice: '***' });
    await user.type(screen.getByLabelText('Choice'), 'Owned synthetic replacement');
    expect((await save(user)).settings.choice).toBe('Owned synthetic replacement');
  });

  it('submits explicit empty only after the operator edits and clears', async () => {
    const user = await open({ type: 'string', ...declaration }, { choice: '***' });
    await user.type(screen.getByLabelText('Choice'), 'Owned edit');
    await user.clear(screen.getByLabelText('Choice'));
    expect((await save(user)).settings.choice).toBe('');
  });

  it('treats an explicitly selected secret enum as a touched credential', async () => {
    const user = await open({ type: 'string', enum: ['first-choice', 'second-choice'], ...declaration }, { choice: '***' });
    await choose(user, 'second-choice');
    expect((await save(user)).settings.choice).toBe('second-choice');
  });
});
