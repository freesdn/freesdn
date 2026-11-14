// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * On a phone the AI Assistant showed a fixed 16rem conversation list beside the
 * chat, leaving the chat about 120px wide (seen at 390px in the demo walk).
 * Below md the list and the chat now take turns at full width: the chat is
 * shown first, a header button opens the list, and choosing a conversation or
 * starting a new one returns to the chat. From md up both stay side by side
 * (`md:flex`). The input hint no longer promises Shift+Enter line breaks in a
 * single-line input.
 */
import type { AxiosResponse } from 'axios';
import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '@/lib/api/client';
import { renderWithProviders } from '@/test-utils';
import AIAssistantPage from '../AIAssistantPage';

const oldAdapter = api.defaults.adapter;

beforeEach(() => {
  api.defaults.adapter = async (config) => {
    const data =
      config.url === '/ai/conversations'
        ? [{ id: 'c1', title: 'Offline APs', provider: 'ollama', model: 'llama3', total_tokens: 10, message_count: 2, updated_at: '2026-11-13T00:00:00Z', created_at: '2026-11-13T00:00:00Z' }]
        : {};
    return { config, data, status: 200, statusText: '200', headers: {} } as AxiosResponse;
  };
});

afterEach(() => {
  api.defaults.adapter = oldAdapter;
});

function panes() {
  const list = screen.getByText('AI Assistant', { selector: 'div' }).closest('div.border-r') as HTMLElement;
  const chat = screen.getByRole('heading', { level: 1 }).closest('div.flex-1') as HTMLElement;
  return { list, chat };
}

describe('AI Assistant at phone width', () => {
  it('shows the chat first and swaps to the list and back', async () => {
    renderWithProviders(<AIAssistantPage />);
    let { list, chat } = panes();
    expect(list.className).toMatch(/(^|\s)hidden(\s|$)/);
    expect(list.className).toContain('md:flex');
    expect(chat.className).not.toMatch(/(^|\s)hidden(\s|$)/);

    fireEvent.click(screen.getByRole('button', { name: 'Conversations' }));
    ({ list, chat } = panes());
    expect(list.className).toContain('w-full');
    expect(list.className).not.toMatch(/(^|\s)hidden(\s|$)/);
    expect(chat.className).toMatch(/(^|\s)hidden(\s|$)/);
    expect(chat.className).toContain('md:flex');

    fireEvent.click(await screen.findByText('Offline APs'));
    ({ list, chat } = panes());
    expect(list.className).toMatch(/(^|\s)hidden(\s|$)/);
    expect(chat.className).not.toMatch(/(^|\s)hidden(\s|$)/);
  });

  it('does not promise multi-line input', () => {
    renderWithProviders(<AIAssistantPage />);
    expect(screen.getByText('Press Enter to send')).toBeTruthy();
    expect(screen.queryByText(/Shift\+Enter/)).toBeNull();
  });
});
