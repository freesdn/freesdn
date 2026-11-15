// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The Storage page, its write dialogs and the Add TrueNAS dialog had no i18n
 * at all: Spanish and Chinese users got English throughout. These tests render
 * the page over the demo API in each shipped language and check the copy is
 * that language's, not English; and that the Add dialog no longer claims
 * FreeSDN never writes to the appliance (the page stages snapshots, datasets
 * and scrubs).
 */
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import i18next, { type i18n as I18n } from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { api } from '@/lib/api/client';
import { demoAxiosAdapter } from '@/demo/mockApi';
import { ToastProvider } from '@/components/ui/toast';
import { TooltipProvider } from '@/components/ui/tooltip';
import StoragePage from '../StoragePage';
import { AddTrueNASDialog } from '../AddTrueNASDialog';

const oldAdapter = api.defaults.adapter;

function i18nFor(lng: string): I18n {
  const resources: Record<string, Record<string, unknown>> = {};
  for (const lang of [lng, 'en']) {
    const dir = resolve(process.cwd(), 'public/locales', lang);
    resources[lang] = {};
    for (const file of readdirSync(dir)) {
      if (file.endsWith('.json')) {
        (resources[lang] as Record<string, unknown>)[file.replace(/\.json$/, '')] = JSON.parse(
          readFileSync(resolve(dir, file), 'utf8'),
        );
      }
    }
  }
  const instance = i18next.createInstance();
  void instance.use(initReactI18next).init({
    lng,
    fallbackLng: 'en',
    defaultNS: 'common',
    ns: Object.keys(resources.en),
    resources: resources as never,
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
  return instance;
}

function renderIn(lng: string, node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18nFor(lng)}>
        <MemoryRouter>
          <ToastProvider>
            <TooltipProvider>{node}</TooltipProvider>
          </ToastProvider>
        </MemoryRouter>
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  api.defaults.adapter = demoAxiosAdapter;
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = oldAdapter;
});

const ENGLISH = ['Sharing & Services', 'Sharing and services', 'Data protection', 'No scrub history', 'New dataset'];

describe('Storage page translations', () => {
  it.each([
    ['es', 'Almacenamiento', 'Uso compartido y servicios', 'Protección de datos', 'Nuevo dataset'],
    ['zh', '存储', '共享与服务', '数据保护', '新建数据集'],
  ])('renders the dashboard in %s', async (lng, title, services, dataProtection, newDataset) => {
    renderIn(lng, <StoragePage />);
    // The heading also holds the capability maturity badge.
    expect(await screen.findByRole('heading', { name: new RegExp(`^${title}`), level: 1 })).toBeTruthy();
    expect(await screen.findByText(services, {}, { timeout: 4000 })).toBeTruthy();
    expect(screen.getByText(dataProtection)).toBeTruthy();
    expect(screen.getByRole('button', { name: new RegExp(newDataset) })).toBeTruthy();
    const text = document.body.textContent ?? '';
    for (const english of ENGLISH) expect(text).not.toContain(english);
  }, 15_000);

  it('translates the snapshot dialog and its validation', async () => {
    renderIn('es', <StoragePage />);
    const snapshotButtons = await screen.findAllByRole('button', { name: /Instantánea/ }, { timeout: 4000 });
    fireEvent.click(snapshotButtons[0]);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Crear una instantánea')).toBeTruthy();
    expect(within(dialog).getByText('Incluir datasets secundarios')).toBeTruthy();
    // The dialog's checkbox is the themed one, not a native input.
    expect(within(dialog).queryByRole('checkbox')?.tagName).toBe('BUTTON');
    fireEvent.change(within(dialog).getByLabelText('Nombre de la instantánea'), { target: { value: '' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preparar instantánea' }));
    expect(await within(dialog).findByText('Nombre de la instantánea es obligatorio')).toBeTruthy();
  }, 15_000);
});

describe('Add TrueNAS dialog', () => {
  it('says what it reads and that changes are staged, not that it never writes', () => {
    renderIn('en', <AddTrueNASDialog open onOpenChange={() => {}} />);
    const dialog = screen.getByRole('dialog');
    const text = dialog.textContent ?? '';
    expect(text).not.toMatch(/never writes/i);
    expect(text).not.toMatch(/read-only to surface/i);
    expect(text).toContain('staged in Pending Changes');
    expect(within(dialog).getByRole('button', { name: 'Show API key' })).toBeTruthy();
  });

  it('is translated in Chinese', () => {
    renderIn('zh', <AddTrueNASDialog open onOpenChange={() => {}} />);
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('添加 TrueNAS 存储')).toBeTruthy();
    expect(within(dialog).getByText('API 密钥所有者')).toBeTruthy();
    expect(within(dialog).getByRole('button', { name: /测试连接/ })).toBeTruthy();
  });
});
