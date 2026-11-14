// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The SLA reports panel was the last untranslated enterprise panel: every
 * label, state and message was English in Spanish and Chinese. These tests
 * render it in each shipped language, and pin two behaviours that came with
 * the translation: the weekly schedule's day is chosen by name (it was a bare
 * 0 to 6 number field) and still sends the backend's 0 = Monday index, and a
 * delivery state is shown by its translated label.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import i18next from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { SLAReportsPanel } from './SLAReportsPanel';

const mock = vi.hoisted(() => ({
  api: {
    list: vi.fn(),
    generate: vi.fn(),
    download: vi.fn(),
    schedules: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    deliveries: vi.fn(),
    cancel: vi.fn(),
  },
  providers: vi.fn(),
}));
vi.mock('@/lib/api/slaReports', () => ({ slaReportsApi: mock.api }));
vi.mock('@/lib/api', () => ({ notificationApi: { getProviders: mock.providers } }));
vi.mock('@/stores/authStore', () => ({
  useAuthStore: (selector: (state: unknown) => unknown) =>
    selector({ user: { id: 'reader', organization_id: 'org' }, hasPermission: () => true }),
}));

function i18nFor(lng: string) {
  const resources: Record<string, Record<string, unknown>> = {};
  for (const lang of new Set([lng, 'en'])) {
    const dir = resolve(process.cwd(), 'public/locales', lang);
    resources[lang] = {};
    for (const file of readdirSync(dir)) {
      if (file.endsWith('.json')) {
        resources[lang][file.replace(/\.json$/, '')] = JSON.parse(readFileSync(resolve(dir, file), 'utf8'));
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

function renderIn(lng: string, path = '/sla/reports') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18nFor(lng)}>
        <MemoryRouter initialEntries={[path]}>
          <SLAReportsPanel policies={[]} />
        </MemoryRouter>
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mock.api.list.mockResolvedValue({ data: { reports: [], total: 0 } });
  mock.api.schedules.mockResolvedValue({
    data: {
      schedules: [
        {
          id: 's1',
          name: 'Board pack',
          frequency: 'quarterly',
          day_of_week: null,
          day_of_month: 1,
          timezone: 'UTC',
          time_of_day: '09:00',
          enabled: false,
          delivery_enabled: false,
          recipients: [],
          sla_policy_ids: [],
        },
      ],
      total: 1,
    },
  });
  mock.api.deliveries.mockResolvedValue({
    data: [{ id: 'd1', recipient_email: 'reader@example.test', state: 'accepted', attempts: 1 }],
  });
  mock.api.create.mockResolvedValue({ data: { id: 'schedule' } });
  mock.providers.mockResolvedValue({ data: [] });
});

describe('SLA reports panel translations', () => {
  it.each([
    ['es', 'Generar un informe', 'Archivo de informes', 'Programaciones de informes', 'Trimestral', 'En pausa', 'Aceptado'],
    ['zh', '生成报告', '报告归档', '报告计划', '每季度', '已暂停', '已接受'],
  ])('renders in %s', async (lng, generate, archive, schedules, quarterly, paused, accepted) => {
    renderIn(lng, '/sla/reports?report=r1');
    expect(screen.getByText(generate)).toBeTruthy();
    expect(screen.getByText(archive)).toBeTruthy();
    expect(screen.getByText(schedules)).toBeTruthy();
    // The schedule row, once it loads: its state and cadence are translated.
    const row = await screen.findByText(new RegExp(`${paused} .*${quarterly}`));
    expect(row.textContent).toContain('09:00');
    expect(await screen.findByText(accepted)).toBeTruthy();
    const text = document.body.textContent ?? '';
    for (const english of ['Generate a report', 'Report archive', 'Report schedules', 'Create schedule', 'Email delivery status']) {
      expect(text).not.toContain(english);
    }
  });

  it('picks the weekly day by name and sends the 0 = Monday index', async () => {
    renderIn('en');
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Weekly ops' } });
    fireEvent.change(screen.getByLabelText('Frequency'), { target: { value: 'weekly' } });
    const day = screen.getByLabelText('Day of the week');
    expect(Array.from((day as HTMLSelectElement).options, (o) => o.text)).toEqual([
      'Monday',
      'Tuesday',
      'Wednesday',
      'Thursday',
      'Friday',
      'Saturday',
      'Sunday',
    ]);
    fireEvent.change(day, { target: { value: '4' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create schedule' }));
    await waitFor(() =>
      expect(mock.api.create).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'Weekly ops', frequency: 'weekly', day_of_week: 4 }),
      ),
    );
  });
});
