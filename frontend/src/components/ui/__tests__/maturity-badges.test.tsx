// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The maturity badges' fallback tooltips are shipped copy, and shipped copy
 * carries no em dashes (a past commit stripped them deliberately). These are
 * the texts an operator sees when the backend record has no note of its own.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInstance } from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CapabilityMaturityBadge } from '../capability-maturity-badge';
import { MaturityBadge } from '../maturity-badge';
import type { AdapterWriteMaturity } from '@/lib/api/adapters';

vi.mock('@/hooks/useCapabilityMaturity', () => ({
  useCapabilityMaturity: () => ({
    maturityFor: () => ({ maturity: 'experimental', title: '', notes: '' }),
  }),
}));

async function tooltipFor(trigger: HTMLElement): Promise<string> {
  const user = userEvent.setup();
  await user.hover(trigger);
  const tip = await screen.findByRole('tooltip');
  return tip.textContent ?? '';
}

describe('maturity badge fallback copy', () => {
  it('capability badge: experimental with no note', async () => {
    render(<CapabilityMaturityBadge info={{ maturity: 'experimental', title: '', notes: '' }} />);
    const text = await tooltipFor(screen.getByText('Experimental'));
    expect(text).toBe(
      'Built but not yet verified end-to-end against real infrastructure. Treat it as experimental.',
    );
    expect(text).not.toMatch(/—/);
  });

  it('capability badge resolved by id falls back the same way', async () => {
    render(<CapabilityMaturityBadge capabilityId="sso" />);
    expect(await tooltipFor(screen.getByText('Experimental'))).not.toMatch(/—/);
  });

  it('adapter badge: experimental with no note', async () => {
    render(<MaturityBadge info={{ maturity: 'experimental', notes: '' }} />);
    const text = await tooltipFor(screen.getByText('Experimental'));
    expect(text).toBe('Implemented but not yet verified on real hardware. Please report results.');
  });

  it.each<[AdapterWriteMaturity, string, string]>([
    ['disabled', 'Writes: Off by design', 'Writes are intentionally disabled; this integration runs read-only.'],
    ['experimental', 'Writes: Experimental', 'Experimental adapter: writes are not verified.'],
  ])('adapter write badge %s', async (writeMaturity, label, expected) => {
    render(
      <MaturityBadge info={{ maturity: 'verified', notes: '', write_maturity: writeMaturity }} />,
    );
    const text = await tooltipFor(screen.getByText(label));
    expect(text).toBe(expected);
  });
});

describe('maturity badges are translated', () => {
  async function spanish() {
    const common = JSON.parse(
      readFileSync(resolve(process.cwd(), 'public/locales/es/common.json'), 'utf8'),
    );
    const instance = createInstance();
    await instance.use(initReactI18next).init({
      lng: 'es',
      fallbackLng: 'es',
      defaultNS: 'common',
      ns: ['common'],
      resources: { es: { common } },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
    });
    return instance;
  }

  it('renders the labels in the operator language', async () => {
    const i18n = await spanish();
    render(
      <I18nextProvider i18n={i18n}>
        <MaturityBadge info={{ maturity: 'verified', notes: '', write_maturity: 'mock_tested' }} />
        <CapabilityMaturityBadge info={{ maturity: 'stable', title: '', notes: '' }} />
      </I18nextProvider>,
    );
    expect(screen.getByText('Lecturas: verificadas')).toBeInTheDocument();
    expect(screen.getByText('Escrituras: probadas con simulaciones')).toBeInTheDocument();
    expect(screen.getByText('Estable')).toBeInTheDocument();
  });
});

