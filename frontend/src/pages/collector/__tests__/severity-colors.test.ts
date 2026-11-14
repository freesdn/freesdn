/**
 * The Collector severity pills cover what the backend stores, and every pill's
 * label meets WCAG AA (4.5:1) in both themes.
 *
 * `SyslogReceiver` writes the RFC 5424 severity names (SEVERITY_NAMES in
 * backend/app/modules/collector/services/syslog.py), where level 6 is spelled
 * `informational`. Both collector pages once keyed their palette on `info`, the
 * dropdown/shorthand spelling, so every stored informational row missed the
 * map and rendered with an un-tokenized light-grey fallback.
 *
 * The palette was then a solid scale with white text on red-400, blue-400 and
 * gray-400 (about 2.5 to 2.8:1), duplicated in both pages. It is now one module
 * (`../severity`) built on theme tokens; the contrast check below resolves each
 * pill's text and background from the token values in index.css, for the
 * light and the dark (default) theme, on a card, on the page background and on
 * a hovered table row.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createElement } from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { PILL_CLASSES, SEVERITY_STYLES, SeverityBadge } from '../severity';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Every value `CollectorLog.severity` can hold, from SEVERITY_NAMES. */
const STORED_SEVERITIES = [
  'emergency',
  'alert',
  'critical',
  'error',
  'warning',
  'notice',
  'informational',
  'debug',
];

describe('severity styles', () => {
  it.each(STORED_SEVERITIES)('has a style for %s', (severity) => {
    expect(SEVERITY_STYLES[severity]).toBeTruthy();
  });

  it('keeps the info shorthand working too', () => {
    // The filter dropdown still submits 'info' (the backend aliases it to
    // 'informational'), and an operator-exported CSV can carry either.
    expect(SEVERITY_STYLES.info).toEqual(SEVERITY_STYLES.informational);
  });

  it.each(['LogExplorerPage.tsx', 'CollectorPage.tsx'])('%s uses the one shared badge', (file) => {
    const source = readFileSync(path.join(here, '..', file), 'utf8');
    expect(source).toContain("from './severity'");
    expect(source).not.toMatch(/SEVERITY_COLORS|bg-(red|blue|gray|orange|yellow)-\d00/);
  });

  it('labels a stored level by its translated name, and an unknown one as sent', () => {
    render(createElement(SeverityBadge, { severity: 'informational' }));
    expect(screen.getByText('Info')).toBeTruthy();
    render(createElement(SeverityBadge, { severity: 'local7-custom' }));
    expect(screen.getByText('local7-custom')).toBeTruthy();
  });
});

// ── WCAG contrast from the theme tokens ─────────────────────────────────────

type RGB = [number, number, number];

function tokens(css: string, selector: RegExp): Record<string, RGB> {
  const block = css.match(selector);
  expect(block, `theme block ${selector} not found in index.css`).toBeTruthy();
  const out: Record<string, RGB> = {};
  for (const m of block![1].matchAll(/--([a-z-]+):\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%\s*;/g)) {
    out[m[1]] = hslToRgb(Number(m[2]), Number(m[3]) / 100, Number(m[4]) / 100);
  }
  return out;
}

function hslToRgb(h: number, s: number, l: number): RGB {
  const k = (n: number) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [f(0), f(8), f(4)];
}

function luminance([r, g, b]: RGB): number {
  const ch = (v: number) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
}

function contrast(a: RGB, b: RGB): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

function over(fg: RGB, bg: RGB, alpha: number): RGB {
  return [0, 1, 2].map((i) => fg[i] * alpha + bg[i] * (1 - alpha)) as RGB;
}

const css = readFileSync(path.join(here, '../../../index.css'), 'utf8');
const THEMES = {
  light: tokens(css, /:root,\s*\.light\s*\{([\s\S]*?)\n\}/),
  dark: tokens(css, /\n\.dark\s*\{([\s\S]*?)\n\}/),
};

function pillColours(classes: string, theme: Record<string, RGB>, surface: RGB) {
  const bg = classes.match(/\bbg-([a-z-]+?)(?:\/(\d+))?(?=\s|$)/);
  const text = classes.match(/\btext-([a-z-]+)(?=\s|$)/);
  expect(text, `no text colour in "${classes}"`).toBeTruthy();
  let background = surface;
  if (bg && bg[1] !== 'transparent') {
    expect(theme[bg[1]], `unknown token ${bg[1]}`).toBeTruthy();
    background = over(theme[bg[1]], surface, bg[2] ? Number(bg[2]) / 100 : 1);
  }
  expect(theme[text![1]], `unknown token ${text![1]}`).toBeTruthy();
  return { text: theme[text![1]], background };
}

describe.each(Object.entries(THEMES))('severity pills in the %s theme', (_name, theme) => {
  const surfaces: Array<[string, RGB]> = [
    ['card', theme.card],
    ['page background', theme.background],
    ['hovered row', over(theme.muted, theme.card, 0.5)],
  ];
  for (const [pill, classes] of Object.entries(PILL_CLASSES)) {
    it.each(surfaces)(`${pill} label is at least 4.5:1 on a %s`, (_surface, colour) => {
      const { text, background } = pillColours(classes, theme, colour);
      expect(contrast(text, background)).toBeGreaterThanOrEqual(4.5);
    });
  }
});
