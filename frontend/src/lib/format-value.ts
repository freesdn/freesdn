// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Display text for a raw value from a vendor API.
 *
 * Several detail tabs (switch DHCP, gateway system/DNS/VPN, AP settings) list
 * whatever key/value pairs the adapter returns, and rendered each value with
 * `String(value)`. Vendors nest freely, so a list of leases became
 * "[object Object],[object Object],..." across the card. Nested values now
 * collapse to a short, honest summary instead.
 */
import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';

export interface ValueLabels {
  yes: string;
  no: string;
  /** Shown for null, undefined, empty strings and empty collections. */
  none: string;
  /** "3 entries": a list of structured items. */
  entries: (n: number) => string;
  /** "5 fields": a nested object that is not worth inlining. */
  fields: (n: number) => string;
}

const MAX_LIST = 5;
const MAX_FIELDS = 3;

function isScalar(v: unknown): v is string | number | boolean | null | undefined {
  return v === null || v === undefined || ['string', 'number', 'boolean'].includes(typeof v);
}

export function formatConfigValue(value: unknown, labels: ValueLabels, depth = 0): string {
  if (value === null || value === undefined || value === '') return labels.none;
  if (typeof value === 'boolean') return value ? labels.yes : labels.no;
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : labels.none;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    if (value.length === 0) return labels.none;
    if (value.every(isScalar)) {
      const shown = value.slice(0, MAX_LIST).map((v) => formatConfigValue(v, labels, depth + 1));
      const more = value.length - MAX_LIST;
      return more > 0 ? `${shown.join(', ')}, +${more}` : shown.join(', ');
    }
    return labels.entries(value.length);
  }
  if (typeof value === 'object') {
    const all = Object.entries(value as Record<string, unknown>);
    if (all.length === 0) return labels.none;
    const scalars = all.filter(([, v]) => isScalar(v) && v !== null && v !== undefined && v !== '');
    // Inline a small flat object ("mode: auto, enabled: Yes"); summarise the rest.
    if (depth > 0 || scalars.length === 0 || scalars.length < all.length) {
      return labels.fields(all.length);
    }
    const shown = scalars
      .slice(0, MAX_FIELDS)
      .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${formatConfigValue(v, labels, depth + 1)}`);
    return scalars.length > MAX_FIELDS ? `${shown.join(', ')}, +${scalars.length - MAX_FIELDS}` : shown.join(', ');
  }
  return String(value);
}

/** `formatConfigValue` bound to the current language. */
export function useConfigValueFormatter(): (value: unknown) => string {
  const { t } = useTranslation('common');
  return useCallback(
    (value: unknown) =>
      formatConfigValue(value, {
        yes: t('FormatValue.yes'),
        no: t('FormatValue.no'),
        none: '-',
        entries: (n) => t('FormatValue.entries', { count: n }),
        fields: (n) => t('FormatValue.fields', { count: n }),
      }),
    [t],
  );
}
