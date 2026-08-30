// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Minimal client-side CSV export helpers.
 *
 * Used by inventory/detail tables (channels, SMART attributes, recording
 * segments, etc.) to let operators export a manifest for ticketing/compliance.
 */

export interface CsvColumn<T> {
  key: keyof T | string;
  header: string;
  /** Optional value accessor; defaults to row[key]. */
  value?: (row: T) => unknown;
}

export function escapeCell(v: unknown): string {
  let s = v == null ? '' : String(v);
  // neutralize spreadsheet formula injection. A cell that starts
  // with = + - @ (or tab/CR) is interpreted as a formula by Excel/LibreOffice/
  // Sheets and can execute (DDE / data exfil). Our exports carry untrusted,
  // device-reported data (channel/SMART names, etc.), so prefix a single quote
  // to force text, the displayed value is unchanged.
  // ...but a NEGATIVE NUMBER is not a formula. Prefixing one turns the cell into
  // text, so a signal_strength of -67 dBm exported as '-67 and could no longer be
  // sorted, filtered or charted. This surfaced when 18 pages were routed onto this
  // helper: their own escapers had no guard, so numbers had always come through.
  // A bare numeric literal cannot execute -- a formula needs an operator or
  // function after the sign ("-1+1", "-CMD()"), neither of which matches the
  // numeric pattern. Exempt strict numerics only.
  const isPlainNumber = /^-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(s);
  if (!isPlainNumber && /^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  // Quote if the cell contains a comma, quote, CR or LF (RFC 4180).
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Serialize rows to a CSV string. With columns, controls order + headers. */
export function toCsv<T>(rows: T[], columns?: CsvColumn<T>[]): string {
  const cols: CsvColumn<T>[] =
    columns ??
    (rows.length
      ? Object.keys(rows[0] as Record<string, unknown>).map((k) => ({ key: k, header: k }))
      : []);
  if (!cols.length) return '';
  const head = cols.map((c) => escapeCell(c.header)).join(',');
  const body = rows
    .map((r) =>
      cols
        .map((c) =>
          escapeCell(c.value ? c.value(r) : (r as Record<string, unknown>)[c.key as string]),
        )
        .join(','),
    )
    .join('\n');
  return `${head}\n${body}`;
}

/** Trigger a browser download of CSV content. */
export function downloadCsv(filename: string, csv: string): void {
  // Prepend a UTF-8 BOM so Excel renders non-ASCII correctly.
  const blob = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename.endsWith('.csv') ? filename : `${filename}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
