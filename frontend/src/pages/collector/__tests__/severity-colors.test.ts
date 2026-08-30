/**
 * The Log Explorer severity palette must cover what the backend stores.
 *
 * `SyslogReceiver` writes the RFC 5424 severity names (SEVERITY_NAMES in
 * backend/app/modules/collector/services/syslog.py), where level 6 is spelled
 * `informational`. Both collector pages keyed SEVERITY_COLORS on `info`, the
 * dropdown/shorthand spelling, so every stored informational row missed the
 * map and rendered with the `?? 'bg-gray-300 text-black'` fallback -- an
 * un-tokenized light-grey pill, in a UI whose default theme is dark, on the
 * single most common severity in the table.
 *
 * The maps are module-private consts inside two page components, so this
 * asserts on the source rather than importing the pages (which would pull the
 * whole query/i18n/router surface in for a lookup table).
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

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

function severityMap(file: string): Record<string, string> {
  const source = readFileSync(path.join(here, '..', file), 'utf8');
  const match = source.match(/const SEVERITY_COLORS: Record<string, string> = \{([\s\S]*?)\n\};/);
  expect(match, `SEVERITY_COLORS not found in ${file}`).toBeTruthy();

  const entries: Record<string, string> = {};
  for (const line of match![1].split('\n')) {
    const kv = line.match(/^\s*([a-z_]+)\s*:\s*'([^']+)'\s*,?\s*$/);
    if (kv) entries[kv[1]] = kv[2];
  }
  return entries;
}

describe.each(['LogExplorerPage.tsx', 'CollectorPage.tsx'])('%s SEVERITY_COLORS', (file) => {
  const map = severityMap(file);

  it.each(STORED_SEVERITIES)('has a badge colour for %s', (severity) => {
    expect(map[severity]).toBeTruthy();
  });

  it('keeps the info shorthand working too', () => {
    // The filter dropdown still submits 'info' (the backend aliases it to
    // 'informational'), and an operator-exported CSV can carry either.
    expect(map.info).toBe(map.informational);
  });
});
