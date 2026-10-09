// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
type Kind = 'firmware' | 'health';
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
function reject(): never { throw new Error('Gateway status is unavailable'); }
function finiteJSON(v: unknown, depth = 0): boolean {
  if (depth > 32) return false;
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return true;
  if (typeof v === 'number') return Number.isFinite(v);
  if (Array.isArray(v)) return v.every(x => finiteJSON(x, depth + 1));
  return record(v) && Object.values(v).every(x => finiteJSON(x, depth + 1));
}

/** Preserve response identity while rejecting incomplete or foreign live reads. */
export function validatedSystemRead<T extends { data: unknown }>(response: T, id: string, kind: Kind): T {
  const envelope = response.data;
  if (!record(envelope) || envelope.gateway_id !== id || !finiteJSON(envelope)) reject();
  if (kind === 'firmware') {
    const body = envelope.firmware;
    if (!record(body)) reject();
    const versions = ['current_version', 'product_version', 'version'].filter(k => k in body).map(k => body[k]);
    if (!versions.length || versions.some(v => typeof v !== 'string' || !v.trim())) reject();
    for (const key of ['update_available', 'needs_update', 'upgrade_available']) {
      if (body[key] != null && typeof body[key] !== 'boolean') reject();
    }
    for (const key of ['latest_version', 'new_version', 'last_check', 'product_name']) {
      if (body[key] != null && typeof body[key] !== 'string') reject();
    }
  } else {
    const rows = envelope.gateways;
    if (!Array.isArray(rows) || !Number.isSafeInteger(envelope.count) || envelope.count !== rows.length) reject();
    const names = new Set<string>();
    for (const row of rows) {
      if (!record(row) || typeof row.name !== 'string' || !row.name.trim() || row.name !== row.name.trim() || names.has(row.name)) reject();
      names.add(row.name);
      if (typeof row.status !== 'string' || !row.status.trim()) reject();
      for (const key of ['address', 'interface', 'monitor_ip', 'status_text']) {
        if (key in row && typeof row[key] !== 'string') reject();
      }
      if ('default_gateway' in row && typeof row.default_gateway !== 'boolean') reject();
      for (const key of ['loss_pct', 'delay_ms', 'stddev_ms']) {
        const v = row[key];
        if (v != null && (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || (key === 'loss_pct' && v > 100))) reject();
      }
    }
  }
  return response;
}
