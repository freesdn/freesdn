// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN

export interface GatewayLogEntry {
  timestamp: string;
  process: string;
  message: string;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const fields = ['timestamp', 'date', '__timestamp__', 'process_name', 'process', 'facility', 'line', 'message', 'msg'] as const;
function text(row: Record<string, unknown>, names: readonly string[]): string {
  for (const name of names) {
    const value = row[name];
    if (typeof value === 'number' || (typeof value === 'string' && value.length)) return String(value);
  }
  return '-';
}

/** Unknown or mismatched responses must not look like a successful empty read. */
export function parseGatewayLogInventory(body: unknown, gatewayId: string, vendor: string): GatewayLogEntry[] | null {
  if (!record(body) || !gatewayId || !vendor || body.gateway_id !== gatewayId || body.vendor !== vendor
    || !Array.isArray(body.logs) || body.logs.length > 200) return null;
  const rows: GatewayLogEntry[] = [];
  for (const entry of body.logs) {
    if (!record(entry)) return null;
    for (const field of fields) {
      const value = entry[field];
      if (value !== undefined && value !== null && typeof value !== 'string'
        && !(typeof value === 'number' && Number.isFinite(value))) return null;
    }
    rows.push({
      timestamp: text(entry, ['timestamp', 'date', '__timestamp__']),
      process: text(entry, ['process_name', 'process', 'facility']),
      message: text(entry, ['line', 'message', 'msg']),
    });
  }
  return rows;
}
