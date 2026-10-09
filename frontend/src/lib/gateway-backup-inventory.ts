// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN

export interface GatewayBackupMetadata {
  filename: string;
  timestamp: string;
  size_bytes: number;
  description: string;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Null means unknown/unavailable; only a complete, matching response can mean empty. */
export function parseGatewayBackupInventory(body: unknown, gatewayId: string): GatewayBackupMetadata[] | null {
  if (!record(body) || !gatewayId || body.gateway_id !== gatewayId
    || typeof body.vendor !== 'string' || !body.vendor
    || !Array.isArray(body.backups) || !Number.isSafeInteger(body.count)
    || body.count !== body.backups.length) return null;

  const filenames = new Set<string>();
  const backups: GatewayBackupMetadata[] = [];
  for (const entry of body.backups) {
    if (!record(entry)) return null;
    const { filename, timestamp, size_bytes, description } = entry;
    if (typeof filename !== 'string' || filename.length < 1 || filename.length > 255
      || /[^a-zA-Z0-9_.-]/.test(filename) || filename.includes('..') || filename === '.'
      || filenames.has(filename) || typeof timestamp !== 'string'
      || typeof size_bytes !== 'number' || !Number.isSafeInteger(size_bytes) || size_bytes < 0
      || typeof description !== 'string') return null;
    filenames.add(filename);
    backups.push({ filename, timestamp, size_bytes, description });
  }
  return backups;
}
