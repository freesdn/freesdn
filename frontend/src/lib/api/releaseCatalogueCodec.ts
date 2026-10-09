// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE: finite catalogue observations. No signature or mutation authority.
 * The transport must separately bound bytes during network I/O and revalidate
 * initiating context after that I/O and this decoder. This file does neither.
 */
import { z } from 'zod';

export class ReleaseCatalogueError extends Error {
  constructor() { super('Release catalogue could not be validated. Refresh after reviewing the current account.'); this.name = 'ReleaseCatalogueError'; }
}
const refuse = (): never => { throw new ReleaseCatalogueError(); };
export const CATALOGUE_BYTES = 16 * 1024 * 1024;
const encoder = new TextEncoder();
const scalar = (value: string) => {
  for (const c of value) {
    const n = c.codePointAt(0)!;
    if (n >= 0xd800 && n <= 0xdfff) return false;
  }
  return true;
};
const text = (maximum: number) => z.string().refine(value => {
  if (value.length > maximum * 2 || !scalar(value) || value.includes('\0')) return false;
  let count = 0;
  for (const _c of value) if (++count > maximum) return false;
  return true;
});
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/).length(36);

function instant(value: string): bigint | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match || match[0] !== value) return null;
  const [, ys, ms, ds, hs, minutes, seconds, fraction = '', zone] = match;
  const [year, month, day, hour, minute, second] = [ys, ms, ds, hs, minutes, seconds].map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1]
    || hour > 23 || minute > 59 || second > 59
    || (zone !== 'Z' && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59))) return null;
  const base = Date.parse(`${ys}-${ms}-${ds}T${hs}:${minutes}:${seconds}${zone}`);
  if (!Number.isFinite(base)) return null;
  return BigInt(base) * 1000n + BigInt(fraction.padEnd(6, '0'));
}
const stamp = text(40).refine(value => instant(value) !== null);
const record = z.strictObject({
  id: uuid, organization_id: uuid.nullable(), version: text(50), platform: text(50), agent_type: text(50),
  download_url: text(500), checksum_sha256: text(64), signature: text(4096).nullable(),
  file_size: z.number().int().min(0).max(10737418240), release_notes: text(20000), min_backend_version: text(50),
  is_latest: z.boolean(), is_prerelease: z.boolean(), published_at: stamp,
  download_count: z.number().int().min(0).max(2147483647),
});
const page = z.strictObject({
  items: z.array(record).max(100), limit: z.number().int().min(1).max(100), has_more: z.boolean(),
  next_published_at: stamp.nullable(), next_id: uuid.nullable(),
});
const requestSchema = z.strictObject({
  limit: z.number().int().min(1).max(100), before_published_at: stamp.optional(), before_id: uuid.optional(),
});
type DeepReadonly<T> = T extends object ? { readonly [P in keyof T]: DeepReadonly<T[P]> } : T;
export type ReleaseCataloguePage = DeepReadonly<z.infer<typeof page>>;
export type ReleaseCataloguePosition = z.infer<typeof requestSchema>;

/** Reject duplicate keys before JSON.parse could discard them. All numeric
 * fields are bounded integers; floats, exponent spelling and arrays beyond the
 * schema limit have no purpose in this exact wire contract.
 */
function wire(raw: unknown, maximum = CATALOGUE_BYTES): unknown {
  if (typeof raw !== 'string' || !raw || raw.length > maximum || !scalar(raw)
    || encoder.encode(raw).byteLength > maximum) return refuse();
  let offset = 0;
  let nodes = 0;
  const space = () => { while (offset < raw.length && /[ \t\r\n]/.test(raw[offset])) offset += 1; };
  const string = (): string => {
    const start = offset;
    if (raw[offset++] !== '"') return refuse();
    while (offset < raw.length) {
      const c = raw[offset++];
      if (c === '\\') { offset += 1; continue; }
      if (c !== '"') continue;
      const value: unknown = JSON.parse(raw.slice(start, offset));
      if (typeof value !== 'string' || !scalar(value)) return refuse();
      return value;
    }
    return refuse();
  };
  const value = (depth: number): unknown => {
    if (depth > 8 || ++nodes > 4000) return refuse();
    space();
    if (raw[offset] === '"') return string();
    if (raw[offset] === '[') {
      offset += 1; space();
      const items: unknown[] = [];
      if (raw[offset] === ']') { offset += 1; return items; }
      while (offset < raw.length && items.length < 100) {
        items.push(value(depth + 1)); space();
        if (raw[offset] === ']') { offset += 1; return items; }
        if (raw[offset++] !== ',') return refuse();
      }
      return refuse();
    }
    if (raw[offset] === '{') {
      offset += 1; space();
      const pairs: [string, unknown][] = [];
      const seen = new Set<string>();
      if (raw[offset] === '}') { offset += 1; return {}; }
      while (offset < raw.length) {
        space(); const key = string(); space();
        if (seen.has(key) || raw[offset++] !== ':') return refuse();
        seen.add(key); pairs.push([key, value(depth + 1)]); space();
        if (raw[offset] === '}') { offset += 1; return Object.fromEntries(pairs); }
        if (raw[offset++] !== ',') return refuse();
      }
      return refuse();
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]] as const) {
      if (raw.startsWith(token, offset)) { offset += token.length; return result; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)/.exec(raw.slice(offset));
    if (!number) return refuse();
    offset += number[0].length;
    const result = Number(number[0]);
    if (!Number.isSafeInteger(result)) return refuse();
    return result;
  };
  try {
    const result = value(0); space();
    if (offset !== raw.length) return refuse();
    return result;
  } catch { return refuse(); }
}

function freeze<T>(value: T): DeepReadonly<T> {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value as DeepReadonly<T>;
}
const earlier = (row: { published_at: string; id: string }, bound: { published_at: string; id: string }) => {
  const a = instant(row.published_at)!;
  const b = instant(bound.published_at)!;
  return a < b || (a === b && row.id < bound.id);
};
/** Capture only a validated navigation position, before any asynchronous work. */
export function captureReleaseCataloguePosition(value: unknown): Readonly<ReleaseCataloguePosition> {
  try {
    const requested = requestSchema.parse(value);
    if ((requested.before_id === undefined) !== (requested.before_published_at === undefined)) return refuse();
    return Object.freeze(requested);
  } catch { return refuse(); }
}
export function decodeReleaseCatalogue(raw: unknown, position: ReleaseCataloguePosition): ReleaseCataloguePage {
  try {
    const requested = captureReleaseCataloguePosition(position);
    const result = page.parse(wire(raw));
    if (result.limit !== requested.limit || result.items.length > result.limit) return refuse();
    const seen = new Set<string>();
    for (let i = 0; i < result.items.length; i += 1) {
      const row = result.items[i];
      if (seen.has(row.id) || (i > 0 && !earlier(row, result.items[i - 1]))) return refuse();
      seen.add(row.id);
      if (requested.before_id !== undefined && !earlier(row, {
        id: requested.before_id, published_at: requested.before_published_at!,
      })) return refuse();
    }
    if (result.has_more) {
      const last = result.items[result.items.length - 1];
      if (result.items.length !== result.limit || !last
        || result.next_id !== last.id || result.next_published_at !== last.published_at) return refuse();
    } else if (result.next_id !== null || result.next_published_at !== null) return refuse();
    return freeze(result);
  } catch { return refuse(); }
}


const promoted = record.omit({ organization_id: true }).extend({
  id: uuid.refine(value => value !== '00000000-0000-0000-0000-000000000000'),
  version: text(50).refine(value => value.trim().length > 0),
  platform: z.enum(['linux', 'windows', 'macos']), agent_type: z.enum(['daemon', 'desktop']),
  checksum_sha256: z.string().length(64).regex(/^[0-9a-f]{64}$/),
  signature: text(4096).refine(value => value.length > 0), is_latest: z.literal(true),
});
export type ReleasePromotionObservation = DeepReadonly<z.infer<typeof promoted>>;

/** A bounded response observation, not independent signature verification or
 * a promise that another authorized writer has not since changed latest.
 * The legacy promotion response does not include organization_id; authority is
 * enforced by the captured transport and server, never inferred from its absence.
 */
export function decodeReleasePromotion(raw: unknown, expectedReleaseId: string): ReleasePromotionObservation {
  try {
    const expected = uuid.parse(expectedReleaseId);
    if (expected === '00000000-0000-0000-0000-000000000000') return refuse();
    const result = promoted.parse(wire(raw, 128 * 1024));
    if (result.id !== expected) return refuse();
    return freeze(result);
  } catch { return refuse(); }
}
