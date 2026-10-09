// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE runtime contracts, not generated OpenAPI types or authority grants. */
import { z } from 'zod';
import type { ReleaseCommandAction } from './releaseOperationTransport';

export class ReleaseCodecError extends Error {
  constructor() { super('Release document or observation could not be validated. Retain the original intent.'); this.name = 'ReleaseCodecError'; }
}
const refuse = (): never => { throw new ReleaseCodecError(); };
const encoder = new TextEncoder();
const uuid = z.string().length(36).regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  .refine(value => value !== '00000000-0000-0000-0000-000000000000');
const digest = z.string().length(64).regex(/^[0-9a-f]{64}$/);
const scalar = (value: string) => [...value].every(c => { const n = c.codePointAt(0)!; return n < 0xd800 || n > 0xdfff; });
// Python len(str) counts code points. Do not shrink the 20,000-character limit
// to 10,000 astral characters through JavaScript UTF-16 .length/.max().
const text = (maximum: number, minimum = 0) => z.string().refine(value =>
  value.length <= maximum * 2 && [...value].length >= minimum && [...value].length <= maximum
  && scalar(value) && !value.includes('\0'));
const integer = (maximum: number) => z.number().int().min(0).max(maximum);
const phase = z.enum(['reserved', 'prepared', 'decided', 'cleaned']);
const identityFields = { operation_id: uuid, release_id: uuid };
const documentFields = { ...identityFields, organization_id: uuid.nullable() };

/** Finite object/scalar protocol parser. Reject ambiguity before JSON.parse can
 * discard a duplicate key; never expose a native parser error with input text.
 * Arrays and float/exponent literals have no place in these exact contracts.
 */
function parseWire(raw: unknown, maximum: number): unknown {
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
    if (depth > 8 || ++nodes > 256) return refuse();
    space();
    if (raw[offset] === '"') return string();
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

// All supported object keys are fixed ASCII names and all numbers are safe
// integers. This encoding matches the server's sort_keys/ensure_ascii=False
// metadata commitment; cross-language vectors require runtime qualification.
function canonical(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return refuse();
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
}
export type Frozen<T> = T extends object ? { readonly [K in keyof T]: Frozen<T[K]> } : T;
function freeze<T>(value: T): Frozen<T> {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value as Frozen<T>;
}
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    const result = schema.safeParse(value);
    if (!result.success) return refuse();
    return result.data;
  } catch { return refuse(); }
}
export function releaseIdentity(value: unknown): string { return parse(uuid, value); }

function timestamp(value: string): bigint | null {
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
const aware = text(40, 1).refine(value => timestamp(value) !== null);
const originalUTC = aware.refine(value => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(?!000000)\d{6})?\+00:00$/.test(value));
const metadataFields = {
  file_size: integer(10737418240), release_notes: text(20000), min_backend_version: text(50),
  is_prerelease: z.boolean(), is_latest: z.boolean(), filename: text(128).nullable(),
};
const publicationMetadata = z.strictObject({ ...metadataFields, version: text(50, 1),
  platform: z.enum(['linux', 'windows', 'macos']), agent_type: z.enum(['daemon', 'desktop']),
  download_url: text(500, 1).refine(value => value.startsWith('/') || value.startsWith('https://')), checksum_sha256: digest,
});
const deletionMetadata = z.strictObject({ ...metadataFields, version: text(50),
  platform: text(50).refine(value => ['linux', 'windows', 'macos'].includes(value.toLowerCase())),
  agent_type: text(50).refine(value => ['daemon', 'desktop'].includes(value.toLowerCase())),
  download_url: text(500), checksum_sha256: z.string().length(64).regex(/^[0-9a-fA-F]{64}$/),
  signature: text(4096).nullable(), published_at: originalUTC,
});
const intentSchema = z.discriminatedUnion('kind', [
  z.strictObject({ ...documentFields, kind: z.literal('publish'), storage_kind: z.enum(['owned', 'external']), metadata: publicationMetadata }),
  z.strictObject({ ...documentFields, kind: z.literal('delete'), metadata: deletionMetadata }),
]).refine(document => {
  if (encoder.encode(canonical(document.metadata)).byteLength > 262144) return false;
  if (document.kind === 'delete') return true;
  const row = document.metadata;
  if (document.storage_kind === 'external') return row.filename === null;
  return row.file_size <= 524288000 && !/[^A-Za-z0-9._+-]/.test(row.version)
    && row.filename !== null && row.filename.length > 0 && !['.', '..'].includes(row.filename)
    && !/[\\/]/.test(row.filename) && row.download_url === `/api/v1/agents/releases/${document.release_id}/binary`;
});
export type ReleaseIntentDocument = Frozen<z.infer<typeof intentSchema>>;
export function decodeReleaseIntent(raw: string): ReleaseIntentDocument {
  return freeze(parse(intentSchema, parseWire(raw, 307200)));
}
async function sha256(raw: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(raw));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
}
export async function releaseIntentCommitment(document: ReleaseIntentDocument): Promise<string> {
  // Revalidate even structurally forged TypeScript values; no caller can pass a
  // digest as a substitute for the complete original document.
  const checked = parse(intentSchema, document);
  const domain = checked.kind === 'publish' ? 'FreeSDN/release-public-metadata/v1\0' : 'FreeSDN/release-deletion-target/v1\0';
  const metadata_sha256 = await sha256(domain + canonical(checked.metadata));
  return sha256(canonical({ format: 1, kind: checked.kind, operation_id: checked.operation_id,
    release_id: checked.release_id, organization_id: checked.organization_id, metadata_sha256,
    ...(checked.kind === 'publish' ? { storage_kind: checked.storage_kind } : {}),
  }));
}

const journal = z.strictObject({ ...documentFields, requested_by: uuid, last_transition_by: uuid,
  kind: z.enum(['publish', 'delete']), storage_kind: z.enum(['owned', 'external', 'legacy']),
  phase, decision: z.enum(['cancelled', 'published', 'deleted']).nullable(), transition_sequence: integer(3),
  created_at: aware, prepared_at: aware.nullable(), decided_at: aware.nullable(), cleaned_at: aware.nullable(),
}).refine(row => {
  if (row.kind === 'publish' && row.storage_kind === 'legacy') return false;
  if (row.decision !== null && row.decision !== 'cancelled' && row.decision !== (row.kind === 'publish' ? 'published' : 'deleted')) return false;
  const prepared = row.prepared_at !== null;
  const fields = row.phase === 'reserved'
    ? row.transition_sequence === 0 && !prepared && row.decision === null && row.decided_at === null && row.cleaned_at === null
    : row.phase === 'prepared'
      ? row.transition_sequence === 1 && prepared && row.decision === null && row.decided_at === null && row.cleaned_at === null
      : row.decision !== null && row.decided_at !== null
        && (row.phase === 'decided' ? row.cleaned_at === null : row.cleaned_at !== null && row.decision !== 'published')
        && row.transition_sequence === (row.phase === 'decided' ? (prepared ? 2 : 1) : (prepared ? 3 : 2))
        && (prepared || row.decision === 'cancelled');
  const stamps = [row.created_at, row.prepared_at, row.decided_at, row.cleaned_at].filter((v): v is string => v !== null).map(v => timestamp(v)!);
  return fields && stamps.every((v, i) => i === 0 || v >= stamps[i - 1]);
});
const noAuthority = { storage_checked: z.literal(false), all_artifact_references_checked: z.literal(false),
  authorization_granted: z.literal(false), absence_authorizes_retry_or_cleanup: z.literal(false) };
const statusSchema = z.strictObject({ ...noAuthority, operation: journal, release_row_present: z.boolean(), observed_at: aware });
const reviewSchema = z.strictObject({ ...noAuthority, intent: intentSchema, intent_sha256: digest,
  operation: journal.nullable(), release_row_present: z.boolean(), deletion_target_matches: z.boolean().nullable(), observed_at: aware,
  historical_observation: z.literal(true), reservation_created: z.literal(false), server_retains_full_intent: z.literal(false),
  save_original_intent_before_mutation: z.literal(true), retry_requires_identical_intent_and_current_authority: z.literal(true),
});
const reservation = z.strictObject({ ...identityFields, phase, decision: z.enum(['published', 'cancelled']).nullable(),
  created: z.boolean(), requested_by: uuid, last_transition_by: uuid });
const preparation = z.strictObject({ ...identityFields, phase: z.literal('prepared'), requested_by: uuid,
  last_transition_by: uuid, publication_or_storage_authorized: z.literal(false) });
const publication = z.strictObject({ ...identityFields, decision: z.literal('published'), newly_published: z.boolean(),
  release_row_present: z.boolean(), current_is_latest: z.boolean().nullable(), artifact_verified_this_call: z.boolean(),
  signature_verified_this_call: z.boolean(), publication_or_storage_authorized: z.literal(false) });
const deletion = z.strictObject({ ...identityFields, phase, decision: z.enum(['deleted', 'cancelled']).nullable(), newly_changed: z.boolean(),
  cleanup_disposition: z.enum(['preserve-live', 'pending-owned-verification', 'no-owned-file', 'retain-unverified', 'not-authorized']),
  bytes_removed: z.literal(false), cleanup_authorized: z.literal(false) });
const cleanup = z.strictObject({ ...identityFields, phase: z.enum(['decided', 'cleaned']), decision: z.enum(['deleted', 'cancelled']),
  disposition: z.enum(['preserve-live', 'no-owned-file', 'retain-unverified', 'retire-owned']), newly_recorded: z.boolean(),
  payload_absence_verified_this_call: z.boolean(), complete: z.boolean(), authorization_granted: z.literal(false),
}).refine(row => row.complete === (row.phase === 'cleaned' && row.disposition !== 'retain-unverified')
  && (!row.payload_absence_verified_this_call || row.disposition === 'retire-owned'));
const resultSchema = z.union([reservation, preparation, publication, deletion, cleanup]);
const envelope = z.strictObject({ ...identityFields, intent_sha256: digest, historical_observation: z.literal(true),
  authorization_granted: z.literal(false), retry_requires_identical_intent_and_current_authority: z.literal(true), result: resultSchema });
type Journal = z.infer<typeof journal>;
export type ReleaseStatusObservation = Frozen<z.infer<typeof statusSchema>>;
export type ReleaseIntentReview = Frozen<z.infer<typeof reviewSchema>>;
export type ReleaseCommandObservation = Frozen<z.infer<typeof envelope>>;
function matches(row: Journal, document: ReleaseIntentDocument): boolean {
  return row.operation_id === document.operation_id && row.release_id === document.release_id
    && row.organization_id === document.organization_id && row.kind === document.kind
    && (document.kind !== 'publish' || row.storage_kind === document.storage_kind);
}
export function decodeReleaseStatus(raw: unknown, operationId: string, document?: ReleaseIntentDocument): ReleaseStatusObservation {
  const checked = parse(statusSchema, parseWire(raw, 524288));
  if (checked.operation.operation_id !== releaseIdentity(operationId) || (document && !matches(checked.operation, document))) return refuse();
  return freeze(checked);
}
export async function decodeReleaseReview(raw: unknown, expected: { operationId: string; releaseId: string; document?: ReleaseIntentDocument }): Promise<ReleaseIntentReview> {
  const checked = parse(reviewSchema, parseWire(raw, 524288));
  if (checked.intent.operation_id !== releaseIdentity(expected.operationId) || checked.intent.release_id !== releaseIdentity(expected.releaseId)
    || (expected.document && canonical(checked.intent) !== canonical(expected.document))
    || (checked.operation && !matches(checked.operation, checked.intent))
    || (checked.intent.kind === 'publish' && checked.deletion_target_matches !== null)
    || checked.intent_sha256 !== await releaseIntentCommitment(checked.intent)) return refuse();
  return freeze(checked);
}
export function validateReleaseAction(document: ReleaseIntentDocument, action: ReleaseCommandAction | 'upload'): void {
  const valid = document.kind === 'delete' ? ['reserve', 'delete', 'cancel', 'cleanup']
    : document.storage_kind === 'owned' ? ['reserve', 'resume', 'publish', 'cancel', 'cleanup', 'upload']
      : ['reserve', 'publish', 'cancel', 'cleanup'];
  if (!valid.includes(action)) refuse();
}
export async function decodeReleaseCommand(raw: unknown, document: ReleaseIntentDocument, action: ReleaseCommandAction | 'upload'): Promise<ReleaseCommandObservation> {
  validateReleaseAction(document, action);
  const checked = parse(envelope, parseWire(raw, 524288));
  if (checked.operation_id !== document.operation_id || checked.release_id !== document.release_id
    || checked.result.operation_id !== checked.operation_id || checked.result.release_id !== checked.release_id
    || checked.intent_sha256 !== await releaseIntentCommitment(document)) return refuse();
  if ('decision' in checked.result && checked.result.decision !== null && checked.result.decision !== 'cancelled'
    && checked.result.decision !== (document.kind === 'publish' ? 'published' : 'deleted')) return refuse();
  const selected = action === 'cleanup' ? cleanup : action === 'resume' || action === 'upload' ? preparation
    : document.kind === 'delete' ? deletion : action === 'publish' ? publication : reservation;
  if (!selected.safeParse(checked.result).success) return refuse();
  return freeze(checked);
}
