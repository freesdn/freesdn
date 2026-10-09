import { describe, expect, it } from 'vitest';
import { CATALOGUE_BYTES, decodeReleaseCatalogue, ReleaseCatalogueError } from '../releaseCatalogueCodec';

const high = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const low = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const stamp = '2026-01-02T03:04:05.123456Z';
const row = (id = high) => ({
  id, organization_id: null, version: '26.1', platform: 'linux', agent_type: 'daemon',
  download_url: 'https://artifact.invalid/not-verified', checksum_sha256: 'a'.repeat(64),
  signature: null as string | null, file_size: 10, release_notes: 'original', min_backend_version: '',
  is_latest: false, is_prerelease: false, published_at: stamp, download_count: 0,
});
const page = () => ({ items: [row()], limit: 2, has_more: false,
  next_published_at: null as string | null, next_id: null as string | null });
const decode = (value: unknown) => decodeReleaseCatalogue(JSON.stringify(value), { limit: 2 });

describe('bounded release catalogue observation codec', () => {
  it('preserves text and records signatures without creating verification or mutation grants', () => {
    const value = page();
    value.items[0].signature = 'recorded-but-not-verified';
    value.items[0].release_notes = '<script>alert(1)</script> 🚀';
    const decoded = decode(value);
    expect(decoded).toEqual(value);
    expect(Object.isFrozen(decoded)).toBe(true);
    expect(Object.isFrozen(decoded.items)).toBe(true);
    expect(Object.isFrozen(decoded.items[0])).toBe(true);
    expect(decoded.items[0]).not.toHaveProperty('verified');
    expect(decoded).not.toHaveProperty('authorization_granted');
  });

  it('preserves all twenty thousand astral characters, matching the server code-point limit', () => {
    const value = page(); value.items[0].release_notes = '🚀'.repeat(20000);
    expect(decode(value).items[0].release_notes).toBe(value.items[0].release_notes);
  });

  it('accepts the exact descending UUID continuation at equal timestamps', () => {
    const value = page(); value.items.push(row(low)); value.has_more = true;
    value.next_id = low; value.next_published_at = stamp;
    expect(decode(value)).toEqual(value);
  });

  it('compares microseconds rather than rounding timestamps to milliseconds', () => {
    const value = page(); value.items.push({ ...row(low), published_at: '2026-01-02T03:04:05.123455Z' });
    expect(decode(value)).toEqual(value);
    value.items[1].published_at = '2026-01-02T03:04:05.123457Z';
    expect(() => decode(value)).toThrow(ReleaseCatalogueError);
  });

  it('accepts an empty terminal page with no synthetic cursor', () => {
    const value = page(); value.items = [];
    expect(decode(value)).toEqual(value);
  });

  it('requires every returned record to precede the captured request cursor', () => {
    const value = page(); value.items[0].id = low;
    const position = { limit: 2, before_id: high, before_published_at: stamp };
    expect(decodeReleaseCatalogue(JSON.stringify(value), position)).toEqual(value);
    value.items[0].id = high;
    expect(() => decodeReleaseCatalogue(JSON.stringify(value), position)).toThrow(ReleaseCatalogueError);
  });

  it.each([
    { limit: 0 }, { limit: 101 }, { limit: 1 }, { limit: 2, before_id: high },
    { limit: 2, before_published_at: stamp }, { limit: 2, before_id: 'invalid', before_published_at: stamp },
  ])('refuses an invalid or mismatched request position %j', position => {
    expect(() => decodeReleaseCatalogue(JSON.stringify(page()), position)).toThrow(ReleaseCatalogueError);
  });

  it.each([
    ['items', null], ['limit', '2'], ['has_more', 'false'], ['next_id', high], ['next_published_at', stamp],
    ['extra', true],
  ])('rejects malformed page field %s', (field, value) => {
    expect(() => decode({ ...page(), [String(field)]: value })).toThrow(ReleaseCatalogueError);
  });

  it.each([
    ['file_size', -1], ['file_size', 10737418241], ['file_size', 1.5], ['file_size', '10'],
    ['download_count', -1], ['download_count', 2147483648], ['is_latest', 1], ['signature', false],
    ['organization_id', 'not-an-id'], ['published_at', '2026-02-30T03:04:05Z'],
    ['published_at', '2026-01-02T03:04:05'], ['version', 'x'.repeat(51)], ['signature', 'x'.repeat(4097)],
    ['release_notes', 'x'.repeat(20001)], ['release_notes', '\ud800'], ['release_notes', '\0'],
  ])('rejects malformed record field %s without including source data in errors', (field, value) => {
    const input = page(); input.items[0] = { ...row(), [String(field)]: value };
    expect(() => decode(input)).toThrow(ReleaseCatalogueError);
    try { decode(input); } catch (error) {
      expect((error as Error).message).toBe('Release catalogue could not be validated. Refresh after reviewing the current account.');
    }
  });

  it.each(Object.keys(row()))('requires recorded field %s even when nullable', field => {
    const value = page(); const malformed = { ...row() } as Record<string, unknown>;
    delete malformed[field];
    expect(() => decode({ ...value, items: [malformed] })).toThrow(ReleaseCatalogueError);
  });

  it.each([
    '{"items":[],"items":[],"limit":2,"has_more":false,"next_id":null,"next_published_at":null}',
    '{"items":[],"it\\u0065ms":[],"limit":2,"has_more":false,"next_id":null,"next_published_at":null}',
    '{"items":[],"limit":2e0,"has_more":false,"next_id":null,"next_published_at":null}',
    '{"items":[],"limit":02,"has_more":false,"next_id":null,"next_published_at":null}',
    '{"items":[],"limit":2,"has_more":false,"next_id":null,"next_published_at":null,}',
    '{"items":[],"limit":2,"has_more":false,"next_id":null,"next_published_at":null} trailing',
  ])('rejects ambiguous or noncanonical JSON %s', raw => {
    expect(() => decodeReleaseCatalogue(raw, { limit: 2 })).toThrow(ReleaseCatalogueError);
  });

  it('rejects duplicate record IDs and out-of-order records', () => {
    const value = page(); value.items.push(row());
    expect(() => decode(value)).toThrow(ReleaseCatalogueError);
    value.items = [row(low), row(high)];
    expect(() => decode(value)).toThrow(ReleaseCatalogueError);
  });

  it('does not accept a misleading continuation or an undersized nonterminal page', () => {
    const value = page(); value.has_more = true; value.next_id = high; value.next_published_at = stamp;
    expect(() => decode(value)).toThrow(ReleaseCatalogueError);
    value.items.push(row(low));
    expect(() => decode(value)).toThrow(ReleaseCatalogueError);
    value.next_id = low;
    expect(decode(value)).toEqual(value);
  });

  it('refuses more than one hundred records and oversized raw bytes', () => {
    const value = { ...page(), limit: 100, items: Array.from({ length: 101 }, () => row()) };
    expect(() => decodeReleaseCatalogue(JSON.stringify(value), { limit: 100 })).toThrow(ReleaseCatalogueError);
    expect(() => decodeReleaseCatalogue(' '.repeat(CATALOGUE_BYTES + 1), { limit: 2 })).toThrow(ReleaseCatalogueError);
  });
});
