// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { saveGatewayConfiguration } from '../gateway-config-download';

const ID = '12345678-1234-4123-8123-123456789abc';
const wrap = (config: unknown) => ({ gateway_id: ID, config });
const archive = { backup_data: 'b3duZWQ=', encoding: 'base64', format: 'tar.gz', scope: '/etc/config/' };
const MAX = 16 * 1024 * 1024;
let created: ReturnType<typeof vi.fn>;
let revoked: ReturnType<typeof vi.fn>;
let click: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.useFakeTimers();
  created = vi.fn().mockReturnValue('blob:owned-sensitive-file');
  revoked = vi.fn();
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: revoked }));
  click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('gateway export validation and browser resource cleanup', () => {
  const invalid = [undefined, null, [], {}, wrap(null), wrap([]), wrap({}),
    wrap({ config_xml: '' }), wrap({ config_xml: ' ' }), wrap({ config_xml: 1 }),
    wrap({ config_xml: true }), wrap({ config_xml: '<config/>', ...archive }),
    { gateway_id: '../private', config: { config_xml: '<config/>' } },
  ];
  it.each(invalid.map((data, index) => ({ data, index })))('refuses malformed envelope $index before creating a URL', ({ data }) => {
    expect(() => saveGatewayConfiguration(data, ID)).toThrow('Configuration download is unavailable');
    expect(created).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  const badArchives = [
    { encoding: undefined }, { encoding: 'utf8' }, { format: 'zip' }, { scope: '/' },
    { backup_data: '' }, { backup_data: '!!!!' }, { backup_data: 'b3duZWQ' },
    { backup_data: 'AB==' }, { backup_data: 'b3du\nZWQ=' }, { backup_data: 1 },
  ];
  it.each(badArchives.map((fields, index) => ({ fields, index })))('refuses invalid or noncanonical base64 archive $index', ({ fields }) => {
    expect(() => saveGatewayConfiguration(wrap({ ...archive, ...fields }), ID)).toThrow();
    expect(created).not.toHaveBeenCalled();
  });

  it.each(['oversize-ascii', 'oversize-utf8', 'unpaired-surrogate'])('refuses invalid text encoding/size: %s', (kind) => {
    const config_xml = kind === 'oversize-ascii' ? 'x'.repeat(MAX + 1)
      : kind === 'oversize-utf8' ? 'α'.repeat(MAX / 2 + 1) : '<config>\ud800</config>';
    expect(() => saveGatewayConfiguration(wrap({ config_xml }), ID)).toThrow();
    expect(created).not.toHaveBeenCalled();
  });

  it('rejects an encoded archive larger than the decoded byte limit', () => {
    const encoded = btoa('x'.repeat(MAX + 1));
    expect(() => saveGatewayConfiguration(wrap({ ...archive, backup_data: encoded }), ID)).toThrow();
    expect(created).not.toHaveBeenCalled();
  });

  it.each(['xml', 'archive'])('accepts the documented byte limit for %s', (kind) => {
    const bytes = 'x'.repeat(MAX);
    const config = kind === 'xml' ? { config_xml: bytes } : { ...archive, backup_data: btoa(bytes) };
    saveGatewayConfiguration(wrap(config), ID);
    expect(created).toHaveBeenCalledOnce();
    expect((created.mock.calls[0][0] as Blob).size).toBe(MAX);
    expect(click).toHaveBeenCalledOnce();
  });

  it('uses a fixed filename and releases the object URL after the browser click', () => {
    let filename: string | undefined;
    click.mockImplementation(function (this: HTMLAnchorElement) { filename = this.download; });
    saveGatewayConfiguration({ ...wrap({ config_xml: '<config/>' }), vendor: '../../evil', filename: 'evil.html' }, ID.toUpperCase());
    expect(filename).toBe(`freesdn-gateway-${ID}-config.xml`);
    expect(document.querySelector('a[download]')).toBeNull();
    expect(revoked).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(revoked).toHaveBeenCalledExactlyOnceWith('blob:owned-sensitive-file');
  });

  it.each(['click', 'append'])('releases the URL immediately when browser %s fails', (kind) => {
    const fail = () => { throw new Error('owned-browser-failure'); };
    if (kind === 'click') click.mockImplementation(fail);
    else vi.spyOn(document.body, 'append').mockImplementation(fail);
    expect(() => saveGatewayConfiguration(wrap({ config_xml: '<config/>' }), ID)).toThrow();
    expect(revoked).toHaveBeenCalledExactlyOnceWith('blob:owned-sensitive-file');
    expect(document.querySelector('a[download]')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
});
