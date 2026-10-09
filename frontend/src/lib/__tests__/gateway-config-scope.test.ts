// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, expect, it, vi } from 'vitest';
import { saveGatewayConfiguration } from '../gateway-config-download';

const ID = '12345678-1234-4123-8123-123456789abc';
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it.each([
  { scope: '/etc/config/', raw: 'owned-ascii' },
  { scope: 'sysupgrade', raw: 'owned-ascii' },
  { scope: '/etc/config/', raw: '\x1f\x8b\x00\xffowned\x00\x80' },
  { scope: 'sysupgrade', raw: '\x1f\x8b\x00\xffowned\x00\x80' },
])('downloads the explicit $scope archive without changing bytes', ({ scope, raw }) => {
  vi.useFakeTimers();
  const created = vi.fn().mockReturnValue('blob:owned-scope-check');
  const revoked = vi.fn();
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: revoked }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toBe(`freesdn-gateway-${ID}-config.tar.gz`);
  });
  saveGatewayConfiguration({ gateway_id: ID, config: { backup_data: btoa(raw), encoding: 'base64', format: 'tar.gz', scope } }, ID);
  expect(created).toHaveBeenCalledOnce();
  expect((created.mock.calls[0][0] as Blob).size).toBe(raw.length);
  expect((created.mock.calls[0][0] as Blob).type).toBe('application/gzip');
  expect(click).toHaveBeenCalledOnce();
  expect(document.querySelector('a[download]')).toBeNull();
  vi.advanceTimersByTime(1000);
  expect(revoked).toHaveBeenCalledExactlyOnceWith('blob:owned-scope-check');
});
