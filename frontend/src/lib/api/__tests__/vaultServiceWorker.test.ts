/// <reference types="node" />
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Actual worker fetch-listener code with controlled globals, not a browser. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import { describe, it } from 'vitest';

const source = readFileSync(resolve('public/sw.js'), 'utf8');
const cases = [
  ['callback-html-offline', '/vault-export-callback.html?state=owned-state&code=owned-code', 'navigate', 'GET', true, 'bypass'],
  ['callback-script-offline', '/vault-export-callback.js', 'navigate', 'GET', true, 'bypass'],
  ['ordinary-navigation-offline', '/backups', 'navigate', 'GET', true, 'shell'],
  ['ordinary-navigation-online', '/backups', 'navigate', 'GET', false, 'network'],
  ['API-bypass', '/api/v1/backups', 'navigate', 'GET', true, 'bypass'],
  ['cross-origin-bypass', 'https://other.example/path', 'navigate', 'GET', true, 'bypass'],
  ['POST-bypass', '/backups', 'navigate', 'POST', true, 'bypass'],
  ['hashed-asset-cache', '/assets/owned-hash.js', 'script', 'GET', false, 'asset'],
] as const;
type Request = { method: string; mode: string; url: string };
type Event = { request: Request; respondWith: (value: Promise<unknown>) => void };

describe('vault callback service-worker exclusion', () => {
  it.each(cases)('%s', async (_name, target, mode, method, offline, expected) => {
    const listeners = new Map<string, (event: Event) => void>(); const calls: string[][] = [];
    const shell = { owned: 'cached-shell' }; const asset = { owned: 'cached-asset' };
    const network = { ok: true, owned: 'network', clone: () => ({ owned: 'cloned-network' }) };
    runInNewContext(source, {
      self: { location: { origin: 'https://owned-ui.example' }, addEventListener: (name: string, handler: (event: Event) => void) => listeners.set(name, handler) },
      URL, Promise,
      fetch: async (request: Request) => { calls.push(['fetch', request.url]); if (offline) throw new Error('Owned offline boundary'); return network; },
      caches: {
        match: async (key: string) => { calls.push(['shell-cache', key]); return shell; },
        open: async (key: string) => { calls.push(['asset-cache', key]); return {
          match: async () => asset, put: (request: Request) => { calls.push(['asset-put', request.url]); },
        }; },
      },
    }, { timeout: 1000 });
    const result: { response: Promise<unknown> | null; responded: boolean } = { response: null, responded: false };
    const request = { method, mode, url: new URL(target, 'https://owned-ui.example').href };
    const event = { request, respondWith: (value: Promise<unknown>) => { assert.equal(result.responded, false); result.responded = true; result.response = Promise.resolve(value); } };
    const handler = listeners.get('fetch'); assert.equal(typeof handler, 'function'); handler!(event);
    const returned = result.response ? await result.response : undefined;
    await Promise.resolve(); await Promise.resolve();
    if (expected === 'bypass') { assert.equal(result.responded, false, 'sensitive/non-SPA request must not enter offline fallback'); assert.deepEqual(calls, []); }
    if (expected === 'shell') { assert.equal(result.responded, true); assert.equal(returned, shell); assert.equal(calls.filter(v => v[0] === 'fetch').length, 1); assert.ok(calls.some(v => v[0] === 'shell-cache' && v[1] === '/index.html')); }
    if (expected === 'network') { assert.equal(result.responded, true); assert.equal(returned, network); assert.equal(calls.filter(v => v[0] === 'shell-cache').length, 0); }
    if (expected === 'asset') { assert.equal(returned, asset); assert.ok(calls.some(v => v[0] === 'asset-put')); }
  });
});
