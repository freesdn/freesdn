// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Happy DOM presentation plus the existing Node runtime's native Fetch stack.
 * Happy DOM returns null for an empty-string Response body; native Fetch returns
 * a ReadableStream. Streaming transport tests need the actual native contract.
 * This is a per-file fixture, not browser/network/deployment acceptance.
 */
import { builtinEnvironments, type Environment } from 'vitest/runtime';

const keys = ['fetch', 'Request', 'Response', 'Headers', 'AbortController', 'AbortSignal',
  'ReadableStream', 'TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams', 'FormData', 'Blob', 'File'] as const;

export default {
  name: 'happy-dom-native-fetch',
  viteEnvironment: 'client',
  async setup(global, options) {
    const saved = keys.map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(global, key);
      if (!descriptor) throw new Error(`Native Fetch fixture requires ${key}`);
      return [key, descriptor] as const;
    });
    const dom = await builtinEnvironments['happy-dom'].setup(global, options);
    try {
      for (const [key, descriptor] of saved) Object.defineProperty(global, key, descriptor);
      const probe = new global.Response('');
      if (!(probe.body instanceof global.ReadableStream)) throw new Error('Native Fetch body probe failed');
      await probe.body.cancel();
    } catch (error) {
      await dom.teardown(global);
      throw error;
    }
    return { async teardown(target) { await dom.teardown(target); } };
  },
} satisfies Environment;
