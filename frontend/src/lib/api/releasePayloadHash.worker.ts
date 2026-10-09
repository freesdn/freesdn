// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { digestReleaseBlob } from './releasePayloadDigest';

// Avoid mixing lib.dom and lib.webworker ambient declarations in the main
// project. This module is loaded only through Vite's dedicated Worker URL.
const channel = globalThis as unknown as {
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  postMessage: (message: unknown) => void;
};
let started = false;
channel.onmessage = event => {
  if (started) return;
  started = true;
  const blob = event.data;
  if (!(blob instanceof Blob)) { channel.postMessage({ type: 'failed' }); return; }
  void digestReleaseBlob(blob, bytes => channel.postMessage({ type: 'progress', bytes }))
    .then(checksum => channel.postMessage({ type: 'complete', bytes: blob.size, checksum }))
    .catch(() => channel.postMessage({ type: 'failed' }));
};
