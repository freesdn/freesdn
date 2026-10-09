// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE local operator workflow. File readback is not a future durability,
 * backup, filesystem-sync or server authorization guarantee. No localStorage,
 * credentials, server document persistence or automatic request replay.
 */
import { useAuthStore } from '@/stores/authStore';
import { captureReleaseRequest } from './releaseOperationClient';
import { decodeReleaseIntent, releaseIntentCommitment } from './releaseOperationCodec';
import { beginReleaseOperationAction, ReleaseTransportError, type ReleaseCommandAction } from './releaseOperationTransport';

export class ReleaseIntentFileError extends Error {
  constructor() { super('The intent file could not be verified. This file action did not send a release request.'); this.name = 'ReleaseIntentFileError'; }
}
type Context = ReturnType<typeof beginReleaseOperationAction>;
export type ReleaseRecoveryAction = ReleaseCommandAction | 'upload';
const MAX_BYTES = 307200;
const FILE_DEADLINE_MS = 10000;
const LIFETIME_MS = 600000;

/** FileReader buffers at most the already-checked 300 KiB document, never the
 * binary release payload. Fatal UTF-8 decoding preserves BOM for codec refusal.
 */
function readFile(file: File, signal: AbortSignal): Promise<string> {
  if (!(file instanceof File) || file.size < 1 || file.size > MAX_BYTES || signal.aborted) {
    return Promise.reject(new ReleaseIntentFileError());
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    let settled = false;
    const finish = (raw?: string) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal.removeEventListener('abort', abort);
      reader.onload = null; reader.onerror = null; reader.onabort = null;
      if (raw === undefined) reject(new ReleaseIntentFileError()); else resolve(raw);
    };
    const abort = () => { finish(); reader.abort(); };
    const timer = setTimeout(abort, FILE_DEADLINE_MS);
    signal.addEventListener('abort', abort, { once: true });
    reader.onerror = () => finish(); reader.onabort = () => finish();
    reader.onload = () => {
      try {
        const result = reader.result;
        if (signal.aborted || !(result instanceof ArrayBuffer) || result.byteLength !== file.size || result.byteLength > MAX_BYTES) return finish();
        finish(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(result));
      } catch { finish(); }
    };
    try { reader.readAsArrayBuffer(file); } catch { finish(); }
  });
}

function buildSession(raw: string, context: Context, initiallyVerified: boolean) {
  const document = decodeReleaseIntent(raw);
  let closed = false;
  let busy = false;
  let verified = initiallyVerified;
  let downloadIssued = false;
  let inspectionRequired = false;
  let reviewed = false;
  let journalObserved = false;
  let readController: AbortController | undefined;
  const children = new Set<ReturnType<typeof captureReleaseRequest>>();
  const listeners = new Set<() => void>();
  const urls = new Map<string, ReturnType<typeof setTimeout>>();
  let unsubscribe: () => void = () => undefined;
  let lifetime: ReturnType<typeof setTimeout> | undefined;
  const notify = () => { for (const listener of listeners) { try { listener(); } catch { /* Observers must not interrupt cleanup. */ } } };
  const dispose = () => {
    if (closed) return;
    closed = true; verified = false; busy = false; readController?.abort();
    context.dispose(); unsubscribe(); if (lifetime !== undefined) clearTimeout(lifetime);
    for (const child of children) child.dispose(); children.clear();
    for (const [url, timer] of urls) { clearTimeout(timer); URL.revokeObjectURL(url); } urls.clear();
    notify(); listeners.clear();
  };
  const assertCurrent = () => {
    if (closed) throw new ReleaseTransportError('not-issued');
    try { context.assertCurrent(); } catch { dispose(); throw new ReleaseTransportError('not-issued'); }
  };
  const releaseURL = (url: string) => {
    const timer = urls.get(url); if (timer !== undefined) clearTimeout(timer);
    urls.delete(url); URL.revokeObjectURL(url);
  };
  try {
    unsubscribe = useAuthStore.subscribe(() => { try { assertCurrent(); } catch { dispose(); } });
    lifetime = setTimeout(dispose, LIFETIME_MS); assertCurrent();
  } catch { dispose(); throw new ReleaseTransportError('not-issued'); }

  const capture = (kind: 'review' | 'inspect' | 'mutation', action?: ReleaseRecoveryAction, file?: Blob) => {
    assertCurrent();
    if (busy || (kind === 'mutation' && (!verified || !reviewed || inspectionRequired || (action !== 'reserve' && !journalObserved)))) throw new ReleaseTransportError('not-issued');
    const child = captureReleaseRequest(kind !== 'mutation' ? { kind: 'review', rawIntent: raw }
      : action === 'upload' ? { kind: 'upload', rawIntent: raw, file: file! }
        : { kind: 'command', rawIntent: raw, action: action as ReleaseCommandAction });
    children.add(child);
    let attempted = false;
    const cancel = () => { child.dispose(); children.delete(child); };
    return Object.freeze({
      dispose: cancel,
      async execute(signal?: AbortSignal) {
        assertCurrent();
        if (attempted || busy || signal?.aborted || (kind === 'mutation' && (!verified || !reviewed || inspectionRequired || (action !== 'reserve' && !journalObserved)))) {
          cancel(); throw new ReleaseTransportError('not-issued');
        }
        attempted = true; busy = true; notify();
        let received = false;
        try {
          const observation = kind === 'inspect' ? await child.inspect(signal) : await child.execute(signal);
          received = true; assertCurrent();
          // A missing journal row is not permission to replay after an unknown
          // outcome. Keep the explicit recovery requirement in that case.
          if (kind !== 'mutation' && 'operation' in observation) {
            journalObserved = observation.operation !== null;
            if (kind === 'review') reviewed = true;
            if (journalObserved) inspectionRequired = false;
          } else if (kind === 'mutation') journalObserved = true;
          return observation;
        } catch (error) {
          const outcome = received || !(error instanceof ReleaseTransportError) ? 'unconfirmed' : error.outcome;
          if (kind === 'mutation' && outcome === 'unconfirmed') inspectionRequired = true;
          throw new ReleaseTransportError(outcome, error instanceof ReleaseTransportError ? error.status : undefined);
        } finally { cancel(); busy = false; if (!closed) notify(); }
      },
    });
  };

  return Object.freeze({
    dispose, assertCurrent,
    subscribe(listener: () => void) {
      if (closed) { try { listener(); } catch { /* No retained observer on a closed session. */ } return () => undefined; }
      listeners.add(listener); return () => { listeners.delete(listener); };
    },
    getState() {
      try { assertCurrent(); } catch { return Object.freeze({ closed: true as const }); }
      return Object.freeze({ closed: false as const, document, busy, fileVerified: verified, downloadIssued, inspectionRequired, reviewed, journalObserved });
    },
    download() {
      assertCurrent(); if (busy) throw new ReleaseIntentFileError();
      let url: string | undefined;
      let anchor: HTMLAnchorElement | undefined;
      try {
        url = URL.createObjectURL(new Blob([raw], { type: 'application/json;charset=utf-8' }));
        anchor = window.document.createElement('a'); anchor.href = url;
        anchor.download = `freesdn-release-intent-${document.operation_id}.json`; anchor.rel = 'noopener';
        window.document.body.appendChild(anchor); assertCurrent(); anchor.click(); assertCurrent();
        urls.set(url, setTimeout(() => releaseURL(url!), 60000)); downloadIssued = true;
        // This only records browser dispatch. It must NOT set fileVerified.
        notify();
      } catch {
        if (url) releaseURL(url); throw new ReleaseIntentFileError();
      } finally { anchor?.remove(); }
    },
    async verifySelectedFile(file: File, signal?: AbortSignal) {
      assertCurrent(); if (busy || signal?.aborted) throw new ReleaseIntentFileError();
      const selected = file; // exact initiating selection, never reread FileList
      busy = true; verified = false; const controller = new AbortController(); readController = controller;
      const abort = () => controller.abort(); signal?.addEventListener('abort', abort, { once: true }); notify();
      try {
        const text = await readFile(selected, controller.signal); assertCurrent();
        const imported = decodeReleaseIntent(text);
        const actual = await releaseIntentCommitment(imported); assertCurrent();
        const expected = await releaseIntentCommitment(document); assertCurrent();
        if (controller.signal.aborted || actual !== expected) throw new ReleaseIntentFileError();
        verified = true;
      } catch { throw new ReleaseIntentFileError(); }
      finally { signal?.removeEventListener('abort', abort); readController = undefined; busy = false; if (!closed) notify(); }
    },
    captureReview() { return capture('review'); },
    captureInspection() { return capture('inspect'); },
    captureMutation(action: ReleaseRecoveryAction, typedOperationId: string, file?: Blob) {
      assertCurrent();
      if (typedOperationId !== document.operation_id) throw new ReleaseTransportError('not-issued');
      // Local readback/typed confirmation are usability safeguards, not server
      // authority. The client and each server phase still validate authority.
      return capture('mutation', action, file);
    },
  });
}
export type ReleaseIntentRetention = ReturnType<typeof buildSession>;

export function beginReleaseIntentRetention(raw: string): ReleaseIntentRetention {
  const context = beginReleaseOperationAction();
  try { return buildSession(raw, context, false); } catch { context.dispose(); throw new ReleaseIntentFileError(); }
}

/** Call at the actual file selection event. Captures context/file before waiting.
 * A file read from the picker is evidence of a readable matching document now,
 * not future disk survival, trustworthy provenance or authorization to replay.
 */
export async function importReleaseIntentFile(file: File, signal?: AbortSignal): Promise<ReleaseIntentRetention> {
  const context = beginReleaseOperationAction();
  const controller = new AbortController(); const abort = () => controller.abort();
  const unsubscribe = useAuthStore.subscribe(() => { try { context.assertCurrent(); } catch { controller.abort(); } });
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const raw = await readFile(file, controller.signal); context.assertCurrent();
    await releaseIntentCommitment(decodeReleaseIntent(raw)); context.assertCurrent();
    if (controller.signal.aborted) throw new ReleaseIntentFileError();
    return buildSession(raw, context, true);
  } catch { context.dispose(); throw new ReleaseIntentFileError(); }
  finally { unsubscribe(); signal?.removeEventListener('abort', abort); }
}
