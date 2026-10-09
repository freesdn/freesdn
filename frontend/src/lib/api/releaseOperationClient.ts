// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** PRIVATE deliberate actions. Not imported by public UI; no durable storage. */
import { beginReleaseOperationAction, ReleaseTransportError, type ReleaseCommandAction } from './releaseOperationTransport';
import { decodeReleaseCommand, decodeReleaseIntent, decodeReleaseReview, decodeReleaseStatus,
  releaseIdentity, releaseIntentCommitment, validateReleaseAction, type ReleaseIntentDocument } from './releaseOperationCodec';

export type ReleaseRequestSelection =
  | { kind: 'command'; rawIntent: string; action: ReleaseCommandAction }
  | { kind: 'upload'; rawIntent: string; file: Blob }
  | { kind: 'review'; rawIntent: string }
  | { kind: 'inspect'; operationId: string }
  | { kind: 'deletion-review'; operationId: string; releaseId: string };

/** Call synchronously at the user interaction, never in a retried/queued task.
 * Input values and a Blob slice are captured now. A future execute() takes only
 * a cancellation signal; it cannot change the chosen action, document or file.
 * Saving originalIntent is an explicit caller workflow, not a claim of durable
 * retention. Dispose on teardown and check current context before later display.
 */
export function captureReleaseRequest(selection: ReleaseRequestSelection) {
  const transport = beginReleaseOperationAction();
  try {
    const kind = selection.kind;
    if (!['command', 'upload', 'review', 'inspect', 'deletion-review'].includes(kind)) throw new ReleaseTransportError('not-issued');
    const raw = 'rawIntent' in selection ? selection.rawIntent : undefined;
    const document = raw === undefined ? undefined : decodeReleaseIntent(raw);
    const action = selection.kind === 'command' ? selection.action : selection.kind === 'upload' ? 'upload' : undefined;
    const operationId = document?.operation_id ?? releaseIdentity('operationId' in selection ? selection.operationId : undefined);
    const releaseId = document?.release_id ?? (selection.kind === 'deletion-review' ? releaseIdentity(selection.releaseId) : undefined);
    if (kind === 'command' || kind === 'upload') validateReleaseAction(document!, action!);
    let file: Blob | undefined;
    if (selection.kind === 'upload') {
      const selectedFile = selection.file;
      if (!(selectedFile instanceof Blob) || document?.kind !== 'publish' || document.storage_kind !== 'owned'
        || selectedFile.size !== document.metadata.file_size) throw new ReleaseTransportError('not-issued');
      // Blob contents are immutable. Do not retain a mutable FileList/input or
      // buffer the complete file in memory. Server verification remains required.
      file = Blob.prototype.slice.call(selectedFile, 0, selectedFile.size, 'application/octet-stream');
    }
    const snapshot = Object.freeze({ kind, operationId, releaseId, action, originalIntent: raw, document });
    let attempted = false;
    const inspect = async (signal?: AbortSignal) => {
      const response = await transport.inspect(operationId, signal);
      try {
        const observation = decodeReleaseStatus(response, operationId, document);
        transport.assertCurrent();
        return observation;
      } catch { throw new ReleaseTransportError('unconfirmed'); }
    };
    return Object.freeze({
      snapshot, assertCurrent: transport.assertCurrent, dispose: transport.dispose, inspect,
      async execute(signal?: AbortSignal) {
        transport.assertCurrent();
        if (attempted || signal?.aborted) throw new ReleaseTransportError('not-issued');
        attempted = true;
        let issued = false;
        try {
          // Validate/hash before any request; never start a mutation as a side
          // effect of constructing the action or reading the retained snapshot.
          if (document) await releaseIntentCommitment(document);
          transport.assertCurrent();
          if (signal?.aborted) throw new ReleaseTransportError('not-issued');
          let observation;
          if (kind === 'inspect') return await inspect(signal);
          if (kind === 'deletion-review') {
            const response = await transport.reviewDeletion(releaseId!, operationId, signal); issued = true;
            observation = await decodeReleaseReview(response, { operationId, releaseId: releaseId! });
            if (observation.intent.kind !== 'delete') throw new ReleaseTransportError('unconfirmed');
          } else if (kind === 'review') {
            const response = await transport.review(raw!, signal); issued = true;
            observation = await decodeReleaseReview(response, { operationId, releaseId: releaseId!, document });
          } else {
            const response = kind === 'upload' ? await transport.upload(operationId, raw!, file!, signal)
              : await transport.command(operationId, action as ReleaseCommandAction, raw!, signal);
            issued = true;
            observation = await decodeReleaseCommand(response, document as ReleaseIntentDocument, action!);
          }
          // Async commitment validation itself yields. A response that was valid
          // before that wait must not be disclosed to a changed local context.
          transport.assertCurrent();
          return observation;
        } catch (error) {
          if (error instanceof ReleaseTransportError) throw new ReleaseTransportError(issued ? 'unconfirmed' : error.outcome, error.status);
          throw new ReleaseTransportError(issued ? 'unconfirmed' : 'not-issued');
        }
      },
    });
  } catch {
    transport.dispose();
    throw new ReleaseTransportError('not-issued');
  }
}
