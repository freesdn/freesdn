// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Planned wire/commitment cases, not external server or browser acceptance. */
/// <reference types="node" />
import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeReleaseCommand, decodeReleaseIntent, decodeReleaseReview, decodeReleaseStatus, releaseIntentCommitment,
  ReleaseCodecError } from '../releaseOperationCodec';
import vectors from './releaseCommitmentVectors.json';

beforeEach(() => { vi.stubGlobal('crypto', webcrypto); });
afterEach(() => { vi.unstubAllGlobals(); });

const actor = '11111111-1111-4111-8111-111111111111';
const source = JSON.parse(vectors[0].raw);
const document = decodeReleaseIntent(vectors[0].raw);
const digest = vectors[0].intent_sha256;
const noAuthority = { storage_checked: false, all_artifact_references_checked: false,
  authorization_granted: false, absence_authorizes_retry_or_cleanup: false };
function journal() {
  return { operation_id: document.operation_id, release_id: document.release_id, organization_id: document.organization_id,
    requested_by: actor, last_transition_by: actor, kind: 'publish', storage_kind: 'owned', phase: 'reserved',
    decision: null, transition_sequence: 0, created_at: '2026-01-01T00:00:00Z', prepared_at: null, decided_at: null, cleaned_at: null };
}
function status() { return { ...noAuthority, operation: journal(), release_row_present: false, observed_at: '2026-01-01T00:00:01Z' }; }
function review() {
  return { ...status(), intent: source, intent_sha256: digest, deletion_target_matches: null,
    historical_observation: true, reservation_created: false, server_retains_full_intent: false,
    save_original_intent_before_mutation: true, retry_requires_identical_intent_and_current_authority: true };
}
function reservation() {
  return { operation_id: document.operation_id, release_id: document.release_id, phase: 'reserved', decision: null,
    created: true, requested_by: actor, last_transition_by: actor };
}
function envelope(result: unknown = reservation()) {
  return { operation_id: document.operation_id, release_id: document.release_id, intent_sha256: digest,
    historical_observation: true, authorization_granted: false, retry_requires_identical_intent_and_current_authority: true, result };
}

describe('complete retained release intent', () => {
  it.each([0, 1, 2, 3, 4, 5, 6, 7])('matches independent Python canonical commitment vector %s', async index => {
    const checked = decodeReleaseIntent(vectors[index].raw);
    expect(await releaseIntentCommitment(checked)).toBe(vectors[index].intent_sha256);
    expect(checked).toEqual(JSON.parse(vectors[index].raw));
    expect(Object.isFrozen(checked)).toBe(true);
    expect(Object.isFrozen(checked.metadata)).toBe(true);
  });

  it.each([
    'root-duplicate', 'escaped-duplicate', 'unknown-field', 'lone-surrogate', 'nul-text', 'numeric-boolean', 'float-size',
    'exponent-size', 'overflow-size', 'identity-newline', 'checksum-newline', 'version-newline', 'owned-url', 'external-filename',
    'too-many-astral', 'deep-object', 'oversize-wire', 'bad-json', 'array-root',
  ])('refuses ambiguous or invalid retained input %s without input disclosure', which => {
    const value = structuredClone(source);
    let raw: string | undefined;
    if (which === 'root-duplicate') raw = vectors[0].raw.replace('{', '{"kind":"delete",');
    if (which === 'escaped-duplicate') raw = vectors[0].raw.replace('"version":', '"ver\\u0073ion":"2.0.0","version":');
    if (which === 'unknown-field') value.authority = 'synthetic-private-marker';
    if (which === 'lone-surrogate') value.metadata.release_notes = '\ud800';
    if (which === 'nul-text') value.metadata.release_notes = '\0';
    if (which === 'numeric-boolean') value.metadata.is_latest = 1;
    if (which === 'float-size') raw = vectors[0].raw.replace('"file_size": 3', '"file_size": 3.0');
    if (which === 'exponent-size') raw = vectors[0].raw.replace('"file_size": 3', '"file_size": 3e0');
    if (which === 'overflow-size') value.metadata.file_size = 524288001;
    if (which === 'identity-newline') value.operation_id += '\n';
    if (which === 'checksum-newline') value.metadata.checksum_sha256 += '\n';
    if (which === 'version-newline') value.metadata.version += '\n';
    if (which === 'owned-url') value.metadata.download_url = '/api/v1/agents/releases/other/binary';
    if (which === 'external-filename') value.storage_kind = 'external';
    if (which === 'too-many-astral') value.metadata.release_notes = '😀'.repeat(20001);
    if (which === 'deep-object') raw = '{"x":'.repeat(10) + '0' + '}'.repeat(10);
    if (which === 'oversize-wire') raw = ' '.repeat(307201);
    if (which === 'bad-json') raw = '{"synthetic-private-marker":';
    if (which === 'array-root') raw = '[]';
    expect(() => decodeReleaseIntent(raw ?? JSON.stringify(value))).toThrow(ReleaseCodecError);
    try { decodeReleaseIntent(raw ?? JSON.stringify(value)); } catch (error) {
      expect(String(error)).not.toContain('synthetic-private-marker');
      expect(error).not.toHaveProperty('issues');
      expect(error).not.toHaveProperty('cause');
    }
  });

  it.each(['2026-02-30T00:00:00+00:00', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000+00:00',
    '2026-01-01T00:00:00.12+00:00', '2026-01-01T00:00:00+01:00', '2026-01-01T00:00:00+00:00\n'])(
    'refuses noncanonical historical timestamp %s instead of silently changing its commitment', stamp => {
      const value = JSON.parse(vectors[5].raw); value.metadata.published_at = stamp;
      expect(() => decodeReleaseIntent(JSON.stringify(value))).toThrow(ReleaseCodecError);
    });
});

describe('bound historical observations', () => {
  it('retains a complete immutable status with no retry or cleanup grant', () => {
    const checked = decodeReleaseStatus(JSON.stringify(status()), document.operation_id, document);
    expect(checked).toEqual(status());
    expect(Object.isFrozen(checked.operation)).toBe(true);
    expect(checked.absence_authorizes_retry_or_cleanup).toBe(false);
  });
  it.each(['missing-flag', 'numeric-flag', 'extra-field', 'wrong-operation', 'wrong-organization', 'phase-mismatch',
    'rewound-microsecond', 'wrong-decision', 'published-cleaned', 'malformed-date', 'duplicate-field'])(
    'refuses incomplete or internally inconsistent status %s', which => {
      const value = JSON.parse(JSON.stringify(status()));
      if (which === 'missing-flag') delete value.storage_checked;
      if (which === 'numeric-flag') value.authorization_granted = 0;
      if (which === 'extra-field') value.future_authority = true;
      if (which === 'wrong-operation') value.operation.operation_id = actor;
      if (which === 'wrong-organization') value.operation.organization_id = actor;
      if (which === 'phase-mismatch') value.operation.phase = 'prepared';
      if (which === 'rewound-microsecond') Object.assign(value.operation, { phase: 'prepared', transition_sequence: 1,
        created_at: '2026-01-01T00:00:00.000002Z', prepared_at: '2026-01-01T00:00:00.000001Z' });
      if (which === 'wrong-decision') Object.assign(value.operation, { phase: 'decided', transition_sequence: 2,
        prepared_at: value.operation.created_at, decided_at: value.operation.created_at, decision: 'deleted' });
      if (which === 'published-cleaned') Object.assign(value.operation, { phase: 'cleaned', transition_sequence: 3,
        prepared_at: value.operation.created_at, decided_at: value.operation.created_at, cleaned_at: value.operation.created_at, decision: 'published' });
      if (which === 'malformed-date') value.observed_at = '2026-02-30T00:00:00Z';
      const raw = which === 'duplicate-field' ? JSON.stringify(value).replace('{', '{"storage_checked":true,') : JSON.stringify(value);
      expect(() => decodeReleaseStatus(raw, document.operation_id, document)).toThrow(ReleaseCodecError);
    });
  it('validates exact review commitment without turning absent history into permission', async () => {
    const value = review();
    const checked = await decodeReleaseReview(JSON.stringify(value), { operationId: document.operation_id, releaseId: document.release_id, document });
    expect(checked).toEqual(value);
    expect(checked.reservation_created).toBe(false);
    expect(checked.server_retains_full_intent).toBe(false);
  });
  it.each(['digest', 'metadata', 'journal', 'storage', 'target', 'missing-retention-flag'])(
    'refuses review mismatch %s', async which => {
      const value = JSON.parse(JSON.stringify(review()));
      if (which === 'digest') value.intent_sha256 = 'a'.repeat(64);
      if (which === 'metadata') value.intent.metadata.release_notes = 'changed';
      if (which === 'journal') value.operation.release_id = actor;
      if (which === 'storage') value.operation.storage_kind = 'external';
      if (which === 'target') value.deletion_target_matches = true;
      if (which === 'missing-retention-flag') delete value.save_original_intent_before_mutation;
      await expect(decodeReleaseReview(JSON.stringify(value), { operationId: document.operation_id, releaseId: document.release_id, document })).rejects.toThrow(ReleaseCodecError);
    });
  it('validates a matching acknowledged reservation as history only', async () => {
    const checked = await decodeReleaseCommand(JSON.stringify(envelope()), document, 'reserve');
    expect(checked).toEqual(envelope()); expect(Object.isFrozen(checked.result)).toBe(true);
    expect(checked.authorization_granted).toBe(false);
  });
  it.each(['resume', 'upload', 'publish', 'cancel', 'cleanup'] as const)(
    'accepts the matching complete %s result without upgrading its authority', async action => {
      const ids = { operation_id: document.operation_id, release_id: document.release_id };
      const result = action === 'resume' || action === 'upload'
        ? { ...ids, phase: 'prepared', requested_by: actor, last_transition_by: actor, publication_or_storage_authorized: false }
        : action === 'publish'
          ? { ...ids, decision: 'published', newly_published: false, release_row_present: false, current_is_latest: null,
            artifact_verified_this_call: false, signature_verified_this_call: false, publication_or_storage_authorized: false }
          : action === 'cancel'
            ? { ...reservation(), phase: 'decided', decision: 'cancelled', created: false }
            : { ...ids, phase: 'cleaned', decision: 'cancelled', disposition: 'retire-owned', newly_recorded: false,
              payload_absence_verified_this_call: true, complete: true, authorization_granted: false };
      expect((await decodeReleaseCommand(JSON.stringify(envelope(result)), document, action)).result).toEqual(result);
    });
  it.each(['reserve', 'delete', 'cancel', 'cleanup'] as const)(
    'accepts matching deletion %s history with the original mixed-case commitment', async action => {
      const retained = decodeReleaseIntent(vectors[5].raw);
      const ids = { operation_id: retained.operation_id, release_id: retained.release_id };
      const result = action === 'cleanup'
        ? { ...ids, phase: 'decided', decision: 'deleted', disposition: 'retain-unverified', newly_recorded: false,
          payload_absence_verified_this_call: false, complete: false, authorization_granted: false }
        : { ...ids, phase: action === 'reserve' ? 'reserved' : 'decided', decision: action === 'reserve' ? null : action === 'cancel' ? 'cancelled' : 'deleted',
          newly_changed: true, cleanup_disposition: 'retain-unverified', bytes_removed: false, cleanup_authorized: false };
      const value = { ...envelope(result), intent_sha256: vectors[5].intent_sha256 };
      expect((await decodeReleaseCommand(JSON.stringify(value), retained, action)).result).toEqual(result);
    });
  it.each(['outer-id', 'inner-id', 'digest', 'action', 'flag', 'extra-result'])(
    'refuses a successful HTTP body with command mismatch %s', async which => {
      const value = JSON.parse(JSON.stringify(envelope()));
      if (which === 'outer-id') value.operation_id = actor;
      if (which === 'inner-id') value.result.release_id = actor;
      if (which === 'digest') value.intent_sha256 = 'b'.repeat(64);
      if (which === 'flag') value.authorization_granted = true;
      if (which === 'extra-result') value.result.cleanup_authorized = true;
      await expect(decodeReleaseCommand(JSON.stringify(value), document, which === 'action' ? 'publish' : 'reserve')).rejects.toThrow(ReleaseCodecError);
    });
  it.each(['incomplete', 'claimed-complete', 'wrong-verification'])(
    'preserves unverified cleanup semantics %s', async which => {
      const result = { operation_id: document.operation_id, release_id: document.release_id, phase: 'decided', decision: 'cancelled',
        disposition: 'retain-unverified', newly_recorded: false, payload_absence_verified_this_call: which === 'wrong-verification',
        complete: which === 'claimed-complete', authorization_granted: false };
      const pending = decodeReleaseCommand(JSON.stringify(envelope(result)), document, 'cleanup');
      if (which === 'incomplete') expect((await pending).result).toEqual(result);
      else await expect(pending).rejects.toThrow(ReleaseCodecError);
    });
});

describe('retained operation kind in cleanup', () => {
  it('refuses a deleted cleanup decision bound to a publication intent even with matching IDs and digest', async () => {
    const result = { operation_id: document.operation_id, release_id: document.release_id, phase: 'cleaned', decision: 'deleted',
      disposition: 'retire-owned', newly_recorded: false, payload_absence_verified_this_call: true, complete: true, authorization_granted: false };
    await expect(decodeReleaseCommand(JSON.stringify(envelope(result)), document, 'cleanup')).rejects.toThrow(ReleaseCodecError);
  });
});
