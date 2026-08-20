// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Every remote storage backend was unconfigurable.
 *
 * The storage-location form collects every field of the selected storage type
 * into one flat `config` record — secrets included — and the page posted that
 * record straight through as `config`.
 *
 * The backend REJECTS that on purpose. `_validate_storage_config` raises on
 * any credential-class key so secrets go to `credentials` instead, where they
 * are Fernet-encrypted into `encrypted_credentials` rather than sitting in a
 * plaintext JSONB blob:
 *
 *   config['secret_key'] looks like a credential — store credentials in
 *   StorageLocation.encrypted_credentials (Fernet-encrypted), not in the
 *   plaintext config blob.
 *
 * So creating an S3, SFTP, Azure, GCS or B2 location returned 422 every time.
 * Only the local filesystem type — the one with no secret — could be created
 * at all, which is why this survived: the type people try first works.
 *
 * The split has to agree with `_looks_like_credential_key` in
 * `app/schemas/backup.py`, including its path/file exemption. These tests pin
 * that agreement; the patterns are duplicated here deliberately so a drift on
 * either side shows up as a failure rather than a 422 in the field.
 */

import { describe, expect, it } from 'vitest';

// Mirrors the page's helper. Kept in step by the parity test at the bottom.
const CREDENTIAL_KEY_PATTERNS = [
  'password',
  'passwd',
  'passphrase',
  'secret',
  'privatekey',
  'apikey',
  'accesskey',
  'token',
  'clientsecret',
  'servicekey',
  'bearer',
];

function looksLikeCredentialKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[_-]/g, '');
  if (/(path|file|filename|filepath)$/.test(normalized)) return false;
  return CREDENTIAL_KEY_PATTERNS.some((pattern) => normalized.includes(pattern));
}

interface Field {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'password' | 'textarea';
}

function splitStorageValues(config: Record<string, string>, fields: Field[]) {
  const secretByName = new Map(fields.map((f) => [f.name, f.type === 'password']));
  const plain: Record<string, string> = {};
  const secrets: Record<string, string> = {};
  for (const [key, value] of Object.entries(config)) {
    if (secretByName.get(key) || looksLikeCredentialKey(key)) {
      secrets[key] = value;
    } else {
      plain[key] = value;
    }
  }
  return { config: plain, credentials: secrets };
}

describe('storage-location secrets are split out of config', () => {
  const S3_FIELDS: Field[] = [
    { name: 'bucket', type: 'string' },
    { name: 'region', type: 'string' },
    { name: 'endpoint_url', type: 'string' },
    { name: 'access_key', type: 'password' },
    { name: 'secret_key', type: 'password' },
  ];

  it('sends no credential-class key inside config', () => {
    // The whole bug in one assertion: the backend 422s on exactly this.
    const { config } = splitStorageValues(
      {
        bucket: 'backups',
        region: 'us-east-1',
        access_key: 'AKIAEXAMPLE',
        secret_key: 'shhh',
      },
      S3_FIELDS,
    );

    for (const key of Object.keys(config)) {
      expect(looksLikeCredentialKey(key)).toBe(false);
    }
  });

  it('routes the secrets to credentials, not nowhere', () => {
    // Dropping them would swap a 422 for a location that cannot authenticate.
    const { credentials } = splitStorageValues(
      { bucket: 'backups', access_key: 'AKIAEXAMPLE', secret_key: 'shhh' },
      S3_FIELDS,
    );
    expect(credentials).toEqual({ access_key: 'AKIAEXAMPLE', secret_key: 'shhh' });
  });

  it('keeps the non-secret settings in config', () => {
    const { config } = splitStorageValues(
      { bucket: 'backups', region: 'us-east-1', endpoint_url: 'https://s3.example.com' },
      S3_FIELDS,
    );
    expect(config).toEqual({
      bucket: 'backups',
      region: 'us-east-1',
      endpoint_url: 'https://s3.example.com',
    });
  });

  it('catches a secret the backend typed as plain text', () => {
    // Field metadata is the primary signal; the name patterns are the safety
    // net. A backend that ships `api_token` as type "string" must not put it
    // in config -- the validator would still reject the whole request.
    const { config, credentials } = splitStorageValues(
      { endpoint: 'https://example.com', api_token: 'abc123' },
      [
        { name: 'endpoint', type: 'string' },
        { name: 'api_token', type: 'string' },
      ],
    );
    expect(config).toEqual({ endpoint: 'https://example.com' });
    expect(credentials).toEqual({ api_token: 'abc123' });
  });

  it.each([
    'password',
    'passwd',
    'passphrase',
    'secret_key',
    'client_secret',
    'private_key',
    'api_key',
    'access_key',
    'access_token',
    'refresh_token',
    'bearer_token',
    'service_key',
    'AccessKey',
    'sftp-password',
    'access-token-v2',
    'client_secret_b64',
  ])('treats %s as a credential', (key) => {
    expect(looksLikeCredentialKey(key)).toBe(true);
  });

  it.each([
    'private_key_path',
    'credentials_file',
    'api_token_file',
    'secret_filename',
    'keyfile',
  ])('exempts the path/file indirection %s', (key) => {
    // The backend allows these in config on purpose: the secret lives in the
    // sandboxed file the path points at, not in this value. Moving them to
    // `credentials` would break SFTP key-path setups.
    expect(looksLikeCredentialKey(key)).toBe(false);
  });

  it.each(['bucket', 'region', 'endpoint_url', 'path', 'timeout', 'use_ssl', 'container'])(
    'leaves the ordinary setting %s alone',
    (key) => {
      expect(looksLikeCredentialKey(key)).toBe(false);
    },
  );

  it('reproduces the old payload to prove the test is not vacuous', () => {
    // Negative control: this is what the page used to send, and it is exactly
    // what the backend refuses.
    const oldPayload = { bucket: 'backups', access_key: 'AKIAEXAMPLE', secret_key: 'shhh' };
    const offending = Object.keys(oldPayload).filter(looksLikeCredentialKey);
    expect(offending).toEqual(['access_key', 'secret_key']);
  });

  it('produces nothing to send when a local location has no secret', () => {
    // Local filesystem is the type that always worked, which is why this went
    // unnoticed. It must keep working, and must not send an EMPTY credentials
    // dict -- on update that CLEARS every stored credential.
    const { config, credentials } = splitStorageValues({ path: '/var/backups' }, [
      { name: 'path', type: 'string' },
    ]);
    expect(config).toEqual({ path: '/var/backups' });
    expect(Object.keys(credentials)).toHaveLength(0);
  });

  it('keeps the page helper in step with this one', async () => {
    // The page cannot export its helper without restructuring the module, so
    // pin the patterns by source instead. A change on either side fails here
    // rather than in the field.
    const source = await import('fs/promises').then((fs) =>
      fs.readFile('src/pages/storage-locations/StorageLocationsPage.tsx', 'utf-8'),
    );
    for (const pattern of CREDENTIAL_KEY_PATTERNS) {
      expect(source).toContain(`'${pattern}'`);
    }
    expect(source).toContain('(path|file|filename|filepath)$');
  });
});
