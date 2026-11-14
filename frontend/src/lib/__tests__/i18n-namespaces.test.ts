// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/// <reference types="node" />
import { readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TRANSLATION_NAMESPACES, type TranslationNamespace } from '@/lib/i18n-namespaces';

const files = (lang: string) =>
  readdirSync(resolve(process.cwd(), 'public/locales', lang))
    .filter((name) => name.endsWith('.json'))
    .map((name) => name.replace(/\.json$/, ''))
    .sort();

describe('TranslationNamespace', () => {
  it('names every locale file, and nothing else', () => {
    expect([...TRANSLATION_NAMESPACES].sort()).toEqual(files('en'));
  });

  it('matches the Spanish and Chinese files too', () => {
    expect(files('es')).toEqual(files('en'));
    expect(files('zh')).toEqual(files('en'));
  });

  it('accepts the Storage namespace (a type error before it was listed)', () => {
    const storage: TranslationNamespace = 'storage';
    expect(TRANSLATION_NAMESPACES).toContain(storage);
  });
});
