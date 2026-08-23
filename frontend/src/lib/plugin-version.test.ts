/**
 * The comparison that decides whether the marketplace offers an update.
 *
 * It has to agree with `_version_tuple` in `app/plugins/loader.py`, because the
 * backend makes the same judgement and refuses anything that is not forward
 * motion. A UI that offers an update the API then rejects with 409 is worse
 * than not offering one: the operator clicks a button that cannot work.
 *
 * Before this existed the card compared nothing at all -- it asked only "is it
 * installed?" -- so a plugin with a newer version in the catalogue read
 * "Installed" for ever and there was no way to update from the UI.
 */

import { describe, expect, it } from 'vitest';

import { compareVersions, isUpdateAvailable, versionTuple } from './plugin-version';

describe('versionTuple', () => {
  it('parses a plain dotted version', () => {
    expect(versionTuple('1.2.3')).toEqual([1, 2, 3]);
  });

  it('compares a pre-release on its numeric head, like the backend', () => {
    expect(versionTuple('1.2.0-beta')).toEqual([1, 2, 0]);
  });

  it('cannot judge a version with no leading number', () => {
    // Deliberately null rather than [0]: treating an unrecognised version as
    // 0.0.0 would offer an update for every plugin we cannot parse.
    expect(versionTuple('nightly')).toBeNull();
    expect(versionTuple('')).toBeNull();
    expect(versionTuple(null)).toBeNull();
    expect(versionTuple(undefined)).toBeNull();
  });
});

describe('compareVersions', () => {
  it('orders by each segment in turn', () => {
    expect(compareVersions('1.2.0', '1.3.0')).toBe(-1);
    expect(compareVersions('2.0.0', '1.9.9')).toBe(1);
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
  });

  it('does not compare segments as text', () => {
    // "10" < "9" as strings, which would hide every tenth release.
    expect(compareVersions('1.9.0', '1.10.0')).toBe(-1);
  });

  it('treats a missing trailing segment as zero', () => {
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('1.2', '1.2.1')).toBe(-1);
  });

  it('refuses to judge when either side is unparseable', () => {
    expect(compareVersions('nightly', '1.0.0')).toBeNull();
    expect(compareVersions('1.0.0', 'nightly')).toBeNull();
  });
});

describe('isUpdateAvailable', () => {
  it('offers a genuinely newer version', () => {
    expect(isUpdateAvailable('1.1.0', '1.2.0')).toBe(true);
  });

  it('does not offer the version already installed', () => {
    expect(isUpdateAvailable('1.2.0', '1.2.0')).toBe(false);
  });

  it('does not offer a downgrade', () => {
    // The backend refuses this with 409 "refusing to roll back", so offering
    // it would put a button on screen that cannot succeed.
    expect(isUpdateAvailable('2.0.0', '1.2.0')).toBe(false);
  });

  it('does not offer anything it cannot judge', () => {
    expect(isUpdateAvailable('nightly', '1.2.0')).toBe(false);
    expect(isUpdateAvailable(null, '1.2.0')).toBe(false);
    expect(isUpdateAvailable('1.2.0', undefined)).toBe(false);
  });

  it('handles the version pair that shipped', () => {
    // hello-world went 1.1.0 -> 1.2.0 in the registry while an instance still
    // had 1.1.0 installed. That is the case this whole feature exists for.
    expect(isUpdateAvailable('1.1.0', '1.2.0')).toBe(true);
  });
});
