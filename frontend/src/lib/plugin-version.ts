/**
 * Comparing plugin versions the same way the backend does.
 *
 * The marketplace decides whether to offer an update by comparing the version
 * an instance has installed against the one the catalogue carries. The backend
 * makes the same comparison and refuses anything that is not forward motion, so
 * the two have to agree: a UI that offers an update the API then rejects with
 * 409 is worse than not offering one at all.
 *
 * Mirrors `_version_tuple` in `app/plugins/loader.py`, including its tolerance.
 * A trailing suffix like "1.2.0-beta" compares on its numeric head, and
 * anything with no leading number at all is "cannot judge" rather than zero --
 * treating an unparseable version as 0.0.0 would offer an update for every
 * plugin whose version string we do not recognise.
 */

/** Dotted version to comparable numbers, or null when it cannot be judged. */
export function versionTuple(value: string | null | undefined): number[] | null {
  if (!value) return null;
  const parts: number[] = [];
  for (const chunk of String(value).trim().split('.')) {
    let digits = '';
    for (const ch of chunk) {
      if (ch >= '0' && ch <= '9') digits += ch;
      else break;
    }
    if (!digits) break;
    parts.push(Number(digits));
  }
  return parts.length ? parts : null;
}

/** -1, 0, 1 as `a` is older, equal, or newer than `b`. null if either is unjudgeable. */
export function compareVersions(
  a: string | null | undefined,
  b: string | null | undefined,
): number | null {
  const ta = versionTuple(a);
  const tb = versionTuple(b);
  if (!ta || !tb) return null;
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    // "1.2" and "1.2.0" are the same version; a missing segment is zero.
    const x = ta[i] ?? 0;
    const y = tb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Is `latest` a version worth offering over `installed`?
 *
 * False when they match, when the installed one is newer (the backend refuses
 * to roll back, so offering it would produce a 409), and when either cannot be
 * parsed.
 */
export function isUpdateAvailable(
  installed: string | null | undefined,
  latest: string | null | undefined,
): boolean {
  return compareVersions(installed, latest) === -1;
}
