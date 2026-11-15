// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Copy text to the clipboard and say truthfully whether it worked.
 *
 * ``navigator.clipboard`` exists only in a secure context (HTTPS or
 * localhost). A self-hosted FreeSDN is often opened over plain HTTP on the
 * LAN (http://10.0.0.5), where it is undefined, and even on HTTPS the write
 * can be refused (permission denied, document not focused). Call sites used
 * ``navigator.clipboard.writeText(text)`` without awaiting or checking it and
 * showed "Copied" regardless, so an operator pasted an empty clipboard, or an
 * old one, into a device or a terminal.
 *
 * This tries the Clipboard API, then the legacy ``execCommand('copy')`` path
 * (which still works on plain HTTP), and resolves true only when one of them
 * reported success.
 */

function legacyCopy(text: string): boolean {
  if (typeof document === 'undefined' || typeof document.execCommand !== 'function') return false;
  const active = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  // Inside a modal, focus traps pull focus back from anything outside the
  // dialog, which would clear the selection before the copy. Put the scratch
  // field inside the dialog the user is in.
  const host =
    (active?.closest('[role="dialog"],[role="alertdialog"]') as HTMLElement | null) ?? document.body;
  const field = document.createElement('textarea');
  field.value = text;
  field.setAttribute('readonly', '');
  field.setAttribute('aria-hidden', 'true');
  field.tabIndex = -1;
  Object.assign(field.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '1px',
    height: '1px',
    padding: '0',
    border: '0',
    opacity: '0',
    pointerEvents: 'none',
  });
  host.appendChild(field);
  let ok: boolean;
  try {
    field.focus({ preventScroll: true });
    field.select();
    field.setSelectionRange(0, text.length);
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  } finally {
    field.remove();
    active?.focus({ preventScroll: true });
  }
  return ok;
}

/** Resolves true only if the text reached the clipboard. Never throws. */
export async function copyText(text: string): Promise<boolean> {
  const secure = typeof window === 'undefined' || window.isSecureContext !== false;
  const api = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
  if (secure && api && typeof api.writeText === 'function') {
    try {
      await api.writeText(text);
      return true;
    } catch {
      // Refused (permission, focus). The legacy path may still be allowed.
    }
  }
  return legacyCopy(text);
}
