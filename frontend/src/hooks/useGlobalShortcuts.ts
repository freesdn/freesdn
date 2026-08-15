// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Global Keyboard Shortcuts
 *
 * UniFi/Linear/Superhuman-style g-prefix navigation:
 *   g h → Dashboard (Home)
 *   g d → Devices
 *   g c → Cameras
 *   g v → VoIP
 *   g a → Alerts
 *   g n → Network
 *   g f → Firewall
 *   g s → Settings
 *   g i → Incidents
 *   g l → Logs
 *
 * Plus single-key shortcuts:
 *   ⌘K / Ctrl+K → Command Palette
 *   ?            → Shortcuts cheatsheet
 *   /            → Focus sidebar search
 *
 * Mount this hook ONCE at the App level. It manages its own listeners.
 */

import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

export interface ShortcutDef {
  key: string;
  description: string;
  group: string;
  action: () => void;
  /** Only fire when the key is preceded by `g` (within 1.5s) */
  gPrefix?: boolean;
}

interface UseGlobalShortcutsOptions {
  onOpenCommandPalette?: () => void;
  onOpenShortcutsCheatsheet?: () => void;
  enabled?: boolean;
}

const G_PREFIX_TIMEOUT_MS = 1500;

/**
 * Returns true if the keypress should be ignored because the user is typing
 * in an input / textarea / contenteditable.
 */
function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (target.isContentEditable) return true;
  // If the focused element is inside a CodeMirror / Monaco editor, don't fire
  if (target.closest('[role="textbox"]')) return true;
  return false;
}

export function useGlobalShortcuts({
  onOpenCommandPalette,
  onOpenShortcutsCheatsheet,
  enabled = true,
}: UseGlobalShortcutsOptions = {}) {
  const navigate = useNavigate();
  // gPressedAt is updated synchronously inside the keydown handler (no
  // re-render needed) so we keep it in a ref rather than state.
  const gPressedAtRef = useRef<number>(0);

  useEffect(() => {
    if (!enabled) return;

    const shortcuts: ShortcutDef[] = [
      // g-prefix nav
      { key: 'h', description: 'Go to Dashboard',  group: 'Navigation', action: () => navigate('/'),           gPrefix: true },
      { key: 'd', description: 'Go to Devices',    group: 'Navigation', action: () => navigate('/devices'),    gPrefix: true },
      { key: 'n', description: 'Go to Network',    group: 'Navigation', action: () => navigate('/network'),    gPrefix: true },
      { key: 'c', description: 'Go to Cameras',    group: 'Navigation', action: () => navigate('/cameras'),    gPrefix: true },
      { key: 'v', description: 'Go to VoIP',       group: 'Navigation', action: () => navigate('/voip'),       gPrefix: true },
      { key: 'f', description: 'Go to Firewall',   group: 'Navigation', action: () => navigate('/firewall'),   gPrefix: true },
      { key: 'a', description: 'Go to Alerts',     group: 'Navigation', action: () => navigate('/alerts'),     gPrefix: true },
      { key: 'i', description: 'Go to Incidents',  group: 'Navigation', action: () => navigate('/incidents'),  gPrefix: true },
      { key: 'l', description: 'Go to Logs',       group: 'Navigation', action: () => navigate('/logs'),       gPrefix: true },
      { key: 'y', description: 'Go to Topology',   group: 'Navigation', action: () => navigate('/topology'),   gPrefix: true },
      { key: 'b', description: 'Go to Backups',    group: 'Navigation', action: () => navigate('/backups'),    gPrefix: true },
      { key: 's', description: 'Go to Sites',      group: 'Navigation', action: () => navigate('/sites'),      gPrefix: true },
      { key: 'u', description: 'Go to Users',      group: 'Navigation', action: () => navigate('/users'),      gPrefix: true },
      { key: 'p', description: 'Go to Plugins',    group: 'Navigation', action: () => navigate('/plugins'),    gPrefix: true },
      { key: 'r', description: 'Go to Reconciliation', group: 'Navigation', action: () => navigate('/reconciliation'), gPrefix: true },
    ];

    const handler = (e: KeyboardEvent) => {
      // Always allow ⌘K / Ctrl+K · even inside inputs
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        onOpenCommandPalette?.();
        return;
      }

      if (isTypingTarget(e.target)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      // ? → cheatsheet (Shift+/ on most layouts)
      if (e.key === '?') {
        e.preventDefault();
        onOpenShortcutsCheatsheet?.();
        return;
      }

      // / → focus sidebar search
      if (e.key === '/') {
        e.preventDefault();
        const search = document.getElementById('freesdn-nav-search') as HTMLInputElement | null;
        search?.focus();
        return;
      }

      // g → start g-prefix sequence
      if (e.key === 'g') {
        gPressedAtRef.current = Date.now();
        return;
      }

      // g-prefix nav
      const since = Date.now() - gPressedAtRef.current;
      if (since < G_PREFIX_TIMEOUT_MS) {
        const match = shortcuts.find((s) => s.gPrefix && s.key === e.key.toLowerCase());
        if (match) {
          e.preventDefault();
          gPressedAtRef.current = 0;
          match.action();
          return;
        }
      }
    };

    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [enabled, navigate, onOpenCommandPalette, onOpenShortcutsCheatsheet]);
}

/**
 * Get the static list of shortcuts (for rendering the cheatsheet dialog).
 * The action is a no-op since the cheatsheet only displays them.
 */
export function getShortcutList(): ShortcutDef[] {
  const noop = () => {};
  return [
    { key: '⌘K / Ctrl K',    description: 'Open command palette',     group: 'General', action: noop },
    { key: '?',              description: 'Show keyboard shortcuts',  group: 'General', action: noop },
    { key: '/',              description: 'Focus sidebar search',     group: 'General', action: noop },

    { key: 'g h',  description: 'Go to Dashboard',     group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g d',  description: 'Go to Devices',       group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g n',  description: 'Go to Network',       group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g c',  description: 'Go to Cameras',       group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g v',  description: 'Go to VoIP',          group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g f',  description: 'Go to Firewall',      group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g a',  description: 'Go to Alerts',        group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g i',  description: 'Go to Incidents',     group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g l',  description: 'Go to Logs',          group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g y',  description: 'Go to Topology',      group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g b',  description: 'Go to Backups',       group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g s',  description: 'Go to Sites',         group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g u',  description: 'Go to Users',         group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g p',  description: 'Go to Plugins',       group: 'Navigation', action: noop, gPrefix: true },
    { key: 'g r',  description: 'Go to Reconciliation', group: 'Navigation', action: noop, gPrefix: true },
  ];
}

/** Whether to show ⌘ (Mac) or Ctrl (others) in shortcut hints. */
export const isMacPlatform =
  typeof navigator !== 'undefined' &&
  /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent || '');
