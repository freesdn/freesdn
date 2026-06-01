// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · ShortcutsCheatsheet
 *
 * Dialog showing all global keyboard shortcuts. Mount it once at the App
 * level alongside CommandPalette. Triggered by `?` global shortcut.
 *
 *   <ShortcutsCheatsheet open={showShortcuts} onOpenChange={setShowShortcuts} />
 */

import { Keyboard } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from './dialog';
import { getShortcutList, isMacPlatform } from '../../hooks/useGlobalShortcuts';
import { cn } from '../../lib/utils';

interface ShortcutsCheatsheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        'inline-flex items-center justify-center min-w-[24px] h-6 px-1.5',
        'rounded border border-border bg-muted',
        'font-mono text-[11px] font-medium text-foreground',
        className,
      )}
    >
      {children}
    </kbd>
  );
}

/** Render a key combo string like "⌘K" or "g d" as styled <Kbd> elements. */
function KeyCombo({ keys }: { keys: string }) {
  const { t } = useTranslation('common');
  // Replace platform-aware "⌘" hint based on actual platform
  const display = isMacPlatform
    ? keys.replace('Ctrl K', '⌘ K').replace('Ctrl', '⌘')
    : keys.replace('⌘ K', 'Ctrl K').replace('⌘K', 'Ctrl K').replace('⌘', 'Ctrl');

  // Tokenize on " / " (alt) then on " " (sequence)
  const alternatives = display.split(' / ');
  return (
    <div className="flex items-center gap-1.5">
      {alternatives.map((alt, ai) => (
        <span key={ai} className="flex items-center gap-1">
          {ai > 0 && (
            <span className="text-muted-foreground text-xs mr-1">
              {t('ShortcutsCheatsheet.or')}
            </span>
          )}
          {alt
            .trim()
            .split(/\s+/)
            .map((k, ki) => (
              <Kbd key={ki}>{k}</Kbd>
            ))}
        </span>
      ))}
    </div>
  );
}

export function ShortcutsCheatsheet({ open, onOpenChange }: ShortcutsCheatsheetProps) {
  const { t } = useTranslation('common');
  const shortcuts = getShortcutList();
  const groups = Array.from(new Set(shortcuts.map((s) => s.group)));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Keyboard className="h-5 w-5 text-muted-foreground" />
            {t('ShortcutsCheatsheet.title')}
          </DialogTitle>
          <DialogDescription>
            {t('ShortcutsCheatsheet.description.before')}{' '}
            <Kbd>?</Kbd> {t('ShortcutsCheatsheet.description.after')}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2">
          {groups.map((group) => (
            <div key={group}>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
                {group}
              </h3>
              <div className="space-y-1.5">
                {shortcuts
                  .filter((s) => s.group === group)
                  .map((s, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between py-1.5 px-2 rounded-md hover:bg-muted/50 transition-colors"
                    >
                      <span className="text-sm text-foreground">{s.description}</span>
                      <KeyCombo keys={s.key} />
                    </div>
                  ))}
              </div>
            </div>
          ))}
        </div>

        <div className="text-xs text-muted-foreground border-t pt-3 mt-2">
          {t('ShortcutsCheatsheet.tip.before')} <Kbd>g</Kbd>
          {t('ShortcutsCheatsheet.tip.middle')} <Kbd>g</Kbd>{' '}
          {t('ShortcutsCheatsheet.tip.after')}
        </div>
      </DialogContent>
    </Dialog>
  );
}
