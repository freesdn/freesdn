// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Promise-based confirmation, replacing ``window.confirm()``.
 *
 * The native prompt cannot be styled or translated, ignores the theme, gives
 * no hint of how much an action touches, and on some browsers offers to
 * suppress further prompts, after which every destructive action on the page
 * runs unasked. This dialog states what will happen, how many items it
 * affects (and which), and styles destructive actions as such.
 *
 *   const confirm = useConfirm();
 *
 *   const onBulkDelete = async () => {
 *     const ok = await confirm({
 *       title: t('VlansPage.confirm.bulkDelete.title'),          // "Delete VLANs"
 *       description: t('VlansPage.confirm.bulkDelete.body'),     // "They are removed from every switch."
 *       count: selected.length,
 *       items: selected.map((v) => v.name),
 *       confirmLabel: t('VlansPage.confirm.bulkDelete.action'),  // "Delete VLANs"
 *       destructive: true,
 *     });
 *     if (!ok) return;
 *     ...
 *   };
 *
 * ``confirm`` resolves true on confirm and false on cancel, Escape or a click
 * outside. Mount ``<ConfirmProvider>`` once near the root (App.tsx does);
 * without one the hook falls back to ``window.confirm`` with the same text, so
 * a confirmation is never skipped and never hangs.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, HelpCircle } from 'lucide-react';
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from './alert-dialog';
import { Button } from './button';
import { Input } from './input';
import { Label } from './label';
import { cn } from '../../lib/utils';
import i18n from 'i18next';

export interface ConfirmOptions {
  /** What is about to happen, as a short heading: "Delete 3 VLANs". */
  title: string;
  /** The consequence, in a sentence or two: "They are removed from every switch." */
  description?: ReactNode;
  /** How many items the action affects. Shown as "This affects N items." */
  count?: number;
  /** Names of the affected items. The first few are listed, the rest counted. */
  items?: string[];
  /** Label for the confirm button. Name the action ("Delete VLANs"), not "OK". */
  confirmLabel?: string;
  /** Label for the cancel button. Defaults to "Cancel". */
  cancelLabel?: string;
  /** Destructive styling (red button, warning icon). Use for deletes, reboots, halts. */
  destructive?: boolean;
  /**
   * For irreversible actions: the operator must type this exact text before
   * the confirm button enables (the resource name works well).
   */
  confirmationText?: string;
}

export type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn | null>(null);

/** How many item names to list before summarising the rest. */
const MAX_LISTED_ITEMS = 5;

function tr(key: string, defaultValue: string, options: Record<string, unknown> = {}): string {
  if (!i18n.isInitialized) {
    return defaultValue.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name: string) => String(options[name] ?? ''));
  }
  const out = i18n.t(`common:ConfirmDialog.${key}`, { defaultValue, ...options });
  return typeof out === 'string' && out ? out : defaultValue;
}

/** Plain-text rendering for the no-provider fallback. */
function toPlainText(options: ConfirmOptions): string {
  const parts = [options.title];
  if (typeof options.description === 'string' && options.description) parts.push(options.description);
  if (typeof options.count === 'number') {
    parts.push(tr('affects', 'This affects {{count}} items.', { count: options.count }));
  }
  if (options.items?.length) {
    const listed = options.items.slice(0, MAX_LISTED_ITEMS).join(', ');
    const rest = options.items.length - MAX_LISTED_ITEMS;
    parts.push(rest > 0 ? `${listed} ${tr('moreItems', 'and {{count}} more', { count: rest })}` : listed);
  }
  return parts.join('\n\n');
}

/**
 * Ask the operator to confirm an action. Resolves true on confirm.
 * See the module comment for usage.
 */
export function useConfirm(): ConfirmFn {
  const fromProvider = useContext(ConfirmContext);
  const fallback = useCallback<ConfirmFn>(
    (options) =>
      // No prompt available at all (a non-browser environment): answer no,
      // so nothing destructive runs unasked.
      Promise.resolve(
        typeof window !== 'undefined' &&
          typeof window.confirm === 'function' &&
          window.confirm(toPlainText(options)),
      ),
    [],
  );
  return fromProvider ?? fallback;
}

interface PendingConfirm {
  options: ConfirmOptions;
  resolve: (value: boolean) => void;
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);
  const pendingRef = useRef<PendingConfirm | null>(null);

  const settle = useCallback((value: boolean) => {
    const current = pendingRef.current;
    pendingRef.current = null;
    setPending(null);
    current?.resolve(value);
  }, []);

  const confirm = useCallback<ConfirmFn>((options) => {
    return new Promise<boolean>((resolve) => {
      // A newer request replaces an open one; the older caller hears "no".
      pendingRef.current?.resolve(false);
      const next = { options, resolve };
      pendingRef.current = next;
      setPending(next);
    });
  }, []);

  // Unmounting with a dialog open (route change) must not leave a caller
  // awaiting forever.
  useEffect(() => () => pendingRef.current?.resolve(false), []);

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <ConfirmDialog
        options={pending?.options ?? null}
        onConfirm={() => settle(true)}
        onCancel={() => settle(false)}
      />
    </ConfirmContext.Provider>
  );
}

interface ConfirmDialogProps {
  options: ConfirmOptions | null;
  onConfirm: () => void;
  onCancel: () => void;
}

function ConfirmDialog({ options, onConfirm, onCancel }: ConfirmDialogProps) {
  const { t } = useTranslation('common');
  const [typed, setTyped] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const open = options !== null;

  useEffect(() => {
    if (open) setTyped('');
  }, [open, options]);

  // Keep the last options while the close animation runs.
  const lastOptions = useRef<ConfirmOptions | null>(null);
  if (options) lastOptions.current = options;
  const shown = options ?? lastOptions.current;
  if (!shown) return null;

  const destructive = !!shown.destructive;
  const needsTyping = !!shown.confirmationText;
  const armed = !needsTyping || typed === shown.confirmationText;
  const items = shown.items ?? [];
  const listed = items.slice(0, MAX_LISTED_ITEMS);
  const remaining = items.length - listed.length;
  const Icon = destructive ? AlertTriangle : HelpCircle;

  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && onCancel()}>
      <AlertDialogContent
        onOpenAutoFocus={(e) => {
          // Cancel takes focus by default (Enter dismisses, not confirms).
          // With a type-to-confirm field, start in the field instead.
          if (needsTyping) {
            e.preventDefault();
            inputRef.current?.focus();
          }
        }}
      >
        <AlertDialogHeader>
          <AlertDialogTitle className={cn('flex items-center gap-2', destructive && 'text-destructive')}>
            <Icon
              className={cn('h-5 w-5 shrink-0', destructive ? 'text-destructive' : 'text-primary')}
              aria-hidden="true"
            />
            {shown.title}
          </AlertDialogTitle>
          {(shown.description || typeof shown.count === 'number') && (
            <AlertDialogDescription asChild>
              <div className="space-y-2">
                {shown.description && <p>{shown.description}</p>}
                {typeof shown.count === 'number' && (
                  <p className="font-medium text-foreground" data-testid="confirm-count">
                    {t('ConfirmDialog.affects', { count: shown.count })}
                  </p>
                )}
              </div>
            </AlertDialogDescription>
          )}
        </AlertDialogHeader>

        {listed.length > 0 && (
          <div className="rounded-md border border-border bg-muted/40 px-3 py-2 text-sm">
            <ul className="space-y-0.5" aria-label={t('ConfirmDialog.itemsLabel')}>
              {listed.map((name, i) => (
                <li key={`${name}-${i}`} className="truncate font-mono text-xs text-foreground">
                  {name}
                </li>
              ))}
            </ul>
            {remaining > 0 && (
              <p className="mt-1 text-xs text-muted-foreground">
                {t('ConfirmDialog.moreItems', { count: remaining })}
              </p>
            )}
          </div>
        )}

        {needsTyping && (
          <div className="space-y-2">
            <Label htmlFor="confirm-dialog-typed" className="text-xs">
              {t('ConfirmDialog.typePrompt', { text: shown.confirmationText })}
            </Label>
            <Input
              id="confirm-dialog-typed"
              ref={inputRef}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={shown.confirmationText}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        )}

        <AlertDialogFooter>
          <AlertDialogCancel>{shown.cancelLabel ?? t('ConfirmDialog.cancel')}</AlertDialogCancel>
          {/* A plain Button, not AlertDialogAction: Action closes the dialog
              before the typed-text check could stop it. */}
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={!armed}
            onClick={onConfirm}
          >
            {shown.confirmLabel ?? t('ConfirmDialog.confirm')}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
