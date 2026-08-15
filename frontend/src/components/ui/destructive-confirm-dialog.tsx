// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Destructive confirmation dialog.
 *
 * Replaces ``window.confirm()`` for irreversible operations where
 * one stray click destroys data: VM delete, snapshot rollback,
 * snapshot delete, backup prune, etc. The native confirm() is
 * dismissible by Enter on the wrong row and has no friction; this
 * dialog requires the operator to **type the resource name** before
 * the destructive button enables.
 *
 * Usage:
 *
 *   const [confirmTarget, setConfirmTarget] = useState<{vmid:number,name:string} | null>(null);
 *
 *   <DestructiveConfirmDialog
 *     open={confirmTarget !== null}
 *     onOpenChange={(o) => !o && setConfirmTarget(null)}
 *     title="Delete VM"
 *     description={`This permanently removes VM ${confirmTarget?.vmid} (${confirmTarget?.name}) and ALL its disks. There is no undo.`}
 *     confirmationText={confirmTarget?.name ?? ''}
 *     confirmLabel="Delete VM"
 *     onConfirm={() => {
 *       if (!confirmTarget) return;
 *       deleteVmMutation.mutate(confirmTarget.vmid);
 *       setConfirmTarget(null);
 *     }}
 *   />
 *
 * The button stays disabled until the typed string EXACTLY matches
 * ``confirmationText`` (case-sensitive). Cancel is the default-focused
 * action, Enter dismisses, not confirms.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AlertTriangle, Eye } from 'lucide-react';
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useUIStore } from '@/stores';

export interface DestructiveConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Heading, e.g. "Delete VM" */
  title: string;
  /** Body, explain blast radius. */
  description: string;
  /** The literal string the operator must re-type to confirm. */
  confirmationText: string;
  /** Button text, e.g. "Delete VM" / "Rollback" / "Prune backups". */
  confirmLabel: string;
  /** Called when the operator types the right value and clicks confirm. */
  onConfirm: () => void;
  /** Disabled state for the confirm button (e.g. mutation in flight). */
  isPending?: boolean;
  /**
   * Whether this confirms a DEVICE write that the backend refuses while
   * read-only mode is on. Defaults to true (all current callers are device
   * writes — VM delete, snapshot, SDN, cert, backup prune). When read-only is
   * on, the dialog warns and disables confirm so the operator isn't sent into a
   * guaranteed 403. Pass false for non-device confirmations (e.g. app-config
   * deletes), which are not gated by read-only mode.
   */
  readOnlyAware?: boolean;
}

export function DestructiveConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmationText,
  confirmLabel,
  onConfirm,
  isPending,
  readOnlyAware = true,
}: DestructiveConfirmDialogProps) {
  const { t } = useTranslation('common');
  const [typed, setTyped] = useState('');
  const readOnlyMode = useUIStore((s) => s.readOnlyMode);
  const blockedByReadOnly = readOnlyAware && readOnlyMode;

  // Reset the typed value whenever the dialog opens/closes so a
  // previous attempt doesn't pre-arm the next one.
  useEffect(() => {
    if (open) setTyped('');
  }, [open]);

  const matches = typed === confirmationText && confirmationText.length > 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-5 w-5" /> {title}
          </DialogTitle>
          <DialogDescription className="pt-2 text-sm">
            {description}
          </DialogDescription>
        </DialogHeader>
        {blockedByReadOnly ? (
          <div className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning">
            <Eye className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>
              {t('DestructiveConfirmDialog.readOnly.message')}{' '}
              <Link
                to="/settings/access"
                onClick={() => onOpenChange(false)}
                className="font-semibold underline underline-offset-2"
              >
                {t('DestructiveConfirmDialog.readOnly.link')}
              </Link>
            </span>
          </div>
        ) : (
          <div className="space-y-2">
            <Label className="text-xs">
              {t('DestructiveConfirmDialog.typePrompt.prefix')}{' '}
              <code className="font-mono px-1 rounded bg-muted">{confirmationText}</code>{' '}
              {t('DestructiveConfirmDialog.typePrompt.suffix')}
            </Label>
            <Input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={confirmationText}
              autoFocus
              // ``autoComplete=off`` prevents browser auto-fill on the
              // confirmation input, which would let a click on a saved
              // suggestion arm the destructive button.
              autoComplete="off"
            />
          </div>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('DestructiveConfirmDialog.cancel')}
          </Button>
          <Button
            variant="destructive"
            disabled={!matches || isPending || blockedByReadOnly}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
