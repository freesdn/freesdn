// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * RegionEditDialog, modal wrapper around RegionEditor that loads a live camera
 * snapshot as the backdrop and returns the drawn polygon/line (0-10000 coords)
 * on save. Used by the detection panels to define privacy masks, line-crossing
 * tripwires, and intrusion zones visually.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { camerasApi } from '@/lib/api';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { RegionEditor, type RegionPoint } from './RegionEditor';

interface RegionEditDialogProps {
  cameraId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  mode: 'polygon' | 'line';
  points: RegionPoint[];
  onSave: (points: RegionPoint[]) => void;
  maxPoints?: number;
}

export function RegionEditDialog({
  cameraId, open, onOpenChange, title, mode, points, onSave, maxPoints,
}: RegionEditDialogProps) {
  const { t } = useTranslation('cameras');
  const [draft, setDraft] = useState<RegionPoint[]>(points);
  const [snapshotUrl, setSnapshotUrl] = useState('');

  // Reset the draft + (re)load a fresh snapshot each time the dialog opens.
  useEffect(() => {
    if (!open) return;
    setDraft(points);
    let cancelled = false;
    camerasApi
      .getSnapshotUrlAsync(cameraId)
      .then((url) => { if (!cancelled) setSnapshotUrl(url); })
      .catch(() => { if (!cancelled) setSnapshotUrl(''); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, cameraId]);

  const minPoints = mode === 'line' ? 2 : 3;
  const valid = draft.length === 0 || draft.length >= minPoints;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {mode === 'line' ? t('RegionEditDialog.lineDesc') : t('RegionEditDialog.polygonDesc')}
          </DialogDescription>
        </DialogHeader>
        {snapshotUrl ? (
          <RegionEditor
            imageUrl={snapshotUrl}
            mode={mode}
            points={draft}
            onChange={setDraft}
            maxPoints={maxPoints}
          />
        ) : (
          <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
            {t('RegionEditDialog.loadingSnapshot')}
          </div>
        )}
        <DialogFooter className="gap-2 sm:gap-3">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('RegionEditDialog.cancel')}
          </Button>
          <Button
            disabled={!valid}
            onClick={() => { onSave(draft); onOpenChange(false); }}
          >
            {t('RegionEditDialog.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default RegionEditDialog;
