// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN

import { CheckCircle, XCircle, Loader2, Clock } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';

export interface BatchDeviceStatus {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped';
  message?: string;
}

interface BatchProgressDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  devices: BatchDeviceStatus[];
  onCancel?: () => void;
  onRetryFailed?: () => void;
  onClose?: () => void;
}

const statusIcon = (status: BatchDeviceStatus['status']) => {
  switch (status) {
    case 'success':
      return <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />;
    case 'running':
      return <Loader2 className="h-4 w-4 text-blue-500 animate-spin shrink-0" />;
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-500 shrink-0" />;
    case 'skipped':
      return <Clock className="h-4 w-4 text-yellow-500 shrink-0" />;
    default:
      return <Clock className="h-4 w-4 text-muted-foreground shrink-0" />;
  }
};

export function BatchProgressDialog({
  open,
  onOpenChange,
  title,
  description,
  devices,
  onCancel,
  onRetryFailed,
  onClose,
}: BatchProgressDialogProps) {
  const { t } = useTranslation('common');
  const total = devices.length;
  const completed = devices.filter(d => d.status === 'success').length;
  const failed = devices.filter(d => d.status === 'failed').length;
  const running = devices.filter(d => d.status === 'running').length;
  const pending = devices.filter(d => d.status === 'pending').length;
  const isDone = running === 0 && pending === 0;
  const progress = total > 0 ? ((completed + failed) / total) * 100 : 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>

        <div className="space-y-4">
          {/* Summary stats */}
          <div className="flex items-center gap-3">
            <div className="flex-1">
              <Progress value={progress} className="h-3" />
            </div>
            <span className="text-sm font-medium tabular-nums whitespace-nowrap">
              {completed + failed} / {total}
            </span>
          </div>

          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-green-500" />
              {t('BatchProgressDialog.stats.success', { count: completed })}
            </span>
            {running > 0 && (
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
                {t('BatchProgressDialog.stats.running', { count: running })}
              </span>
            )}
            {failed > 0 && (
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                {t('BatchProgressDialog.stats.failed', { count: failed })}
              </span>
            )}
            {pending > 0 && (
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-muted-foreground" />
                {t('BatchProgressDialog.stats.pending', { count: pending })}
              </span>
            )}
          </div>

          {/* Per-device list */}
          <ScrollArea className="max-h-[300px]">
            <div className="space-y-1.5">
              {devices.map(device => (
                <div
                  key={device.id}
                  className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {statusIcon(device.status)}
                    <span className="font-medium truncate">{device.name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {device.message && (
                      <span className="hidden sm:inline-block text-xs text-muted-foreground max-w-[150px] truncate">{device.message}</span>
                    )}
                    <Badge
                      variant={
                        device.status === 'success' ? 'outline' :
                        device.status === 'failed' ? 'destructive' :
                        device.status === 'running' ? 'default' : 'secondary'
                      }
                      className="text-xs capitalize"
                    >
                      {t(`BatchProgressDialog.status.${device.status}`)}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>

          {/* Action buttons */}
          <div className="flex justify-end gap-2 pt-2">
            {!isDone && onCancel && (
              <Button variant="destructive" size="sm" onClick={onCancel}>
                {t('BatchProgressDialog.actions.cancel')}
              </Button>
            )}
            {isDone && failed > 0 && onRetryFailed && (
              <Button variant="outline" size="sm" onClick={onRetryFailed}>
                {t('BatchProgressDialog.actions.retryFailed', { count: failed })}
              </Button>
            )}
            {isDone && (
              <Button size="sm" onClick={onClose || (() => onOpenChange(false))}>
                {failed > 0 ? t('BatchProgressDialog.actions.close') : t('BatchProgressDialog.actions.done')}
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
