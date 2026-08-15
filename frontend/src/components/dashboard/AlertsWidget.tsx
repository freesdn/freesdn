// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Alerts Widget
 * 
 * Critical alerts and notifications dashboard widget
 */

import { motion, AnimatePresence } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { formatDistanceToNow, isValid } from 'date-fns';
import {
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  XCircle,
  ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';

export interface Alert {
  id: string;
  severity: 'critical' | 'warning' | 'info' | 'success';
  title: string;
  message: string;
  timestamp: string | Date;
  source?: string;
  acknowledged?: boolean;
}

interface AlertsWidgetProps {
  alerts: Alert[];
  maxDisplay?: number;
  onAcknowledge?: (alertId: string) => void;
  onViewAll?: () => void;
  className?: string;
}

const severityConfig = {
  critical: {
    icon: XCircle,
    color: 'text-destructive',
    bg: 'bg-destructive/10',
    border: 'border-destructive/20',
    badge: 'bg-destructive text-destructive-foreground',
  },
  warning: {
    icon: AlertTriangle,
    color: 'text-warning',
    bg: 'bg-warning/10',
    border: 'border-warning/20',
    badge: 'bg-warning text-warning-foreground',
  },
  info: {
    icon: Info,
    color: 'text-info',
    bg: 'bg-info/10',
    border: 'border-info/20',
    badge: 'bg-info text-info-foreground',
  },
  success: {
    icon: CheckCircle,
    color: 'text-success',
    bg: 'bg-success/10',
    border: 'border-success/20',
    badge: 'bg-success text-success-foreground',
  },
};

export function AlertsWidget({
  alerts,
  maxDisplay = 5,
  onAcknowledge,
  onViewAll,
  className,
}: AlertsWidgetProps) {
  const { t } = useTranslation('common');
  const unacknowledged = alerts.filter(a => !a.acknowledged);
  const criticalCount = unacknowledged.filter(a => a.severity === 'critical').length;
  const displayAlerts = alerts.slice(0, maxDisplay);

  if (alerts.length === 0) {
    return (
      <div className={cn('flex flex-col items-center justify-center py-12', className)}>
        <div className="rounded-full bg-success/10 p-4">
          <CheckCircle className="h-8 w-8 text-success" />
        </div>
        <p className="mt-4 text-sm font-medium">{t('AlertsWidget.empty.title')}</p>
        <p className="text-xs text-muted-foreground">{t('AlertsWidget.empty.description')}</p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-3', className)}>
      {/* Summary */}
      {criticalCount > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 px-3 py-2"
        >
          <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
          <span className="text-sm font-medium text-destructive">
            {criticalCount === 1
              ? t('AlertsWidget.summary.criticalOne', { count: criticalCount })
              : t('AlertsWidget.summary.criticalMany', { count: criticalCount })}
          </span>
        </motion.div>
      )}

      {/* Alert list */}
      <ScrollArea className="max-h-[280px]">
        <AnimatePresence mode="popLayout">
          {displayAlerts.map((alert, index) => (
            <AlertItem
              key={alert.id}
              alert={alert}
              index={index}
              onAcknowledge={onAcknowledge}
            />
          ))}
        </AnimatePresence>
      </ScrollArea>

      {/* View all button */}
      {alerts.length > maxDisplay && (
        <Button
          variant="ghost"
          className="w-full justify-between"
          onClick={onViewAll}
        >
          <span>{t('AlertsWidget.viewAll', { count: alerts.length })}</span>
          <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

function AlertItem({
  alert,
  index,
  onAcknowledge,
}: {
  alert: Alert;
  index: number;
  onAcknowledge?: (id: string) => void;
}) {
  const { t } = useTranslation('common');
  const config = severityConfig[alert.severity] ?? severityConfig.info;
  const Icon = config.icon;
  const timestamp = typeof alert.timestamp === 'string' 
    ? new Date(alert.timestamp) 
    : alert.timestamp;

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ delay: index * 0.03 }}
      className={cn(
        'group flex gap-3 rounded-lg border p-3 mb-2 transition-colors',
        config.border,
        alert.acknowledged && 'opacity-50'
      )}
    >
      <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded-lg', config.bg)}>
        <Icon className={cn('h-4 w-4', config.color)} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <p className="text-sm font-medium leading-tight">{alert.title}</p>
          <time className="shrink-0 text-[10px] text-muted-foreground">
            {isValid(timestamp) ? formatDistanceToNow(timestamp, { addSuffix: true }) : '—'}
          </time>
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">
          {alert.message}
        </p>
        {alert.source && (
          <Badge variant="outline" className="mt-1.5 text-[10px] h-5">
            {alert.source}
          </Badge>
        )}
      </div>

      {!alert.acknowledged && onAcknowledge && (
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 shrink-0 opacity-0 group-hover:opacity-100 focus:opacity-100"
          onClick={() => onAcknowledge(alert.id)}
          aria-label={t('AlertsWidget.acknowledgeAlert', { title: alert.title })}
          title={t('AlertsWidget.acknowledge')}
        >
          <CheckCircle className="h-4 w-4" />
        </Button>
      )}
    </motion.div>
  );
}
