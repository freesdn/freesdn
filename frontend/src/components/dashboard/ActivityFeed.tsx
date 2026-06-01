// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Activity Feed Component
 * 
 * Real-time activity feed with event types and timestamps
 */

import { motion, AnimatePresence } from 'framer-motion';
import { formatDistanceToNow, isValid } from 'date-fns';
import {
  Activity,
  Server,
  Wifi,
  WifiOff,
  AlertTriangle,
  Settings,
  User,
  RefreshCw,
  Zap,
  LucideIcon,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';

export interface ActivityEvent {
  id: string;
  type: 'device_online' | 'device_offline' | 'config_change' | 'alert' | 'user_action' | 'sync' | 'automation';
  title: string;
  description?: string;
  timestamp: string | Date;
  severity?: 'info' | 'success' | 'warning' | 'error';
  metadata?: {
    device?: string;
    user?: string;
    site?: string;
  };
}

const eventConfig: Record<ActivityEvent['type'], { icon: LucideIcon; color: string }> = {
  device_online: { icon: Wifi, color: 'text-success bg-success/10' },
  device_offline: { icon: WifiOff, color: 'text-destructive bg-destructive/10' },
  config_change: { icon: Settings, color: 'text-info bg-info/10' },
  alert: { icon: AlertTriangle, color: 'text-warning bg-warning/10' },
  user_action: { icon: User, color: 'text-primary bg-primary/10' },
  sync: { icon: RefreshCw, color: 'text-info bg-info/10' },
  automation: { icon: Zap, color: 'text-primary bg-primary/10' },
};

interface ActivityFeedProps {
  events: ActivityEvent[];
  maxHeight?: number;
  showEmpty?: boolean;
  className?: string;
}

export function ActivityFeed({ 
  events, 
  maxHeight = 400, 
  showEmpty = true,
  className
}: ActivityFeedProps) {
  const { t } = useTranslation('common');

  if (events.length === 0 && showEmpty) {
    return (
      <div className={cn('flex flex-col items-center justify-center py-12', className)}>
        <Activity className="h-12 w-12 text-muted-foreground/30" />
        <p className="mt-4 text-sm text-muted-foreground">{t('ActivityFeed.empty')}</p>
      </div>
    );
  }

  return (
    <ScrollArea className={className} style={{ maxHeight }}>
      <div className="space-y-1">
        <AnimatePresence mode="popLayout">
          {events.map((event, index) => (
            <ActivityItem key={event.id} event={event} index={index} />
          ))}
        </AnimatePresence>
      </div>
    </ScrollArea>
  );
}

function ActivityItem({ event, index }: { event: ActivityEvent; index: number }) {
  const config = eventConfig[event.type] || eventConfig.user_action;
  const Icon = config.icon;
  
  const timestamp = typeof event.timestamp === 'string' 
    ? new Date(event.timestamp) 
    : event.timestamp;

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ delay: index * 0.05 }}
      className="group flex gap-3 rounded-lg p-3 transition-colors hover:bg-muted/50"
    >
      <div className={cn(
        'flex h-9 w-9 shrink-0 items-center justify-center rounded-full',
        config.color.split(' ')[1]
      )}>
        <Icon className={cn('h-4 w-4', config.color.split(' ')[0])} />
      </div>
      
      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <p className="text-sm font-medium leading-tight">{event.title}</p>
          <time className="shrink-0 text-xs text-muted-foreground">
            {isValid(timestamp) ? formatDistanceToNow(timestamp, { addSuffix: true }) : '—'}
          </time>
        </div>
        {event.description && (
          <p className="mt-1 text-xs text-muted-foreground line-clamp-2">
            {event.description}
          </p>
        )}
        {event.metadata && (
          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
            {event.metadata.site && (
              <span className="flex items-center gap-1">
                <Server className="h-3 w-3" />
                {event.metadata.site}
              </span>
            )}
            {event.metadata.device && (
              <span className="flex items-center gap-1">
                <Wifi className="h-3 w-3" />
                {event.metadata.device}
              </span>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}
