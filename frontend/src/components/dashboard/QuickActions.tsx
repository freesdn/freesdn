// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Quick Actions Widget
 * 
 * Common actions with keyboard shortcuts
 */

import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import {
  Plus,
  RefreshCw,
  Radar,
  Download,
  LucideIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface QuickAction {
  id: string;
  label: string;
  description?: string;
  icon: LucideIcon;
  shortcut?: string;
  variant?: 'default' | 'secondary' | 'outline' | 'ghost';
  onClick: () => void;
}

interface QuickActionsProps {
  actions?: QuickAction[];
  onAddDevice?: () => void;
  onDiscovery?: () => void;
  onSync?: () => void;
  onBackup?: () => void;
  className?: string;
}

const buildDefaultActions = (
  t: TFunction,
): Omit<QuickAction, 'onClick'>[] => [
  {
    id: 'add-device',
    label: t('QuickActions.actions.addDevice.label'),
    description: t('QuickActions.actions.addDevice.description'),
    icon: Plus,
    shortcut: '⌘N',
    variant: 'default',
  },
  {
    id: 'discovery',
    label: t('QuickActions.actions.discovery.label'),
    description: t('QuickActions.actions.discovery.description'),
    icon: Radar,
    shortcut: '⌘D',
    variant: 'outline',
  },
  {
    id: 'sync',
    label: t('QuickActions.actions.sync.label'),
    description: t('QuickActions.actions.sync.description'),
    icon: RefreshCw,
    shortcut: '⌘R',
    variant: 'outline',
  },
  {
    id: 'backup',
    label: t('QuickActions.actions.backup.label'),
    description: t('QuickActions.actions.backup.description'),
    icon: Download,
    variant: 'outline',
  },
];

export function QuickActions({ 
  actions,
  onAddDevice,
  onDiscovery,
  onSync,
  onBackup,
  className 
}: QuickActionsProps) {
  const { t } = useTranslation('common');

  const actionHandlers: Record<string, (() => void) | undefined> = {
    'add-device': onAddDevice,
    'discovery': onDiscovery,
    'sync': onSync,
    'backup': onBackup,
  };

  const resolvedActions = actions || buildDefaultActions(t).map(action => ({
    ...action,
    onClick: actionHandlers[action.id] || (() => {}),
  }));

  return (
    // Single column · narrow right-rail use case is the common one. Tiles
    // would overflow at 2 columns inside a 1/3-width sidebar Card.
    <div className={cn('flex flex-col gap-2', className)}>
      {resolvedActions.map((action, index) => (
        <motion.div
          key={action.id}
          initial={{ opacity: 0, scale: 0.97 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: index * 0.04 }}
        >
          <Button
            variant={action.variant || 'outline'}
            className={cn(
              'w-full justify-start gap-3 h-auto py-2.5 px-3',
              action.variant === 'default' && 'bg-primary hover:bg-primary/90',
            )}
            onClick={action.onClick}
          >
            <action.icon className="h-4 w-4 shrink-0" />
            <div className="flex-1 text-left min-w-0">
              <p className="text-sm font-medium leading-tight truncate">{action.label}</p>
              {action.description && (
                <p className="text-[11px] opacity-70 leading-tight truncate">
                  {action.description}
                </p>
              )}
            </div>
            {action.shortcut && (
              <kbd className="hidden lg:inline-flex h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground shrink-0">
                {action.shortcut}
              </kbd>
            )}
          </Button>
        </motion.div>
      ))}
    </div>
  );
}
