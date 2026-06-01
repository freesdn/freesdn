// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Context Actions Menu
 *
 * A dropdown button that collects context actions from all enabled modules
 * for a specific entity type and renders them as menu items.
 * Clicking a menu item opens the action's component as a modal dialog.
 */

import { Suspense, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { MoreHorizontal } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { moduleManifests } from '@/modules';
import type { EntityType, ModuleContextAction } from '@/modules/types';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ContextActionsMenuProps {
  entityType: EntityType;
  entityId: string;
  /** Pass entity data for condition evaluation */
  entity?: Record<string, unknown>;
  /** Set of enabled module IDs (if not provided, all modules are enabled) */
  enabledModuleIds?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Collects context actions from all enabled modules for the given entity type
 * and renders them as a "more actions" dropdown button.
 *
 * Usage:
 * ```tsx
 * <ContextActionsMenu entityType="device" entityId={deviceId} entity={device} />
 * ```
 */
export function ContextActionsMenu({
  entityType,
  entityId,
  entity,
  enabledModuleIds,
}: ContextActionsMenuProps) {
  const { t } = useTranslation('common');
  const enabledSet = enabledModuleIds ? new Set(enabledModuleIds) : null;
  const [activeAction, setActiveAction] = useState<ModuleContextAction | null>(null);

  const actions = moduleManifests
    .filter((m) => !enabledSet || enabledSet.has(m.id))
    .flatMap((m) => m.contextActions ?? [])
    .filter((a) => a.entityType === entityType)
    .filter((a) => !a.condition || (entity && a.condition(entity)));

  if (actions.length === 0) return null;

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm">
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {actions.map((action) => (
            <DropdownMenuItem
              key={action.id}
              onClick={() => setActiveAction(action)}
              className="gap-2"
            >
              <action.icon className="h-4 w-4" />
              {action.label}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Action dialog */}
      {activeAction && (
        <Dialog open onOpenChange={() => setActiveAction(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{activeAction.label}</DialogTitle>
            </DialogHeader>
            <Suspense fallback={<div className="py-8 text-center text-sm text-muted-foreground">{t('ContextActionsMenu.loading')}</div>}>
              <activeAction.component
                entityId={entityId}
                onClose={() => setActiveAction(null)}
              />
            </Suspense>
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}
