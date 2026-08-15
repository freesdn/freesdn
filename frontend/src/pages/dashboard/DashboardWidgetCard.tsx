// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DashboardWidgetCard
 * =====================
 *
 * Standardised card wrapper used by every customisable dashboard widget.
 * Renders the title + icon header and, when the user is in customise mode,
 * adds:
 *   - a dashed primary outline so the card visibly says "I'm editable"
 *   - a drag handle in the top-left (useSortable from dnd-kit)
 *   - an X button in the top-right that calls `onRemove`
 *
 * The component does NOT decide whether the user can customise · the parent
 * passes `editing` based on the dashboard layout store.
 */

import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { useTranslation } from 'react-i18next';
import { GripVertical, Package, X, type LucideIcon } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { SectionBoundary } from '@/components/SectionBoundary';
import { cn } from '@/lib/utils';

export interface DashboardWidgetCardProps {
  /** Widget id (forwarded to onRemove for the layout store) */
  id: string;
  title: string;
  icon?: LucideIcon;
  /** Tailwind colSpan classes · controlled by registry colSpan */
  colSpanClass?: string;
  /** When true, renders the dashed outline + drag handle + X-to-remove affordance */
  editing?: boolean;
  /** Called with widget id when the X button is clicked */
  onRemove?: (id: string) => void;
  children: React.ReactNode;
  /** Optional className passthrough for the outer Card */
  className?: string;
}

export function DashboardWidgetCard({
  id,
  title,
  icon: Icon = Package,
  colSpanClass,
  editing = false,
  onRemove,
  children,
  className,
}: DashboardWidgetCardProps) {
  const { t } = useTranslation('dashboard');
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id, disabled: !editing });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    // Lift dragged card visually
    opacity: isDragging ? 0.6 : 1,
    zIndex: isDragging ? 50 : undefined,
  };

  return (
    <div ref={setNodeRef} style={style} className={cn(colSpanClass)}>
      <Card
        className={cn(
          'relative h-full transition-all',
          editing && 'ring-2 ring-dashed ring-primary/40 ring-offset-2 ring-offset-background',
          isDragging && 'shadow-2xl',
          className,
        )}
      >
        {editing && (
          <>
            {/* Drag handle · top-left, listeners attached so only this triggers drag */}
            <button
              type="button"
              className="absolute top-2 left-2 z-10 inline-flex h-7 w-7 items-center justify-center rounded-full bg-card border border-border shadow-sm cursor-grab active:cursor-grabbing hover:bg-muted touch-none"
              aria-label={t('DashboardWidgetCard.dragHandle.ariaLabel', { title })}
              title={t('DashboardWidgetCard.dragHandle.title')}
              {...attributes}
              {...listeners}
            >
              <GripVertical className="h-3.5 w-3.5 text-muted-foreground" />
            </button>
            {/* Remove · top-right */}
            {onRemove && (
              <Button
                variant="ghost"
                size="icon"
                className="absolute top-2 right-2 z-10 h-7 w-7 rounded-full bg-card border border-border shadow-sm hover:bg-destructive hover:text-destructive-foreground"
                onClick={() => onRemove(id)}
                aria-label={t('DashboardWidgetCard.remove.ariaLabel', { title })}
                title={t('DashboardWidgetCard.remove.title', { title })}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            )}
          </>
        )}
        <CardHeader className={cn('pb-2', editing && 'pl-12 pr-12')}>
          <CardTitle className="text-base font-medium flex items-center gap-2">
            <Icon className="h-4 w-4 text-muted-foreground" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <SectionBoundary>{children}</SectionBoundary>
        </CardContent>
      </Card>
    </div>
  );
}
