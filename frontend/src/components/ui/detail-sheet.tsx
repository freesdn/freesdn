// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · DetailSheet primitive
 *
 * A thin opinionated wrapper around the shadcn `<Sheet>` for the
 * "click row → see details in side panel" pattern. Standardizes the
 * UniFi-style inspect-without-navigate UX:
 *
 *   - Slides in from the RIGHT
 *   - Header: icon + title + description + status pill (close button top-right)
 *   - Body: scrollable
 *   - Footer: secondary actions (left) + primary action (right), sticky
 *
 * Example
 * -------
 * ```tsx
 * <DetailSheet
 *   open={!!selectedDevice}
 *   onOpenChange={(o) => !o && setSelectedDevice(null)}
 *   icon={DeviceTypeIcon}
 *   title={selectedDevice?.name}
 *   description={`${selectedDevice?.vendor} ${selectedDevice?.model}`}
 *   status={<StatusBadge variant="online" />}
 *   primaryAction={{ label: 'View details', onClick: () => navigate(...) }}
 *   secondaryActions={[{ label: 'Reboot', icon: Power, onClick: handleReboot }]}
 * >
 *   <div className="space-y-4">…body…</div>
 * </DetailSheet>
 * ```
 *
 * Adoption is incremental · pages migrate independently.
 */

import { ReactNode } from 'react';
import type { ComponentType, SVGProps } from 'react';
import type { LucideIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '../../lib/utils';
import { Button } from './button';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
} from './sheet';

// Accept either a Lucide icon or any React component that renders an SVG.
// Some adopters pass `DeviceTypeIcon` (a custom wrapper) · keep it loose.
type IconComponent = LucideIcon | ComponentType<SVGProps<SVGSVGElement>>;

export interface DetailSheetAction {
  /** Visible label */
  label: string;
  /** Optional leading icon */
  icon?: IconComponent;
  /** Click handler */
  onClick?: () => void;
  /** Visual variant · defaults to 'default' for primary, 'outline' for secondary */
  variant?: 'default' | 'outline' | 'ghost' | 'destructive' | 'secondary';
  /** Loading state · disables the button and shows the icon spinning if any */
  loading?: boolean;
  /** Disabled state */
  disabled?: boolean;
  /** Optional override for the underlying button type */
  type?: 'button' | 'submit';
}

export interface DetailSheetProps {
  /** Open state · controlled */
  open: boolean;
  /** Setter · should call with `false` when the user dismisses */
  onOpenChange: (open: boolean) => void;
  /** Title shown in the header */
  title?: ReactNode;
  /** Subtitle / description under the title */
  description?: ReactNode;
  /** Optional icon next to the title */
  icon?: IconComponent;
  /** Optional status pill (e.g. <StatusBadge variant="online" />) · rendered top-right of the title row */
  status?: ReactNode;
  /** Body content · scrollable */
  children?: ReactNode;
  /** Primary action · rendered on the right of the footer */
  primaryAction?: DetailSheetAction;
  /** Secondary actions · rendered on the left of the footer */
  secondaryActions?: DetailSheetAction[];
  /** When true, content area uses the wider variant (`sm:max-w-xl`); default is `sm:max-w-md`. */
  wide?: boolean;
  /** Optional className passthrough for the SheetContent */
  className?: string;
  /** Optional className passthrough for the body wrapper */
  bodyClassName?: string;
}

function renderActionButton(
  action: DetailSheetAction,
  fallbackVariant: DetailSheetAction['variant'],
) {
  const Icon = action.icon;
  return (
    <Button
      key={action.label}
      type={action.type ?? 'button'}
      variant={action.variant ?? fallbackVariant}
      onClick={action.onClick}
      disabled={action.disabled || action.loading}
      size="sm"
    >
      {Icon ? (
        <Icon
          className={cn('h-4 w-4', action.label && 'mr-2', action.loading && 'animate-spin')}
        />
      ) : null}
      {action.label}
    </Button>
  );
}

export function DetailSheet({
  open,
  onOpenChange,
  title,
  description,
  icon: Icon,
  status,
  children,
  primaryAction,
  secondaryActions,
  wide = false,
  className,
  bodyClassName,
}: DetailSheetProps) {
  const { t } = useTranslation('common');
  const hasFooter = !!primaryAction || (secondaryActions && secondaryActions.length > 0);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className={cn(
          // Override sheet's default `w-3/4 sm:max-w-xl` for a tighter inspect panel.
          'w-full p-0 flex flex-col gap-0',
          wide ? 'sm:max-w-xl' : 'sm:max-w-md',
          className,
        )}
      >
        {/* Header */}
        <div className="px-4 sm:px-6 pt-4 sm:pt-6 pb-4 border-b border-border">
          <div className="flex items-start gap-3 pr-8">
            {Icon ? (
              <div className="flex-shrink-0 h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <Icon className="h-5 w-5 text-primary" />
              </div>
            ) : null}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                {title ? (
                  <SheetTitle className="text-lg font-semibold leading-tight truncate">
                    {title}
                  </SheetTitle>
                ) : (
                  // Radix requires a Title for a11y · render an sr-only fallback.
                  <SheetTitle className="sr-only">{t('DetailSheet.srTitle')}</SheetTitle>
                )}
                {status ? <span className="flex-shrink-0">{status}</span> : null}
              </div>
              {description ? (
                <SheetDescription className="mt-0.5 text-sm text-muted-foreground line-clamp-2">
                  {description}
                </SheetDescription>
              ) : null}
            </div>
          </div>
        </div>

        {/* Body */}
        <div
          className={cn(
            'flex-1 min-h-0 overflow-y-auto px-4 sm:px-6 py-4 sm:py-5',
            bodyClassName,
          )}
        >
          {children}
        </div>

        {/* Footer (sticky bottom) */}
        {hasFooter ? (
          <div className="px-4 sm:px-6 py-3 border-t border-border bg-card flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              {(secondaryActions ?? []).map((a) => renderActionButton(a, 'outline'))}
            </div>
            <div className="flex items-center gap-2 sm:flex-shrink-0">
              {primaryAction ? renderActionButton(primaryAction, 'default') : null}
            </div>
          </div>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
