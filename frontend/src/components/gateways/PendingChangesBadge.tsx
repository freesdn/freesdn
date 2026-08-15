// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * PendingChangesBadge, header button + pending-count poll.
 *
 * Lives next to the Sync button on ``GatewayDetailPage``. Renders the
 * count of staged-but-not-yet-applied changes for THIS gateway and
 * opens the drawer when clicked. Polls every 8s so the count stays
 * fresh even when the operator is staging from another tab.
 *
 * Stays mounted whether the drawer is open or closed, the count
 * fetch is cheap (each domain caps at 200, only the pending status
 * is requested) and operators expect to see the badge update live.
 */
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { ClipboardList } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  listChangesForGateway,
  type GatewayVendor,
} from '@/lib/api';

import { pendingChangesQueryKey } from './PendingChangesDrawer';

export interface PendingChangesBadgeProps {
  vendor: GatewayVendor;
  gatewayId: string;
  /** Open/close handler, typically the same useState pair as the drawer. */
  onOpenChange: (open: boolean) => void;
  /** Drawer state (used to nudge a refetch on open). */
  open: boolean;
}

export function PendingChangesBadge({
  vendor,
  gatewayId,
  onOpenChange,
  open,
}: PendingChangesBadgeProps) {
  const { t } = useTranslation('common');

  // Re-uses the drawer's query key so opening the drawer doesn't
  // trigger a duplicate fetch, react-query dedupes by key.
  const query = useQuery({
    queryKey: pendingChangesQueryKey(vendor, gatewayId),
    queryFn: () =>
      listChangesForGateway(vendor, gatewayId, { status: 'pending' }),
    enabled: !!gatewayId,
    refetchInterval: 8_000,
    refetchOnWindowFocus: true,
    staleTime: 4_000,
  });

  const count = query.data?.length ?? 0;

  // Pulse the icon briefly when count increases (operator just
  // staged something), visual cue that there's work waiting.
  const prevCount = useRef(count);
  const pulseRef = useRef<HTMLSpanElement | null>(null);
  useEffect(() => {
    if (count > prevCount.current && pulseRef.current) {
      pulseRef.current.classList.remove('animate-ping');
      // Force reflow so the same class can re-trigger.
      void pulseRef.current.offsetWidth;
      pulseRef.current.classList.add('animate-ping');
    }
    prevCount.current = count;
  }, [count]);

  // Hide when there's nothing to apply. Operators got annoyed by a
  // permanent "Pending (0)" pill in earlier prototypes.
  if (count === 0) {
    return (
      <Button
        variant="ghost"
        size="sm"
        onClick={() => onOpenChange(!open)}
        aria-label={t('PendingChangesBadge.ariaLabel.open')}
        title={t('PendingChangesBadge.title.none')}
        className="text-muted-foreground"
      >
        <ClipboardList className="h-4 w-4 mr-1" />
        {t('PendingChangesBadge.label')}
      </Button>
    );
  }

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() => onOpenChange(!open)}
      aria-label={t('PendingChangesBadge.ariaLabel.openStaged', { count })}
      title={
        count === 1
          ? t('PendingChangesBadge.title.one', { count })
          : t('PendingChangesBadge.title.many', { count })
      }
      className="relative"
    >
      <ClipboardList className="h-4 w-4 mr-1" />
      {t('PendingChangesBadge.label')}
      <Badge variant="default" className={cn('ml-2', 'tabular-nums')}>
        {count}
      </Badge>
      {/* small pulse marker, overlaps the badge corner */}
      <span
        ref={pulseRef}
        aria-hidden="true"
        className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-primary opacity-75"
      />
    </Button>
  );
}
