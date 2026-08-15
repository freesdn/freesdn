// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useTranslation } from 'react-i18next';
import { Badge } from '@/components/ui/badge';

export function HealthStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('enterprise');
  const variants: Record<string, { label: string; className: string }> = {
    healthy:  { label: t('HealthStatusBadge.status.healthy'),  className: 'bg-green-500/10 text-green-500 border-green-500/20' },
    warning:  { label: t('HealthStatusBadge.status.warning'),  className: 'bg-amber-500/10 text-amber-500 border-amber-500/20' },
    degraded: { label: t('HealthStatusBadge.status.degraded'), className: 'bg-orange-500/10 text-orange-500 border-orange-500/20' },
    critical: { label: t('HealthStatusBadge.status.critical'), className: 'bg-red-500/10 text-red-500 border-red-500/20' },
    unknown:  { label: t('HealthStatusBadge.status.unknown'),  className: 'bg-muted text-muted-foreground' },
  };
  const v = variants[status] ?? variants.unknown;
  return <Badge variant="outline" className={v.className}>{v.label}</Badge>;
}
