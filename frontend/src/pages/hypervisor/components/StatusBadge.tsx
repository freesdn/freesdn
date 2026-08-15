// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { CheckCircle, Play, Square, Pause, XCircle, Clock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

const STATUS_MAP: Record<string, { variant: 'default' | 'secondary' | 'destructive' | 'outline'; icon: typeof CheckCircle }> = {
  online: { variant: 'default', icon: CheckCircle },
  running: { variant: 'default', icon: Play },
  stopped: { variant: 'secondary', icon: Square },
  paused: { variant: 'outline', icon: Pause },
  offline: { variant: 'destructive', icon: XCircle },
};

export function statusBadge(status: string) {
  const cfg = STATUS_MAP[status] || { variant: 'secondary' as const, icon: Clock };
  const Icon = cfg.icon;
  return (
    <Badge variant={cfg.variant} className="gap-1">
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}
