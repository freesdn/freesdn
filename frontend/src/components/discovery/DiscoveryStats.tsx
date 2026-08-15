// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DiscoveryStats - Summary statistics cards for the discovery page.
 */

import {
  Radar,
  Server,
  CheckCircle,
  Wifi,
  Clock,
  AlertCircle,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface DiscoveryStatsProps {
  totalScans: number;
  devicesFound: number;
  devicesAdopted: number;
  activeScans: number;
  pendingDevices: number;
  failedScans: number;
}

const stats = [
  {
    key: 'totalScans',
    labelKey: 'totalScans',
    icon: Radar,
    color: 'text-blue-500',
    bg: 'bg-blue-500/10',
  },
  {
    key: 'devicesFound',
    labelKey: 'devicesFound',
    icon: Server,
    color: 'text-emerald-500',
    bg: 'bg-emerald-500/10',
  },
  {
    key: 'devicesAdopted',
    labelKey: 'devicesAdopted',
    icon: CheckCircle,
    color: 'text-emerald-500',
    bg: 'bg-emerald-500/10',
  },
  {
    key: 'activeScans',
    labelKey: 'activeScans',
    icon: Wifi,
    color: 'text-amber-500',
    bg: 'bg-amber-500/10',
    warnWhen: (v: number) => v > 0,
  },
  {
    key: 'pendingDevices',
    labelKey: 'pendingDevices',
    icon: Clock,
    color: 'text-amber-500',
    bg: 'bg-amber-500/10',
    warnWhen: (v: number) => v > 0,
  },
  {
    key: 'failedScans',
    labelKey: 'failedScans',
    icon: AlertCircle,
    color: 'text-red-500',
    bg: 'bg-red-500/10',
    warnWhen: (v: number) => v > 0,
  },
] as const;

export default function DiscoveryStats(props: DiscoveryStatsProps) {
  const { t } = useTranslation('common');
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
      {stats.map((stat) => {
        const value = props[stat.key as keyof DiscoveryStatsProps];
        const Icon = stat.icon;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const isWarning = 'warnWhen' in stat && (stat as any).warnWhen(value);
        return (
          <Card key={stat.key}>
            <CardContent noOffset className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">{t(`DiscoveryStats.stats.${stat.labelKey}`)}</p>
                  <p
                    className={cn(
                      'text-2xl font-bold',
                      isWarning && stat.color,
                    )}
                  >
                    {value}
                  </p>
                </div>
                <div className={cn('w-9 h-9 rounded-lg flex items-center justify-center', stat.bg)}>
                  <Icon className={cn('h-5 w-5', stat.color)} />
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
