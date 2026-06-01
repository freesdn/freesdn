// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Device Status Widget
 * 
 * Visual breakdown of device health with donut chart
 */

import { motion } from 'framer-motion';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Wifi, WifiOff, AlertTriangle, HelpCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';

interface DeviceStatusData {
  online: number;
  offline: number;
  warning: number;
  unknown: number;
}

interface DeviceStatusWidgetProps {
  data: DeviceStatusData;
  className?: string;
}

// Recharts requires raw hex colors for chart cells; semantic equivalents documented inline
// labelKey is a suffix translated at the render site (constant lives at module scope, can't call t())
const statusConfig = [
  { key: 'online', labelKey: 'status.online', color: '#10b981', icon: Wifi, tintClass: 'bg-success/10', iconClass: 'text-success' }, // success
  { key: 'offline', labelKey: 'status.offline', color: '#ef4444', icon: WifiOff, tintClass: 'bg-destructive/10', iconClass: 'text-destructive' }, // destructive
  { key: 'warning', labelKey: 'status.warning', color: '#f59e0b', icon: AlertTriangle, tintClass: 'bg-warning/10', iconClass: 'text-warning' }, // warning
  { key: 'unknown', labelKey: 'status.unknown', color: '#6b7280', icon: HelpCircle, tintClass: 'bg-muted', iconClass: 'text-muted-foreground' }, // muted
] as const;

export function DeviceStatusWidget({ data, className }: DeviceStatusWidgetProps) {
  const { t } = useTranslation('common');
  const total = data.online + data.offline + data.warning + data.unknown;

  const chartData = statusConfig.map(({ key, labelKey, color }) => ({
    name: t(`DeviceStatusWidget.${labelKey}`),
    value: data[key],
    color,
  })).filter(d => d.value > 0);

  const onlinePercentage = total > 0 ? Math.round((data.online / total) * 100) : 0;

  return (
    <div className={cn('space-y-4', className)}>
      {/* Chart */}
      <div className="relative h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
              animationBegin={0}
              animationDuration={800}
            >
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="rounded-lg border bg-popover px-3 py-2 text-sm shadow-md">
                      <p className="font-medium">{payload[0].name}</p>
                      <p className="text-muted-foreground">{t('DeviceStatusWidget.tooltip.devices', { n: payload[0].value as number })}</p>
                    </div>
                  );
                }
                return null;
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span 
            className="text-3xl font-bold"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.3, type: 'spring' }}
          >
            {onlinePercentage}%
          </motion.span>
          <span className="text-xs text-muted-foreground">{t('DeviceStatusWidget.status.online')}</span>
        </div>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-2">
        {statusConfig.map(({ key, labelKey, icon: Icon, tintClass, iconClass }) => (
          <motion.div
            key={key}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="flex items-center gap-2 rounded-lg p-2 transition-colors hover:bg-muted/50"
          >
            <div className={cn('flex h-8 w-8 items-center justify-center rounded-lg', tintClass)}>
              <Icon className={cn('h-4 w-4', iconClass)} />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium">{data[key]}</p>
              <p className="text-xs text-muted-foreground">{t(`DeviceStatusWidget.${labelKey}`)}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
