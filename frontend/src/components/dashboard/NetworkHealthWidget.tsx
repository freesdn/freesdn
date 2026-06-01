// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Network Health Widget
 * 
 * Network performance metrics with mini sparklines
 */

import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import {
  AreaChart,
  Area,
  ResponsiveContainer,
} from 'recharts';
import { 
  Activity, 
  Gauge, 
  Download, 
  Upload, 
  Clock,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NetworkMetric {
  label: string;
  value: string;
  unit: string;
  trend: number[];
  status: 'good' | 'warning' | 'critical';
  icon: typeof Activity;
}

interface NetworkHealthWidgetProps {
  latency: { value: number; history: number[] };
  throughput: { download: number; upload: number; history: { download: number; upload: number }[] };
  packetLoss: { value: number; history: number[] };
  uptime: { value: number; label: string };
  className?: string;
}

// stroke hex values are required by Recharts; bg/text use semantic tokens
const statusColors = {
  good: { bg: 'bg-success/10', text: 'text-success', stroke: '#10b981' },
  warning: { bg: 'bg-warning/10', text: 'text-warning', stroke: '#f59e0b' },
  critical: { bg: 'bg-destructive/10', text: 'text-destructive', stroke: '#ef4444' },
};

function MiniSparkline({ 
  data, 
  color = '#3b82f6',
  height = 32 
}: { 
  data: number[]; 
  color?: string;
  height?: number;
}) {
  const chartData = data.map((value, index) => ({ value, index }));
  
  return (
    <div style={{ height, width: '100%' }}>
      <ResponsiveContainer>
        <AreaChart data={chartData} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={`gradient-${color}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.3} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <Area
            type="monotone"
            dataKey="value"
            stroke={color}
            strokeWidth={1.5}
            fill={`url(#gradient-${color})`}
            animationDuration={500}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function MetricCard({
  label,
  value,
  unit,
  trend,
  status,
  icon: Icon,
  delay = 0,
}: NetworkMetric & { delay?: number }) {
  const colors = statusColors[status];
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="space-y-2"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={cn('rounded-lg p-1.5', colors.bg)}>
            <Icon className={cn('h-3.5 w-3.5', colors.text)} />
          </div>
          <span className="text-xs font-medium text-muted-foreground">{label}</span>
        </div>
        <span className="text-sm font-semibold">
          {value}
          <span className="text-xs font-normal text-muted-foreground ml-0.5">{unit}</span>
        </span>
      </div>
      <MiniSparkline data={trend} color={colors.stroke} />
    </motion.div>
  );
}

export function NetworkHealthWidget({ 
  latency, 
  throughput, 
  packetLoss, 
  uptime,
  className
}: NetworkHealthWidgetProps) {
  const { t } = useTranslation('common');

  const getLatencyStatus = (ms: number): 'good' | 'warning' | 'critical' => {
    if (ms < 50) return 'good';
    if (ms < 100) return 'warning';
    return 'critical';
  };

  const getPacketLossStatus = (percent: number): 'good' | 'warning' | 'critical' => {
    if (percent < 1) return 'good';
    if (percent < 5) return 'warning';
    return 'critical';
  };

  return (
    <div className={cn('space-y-4', className)}>
      {/* Main metrics grid */}
      <div className="grid gap-4">
        <MetricCard
          label={t('NetworkHealthWidget.metrics.latency')}
          value={latency.value.toString()}
          unit="ms"
          trend={latency.history}
          status={getLatencyStatus(latency.value)}
          icon={Gauge}
          delay={0}
        />
        
        <MetricCard
          label={t('NetworkHealthWidget.metrics.packetLoss')}
          value={packetLoss.value.toFixed(2)}
          unit="%"
          trend={packetLoss.history}
          status={getPacketLossStatus(packetLoss.value)}
          icon={Activity}
          delay={0.1}
        />
      </div>

      {/* Throughput */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="rounded-lg border bg-muted/30 p-3"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-muted-foreground">{t('NetworkHealthWidget.throughput.title')}</span>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="flex items-center gap-2">
            <Download className="h-4 w-4 text-success" />
            <div>
              <p className="text-sm font-semibold">{throughput.download.toFixed(1)} Mbps</p>
              <p className="text-xs text-muted-foreground">{t('NetworkHealthWidget.throughput.download')}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Upload className="h-4 w-4 text-info" />
            <div>
              <p className="text-sm font-semibold">{throughput.upload.toFixed(1)} Mbps</p>
              <p className="text-xs text-muted-foreground">{t('NetworkHealthWidget.throughput.upload')}</p>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Uptime */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="flex items-center justify-between rounded-lg border bg-muted/30 p-3"
      >
        <div className="flex items-center gap-2">
          <div className="rounded-lg bg-success/10 p-1.5">
            <Clock className="h-3.5 w-3.5 text-success" />
          </div>
          <span className="text-xs font-medium text-muted-foreground">{t('NetworkHealthWidget.uptime.title')}</span>
        </div>
        <div className="text-right">
          <p className="text-sm font-semibold">{uptime.value.toFixed(2)}%</p>
          <p className="text-xs text-muted-foreground">{uptime.label}</p>
        </div>
      </motion.div>
    </div>
  );
}
