// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - System Status Widget
 * 
 * System health and service status overview
 */

import { motion } from 'framer-motion';
import {
  HardDrive,
  Cpu,
  MemoryStick,
  CheckCircle,
  AlertCircle,
  XCircle,
  Clock,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';

interface ServiceStatus {
  id: string;
  name: string;
  status: 'healthy' | 'degraded' | 'down';
  latency?: number;
  uptime?: string;
}

interface SystemStatusWidgetProps {
  services: ServiceStatus[];
  resources?: {
    cpu: number;
    memory: number;
    disk: number;
  };
  version?: string;
  className?: string;
}

const statusConfig = {
  healthy: {
    icon: CheckCircle,
    color: 'text-success',
    bg: 'bg-success',
    labelKey: 'status.healthy',
  },
  degraded: {
    icon: AlertCircle,
    color: 'text-warning',
    bg: 'bg-warning',
    labelKey: 'status.degraded',
  },
  down: {
    icon: XCircle,
    color: 'text-destructive',
    bg: 'bg-destructive',
    labelKey: 'status.down',
  },
};

export function SystemStatusWidget({
  services,
  resources,
  version,
  className,
}: SystemStatusWidgetProps) {
  const { t } = useTranslation('common');
  const healthyCount = services.filter(s => s.status === 'healthy').length;
  const allHealthy = healthyCount === services.length;

  return (
    <div className={cn('space-y-4', className)}>
      {/* Overall status */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={cn(
          'flex items-center gap-3 rounded-lg border p-3',
          allHealthy
            ? 'border-success/20 bg-success/5'
            : 'border-warning/20 bg-warning/5'
        )}
      >
        <div className={cn(
          'flex h-10 w-10 items-center justify-center rounded-full',
          allHealthy ? 'bg-success/10' : 'bg-warning/10'
        )}>
          {allHealthy ? (
            <CheckCircle className="h-5 w-5 text-success" />
          ) : (
            <AlertCircle className="h-5 w-5 text-warning" />
          )}
        </div>
        <div>
          <p className="text-sm font-medium">
            {allHealthy
              ? t('SystemStatusWidget.overall.allOperational')
              : t('SystemStatusWidget.overall.needsAttention')}
          </p>
          <p className="text-xs text-muted-foreground">
            {t('SystemStatusWidget.overall.servicesHealthy', {
              healthy: healthyCount,
              total: services.length,
            })}
            {version && ` • v${version}`}
          </p>
        </div>
      </motion.div>

      {/* Services list */}
      <div className="space-y-2">
        {services.map((service, index) => (
          <ServiceRow key={service.id} service={service} index={index} />
        ))}
      </div>

      {/* Resource usage */}
      {resources && (
        <div className="space-y-3 pt-2">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            {t('SystemStatusWidget.resources.heading')}
          </p>
          <ResourceBar
            label={t('SystemStatusWidget.resources.cpu')}
            value={resources.cpu}
            icon={Cpu}
          />
          <ResourceBar
            label={t('SystemStatusWidget.resources.memory')}
            value={resources.memory}
            icon={MemoryStick}
          />
          <ResourceBar
            label={t('SystemStatusWidget.resources.disk')}
            value={resources.disk}
            icon={HardDrive}
          />
        </div>
      )}
    </div>
  );
}

function ServiceRow({ 
  service, 
  index 
}: { 
  service: ServiceStatus;
  index: number;
}) {
  const { t } = useTranslation('common');
  const config = statusConfig[service.status];

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="flex items-center justify-between rounded-lg px-3 py-2 transition-colors hover:bg-muted/50"
    >
      <div className="flex items-center gap-3">
        <span className={cn('h-2 w-2 rounded-full', config.bg)} />
        <span className="text-sm font-medium">{service.name}</span>
      </div>
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        {service.latency !== undefined && (
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {t('SystemStatusWidget.service.latencyMs', { latency: service.latency })}
          </span>
        )}
        <span className={config.color}>
          {t(`SystemStatusWidget.${config.labelKey}`)}
        </span>
      </div>
    </motion.div>
  );
}

function ResourceBar({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: number;
  icon: typeof Cpu;
}) {
  const getColor = (v: number) => {
    if (v < 60) return 'bg-success';
    if (v < 80) return 'bg-warning';
    return 'bg-destructive';
  };

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="flex items-center gap-1.5 text-muted-foreground">
          <Icon className="h-3 w-3" />
          {label}
        </span>
        <span className="font-medium">{value}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          className={cn('h-full rounded-full', getColor(value))}
        />
      </div>
    </div>
  );
}
