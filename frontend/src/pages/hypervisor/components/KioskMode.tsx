// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { X, Server } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { hypervisorApi } from '@/lib/api';
import { DashboardObservation } from './DashboardObservation';
import { useObservationFreshness } from './dashboardObservationState';

interface KioskModeProps {
  controllerId: string;
  onExit: () => void;
}

function RingChart({ value, size = 120, strokeWidth = 10, color = '#3b82f6' }: {
  value: number;
  size?: number;
  strokeWidth?: number;
  color?: string;
}) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;

  return (
    <svg width={size} height={size} className="transform -rotate-90">
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        className="text-gray-800"
      />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        className="transition-all duration-700"
      />
    </svg>
  );
}

export function KioskMode({ controllerId, onExit }: KioskModeProps) {
  const { t } = useTranslation('hypervisor');
  const [currentTime, setCurrentTime] = useState(new Date());
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') onExit(); };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onExit]);
  const { data: response, isError, isPending } = useQuery({
    queryKey: ['hypervisor', 'kiosk', 'dashboard', controllerId],
    queryFn: () => hypervisorApi.getDashboard(controllerId),
    enabled: !!controllerId,
    retry: false,
    refetchInterval: 10_000,
  });
  const dash = response?.data;
  const freshness = useObservationFreshness(dash);
  const validIdentity = !!controllerId && dash?.controller_id === controllerId;
  const show = !isError && !isPending && validIdentity && freshness.state === 'current';
  const unknown = t('HypervisorPage.stats.unknown');
  const count = (value: number | null) => value == null ? unknown : value;
  return <div className="fixed inset-0 z-50 bg-background text-foreground overflow-auto">
    <div className="flex items-center justify-between px-4 sm:px-8 py-4 border-b border-border">
      <div className="flex items-center gap-4 flex-wrap"><Server className="h-6 w-6 text-primary" />
        <span>{t('KioskMode.header.title')}</span><span className="text-2xl font-mono">{currentTime.toLocaleTimeString()}</span>
      </div>
      <Button variant="ghost" size="sm" onClick={onExit} aria-label={t('DashboardObservation.exitKiosk')}><X className="h-5 w-5" /></Button>
    </div>
    <div className="p-4 sm:p-8 space-y-6">
      {isPending && controllerId ? <p role="status">{t('DashboardObservation.loading')}</p>
        : isError || !validIdentity ? <div role="alert"><p className="text-destructive">{t('KioskMode.error.connectionLost')}</p><p>{t('KioskMode.error.autoRetrying')}</p></div>
          : dash && <DashboardObservation data={dash} />}
      {show && dash && <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {([
          { key: 'cpu', value: dash.cpu_usage_percent },
          { key: 'memory', value: dash.memory_usage_percent },
          { key: 'node_filesystem', value: dash.storage_usage_percent },
        ] as const).map(item => {
          const available = dash.metric_coverage?.[item.key]?.status === 'available' && item.value != null && Number.isFinite(item.value) && item.value >= 0 && item.value <= 100;
          return <div key={item.key} className="bg-card rounded-xl p-8 flex flex-col items-center border border-border">
            <h2 className="mb-4 text-muted-foreground">{t(`DashboardObservation.metrics.${item.key}`)}</h2>
            {available ? <div className="relative" data-testid={`kiosk-gauge-${item.key}`}>
              <RingChart value={item.value!} size={160} color={item.value! > 85 ? 'var(--color-destructive)' : 'var(--color-primary)'} />
              <strong className="absolute inset-0 flex items-center justify-center text-4xl">{item.value}%</strong>
            </div> : <p className="text-3xl text-warning">{unknown}</p>}
          </div>;
        })}
        <div className="bg-card rounded-xl p-8 border border-border">
          <h2 className="mb-4">{t('KioskMode.metrics.nodeStatus')}</h2>
          {dash.nodes.map(node => <p key={node.node} className="flex justify-between gap-4"><span>{node.node}</span><span className={node.status === 'online' ? 'text-success' : node.status === 'offline' ? 'text-destructive' : 'text-warning'}>{t(`DashboardObservation.nodeStatus.${node.status}`)}</span></p>)}
          <p className="mt-4 text-muted-foreground">{count(dash.online_nodes)} / {count(dash.total_nodes)}</p>
        </div>
        {([
          ['virtualMachines', dash.running_vms, dash.total_vms],
          ['containers', dash.running_containers, dash.total_containers],
        ] as const).map(([key, running, total]) => <div key={key} className="bg-card rounded-xl p-8 border border-border">
          <h2>{t(`KioskMode.metrics.${key}`)}</h2><p className="mt-6 text-4xl">{count(running)} / {count(total)}</p><p className="mt-4 text-muted-foreground">{t('KioskMode.metrics.running')}</p>
        </div>)}
      </div>}
      {!isPending && !isError && validIdentity && freshness.state !== 'current' && <p role="alert" className="text-warning">{t('DashboardObservation.refreshRequired')}</p>}
    </div>
  </div>;
}
