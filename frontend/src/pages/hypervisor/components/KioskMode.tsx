// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Kiosk Mode
 * Fullscreen NOC display with auto-refresh dashboard metrics
 */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { X, Server, Monitor, Box, Cpu, MemoryStick, HardDrive } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { hypervisorApi } from '@/lib/api';
import { formatBytes } from './helpers';
import type { HypervisorNode } from '@/lib/api';

interface KioskModeProps {
  controllerId: string;
  nodes: HypervisorNode[];
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

export function KioskMode({ controllerId, nodes, onExit }: KioskModeProps) {
  const { t } = useTranslation('hypervisor');
  const [currentTime, setCurrentTime] = useState(new Date());

  // Auto-update clock every second
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // ESC key to exit
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onExit();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onExit]);

  // Dashboard data with 10s auto-refresh
  const { data: dashResp, isError } = useQuery({
    queryKey: ['hypervisor', 'kiosk', 'dashboard', controllerId],
    queryFn: () => hypervisorApi.getDashboard(controllerId),
    enabled: !!controllerId,
    refetchInterval: 10_000,
  });
  const dash = dashResp?.data;

  const cpuColor = (dash?.cpu_usage_percent ?? 0) > 80 ? '#ef4444' : (dash?.cpu_usage_percent ?? 0) > 60 ? '#f59e0b' : '#3b82f6';
  const memColor = (dash?.memory_usage_percent ?? 0) > 80 ? '#ef4444' : (dash?.memory_usage_percent ?? 0) > 60 ? '#f59e0b' : '#8b5cf6';
  const storColor = (dash?.storage_usage_percent ?? 0) > 85 ? '#ef4444' : (dash?.storage_usage_percent ?? 0) > 70 ? '#f59e0b' : '#10b981';

  return (
    <div className="fixed inset-0 z-50 bg-gray-950 text-white overflow-auto">
      {/* Header */}
      <div className="flex items-center justify-between px-4 sm:px-8 py-4 border-b border-gray-800">
        <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
          <Server className="h-6 w-6 text-blue-400 hidden sm:block" />
          <span className="text-sm sm:text-lg font-medium text-gray-300">{t('KioskMode.header.title')}</span>
          <span className="text-2xl sm:text-4xl font-mono tabular-nums text-white">
            {currentTime.toLocaleTimeString()}
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={onExit}
          className="text-gray-400 hover:text-white hover:bg-gray-800"
        >
          <X className="h-5 w-5" />
        </Button>
      </div>

      {/* Error State */}
      {isError && (
        <div className="col-span-full text-center py-8">
          <p className="text-red-400 text-xl">{t('KioskMode.error.connectionLost')}</p>
          <p className="text-gray-500 text-sm mt-2">{t('KioskMode.error.autoRetrying')}</p>
        </div>
      )}

      {/* Main Grid */}
      <div className="p-4 sm:p-8 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-8">
        {/* CPU Usage */}
        <div className="bg-gray-900 rounded-xl p-8 flex flex-col items-center justify-center border border-gray-800">
          <div className="flex items-center gap-2 mb-4 text-gray-400">
            <Cpu className="h-5 w-5" />
            <span className="text-sm font-medium uppercase tracking-wider">{t('KioskMode.metrics.cpuUsage')}</span>
          </div>
          <div className="relative">
            <RingChart value={dash?.cpu_usage_percent ?? 0} size={160} strokeWidth={12} color={cpuColor} />
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-6xl font-bold tabular-nums">{dash?.cpu_usage_percent ?? 0}</span>
              <span className="text-2xl text-gray-400 ml-1">%</span>
            </div>
          </div>
          <p className="text-sm text-gray-500 mt-4">{t('KioskMode.metrics.cores', { count: dash?.total_cpu_cores ?? 0 })}</p>
        </div>

        {/* Memory Usage */}
        <div className="bg-gray-900 rounded-xl p-8 flex flex-col items-center justify-center border border-gray-800">
          <div className="flex items-center gap-2 mb-4 text-gray-400">
            <MemoryStick className="h-5 w-5" />
            <span className="text-sm font-medium uppercase tracking-wider">{t('KioskMode.metrics.memoryUsage')}</span>
          </div>
          <div className="relative">
            <RingChart value={dash?.memory_usage_percent ?? 0} size={160} strokeWidth={12} color={memColor} />
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-6xl font-bold tabular-nums">{dash?.memory_usage_percent ?? 0}</span>
              <span className="text-2xl text-gray-400 ml-1">%</span>
            </div>
          </div>
          <p className="text-sm text-gray-500 mt-4">{t('KioskMode.metrics.total', { value: formatBytes(dash?.total_memory_bytes ?? 0) })}</p>
        </div>

        {/* Storage Usage */}
        <div className="bg-gray-900 rounded-xl p-8 flex flex-col items-center justify-center border border-gray-800">
          <div className="flex items-center gap-2 mb-4 text-gray-400">
            <HardDrive className="h-5 w-5" />
            <span className="text-sm font-medium uppercase tracking-wider">{t('KioskMode.metrics.storageUsage')}</span>
          </div>
          <div className="relative">
            <RingChart value={dash?.storage_usage_percent ?? 0} size={160} strokeWidth={12} color={storColor} />
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-6xl font-bold tabular-nums">{dash?.storage_usage_percent ?? 0}</span>
              <span className="text-2xl text-gray-400 ml-1">%</span>
            </div>
          </div>
          <p className="text-sm text-gray-500 mt-4">{t('KioskMode.metrics.total', { value: formatBytes(dash?.total_storage_bytes ?? 0) })}</p>
        </div>

        {/* Node Status Grid */}
        <div className="bg-gray-900 rounded-xl p-8 border border-gray-800">
          <div className="flex items-center gap-2 mb-6 text-gray-400">
            <Server className="h-5 w-5" />
            <span className="text-sm font-medium uppercase tracking-wider">{t('KioskMode.metrics.nodeStatus')}</span>
          </div>
          <div className="grid grid-cols-2 gap-3">
            {nodes.map((node) => (
              <div
                key={node.node}
                className="flex items-center gap-2 p-3 rounded-lg bg-gray-800/50"
              >
                <div className={`h-3 w-3 rounded-full ${node.status === 'online' ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm font-medium truncate">{node.node}</span>
              </div>
            ))}
          </div>
          <p className="text-sm text-gray-500 mt-4">
            {t('KioskMode.metrics.nodesOnline', {
              online: nodes.filter((n) => n.status === 'online').length,
              total: nodes.length,
            })}
          </p>
        </div>

        {/* Running VMs */}
        <div className="bg-gray-900 rounded-xl p-8 flex flex-col items-center justify-center border border-gray-800">
          <div className="flex items-center gap-2 mb-4 text-gray-400">
            <Monitor className="h-5 w-5" />
            <span className="text-sm font-medium uppercase tracking-wider">{t('KioskMode.metrics.virtualMachines')}</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-6xl font-bold tabular-nums text-blue-400">
              {dash?.running_vms ?? 0}
            </span>
            <span className="text-2xl text-gray-500">/ {dash?.total_vms ?? 0}</span>
          </div>
          <Badge variant="outline" className="mt-4 text-gray-400 border-gray-700">
            {t('KioskMode.metrics.running')}
          </Badge>
        </div>

        {/* Running Containers */}
        <div className="bg-gray-900 rounded-xl p-8 flex flex-col items-center justify-center border border-gray-800">
          <div className="flex items-center gap-2 mb-4 text-gray-400">
            <Box className="h-5 w-5" />
            <span className="text-sm font-medium uppercase tracking-wider">{t('KioskMode.metrics.containers')}</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-6xl font-bold tabular-nums text-purple-400">
              {dash?.running_containers ?? 0}
            </span>
            <span className="text-2xl text-gray-500">/ {dash?.total_containers ?? 0}</span>
          </div>
          <Badge variant="outline" className="mt-4 text-gray-400 border-gray-700">
            {t('KioskMode.metrics.running')}
          </Badge>
        </div>
      </div>
    </div>
  );
}
