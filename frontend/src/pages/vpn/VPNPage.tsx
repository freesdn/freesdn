/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useState, useEffect, Suspense } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Wifi,
  WifiOff,
  Activity,
  Server,
  Globe,
  MapPin,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Settings,
  Play,
  Square,
  Network,
  ExternalLink,
  Plus,
  Pencil,
  Trash2,
  Lock,
  RefreshCw,
  BarChart3,
  Zap,
  Route,
  ChevronDown,
  HeartPulse,
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
} from 'recharts';
import { PageHeader, PageTabs, type PageTab } from '@/components/layout';
import { CapabilityMaturityBadge } from '@/components/ui/capability-maturity-badge';
import { useParams } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { StatsGrid } from '@/components/ui/stats-grid';
import { DataTable } from '@/components/ui/data-table';
import type { DataTableColumn } from '@/components/ui/data-table';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import OverlayDiscoveryTab from '@/components/vpn/OverlayDiscoveryTab';
import { useToast } from '@/hooks/use-toast';
import {
  vpnApi,
  sitesApiV2,
  type VPNConnection,
  type VPNConnectionCreate,
  type VPNType,
  type TailscaleNode,
  type NetbirdPeer,
  type Site,
  type SiteVPNConfig,
  type VPNEvent,
  type VPNTunnelTemplateCreate,
  type VPNRouteConflict,
  type VPNCertExpiry,
} from '@/lib/api';
import TailscaleSetupWizard from './TailscaleSetupWizard';

const VPNTopologyTab = React.lazy(() => import('./VPNTopologyTab'));

// ─── Status helpers ──────────────────────────────────────────────────────────

const statusColors: Record<string, string> = {
  connected: 'bg-success/10 text-success border-success/20',
  active: 'bg-success/10 text-success border-success/20',
  online: 'bg-success/10 text-success border-success/20',
  disconnected: 'bg-destructive/10 text-destructive border-destructive/20',
  offline: 'bg-destructive/10 text-destructive border-destructive/20',
  error: 'bg-destructive/10 text-destructive border-destructive/20',
  connecting: 'bg-warning/10 text-warning border-warning/20',
  idle: 'bg-muted text-muted-foreground border-border',
  not_configured: 'bg-muted text-muted-foreground border-border',
};

const statusIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  connected: CheckCircle,
  active: CheckCircle,
  online: CheckCircle,
  disconnected: XCircle,
  offline: XCircle,
  error: AlertTriangle,
  connecting: Activity,
  idle: Clock,
  not_configured: Clock,
};

const vpnTypeLabels: Record<string, string> = {
  tailscale: 'Tailscale',
  wireguard: 'WireGuard',
  openvpn: 'OpenVPN',
  netbird: 'Netbird',
  ipsec: 'IPsec',
  zerotier: 'ZeroTier',
  generic: 'Generic',
};

const vpnTypeColors: Record<string, string> = {
  tailscale: 'bg-blue-500/10 text-blue-600 border-blue-500/20',
  wireguard: 'bg-purple-500/10 text-purple-600 border-purple-500/20',
  openvpn: 'bg-orange-500/10 text-orange-600 border-orange-500/20',
  netbird: 'bg-teal-500/10 text-teal-600 border-teal-500/20',
  ipsec: 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20',
  zerotier: 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20',
  generic: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20',
};

const severityColors: Record<string, string> = {
  info: 'bg-blue-500/10 text-blue-600 border-blue-500/20',
  warning: 'bg-warning/10 text-warning border-warning/20',
  error: 'bg-destructive/10 text-destructive border-destructive/20',
  critical: 'bg-red-700/10 text-red-700 border-red-700/20',
};

const tunnelStatusColors: Record<string, string> = {
  pending: 'bg-muted text-muted-foreground border-border',
  provisioning: 'bg-warning/10 text-warning border-warning/20',
  active: 'bg-success/10 text-success border-success/20',
  error: 'bg-destructive/10 text-destructive border-destructive/20',
  disabled: 'bg-muted text-muted-foreground border-border',
};

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  if (bytes < 0) return '-' + formatBytes(-bytes);
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

// ─── Reconnect Status Badge ─────────────────────────────────────────────────

function ReconnectStatusBadge({ connectionId }: { connectionId: string }) {
  const { t } = useTranslation('vpn');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: reconnectStatus } = useQuery({
    queryKey: ['vpnReconnectStatus', connectionId],
    queryFn: async () => (await vpnApi.getReconnectStatus(connectionId)).data,
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
  });

  const resetMutation = useMutation({
    mutationFn: async () => (await vpnApi.resetReconnect(connectionId)).data,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['vpnReconnectStatus', connectionId] });
      queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
      toast({ title: t('VPNPage.reconnect.resetToast'), description: data.message });
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.common.error'), description: err?.response?.data?.detail || t('VPNPage.reconnect.resetFailed'), variant: 'destructive' });
    },
  });

  if (!reconnectStatus) return null;

  if (reconnectStatus.state === 'retrying') {
    const nextRetryIn = reconnectStatus.next_retry_at
      ? Math.max(0, Math.round((new Date(reconnectStatus.next_retry_at).getTime() - Date.now()) / 1000))
      : reconnectStatus.backoff_seconds;
    return (
      <Badge variant="outline" className="bg-warning/10 text-warning border-warning/20 text-xs">
        <RefreshCw className="mr-1 h-3 w-3 animate-spin" />
        {t('VPNPage.reconnect.retrying', { attempt: reconnectStatus.attempt_count, max: reconnectStatus.max_attempts, seconds: nextRetryIn })}
      </Badge>
    );
  }

  if (reconnectStatus.state === 'exhausted') {
    return (
      <div className="flex items-center gap-2">
        <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20 text-xs">
          {t('VPNPage.reconnect.exhausted')}
        </Badge>
        <Button
          variant="outline"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={() => resetMutation.mutate()}
          disabled={resetMutation.isPending}
        >
          {resetMutation.isPending ? <RefreshCw className="h-3 w-3 animate-spin" /> : t('VPNPage.reconnect.reset')}
        </Button>
      </div>
    );
  }

  return null;
}

// ─── VPN Health History Chart ────────────────────────────────────────────────

const healthTimeRanges = [
  { label: '1H', value: 1 },
  { label: '6H', value: 6 },
  { label: '24H', value: 24 },
  { label: '7D', value: 168 },
] as const;

interface HealthChartPoint {
  time: string;
  label: string;
  latency: number | null;
  healthy: boolean;
  status: string;
  error: string | null;
}

function formatHealthTime(isoString: string, rangeHours: number): string {
  const d = new Date(isoString);
  if (rangeHours <= 6) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (rangeHours <= 24) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// Custom dot that renders green for healthy, red for unhealthy
function HealthDot(props: any) {
  const { cx, cy, payload } = props;
  if (cx == null || cy == null || !payload) return null;
  const color = payload.healthy ? 'hsl(var(--success, 142 71% 45%))' : 'hsl(var(--destructive, 0 84% 60%))';
  return (
    <circle cx={cx} cy={cy} r={3} fill={color} stroke={color} strokeWidth={1} />
  );
}

function VPNHealthHistoryChart({ connectionId }: { connectionId: string }) {
  const { t } = useTranslation('vpn');
  const [rangeHours, setRangeHours] = useState<number>(24);

  const { data: healthRecords, isLoading, isError } = useQuery({
    queryKey: ['vpnHealthHistory', connectionId, rangeHours],
    queryFn: async () => (await vpnApi.getHealthHistory(connectionId, rangeHours, 200)).data,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
  });

  const chartData: HealthChartPoint[] = React.useMemo(() => {
    if (!healthRecords || healthRecords.length === 0) return [];
    return healthRecords
      .slice()
      .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
      .map((r) => ({
        time: r.time,
        label: formatHealthTime(r.time, rangeHours),
        latency: r.latency_ms,
        healthy: r.is_healthy,
        status: r.status,
        error: r.error_message,
      }));
  }, [healthRecords, rangeHours]);

  // Compute stats
  const stats = React.useMemo(() => {
    if (chartData.length === 0) return null;
    const validLatencies = chartData.filter((p) => p.latency != null).map((p) => p.latency!);
    const healthyCount = chartData.filter((p) => p.healthy).length;
    return {
      avgLatency: validLatencies.length > 0 ? Math.round(validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length) : null,
      maxLatency: validLatencies.length > 0 ? Math.round(Math.max(...validLatencies)) : null,
      uptimePercent: Math.round((healthyCount / chartData.length) * 100),
      total: chartData.length,
    };
  }, [chartData]);

  return (
    <div className="space-y-3">
      {/* Header with time range selector */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <HeartPulse className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium text-muted-foreground">{t('VPNPage.health.title')}</span>
          {stats && (
            <div className="flex items-center gap-3 ml-3 text-xs text-muted-foreground">
              <span>{t('VPNPage.health.uptime')} <span className={stats.uptimePercent >= 95 ? 'text-green-600 font-medium' : stats.uptimePercent >= 80 ? 'text-yellow-600 font-medium' : 'text-red-600 font-medium'}>{stats.uptimePercent}%</span></span>
              {stats.avgLatency != null && <span>{t('VPNPage.health.avg', { value: stats.avgLatency })}</span>}
              {stats.maxLatency != null && <span>{t('VPNPage.health.max', { value: stats.maxLatency })}</span>}
            </div>
          )}
        </div>
        <div className="flex gap-1 rounded-lg bg-muted p-0.5">
          {healthTimeRanges.map((range) => (
            <Button
              key={range.value}
              variant="ghost"
              size="sm"
              className={`h-6 px-2 text-xs ${rangeHours === range.value ? 'bg-background shadow-sm' : ''}`}
              onClick={() => setRangeHours(range.value)}
            >
              {range.label}
            </Button>
          ))}
        </div>
      </div>

      {/* Chart area */}
      {isLoading ? (
        <div className="h-[180px] flex items-center justify-center">
          <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      ) : isError ? (
        <div className="h-[180px] flex items-center justify-center text-sm text-destructive">
          {t('VPNPage.health.loadError')}
        </div>
      ) : chartData.length === 0 ? (
        <div className="h-[180px] flex flex-col items-center justify-center text-sm text-muted-foreground">
          <HeartPulse className="h-8 w-8 mb-2 opacity-30" />
          {t('VPNPage.health.noData')}
        </div>
      ) : (
        <div className="h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="hsl(var(--border))" />
              <XAxis
                dataKey="label"
                axisLine={false}
                tickLine={false}
                tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 10 }}
                tickMargin={6}
                interval="preserveStartEnd"
                minTickGap={40}
              />
              <YAxis
                axisLine={false}
                tickLine={false}
                tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 10 }}
                tickMargin={6}
                unit="ms"
                domain={[0, 'auto']}
              />
              <RechartsTooltip
                content={({ active, payload }) => {
                  if (!active || !payload || payload.length === 0) return null;
                  const point = payload[0]?.payload as HealthChartPoint | undefined;
                  if (!point) return null;
                  return (
                    <div className="rounded-lg border bg-popover px-3 py-2 shadow-md text-sm">
                      <p className="text-xs text-muted-foreground mb-1">
                        {new Date(point.time).toLocaleString()}
                      </p>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <span className={`h-2 w-2 rounded-full ${point.healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                        <span className="font-medium">{point.healthy ? t('VPNPage.health.healthy') : t('VPNPage.health.unhealthy')}</span>
                      </div>
                      {point.latency != null && (
                        <p>{t('VPNPage.health.latency')} <span className="font-mono">{point.latency}ms</span></p>
                      )}
                      {point.error && (
                        <p className="text-destructive text-xs mt-1 max-w-[200px] truncate">{point.error}</p>
                      )}
                    </div>
                  );
                }}
              />
              <Line
                type="monotone"
                dataKey="latency"
                stroke="hsl(var(--primary))"
                strokeWidth={2}
                dot={<HealthDot />}
                activeDot={{ r: 5 }}
                connectNulls
                animationDuration={300}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

// ─── VPN Connection Card (with actions) ──────────────────────────────────────

function VPNConnectionCard({
  connection,
  onEdit,
  onDelete,
  onAction,
  isActioning,
}: {
  connection: VPNConnection;
  onEdit: (c: VPNConnection) => void;
  onDelete: (c: VPNConnection) => void;
  onAction: (id: string, action: 'connect' | 'disconnect') => void;
  isActioning: boolean;
}) {
  const { t } = useTranslation('vpn');
  const StatusIcon = statusIcons[connection.status] || Activity;
  const isConnected = connection.status === 'connected';
  const isError = connection.status === 'error';
  const [showHealth, setShowHealth] = useState(false);

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <Card className="h-full hover:border-primary/30 transition-colors">
        <CardContent noOffset className="p-4">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${isConnected ? 'bg-green-500/10' : 'bg-muted'}`}>
                <Shield className={`h-5 w-5 ${isConnected ? 'text-green-500' : 'text-muted-foreground'}`} />
              </div>
              <div>
                <div className="font-medium">{connection.name}</div>
                <Badge variant="outline" className={`text-xs mt-1 ${vpnTypeColors[connection.vpn_type] || vpnTypeColors.generic}`}>
                  {vpnTypeLabels[connection.vpn_type] || connection.vpn_type}
                </Badge>
              </div>
            </div>
            <Badge variant="outline" className={statusColors[connection.status] || 'bg-muted text-muted-foreground border-border'}>
              <StatusIcon className="mr-1 h-3 w-3" />
              {connection.status}
            </Badge>
          </div>

          {/* Reconnect status for error connections */}
          {isError && (
            <div className="mb-3">
              <ReconnectStatusBadge connectionId={connection.id} />
            </div>
          )}

          {/* Connection details */}
          <div className="grid grid-cols-2 gap-2 text-sm">
            {connection.endpoint && (
              <div>
                <span className="text-muted-foreground">{t('VPNPage.connectionCard.endpoint')}</span>
                <span className="ml-1 font-mono text-xs">{connection.endpoint}{connection.port ? `:${connection.port}` : ''}</span>
              </div>
            )}
            {connection.local_ip && (
              <div>
                <span className="text-muted-foreground">{t('VPNPage.connectionCard.localIp')}</span>
                <span className="ml-1 font-mono text-xs">{connection.local_ip}</span>
              </div>
            )}
            {connection.latency_ms != null && connection.latency_ms > 0 && (
              <div>
                <span className="text-muted-foreground">{t('VPNPage.connectionCard.latency')}</span>
                <span className="ml-1">{connection.latency_ms}ms</span>
              </div>
            )}
            {(connection.rx_bytes != null && connection.rx_bytes > 0) && (
              <div>
                <span className="text-muted-foreground">{t('VPNPage.connectionCard.traffic')}</span>
                <span className="ml-1">{formatBytes(connection.rx_bytes!)} / {formatBytes(connection.tx_bytes || 0)}</span>
              </div>
            )}
            {(connection.connected_since || connection.connected_at) && isConnected && (
              <div className="col-span-2">
                <span className="text-muted-foreground">{t('VPNPage.connectionCard.uptime')}</span>
                <span className="ml-1">{formatDuration(Date.now() / 1000 - new Date(connection.connected_since || connection.connected_at!).getTime() / 1000)}</span>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="mt-4 pt-3 border-t flex gap-2">
            {isConnected ? (
              <Button
                variant="outline"
                size="sm"
                className="flex-1 text-destructive hover:text-destructive"
                onClick={() => {
                  if (confirm(t('VPNPage.connectionCard.disconnectConfirm', { name: connection.name }))) {
                    onAction(connection.id, 'disconnect');
                  }
                }}
                disabled={isActioning}
              >
                {isActioning ? <RefreshCw className="mr-1 h-3 w-3 animate-spin" /> : <Square className="mr-1 h-3 w-3" />}
                {t('VPNPage.connectionCard.disconnect')}
              </Button>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="flex-1 text-green-600 hover:text-green-600"
                onClick={() => onAction(connection.id, 'connect')}
                disabled={isActioning}
              >
                {isActioning ? <RefreshCw className="mr-1 h-3 w-3 animate-spin" /> : <Play className="mr-1 h-3 w-3" />}
                {t('VPNPage.connectionCard.connect')}
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => onEdit(connection)} aria-label={t('VPNPage.connectionCard.editAria')}>
              <Pencil className="h-3 w-3" />
            </Button>
            <Button variant="outline" size="sm" className="text-destructive hover:text-destructive" onClick={() => onDelete(connection)} aria-label={t('VPNPage.connectionCard.deleteAria')}>
              <Trash2 className="h-3 w-3" />
            </Button>
          </div>

          {/* Health History toggle */}
          <button
            type="button"
            className="mt-3 pt-2 border-t w-full flex items-center justify-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            onClick={() => setShowHealth((prev) => !prev)}
          >
            <HeartPulse className="h-3 w-3" />
            {showHealth ? t('VPNPage.connectionCard.hideHealth') : t('VPNPage.connectionCard.showHealth')}
            <ChevronDown className={`h-3 w-3 transition-transform ${showHealth ? 'rotate-180' : ''}`} />
          </button>

          {/* Expandable health history chart (lazy-loaded) */}
          <AnimatePresence>
            {showHealth && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="mt-3">
                  <VPNHealthHistoryChart connectionId={connection.id} />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─── Create / Edit Connection Dialog ─────────────────────────────────────────

function ConnectionFormDialog({
  open,
  onOpenChange,
  connection,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  connection?: VPNConnection | null;
}) {
  const { t } = useTranslation('vpn');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const isEdit = !!connection;

  const [name, setName] = useState('');
  const [vpnType, setVpnType] = useState<VPNType>('tailscale');
  const [endpoint, setEndpoint] = useState('');
  const [port, setPort] = useState('');
  const [localIp, setLocalIp] = useState('');
  const [remoteIp, setRemoteIp] = useState('');
  const [allowedIps, setAllowedIps] = useState('');
  const [dnsServers, setDnsServers] = useState('');
  // OpenVPN
  const [ovpnConfigPath, setOvpnConfigPath] = useState('');
  const [ovpnProtocol, setOvpnProtocol] = useState('udp');
  const [ovpnConfigContent, setOvpnConfigContent] = useState('');
  // WireGuard
  const [wgConfigContent, setWgConfigContent] = useState('');
  // Netbird
  const [netbirdSetupKey, setNetbirdSetupKey] = useState('');
  const [netbirdMgmtUrl, setNetbirdMgmtUrl] = useState('');

  useEffect(() => {
    if (connection) {
      setName(connection.name || '');
      setVpnType(connection.vpn_type || 'tailscale');
      setEndpoint(connection.endpoint || '');
      setPort(connection.port?.toString() || '');
      setLocalIp(connection.local_ip || '');
      setRemoteIp(connection.remote_ip || '');
      setAllowedIps(connection.allowed_ips?.join(', ') || '');
      setDnsServers(connection.dns_servers?.join(', ') || '');
      setOvpnConfigPath(connection.openvpn_config_path || '');
      setOvpnProtocol(connection.openvpn_protocol || 'udp');
      setOvpnConfigContent(''); // write-only field, never returned by API
      setWgConfigContent(''); // write-only field, never returned by API
      setNetbirdSetupKey(''); // write-only field, never returned by API
      setNetbirdMgmtUrl(connection.netbird_management_url || '');
    } else {
      setName(''); setVpnType('tailscale'); setEndpoint(''); setPort('');
      setLocalIp(''); setRemoteIp(''); setAllowedIps(''); setDnsServers('');
      setOvpnConfigPath(''); setOvpnProtocol('udp'); setOvpnConfigContent('');
      setWgConfigContent(''); setNetbirdSetupKey(''); setNetbirdMgmtUrl('');
    }
  }, [connection, open]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: VPNConnectionCreate = {
        name,
        vpn_type: vpnType,
        endpoint: endpoint || undefined,
        port: port ? parseInt(port) : undefined,
        local_ip: localIp || undefined,
        remote_ip: remoteIp || undefined,
        allowed_ips: allowedIps ? allowedIps.split(',').map(s => s.trim()).filter(Boolean) : undefined,
        dns_servers: dnsServers ? dnsServers.split(',').map(s => s.trim()).filter(Boolean) : undefined,
        openvpn_config_path: vpnType === 'openvpn' ? ovpnConfigPath || undefined : undefined,
        openvpn_protocol: vpnType === 'openvpn' ? ovpnProtocol : undefined,
        openvpn_config_content: vpnType === 'openvpn' ? ovpnConfigContent || undefined : undefined,
        wireguard_config_content: vpnType === 'wireguard' ? wgConfigContent || undefined : undefined,
        netbird_setup_key: vpnType === 'netbird' ? netbirdSetupKey || undefined : undefined,
        netbird_management_url: vpnType === 'netbird' ? netbirdMgmtUrl || undefined : undefined,
      };
      if (isEdit && connection) {
        return (await vpnApi.updateConnection(connection.id, payload)).data;
      }
      return (await vpnApi.createConnection(payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
      toast({
        title: isEdit ? t('VPNPage.connectionForm.updatedToast') : t('VPNPage.connectionForm.createdToast'),
        description: isEdit ? t('VPNPage.connectionForm.updatedDesc', { name }) : t('VPNPage.connectionForm.createdDesc', { name }),
      });
      onOpenChange(false);
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.common.error'), description: err?.response?.data?.detail || err.message || t('VPNPage.connectionForm.saveFailed'), variant: 'destructive' });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? t('VPNPage.connectionForm.editTitle') : t('VPNPage.connectionForm.newTitle')}</DialogTitle>
          <DialogDescription>
            {isEdit ? t('VPNPage.connectionForm.editDescription') : t('VPNPage.connectionForm.newDescription')}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t('VPNPage.connectionForm.connectionName')}</Label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder={t('VPNPage.connectionForm.connectionNamePlaceholder')} />
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.connectionForm.vpnProvider')}</Label>
            <Select value={vpnType} onValueChange={(v) => setVpnType(v as VPNType)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="tailscale">Tailscale</SelectItem>
                <SelectItem value="wireguard">WireGuard</SelectItem>
                <SelectItem value="openvpn">OpenVPN</SelectItem>
                <SelectItem value="netbird">Netbird</SelectItem>
                <SelectItem value="ipsec">IPsec</SelectItem>
                <SelectItem value="zerotier">ZeroTier</SelectItem>
                <SelectItem value="generic">Generic</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>{t('VPNPage.connectionForm.endpoint')}</Label>
              <Input value={endpoint} onChange={e => setEndpoint(e.target.value)} placeholder="vpn.example.com" />
            </div>
            <div className="space-y-2">
              <Label>{t('VPNPage.connectionForm.port')}</Label>
              <Input value={port} onChange={e => setPort(e.target.value)} placeholder="51820" type="number" />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>{t('VPNPage.connectionForm.localIp')}</Label>
              <Input value={localIp} onChange={e => setLocalIp(e.target.value)} placeholder="10.0.0.2" />
            </div>
            <div className="space-y-2">
              <Label>{t('VPNPage.connectionForm.remoteIp')}</Label>
              <Input value={remoteIp} onChange={e => setRemoteIp(e.target.value)} placeholder="10.0.0.1" />
            </div>
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.connectionForm.allowedIps')}</Label>
            <Input value={allowedIps} onChange={e => setAllowedIps(e.target.value)} placeholder="10.0.0.0/24, 192.168.1.0/24" />
            <p className="text-xs text-muted-foreground">{t('VPNPage.connectionForm.allowedIpsHelp')}</p>
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.connectionForm.dnsServers')}</Label>
            <Input value={dnsServers} onChange={e => setDnsServers(e.target.value)} placeholder="1.1.1.1, 8.8.8.8" />
          </div>

          {/* OpenVPN-specific */}
          {vpnType === 'openvpn' && (
            <div className="space-y-3 p-3 rounded-lg border bg-orange-500/5">
              <h4 className="text-sm font-medium text-orange-700">{t('VPNPage.connectionForm.openvpnSettings')}</h4>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.ovpnConfigContent')}</Label>
                <Textarea
                  value={ovpnConfigContent}
                  onChange={e => setOvpnConfigContent(e.target.value)}
                  placeholder={'client\nremote vpn.example.com 1194\nproto udp\ncipher AES-256-CBC\n<ca>...</ca>\n<cert>...</cert>\n<key>...</key>'}
                  className="font-mono text-xs"
                  rows={8}
                />
                <p className="text-xs text-muted-foreground">{t('VPNPage.connectionForm.ovpnConfigContentHelp')}</p>
              </div>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.protocol')}</Label>
                <Select value={ovpnProtocol} onValueChange={setOvpnProtocol}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="udp">UDP</SelectItem>
                    <SelectItem value="tcp">TCP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          {/* WireGuard-specific */}
          {vpnType === 'wireguard' && (
            <div className="space-y-3 p-3 rounded-lg border bg-purple-500/5">
              <h4 className="text-sm font-medium text-purple-700">{t('VPNPage.connectionForm.wireguardSettings')}</h4>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.wgConfigContent')}</Label>
                <Textarea
                  value={wgConfigContent}
                  onChange={e => setWgConfigContent(e.target.value)}
                  placeholder={'[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.0.0.0/24'}
                  className="font-mono text-xs"
                  rows={8}
                />
                <p className="text-xs text-muted-foreground">{t('VPNPage.connectionForm.wgConfigContentHelp')}</p>
              </div>
            </div>
          )}

          {/* Netbird-specific */}
          {vpnType === 'netbird' && (
            <div className="space-y-3 p-3 rounded-lg border bg-teal-500/5">
              <h4 className="text-sm font-medium text-teal-700">{t('VPNPage.connectionForm.netbirdSettings')}</h4>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.setupKey')}</Label>
                <Input value={netbirdSetupKey} onChange={e => setNetbirdSetupKey(e.target.value)} placeholder={t('VPNPage.connectionForm.setupKeyPlaceholder')} type="password" />
              </div>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.managementUrl')}</Label>
                <Input value={netbirdMgmtUrl} onChange={e => setNetbirdMgmtUrl(e.target.value)} placeholder="https://api.netbird.io" />
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('VPNPage.common.cancel')}</Button>
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending || !name}>
            {saveMutation.isPending ? t('VPNPage.common.saving') : isEdit ? t('VPNPage.connectionForm.updateConnection') : t('VPNPage.connectionForm.createConnection')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Delete Confirmation Dialog ──────────────────────────────────────────────

function DeleteConnectionDialog({
  open,
  onOpenChange,
  connection,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  connection: VPNConnection | null;
}) {
  const { t } = useTranslation('vpn');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const deleteMutation = useMutation({
    mutationFn: async () => {
      if (!connection) return;
      await vpnApi.deleteConnection(connection.id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
      toast({ title: t('VPNPage.deleteDialog.deletedToast'), description: t('VPNPage.deleteDialog.deletedDesc', { name: connection?.name }) });
      onOpenChange(false);
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.common.error'), description: err?.response?.data?.detail || t('VPNPage.deleteDialog.deleteFailed'), variant: 'destructive' });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('VPNPage.deleteDialog.title')}</DialogTitle>
          <DialogDescription>
            {t('VPNPage.deleteDialog.confirmPrefix')} <strong>{connection?.name}</strong>{t('VPNPage.deleteDialog.confirmSuffix')}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('VPNPage.common.cancel')}</Button>
          <Button variant="destructive" onClick={() => deleteMutation.mutate()} disabled={deleteMutation.isPending}>
            {deleteMutation.isPending ? t('VPNPage.deleteDialog.deleting') : t('VPNPage.common.delete')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Tailscale Node Card ─────────────────────────────────────────────────────

function TailscaleNodeCard({
  node,
  onPing,
  isPinging,
}: {
  node: TailscaleNode;
  onPing: (hostname: string) => void;
  isPinging: boolean;
}) {
  const { t } = useTranslation('vpn');
  const StatusIcon = statusIcons[node.status] || Activity;
  const isOnline = node.status === 'online' || node.online;

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <Card className="h-full hover:border-primary/30 transition-colors">
        <CardContent noOffset className="p-4">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${isOnline ? 'bg-green-500/10' : 'bg-muted'}`}>
                <Server className={`h-5 w-5 ${isOnline ? 'text-green-500' : 'text-muted-foreground'}`} />
              </div>
              <div>
                <div className="font-medium">{node.name}</div>
                <div className="text-xs text-muted-foreground font-mono">{node.dns_name}</div>
              </div>
            </div>
            <Badge variant="outline" className={statusColors[node.status]}>
              <StatusIcon className="mr-1 h-3 w-3" />
              {isOnline ? t('VPNPage.common.online') : t('VPNPage.common.offline')}
            </Badge>
          </div>

          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('VPNPage.tailscaleNode.tailscaleIp')}</span>
              <span className="font-mono">{node.tailscale_ip || node.tailscale_ips?.[0] || t('VPNPage.common.na')}</span>
            </div>
            {(node.public_ip || node.tailscale_ips?.[1]) && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">{t('VPNPage.tailscaleNode.publicIp')}</span>
                <span className="font-mono">{node.public_ip || node.tailscale_ips?.[1]}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('VPNPage.tailscaleNode.os')}</span>
              <span>{node.os}</span>
            </div>
            {node.relay && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">{t('VPNPage.tailscaleNode.relay')}</span>
                <span>{node.relay}</span>
              </div>
            )}
          </div>

          {node.advertised_routes && node.advertised_routes.length > 0 && (
            <div className="mt-4 pt-4 border-t">
              <div className="text-xs text-muted-foreground mb-2">{t('VPNPage.tailscaleNode.advertisedRoutes')}</div>
              <div className="flex flex-wrap gap-1">
                {node.advertised_routes.map((route) => (
                  <Badge key={route} variant="secondary" className="text-xs font-mono">{route}</Badge>
                ))}
              </div>
            </div>
          )}

          {node.tags && node.tags.length > 0 && (
            <div className="mt-4 pt-4 border-t">
              <div className="text-xs text-muted-foreground mb-2">{t('VPNPage.tailscaleNode.tags')}</div>
              <div className="flex flex-wrap gap-1">
                {node.tags.map((tag) => (
                  <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
                ))}
              </div>
            </div>
          )}

          <div className="mt-4 pt-4 border-t flex gap-2">
            <Button variant="outline" size="sm" className="flex-1" onClick={() => onPing(node.name)} disabled={!isOnline || isPinging}>
              {isPinging ? <RefreshCw className="mr-1 h-3 w-3 animate-spin" /> : <Activity className="mr-1 h-3 w-3" />}
              {t('VPNPage.common.ping')}
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─── Netbird Peer Card ───────────────────────────────────────────────────────

function NetbirdPeerCard({
  peer,
  onPing,
  isPinging,
}: {
  peer: NetbirdPeer;
  onPing: (target: string) => void;
  isPinging: boolean;
}) {
  const { t } = useTranslation('vpn');
  const isOnline = peer.status === 'connected' || peer.status === 'online';

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <Card className="h-full hover:border-primary/30 transition-colors">
        <CardContent noOffset className="p-4">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${isOnline ? 'bg-teal-500/10' : 'bg-muted'}`}>
                <Network className={`h-5 w-5 ${isOnline ? 'text-teal-500' : 'text-muted-foreground'}`} />
              </div>
              <div>
                <div className="font-medium">{peer.name}</div>
                <div className="text-xs text-muted-foreground font-mono">{peer.hostname}</div>
              </div>
            </div>
            <Badge variant="outline" className={isOnline ? statusColors.connected : statusColors.disconnected}>
              {isOnline ? <CheckCircle className="mr-1 h-3 w-3" /> : <XCircle className="mr-1 h-3 w-3" />}
              {peer.status}
            </Badge>
          </div>

          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('VPNPage.netbirdPeer.ipAddress')}</span>
              <span className="font-mono">{peer.ip}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">{t('VPNPage.netbirdPeer.connection')}</span>
              <span>{peer.direct ? t('VPNPage.netbirdPeer.directP2P') : (peer.relay ? t('VPNPage.netbirdPeer.relayWith', { relay: peer.relay }) : t('VPNPage.netbirdPeer.relay'))}</span>
            </div>
            {peer.last_handshake && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">{t('VPNPage.netbirdPeer.lastHandshake')}</span>
                <span>{new Date(peer.last_handshake).toLocaleTimeString()}</span>
              </div>
            )}
          </div>

          {peer.routes && peer.routes.length > 0 && (
            <div className="mt-4 pt-4 border-t">
              <div className="text-xs text-muted-foreground mb-2">{t('VPNPage.netbirdPeer.routes')}</div>
              <div className="flex flex-wrap gap-1">
                {peer.routes.map((route) => (
                  <Badge key={route} variant="secondary" className="text-xs font-mono">{route}</Badge>
                ))}
              </div>
            </div>
          )}

          <div className="mt-4 pt-4 border-t flex gap-2">
            <Button variant="outline" size="sm" className="flex-1" onClick={() => onPing(peer.ip)} disabled={!isOnline || isPinging}>
              {isPinging ? <RefreshCw className="mr-1 h-3 w-3 animate-spin" /> : <Activity className="mr-1 h-3 w-3" />}
              {t('VPNPage.common.ping')}
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─── Site VPN Configuration Dialog (enhanced) ────────────────────────────────

function SiteVPNConfigDialog({
  open,
  onOpenChange,
  site,
  config,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  site: Site;
  config?: SiteVPNConfig;
}) {
  const { t } = useTranslation('vpn');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [vpnType, setVpnType] = useState(config?.vpn_type || 'tailscale');
  const [tailscaleHostname, setTailscaleHostname] = useState(config?.tailscale_hostname || config?.tailscale_node || '');
  const [wireguardInterface, setWireguardInterface] = useState(config?.wireguard_interface || '');
  const [remoteSubnets, setRemoteSubnets] = useState(config?.remote_subnets?.join(', ') || '');
  const [healthCheckIp, setHealthCheckIp] = useState(config?.health_check_ip || '');
  // OpenVPN
  const [ovpnConfigPath, setOvpnConfigPath] = useState(config?.openvpn_config_path || '');
  const [ovpnProtocol, setOvpnProtocol] = useState(config?.openvpn_protocol || 'udp');
  // Netbird
  const [netbirdPeerId, setNetbirdPeerId] = useState(config?.netbird_peer_id || '');
  const [netbirdGroup, setNetbirdGroup] = useState(config?.netbird_group || '');

  const updateMutation = useMutation({
    mutationFn: async () => {
      const data: Partial<SiteVPNConfig> = {
        vpn_type: vpnType,
        tailscale_hostname: vpnType === 'tailscale' ? tailscaleHostname || undefined : undefined,
        tailscale_node: vpnType === 'tailscale' ? tailscaleHostname || undefined : undefined,
        wireguard_interface: vpnType === 'wireguard' ? wireguardInterface || undefined : undefined,
        health_check_ip: healthCheckIp || undefined,
        remote_subnets: remoteSubnets.split(',').map((s: string) => s.trim()).filter(Boolean),
        openvpn_config_path: vpnType === 'openvpn' ? ovpnConfigPath || undefined : undefined,
        openvpn_protocol: vpnType === 'openvpn' ? ovpnProtocol : undefined,
        netbird_peer_id: vpnType === 'netbird' ? netbirdPeerId || undefined : undefined,
        netbird_group: vpnType === 'netbird' ? netbirdGroup || undefined : undefined,
      };
      return (await vpnApi.updateSiteConfig(site.id, data)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siteVpnConfigs'] });
      toast({ title: t('VPNPage.siteConfig.updatedToast'), description: t('VPNPage.siteConfig.updatedDesc', { name: site.name }) });
      onOpenChange(false);
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.common.error'), description: err?.response?.data?.detail || t('VPNPage.siteConfig.saveFailed'), variant: 'destructive' });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t('VPNPage.siteConfig.title', { name: site.name })}</DialogTitle>
          <DialogDescription>{t('VPNPage.siteConfig.description')}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t('VPNPage.siteConfig.vpnType')}</Label>
            <Select value={vpnType} onValueChange={setVpnType}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="tailscale">Tailscale</SelectItem>
                <SelectItem value="wireguard">WireGuard</SelectItem>
                <SelectItem value="openvpn">OpenVPN</SelectItem>
                <SelectItem value="netbird">Netbird</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {vpnType === 'tailscale' && (
            <div className="space-y-2">
              <Label>{t('VPNPage.siteConfig.tailscaleHostname')}</Label>
              <Input value={tailscaleHostname} onChange={e => setTailscaleHostname(e.target.value)} placeholder={t('VPNPage.siteConfig.tailscaleHostnamePlaceholder')} />
              <p className="text-xs text-muted-foreground">{t('VPNPage.siteConfig.tailscaleHostnameHelp')}</p>
            </div>
          )}

          {vpnType === 'wireguard' && (
            <div className="space-y-2">
              <Label>{t('VPNPage.siteConfig.wireguardInterface')}</Label>
              <Input value={wireguardInterface} onChange={e => setWireguardInterface(e.target.value)} placeholder="e.g., wg0" />
            </div>
          )}

          {vpnType === 'openvpn' && (
            <div className="space-y-3 p-3 rounded-lg border bg-orange-500/5">
              <h4 className="text-sm font-medium text-orange-700">{t('VPNPage.connectionForm.openvpnSettings')}</h4>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.configFilePath')}</Label>
                <Input value={ovpnConfigPath} onChange={e => setOvpnConfigPath(e.target.value)} placeholder="/etc/openvpn/client/office.conf" />
              </div>
              <div className="space-y-2">
                <Label>{t('VPNPage.connectionForm.protocol')}</Label>
                <Select value={ovpnProtocol} onValueChange={setOvpnProtocol}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="udp">UDP</SelectItem>
                    <SelectItem value="tcp">TCP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          {vpnType === 'netbird' && (
            <div className="space-y-3 p-3 rounded-lg border bg-teal-500/5">
              <h4 className="text-sm font-medium text-teal-700">{t('VPNPage.connectionForm.netbirdSettings')}</h4>
              <div className="space-y-2">
                <Label>{t('VPNPage.siteConfig.peerId')}</Label>
                <Input value={netbirdPeerId} onChange={e => setNetbirdPeerId(e.target.value)} placeholder={t('VPNPage.siteConfig.peerIdPlaceholder')} />
              </div>
              <div className="space-y-2">
                <Label>{t('VPNPage.siteConfig.networkGroup')}</Label>
                <Input value={netbirdGroup} onChange={e => setNetbirdGroup(e.target.value)} placeholder="e.g., office-network" />
              </div>
            </div>
          )}

          <div className="space-y-2">
            <Label>{t('VPNPage.siteConfig.remoteSubnets')}</Label>
            <Input value={remoteSubnets} onChange={e => setRemoteSubnets(e.target.value)} placeholder="e.g., 192.168.1.0/24, 10.0.0.0/8" />
            <p className="text-xs text-muted-foreground">{t('VPNPage.siteConfig.remoteSubnetsHelp')}</p>
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.siteConfig.healthCheckIp')}</Label>
            <Input value={healthCheckIp} onChange={e => setHealthCheckIp(e.target.value)} placeholder="e.g., 192.168.1.1" />
            <p className="text-xs text-muted-foreground">{t('VPNPage.siteConfig.healthCheckIpHelp')}</p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('VPNPage.common.cancel')}</Button>
          <Button onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}>
            {updateMutation.isPending ? t('VPNPage.common.saving') : t('VPNPage.siteConfig.saveConfiguration')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create Tunnel Template Dialog ───────────────────────────────────────────

function CreateTemplateDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t } = useTranslation('vpn');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [vpnType, setVpnType] = useState<'ipsec' | 'wireguard' | 'openvpn'>('wireguard');
  const [topology, setTopology] = useState<'hub_spoke' | 'full_mesh' | 'point_to_point'>('point_to_point');
  const [defaultSubnets, setDefaultSubnets] = useState('');

  useEffect(() => {
    if (open) {
      setName('');
      setVpnType('wireguard');
      setTopology('point_to_point');
      setDefaultSubnets('');
    }
  }, [open]);

  const createMutation = useMutation({
    mutationFn: async () => {
      const payload: VPNTunnelTemplateCreate = {
        name,
        vpn_type: vpnType,
        topology,
        default_subnets: defaultSubnets ? defaultSubnets.split(',').map(s => s.trim()).filter(Boolean) : undefined,
      };
      return (await vpnApi.orchestration.createTemplate(payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpnTunnelTemplates'] });
      toast({ title: t('VPNPage.templateDialog.createdToast'), description: t('VPNPage.templateDialog.createdDesc', { name }) });
      onOpenChange(false);
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.common.error'), description: err?.response?.data?.detail || t('VPNPage.templateDialog.createFailed'), variant: 'destructive' });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('VPNPage.templateDialog.title')}</DialogTitle>
          <DialogDescription>{t('VPNPage.templateDialog.description')}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t('VPNPage.templateDialog.templateName')}</Label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder={t('VPNPage.templateDialog.templateNamePlaceholder')} />
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.templateDialog.vpnType')}</Label>
            <Select value={vpnType} onValueChange={(v) => setVpnType(v as 'ipsec' | 'wireguard' | 'openvpn')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="wireguard">WireGuard</SelectItem>
                <SelectItem value="ipsec">IPsec</SelectItem>
                <SelectItem value="openvpn">OpenVPN</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.templateDialog.topology')}</Label>
            <Select value={topology} onValueChange={(v) => setTopology(v as 'hub_spoke' | 'full_mesh' | 'point_to_point')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="point_to_point">{t('VPNPage.templateDialog.topologyPointToPoint')}</SelectItem>
                <SelectItem value="hub_spoke">{t('VPNPage.templateDialog.topologyHubSpoke')}</SelectItem>
                <SelectItem value="full_mesh">{t('VPNPage.templateDialog.topologyFullMesh')}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>{t('VPNPage.templateDialog.defaultSubnets')}</Label>
            <Input value={defaultSubnets} onChange={e => setDefaultSubnets(e.target.value)} placeholder="10.0.0.0/24, 192.168.0.0/24" />
            <p className="text-xs text-muted-foreground">{t('VPNPage.templateDialog.defaultSubnetsHelp')}</p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t('VPNPage.common.cancel')}</Button>
          <Button onClick={() => createMutation.mutate()} disabled={createMutation.isPending || !name}>
            {createMutation.isPending ? t('VPNPage.templateDialog.creating') : t('VPNPage.templateDialog.createTemplate')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main VPN Page ───────────────────────────────────────────────────────────

const VPN_TAB_VALUES = [
  'overview', 'connections', 'discovery', 'tailscale', 'netbird', 'sites',
  'events', 'metrics', 'tunnels', 'topology', 'conflicts', 'certificates',
] as const;

export default function VPNPage() {
  const { t } = useTranslation('vpn');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { tab: tabParam } = useParams<{ tab?: string }>();
  const activeTab =
    (VPN_TAB_VALUES as readonly string[]).includes(tabParam ?? '') ? (tabParam as string) : 'overview';
  const [pingingNode, setPingingNode] = useState<string | null>(null);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [selectedSite, setSelectedSite] = useState<Site | null>(null);
  // Connection CRUD dialogs
  const [connectionFormOpen, setConnectionFormOpen] = useState(false);
  const [editingConnection, setEditingConnection] = useState<VPNConnection | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deletingConnection, setDeletingConnection] = useState<VPNConnection | null>(null);
  const [actioningIds, setActioningIds] = useState<Set<string>>(new Set());
  // Events filter
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  // Tunnels
  const [createTemplateOpen, setCreateTemplateOpen] = useState(false);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Queries ──

  const {
    data: connections,
    isLoading: connectionsLoading,
    isError: connectionsError,
    refetch: refetchConnections,
  } = useQuery({
    queryKey: ['vpnConnections'],
    queryFn: async () => (await vpnApi.listConnections()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
  });

  const {
    data: tailscaleStatus,
    isLoading: tailscaleLoading,
    isError: tailscaleError,
    refetch: refetchTailscale,
  } = useQuery({
    queryKey: ['tailscaleStatus'],
    queryFn: async () => (await vpnApi.tailscale.getStatus()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
  });

  const {
    data: netbirdStatus,
    isLoading: netbirdLoading,
    isError: netbirdError,
    refetch: refetchNetbird,
  } = useQuery({
    queryKey: ['netbirdStatus'],
    queryFn: async () => (await vpnApi.netbird.getStatus()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
  });

  const { data: sitesData, isError: sitesError } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => (await sitesApiV2.list({ page_size: 200 })).data,
  });
  const sites = sitesData?.items || [];

  const { data: vpnDashboard } = useQuery({
    queryKey: ['vpn', 'dashboard'],
    queryFn: async () => (await vpnApi.getDashboard()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
  });

  // Events query
  const {
    data: eventsData,
    isLoading: eventsLoading,
    isError: eventsError,
  } = useQuery({
    queryKey: ['vpnEvents', { severity: severityFilter === 'all' ? undefined : severityFilter, siteId: selectedSiteId }],
    queryFn: async () => (await vpnApi.events.list({
      site_id: selectedSiteId || undefined,
      severity: severityFilter === 'all' ? undefined : severityFilter,
      limit: 100,
    })).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
    enabled: activeTab === 'events',
  });

  // Metrics query
  const {
    data: aggregateMetrics,
    isLoading: metricsLoading,
    isError: metricsError,
  } = useQuery({
    queryKey: ['vpnAggregateMetrics'],
    queryFn: async () => (await vpnApi.getAggregateMetrics()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
    enabled: activeTab === 'metrics',
  });

  // Tunnels queries
  const {
    data: tunnelsData,
    isLoading: tunnelsLoading,
    isError: tunnelsError,
  } = useQuery({
    queryKey: ['vpn', 'tunnels'],
    queryFn: async () => (await vpnApi.orchestration.listTunnels()).data,
    refetchInterval: 30000,
    refetchIntervalInBackground: false,
    enabled: activeTab === 'tunnels',
  });

  const {
    data: templatesData,
    isLoading: templatesLoading,
    isError: templatesError,
  } = useQuery({
    queryKey: ['vpnTunnelTemplates'],
    queryFn: async () => (await vpnApi.orchestration.listTemplates()).data,
    enabled: activeTab === 'tunnels',
  });

  // Route conflicts query
  const {
    data: conflictsData,
    isLoading: conflictsLoading,
    isError: conflictsError,
  } = useQuery({
    queryKey: ['vpnRouteConflicts'],
    queryFn: async () => (await vpnApi.getRouteConflicts()).data,
    refetchInterval: 60000,
    refetchIntervalInBackground: false,
    enabled: activeTab === 'conflicts',
  });

  // Certificates query
  const {
    data: certsData,
    isLoading: certsLoading,
    isError: certsError,
  } = useQuery({
    queryKey: ['vpnCertsExpiring'],
    queryFn: async () => (await vpnApi.certs.getExpiring(90)).data,
    refetchInterval: 60000,
    refetchIntervalInBackground: false,
    enabled: activeTab === 'certificates',
  });

  // ── Mutations ──

  const pingTailscaleMutation = useMutation({
    mutationFn: async (hostname: string) => {
      setPingingNode(hostname);
      return (await vpnApi.tailscale.ping(hostname)).data;
    },
    onSuccess: (data) => {
      toast({ title: t('VPNPage.toasts.pingResult'), description: data.reachable ? t('VPNPage.toasts.reachable', { latency: data.latency_ms }) : t('VPNPage.toasts.unreachable') });
    },
    onError: (err: Error) => {
      toast({ title: t('VPNPage.toasts.operationFailed'), description: err.message, variant: 'destructive' });
    },
    onSettled: () => setPingingNode(null),
  });

  const pingNetbirdMutation = useMutation({
    mutationFn: async (target: string) => {
      setPingingNode(target);
      return (await vpnApi.netbird.ping(target)).data;
    },
    onSuccess: (data) => {
      toast({ title: t('VPNPage.toasts.pingResult'), description: data.reachable ? t('VPNPage.toasts.reachable', { latency: data.latency_ms }) : t('VPNPage.toasts.unreachable') });
    },
    onError: (err: Error) => {
      toast({ title: t('VPNPage.toasts.operationFailed'), description: err.message, variant: 'destructive' });
    },
    onSettled: () => setPingingNode(null),
  });

  const actionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: string; action: 'connect' | 'disconnect' }) => {
      setActioningIds((prev) => new Set(prev).add(id));
      return (await vpnApi.connectionAction(id, action)).data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['vpnConnections'] });
      toast({ title: data.success ? t('VPNPage.toasts.success') : t('VPNPage.toasts.notice'), description: data.message });
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.toasts.actionFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
    onSettled: (_d, _e, vars) => {
      setActioningIds((prev) => { const next = new Set(prev); next.delete(vars.id); return next; });
    },
  });

  const tunnelActionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: string; action: 'enable' | 'disable' | 'reprovision' }) => {
      return (await vpnApi.orchestration.tunnelAction(id, action)).data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['vpn', 'tunnels'] });
      toast({ title: t('VPNPage.toasts.tunnelAction'), description: data.message });
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.toasts.actionFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const teardownMutation = useMutation({
    mutationFn: async (id: string) => {
      await vpnApi.orchestration.teardownTunnel(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn', 'tunnels'] });
      toast({ title: t('VPNPage.toasts.tunnelRemoved'), description: t('VPNPage.toasts.tunnelRemovedDesc') });
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.toasts.teardownFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const certScanMutation = useMutation({
    mutationFn: async () => (await vpnApi.certs.scan()).data,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['vpnCertsExpiring'] });
      toast({ title: t('VPNPage.toasts.certScanComplete'), description: t('VPNPage.toasts.certScanCompleteDesc', { scanned: data.scanned, updated: data.updated, errors: data.errors }) });
    },
    onError: (err: any) => {
      toast({ title: t('VPNPage.toasts.certScanFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── WebSocket VPN event listener ──

  useEffect(() => {
    function handleVpnEvent(e: Event) {
      const { type, data } = (e as CustomEvent).detail as { type: string; data: any };
      const connectionName = data?.connection_name || data?.name || '';

      switch (type) {
        case 'vpn_connection_down':
          toast({
            title: t('VPNPage.wsEvents.connectionDown'),
            description: connectionName
              ? t('VPNPage.wsEvents.connectionDownNamed', { name: connectionName })
              : t('VPNPage.wsEvents.connectionDownGeneric'),
            variant: 'destructive',
          });
          break;
        case 'vpn_connection_restored':
          toast({
            title: t('VPNPage.wsEvents.connectionRestored'),
            description: connectionName
              ? t('VPNPage.wsEvents.connectionRestoredNamed', { name: connectionName })
              : t('VPNPage.wsEvents.connectionRestoredGeneric'),
          });
          break;
        case 'vpn_health_degraded':
          toast({
            title: t('VPNPage.wsEvents.healthDegraded'),
            description: data?.reason || t('VPNPage.wsEvents.healthDegradedGeneric'),
            variant: 'destructive',
          });
          break;
        case 'vpn_tunnel_status_changed':
          toast({
            title: t('VPNPage.wsEvents.tunnelStatusChanged'),
            description: data?.tunnel_name
              ? t('VPNPage.wsEvents.tunnelStatusChangedNamed', { name: data.tunnel_name, status: data?.status || t('VPNPage.wsEvents.updated') })
              : t('VPNPage.wsEvents.tunnelStatusChangedGeneric'),
          });
          break;
        case 'vpn_reconnect_started':
          toast({
            title: t('VPNPage.wsEvents.reconnectStarted'),
            description: connectionName
              ? t('VPNPage.wsEvents.reconnectStartedNamed', { name: connectionName })
              : t('VPNPage.wsEvents.reconnectStartedGeneric'),
          });
          break;
        case 'vpn_reconnect_exhausted':
          toast({
            title: t('VPNPage.wsEvents.reconnectFailed'),
            description: connectionName
              ? t('VPNPage.wsEvents.reconnectFailedNamed', { name: connectionName })
              : t('VPNPage.wsEvents.reconnectFailedGeneric'),
            variant: 'destructive',
          });
          break;
      }
    }

    window.addEventListener('freesdn:vpn-event', handleVpnEvent);
    return () => window.removeEventListener('freesdn:vpn-event', handleVpnEvent);
  }, [toast, t]);

  // ── Stats ──

  const activeConnections = connections?.filter(c => c.status === 'connected').length || 0;
  const totalConnections = connections?.length || 0;
  const tailscaleOnline = tailscaleStatus?.connected || tailscaleStatus?.self?.online || tailscaleStatus?.self_node?.online || false;
  const tailscalePeers = tailscaleStatus?.peers?.filter((p: TailscaleNode) => p.online).length || 0;
  const netbirdConnected = netbirdStatus?.connected || false;
  const netbirdPeerCount = netbirdStatus?.connected_peers || 0;

  // Tailscale + NetBird both use 100.64.0.0/10 and collide on one host. Warn when
  // both overlays are configured (FreeSDN runs Tailscale with --netfilter-mode=off
  // to let them coexist — see backend _resolve_tailscale_netfilter_mode).
  const overlayCoexistence =
    (connections || []).some(c => c.vpn_type === 'tailscale') &&
    (connections || []).some(c => c.vpn_type === 'netbird');

  const hasQueryError = connectionsError || tailscaleError || netbirdError || sitesError;

  const handleRefresh = () => {
    refetchConnections();
    refetchTailscale();
    refetchNetbird();
  };

  const handleEditConnection = (c: VPNConnection) => {
    setEditingConnection(c);
    setConnectionFormOpen(true);
  };

  const handleNewConnection = () => {
    setEditingConnection(null);
    setConnectionFormOpen(true);
  };

  const handleDeleteConnection = (c: VPNConnection) => {
    setDeletingConnection(c);
    setDeleteDialogOpen(true);
  };

  // ── Events table columns ──

  const eventColumns: DataTableColumn<VPNEvent>[] = [
    {
      id: 'time',
      header: t('VPNPage.eventColumns.time'),
      cell: (row) => (
        <span className="text-sm whitespace-nowrap">
          {new Date(row.created_at).toLocaleString()}
        </span>
      ),
      sortable: true,
    },
    {
      id: 'event_type',
      header: t('VPNPage.eventColumns.type'),
      accessorKey: 'event_type',
      cell: (row) => (
        <span className="text-sm font-mono">{row.event_type}</span>
      ),
      sortable: true,
    },
    {
      id: 'severity',
      header: t('VPNPage.eventColumns.severity'),
      cell: (row) => (
        <Badge variant="outline" className={`text-xs ${severityColors[row.severity] || ''}`}>
          {row.severity}
        </Badge>
      ),
      sortable: true,
    },
    {
      id: 'title',
      header: t('VPNPage.eventColumns.title'),
      accessorKey: 'title',
      cell: (row) => (
        <span className="text-sm">{row.title}</span>
      ),
    },
    {
      id: 'site',
      header: t('VPNPage.eventColumns.site'),
      cell: (row) => {
        if (!row.site_id) return <span className="text-muted-foreground text-sm">--</span>;
        const site = sites.find(s => s.id === row.site_id);
        return <span className="text-sm">{site?.name || row.site_id.slice(0, 8)}</span>;
      },
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <PageHeader
          title={t('VPNPage.header.title')}
          titleBadge={<CapabilityMaturityBadge capabilityId="vpn" />}
          description={t('VPNPage.header.description')}
          icon={Shield}
          onRefresh={handleRefresh}
          refreshing={connectionsLoading || tailscaleLoading || netbirdLoading}
        />
      </motion.div>

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('VPNPage.errors.someDataFailed')}</span>
          </CardContent>
        </Card>
      )}

      {overlayCoexistence && (
        <Card className="border-amber-500/50 bg-amber-500/5">
          <CardContent noOffset className="p-4 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
            <div className="text-sm space-y-1">
              <p className="font-medium text-amber-700">{t('VPNPage.coexistence.title')}</p>
              <p className="text-muted-foreground">{t('VPNPage.coexistence.body')}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <StatsGrid
        columns={4}
        stats={[
          {
            title: t('VPNPage.stats.activeConnections'),
            value: activeConnections,
            icon: Shield,
            variant: 'success',
            description: t('VPNPage.stats.activeConnectionsDesc', { total: totalConnections }),
          },
          {
            title: t('VPNPage.providers.tailscale'),
            value: tailscaleOnline ? t('VPNPage.common.connected') : t('VPNPage.common.offline'),
            icon: tailscaleOnline ? Wifi : WifiOff,
            variant: tailscaleOnline ? 'success' : 'destructive',
            description: t('VPNPage.stats.peersOnline', { count: tailscalePeers }),
          },
          {
            title: t('VPNPage.providers.netbird'),
            value: netbirdConnected ? t('VPNPage.common.connected') : t('VPNPage.common.offline'),
            icon: netbirdConnected ? Network : WifiOff,
            variant: netbirdConnected ? 'success' : 'destructive',
            description: t('VPNPage.stats.peersConnected', { count: netbirdPeerCount }),
          },
          {
            title: t('VPNPage.stats.onlinePeers'),
            value: tailscalePeers + netbirdPeerCount,
            icon: Server,
            variant: 'primary',
            description: t('VPNPage.stats.onlinePeersDesc'),
          },
          {
            title: t('VPNPage.stats.sitesWithVpn'),
            value: vpnDashboard?.sites_with_vpn ?? 0,
            icon: Globe,
            variant: 'info',
            description: t('VPNPage.stats.sitesWithVpnDesc'),
          },
        ]}
      />

      {/* Tabs */}
      <PageTabs
        basePath="/vpn"
        tabs={[
          {
            value: 'overview',
            label: t('VPNPage.tabs.overview'),
            content: (
              <div className="space-y-6">
          {/* Provider Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Tailscale */}
            <Card className="hover:border-blue-500/30 transition-colors">
              <CardContent noOffset className="p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className={`p-2 rounded-lg ${tailscaleOnline ? 'bg-blue-500/10' : 'bg-muted'}`}>
                    <Globe className={`h-5 w-5 ${tailscaleOnline ? 'text-blue-500' : 'text-muted-foreground'}`} />
                  </div>
                  <div>
                    <div className="font-medium">{t('VPNPage.providers.tailscale')}</div>
                    <div className="text-xs text-muted-foreground">{t('VPNPage.providers.meshVpn')}</div>
                  </div>
                  <Badge variant="outline" className={`ml-auto ${tailscaleOnline ? statusColors.connected : statusColors.disconnected}`}>
                    {tailscaleOnline ? t('VPNPage.common.connected') : t('VPNPage.common.offline')}
                  </Badge>
                </div>
                <div className="text-sm text-muted-foreground">
                  {t('VPNPage.stats.peersOnline', { count: tailscalePeers })}
                  {tailscaleStatus?.tailnet_name && <> &middot; {tailscaleStatus.tailnet_name}</>}
                </div>
              </CardContent>
            </Card>

            {/* Netbird */}
            <Card className="hover:border-teal-500/30 transition-colors">
              <CardContent noOffset className="p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className={`p-2 rounded-lg ${netbirdConnected ? 'bg-teal-500/10' : 'bg-muted'}`}>
                    <Network className={`h-5 w-5 ${netbirdConnected ? 'text-teal-500' : 'text-muted-foreground'}`} />
                  </div>
                  <div>
                    <div className="font-medium">{t('VPNPage.providers.netbird')}</div>
                    <div className="text-xs text-muted-foreground">{t('VPNPage.providers.p2pMesh')}</div>
                  </div>
                  <Badge variant="outline" className={`ml-auto ${netbirdConnected ? statusColors.connected : statusColors.disconnected}`}>
                    {netbirdConnected ? t('VPNPage.common.connected') : t('VPNPage.common.offline')}
                  </Badge>
                </div>
                <div className="text-sm text-muted-foreground">
                  {t('VPNPage.stats.peersConnected', { count: netbirdPeerCount })}
                </div>
              </CardContent>
            </Card>

            {/* WireGuard */}
            <Card className="hover:border-purple-500/30 transition-colors">
              <CardContent noOffset className="p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 rounded-lg bg-purple-500/10">
                    <Lock className="h-5 w-5 text-purple-500" />
                  </div>
                  <div>
                    <div className="font-medium">{t('VPNPage.providers.wireguard')}</div>
                    <div className="text-xs text-muted-foreground">{t('VPNPage.providers.tunnelVpn')}</div>
                  </div>
                  <Badge variant="outline" className="ml-auto bg-muted text-muted-foreground">
                    {t('VPNPage.providers.activeCount', { count: connections?.filter(c => c.vpn_type === 'wireguard' && (c.status === 'connected')).length || 0 })}
                  </Badge>
                </div>
                <div className="text-sm text-muted-foreground">
                  {t('VPNPage.providers.tunnelsConfigured', { count: connections?.filter(c => c.vpn_type === 'wireguard').length || 0 })}
                </div>
              </CardContent>
            </Card>

            {/* OpenVPN */}
            <Card className="hover:border-orange-500/30 transition-colors">
              <CardContent noOffset className="p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 rounded-lg bg-orange-500/10">
                    <Shield className="h-5 w-5 text-orange-500" />
                  </div>
                  <div>
                    <div className="font-medium">{t('VPNPage.providers.openvpn')}</div>
                    <div className="text-xs text-muted-foreground">{t('VPNPage.providers.classicVpn')}</div>
                  </div>
                  <Badge variant="outline" className="ml-auto bg-muted text-muted-foreground">
                    {t('VPNPage.providers.activeCount', { count: connections?.filter(c => c.vpn_type === 'openvpn' && (c.status === 'connected')).length || 0 })}
                  </Badge>
                </div>
                <div className="text-sm text-muted-foreground">
                  {t('VPNPage.providers.connectionsConfigured', { count: connections?.filter(c => c.vpn_type === 'openvpn').length || 0 })}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tailscale Quick Status */}
          {tailscaleStatus && (
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Globe className="h-4 w-4 text-blue-500" />
                    {t('VPNPage.overview.tailscaleNetwork')}
                  </CardTitle>
                  <Badge variant="outline" className={tailscaleOnline ? statusColors.online : statusColors.offline}>
                    {tailscaleOnline ? t('VPNPage.common.connected') : t('VPNPage.common.offline')}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.hostname')}</span>
                    <span className="ml-1 font-medium">{(tailscaleStatus.self || tailscaleStatus.self_node)?.name}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.tailscaleIp')}</span>
                    <span className="ml-1 font-mono">{(tailscaleStatus.self || tailscaleStatus.self_node)?.tailscale_ip || (tailscaleStatus.self || tailscaleStatus.self_node)?.tailscale_ips?.[0]}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.tailnet')}</span>
                    <span className="ml-1">{tailscaleStatus.tailnet_name || t('VPNPage.common.na')}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.magicDns')}</span>
                    <span className="ml-1">{tailscaleStatus.magic_dns_enabled ? t('VPNPage.common.enabled') : t('VPNPage.common.disabled')}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Netbird Quick Status */}
          {netbirdStatus && netbirdStatus.connected && (
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Network className="h-4 w-4 text-teal-500" />
                    {t('VPNPage.overview.netbirdNetwork')}
                  </CardTitle>
                  <Badge variant="outline" className={statusColors.connected}>
                    {t('VPNPage.common.connected')}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.ip')}</span>
                    <span className="ml-1 font-mono">{netbirdStatus.self_ip}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.fqdn')}</span>
                    <span className="ml-1 font-mono">{netbirdStatus.fqdn || t('VPNPage.common.na')}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.interface')}</span>
                    <span className="ml-1">{netbirdStatus.interface || 'wt0'}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('VPNPage.overview.peers')}</span>
                    <span className="ml-1">{netbirdStatus.connected_peers} / {netbirdStatus.peer_count}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Recent Connections */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">{t('VPNPage.overview.allConnections')}</h3>
              <Button size="sm" onClick={handleNewConnection}>
                <Plus className="mr-1 h-4 w-4" />
                {t('VPNPage.actions.newConnection')}
              </Button>
            </div>
            {connectionsLoading ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[1, 2].map((i) => (
                  <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-24 w-full" /></CardContent></Card>
                ))}
              </div>
            ) : connections && connections.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {connections.map((conn) => (
                  <VPNConnectionCard
                    key={conn.id || conn.name}
                    connection={conn}
                    onEdit={handleEditConnection}
                    onDelete={handleDeleteConnection}
                    onAction={(id, action) => actionMutation.mutate({ id, action })}
                    isActioning={actioningIds.has(conn.id)}
                  />
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Shield}
                title={t('VPNPage.overview.emptyTitle')}
                description={t('VPNPage.overview.emptyDescription')}
                action={{ label: t('VPNPage.overview.emptyAction'), onClick: handleNewConnection, icon: Plus }}
                variant="card"
              />
            )}
          </div>
              </div>
            ),
          },
          {
            value: 'connections',
            label: t('VPNPage.tabs.connections'),
            content: (
              <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">{t('VPNPage.connections.heading')}</h3>
              <p className="text-sm text-muted-foreground">{t('VPNPage.connections.subtitle')}</p>
            </div>
            <Button onClick={handleNewConnection}>
              <Plus className="mr-1 h-4 w-4" />
              {t('VPNPage.actions.newConnection')}
            </Button>
          </div>

          {connectionsLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-40 w-full" /></CardContent></Card>
              ))}
            </div>
          ) : connections && connections.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {connections.map((conn) => (
                <VPNConnectionCard
                  key={conn.id || conn.name}
                  connection={conn}
                  onEdit={handleEditConnection}
                  onDelete={handleDeleteConnection}
                  onAction={(id, action) => actionMutation.mutate({ id, action })}
                  isActioning={actioningIds.has(conn.id)}
                />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={Shield}
              title={t('VPNPage.connections.emptyTitle')}
              description={t('VPNPage.connections.emptyDescription')}
              action={{ label: t('VPNPage.connections.emptyAction'), onClick: handleNewConnection, icon: Plus }}
              variant="card"
            />
          )}
              </div>
            ),
          },
          {
            value: 'discovery',
            label: t('VPNPage.tabs.discovery'),
            content: <OverlayDiscoveryTab active={activeTab === 'discovery'} />,
          },
          {
            value: 'tailscale',
            label: 'Tailscale',
            content: (
              <div className="space-y-6">
          {/* Setup Wizard · always shown to manage lifecycle */}
          <TailscaleSetupWizard />

          {/* Peer Grid · shown when Tailscale is connected with peers */}
          {tailscaleLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-48 w-full" /></CardContent></Card>
              ))}
            </div>
          ) : tailscaleStatus?.peers && tailscaleStatus.peers.length > 0 ? (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('VPNPage.tailscaleTab.tailnetPeers')}</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {(tailscaleStatus.self || tailscaleStatus.self_node) && (
                  <TailscaleNodeCard
                    node={(tailscaleStatus.self || tailscaleStatus.self_node)!}
                    onPing={pingTailscaleMutation.mutate}
                    isPinging={pingingNode === (tailscaleStatus.self || tailscaleStatus.self_node)!.name}
                  />
                )}
                {tailscaleStatus.peers.map((peer: TailscaleNode) => (
                  <TailscaleNodeCard
                    key={peer.name}
                    node={peer}
                    onPing={pingTailscaleMutation.mutate}
                    isPinging={pingingNode === peer.name}
                  />
                ))}
              </div>
            </div>
          ) : (tailscaleStatus?.self || tailscaleStatus?.self_node) ? (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">{t('VPNPage.tailscaleTab.tailnetPeers')}</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <TailscaleNodeCard
                  node={(tailscaleStatus.self || tailscaleStatus.self_node)!}
                  onPing={pingTailscaleMutation.mutate}
                  isPinging={pingingNode === (tailscaleStatus.self || tailscaleStatus.self_node)!.name}
                />
                <Card className="col-span-2">
                  <EmptyState
                    icon={Globe}
                    title={t('VPNPage.tailscaleTab.emptyTitle')}
                    description={t('VPNPage.tailscaleTab.emptyDescription')}
                  />
                </Card>
              </div>
            </div>
          ) : null}
              </div>
            ),
          },
          {
            value: 'netbird',
            label: 'Netbird',
            content: (
              <div className="space-y-6">
          {netbirdLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-48 w-full" /></CardContent></Card>
              ))}
            </div>
          ) : netbirdStatus?.connected && netbirdStatus.peers?.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {netbirdStatus.peers.map((peer: NetbirdPeer) => (
                <NetbirdPeerCard
                  key={peer.id}
                  peer={peer}
                  onPing={pingNetbirdMutation.mutate}
                  isPinging={pingingNode === peer.ip}
                />
              ))}
            </div>
          ) : netbirdStatus?.connected ? (
            <Card className="p-12">
              <div className="flex flex-col items-center justify-center text-center">
                <Network className="h-12 w-12 text-muted-foreground/50 mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNPage.netbirdTab.connectedNoPeersTitle')}</h3>
                <p className="text-muted-foreground max-w-md">
                  {t('VPNPage.netbirdTab.connectedNoPeersDescription')}
                </p>
              </div>
            </Card>
          ) : (
            <Card className="p-12">
              <div className="flex flex-col items-center justify-center text-center">
                <Network className="h-12 w-12 text-muted-foreground/50 mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNPage.netbirdTab.notConnectedTitle')}</h3>
                <p className="text-muted-foreground max-w-md">
                  {t('VPNPage.netbirdTab.notConnectedDescription')}
                </p>
                <a href="https://netbird.io/download" target="_blank" rel="noopener noreferrer" className="mt-4">
                  <Button variant="outline">
                    <ExternalLink className="mr-1 h-4 w-4" />
                    {t('VPNPage.netbirdTab.getNetbird')}
                  </Button>
                </a>
              </div>
            </Card>
          )}
              </div>
            ),
          },
          {
            value: 'sites',
            label: t('VPNPage.tabs.sites'),
            content: (
              <div className="space-y-6">
          <div>
            <h3 className="text-lg font-semibold mb-1">{t('VPNPage.sitesTab.heading')}</h3>
            <p className="text-sm text-muted-foreground mb-4">{t('VPNPage.sitesTab.subtitle')}</p>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {sites.map((site) => (
              <Card key={site.id} className="hover:border-primary/30 transition-colors">
                <CardContent noOffset className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-muted">
                        <MapPin className="h-5 w-5 text-muted-foreground" />
                      </div>
                      <div>
                        <div className="font-medium">{site.name}</div>
                        <div className="text-sm text-muted-foreground">
                          {site.address || t('VPNPage.sitesTab.noAddress')}
                        </div>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setSelectedSite(site);
                        setConfigDialogOpen(true);
                      }}
                    >
                      <Settings className="mr-1 h-4 w-4" />
                      {t('VPNPage.sitesTab.configureVpn')}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}

            {sites.length === 0 && (
              <Card className="p-12">
                <div className="flex flex-col items-center justify-center text-center">
                  <Globe className="h-12 w-12 text-muted-foreground/50 mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNPage.sitesTab.emptyTitle')}</h3>
                  <p className="text-muted-foreground max-w-md">
                    {t('VPNPage.sitesTab.emptyDescription')}
                  </p>
                </div>
              </Card>
            )}
          </div>
              </div>
            ),
          },
          {
            value: 'events',
            label: t('VPNPage.tabs.events'),
            content: (
              <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">{t('VPNPage.eventsTab.heading')}</h3>
              <p className="text-sm text-muted-foreground">{t('VPNPage.eventsTab.subtitle')}</p>
            </div>
          </div>

          {/* Severity filter buttons */}
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground mr-1">{t('VPNPage.eventsTab.severityLabel')}</span>
            {['all', 'info', 'warning', 'error', 'critical'].map((sev) => (
              <Button
                key={sev}
                variant={severityFilter === sev ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(sev)}
                className="capitalize"
              >
                {t(`VPNPage.severity.${sev}`)}
              </Button>
            ))}
          </div>

          {eventsError && (
            <Card className="border-destructive">
              <CardContent noOffset className="p-4 flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <span className="text-sm">{t('VPNPage.eventsTab.loadError')}</span>
              </CardContent>
            </Card>
          )}

          <DataTable<VPNEvent>
            data={eventsData?.events || []}
            columns={eventColumns}
            isLoading={eventsLoading}
            searchable
            searchPlaceholder={t('VPNPage.eventsTab.searchPlaceholder')}
            emptyState={
              <EmptyState
                icon={Zap}
                title={t('VPNPage.eventsTab.emptyTitle')}
                description={severityFilter !== 'all'
                  ? t('VPNPage.eventsTab.emptyDescriptionFiltered', { severity: severityFilter })
                  : t('VPNPage.eventsTab.emptyDescription')}
              />
            }
          />
              </div>
            ),
          },
          {
            value: 'metrics',
            label: t('VPNPage.tabs.metrics'),
            content: (
              <div className="space-y-6">
          <div>
            <h3 className="text-lg font-semibold">{t('VPNPage.metricsTab.heading')}</h3>
            <p className="text-sm text-muted-foreground">{t('VPNPage.metricsTab.subtitle')}</p>
          </div>

          {metricsError && (
            <Card className="border-destructive">
              <CardContent noOffset className="p-4 flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <span className="text-sm">{t('VPNPage.metricsTab.loadError')}</span>
              </CardContent>
            </Card>
          )}

          {metricsLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-20 w-full" /></CardContent></Card>
              ))}
            </div>
          ) : aggregateMetrics ? (
            <>
              <StatsGrid
                columns={4}
                stats={[
                  {
                    title: t('VPNPage.metricsTab.totalRx'),
                    value: formatBytes(aggregateMetrics.total_rx_bytes),
                    icon: Activity,
                    variant: 'primary',
                    description: t('VPNPage.metricsTab.totalRxDesc'),
                  },
                  {
                    title: t('VPNPage.metricsTab.totalTx'),
                    value: formatBytes(aggregateMetrics.total_tx_bytes),
                    icon: Activity,
                    variant: 'primary',
                    description: t('VPNPage.metricsTab.totalTxDesc'),
                  },
                  {
                    title: t('VPNPage.metricsTab.avgLatency'),
                    value: aggregateMetrics.avg_latency_ms != null ? `${aggregateMetrics.avg_latency_ms.toFixed(1)}ms` : t('VPNPage.common.na'),
                    icon: Clock,
                    variant: 'primary',
                    description: t('VPNPage.metricsTab.avgLatencyDesc'),
                  },
                  {
                    title: t('VPNPage.metricsTab.connections'),
                    value: aggregateMetrics.connection_count,
                    icon: Shield,
                    variant: 'primary',
                    description: t('VPNPage.metricsTab.connectionsDesc'),
                  },
                ]}
              />

              {/* Connections by Provider */}
              {aggregateMetrics.by_provider && Object.keys(aggregateMetrics.by_provider).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <BarChart3 className="h-4 w-4" />
                      {t('VPNPage.metricsTab.connectionsByProvider')}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {Object.entries(aggregateMetrics.by_provider).map(([provider, stats]) => (
                        <div key={provider} className="flex items-center justify-between p-3 rounded-lg border">
                          <div className="flex items-center gap-3">
                            <Badge variant="outline" className={`${vpnTypeColors[provider] || vpnTypeColors.generic}`}>
                              {vpnTypeLabels[provider] || provider}
                            </Badge>
                            <span className="text-sm font-medium">{t('VPNPage.metricsTab.connectionCount', { count: stats.count })}</span>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-muted-foreground">
                            <span>{t('VPNPage.metricsTab.rx', { value: formatBytes(stats.rx_bytes) })}</span>
                            <span>{t('VPNPage.metricsTab.tx', { value: formatBytes(stats.tx_bytes) })}</span>
                            <span>{t('VPNPage.metricsTab.latency', { value: stats.avg_latency_ms != null ? `${stats.avg_latency_ms.toFixed(1)}ms` : t('VPNPage.common.na') })}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card className="p-12">
              <div className="flex flex-col items-center justify-center text-center">
                <BarChart3 className="h-12 w-12 text-muted-foreground/50 mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNPage.metricsTab.emptyTitle')}</h3>
                <p className="text-muted-foreground max-w-md">
                  {t('VPNPage.metricsTab.emptyDescription')}
                </p>
              </div>
            </Card>
          )}
              </div>
            ),
          },
          {
            value: 'tunnels',
            label: t('VPNPage.tabs.tunnels'),
            content: (
              <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">{t('VPNPage.tunnelsTab.heading')}</h3>
              <p className="text-sm text-muted-foreground">{t('VPNPage.tunnelsTab.subtitle')}</p>
            </div>
            <Button size="sm" onClick={() => setCreateTemplateOpen(true)}>
              <Plus className="mr-1 h-4 w-4" />
              {t('VPNPage.actions.createTemplate')}
            </Button>
          </div>

          {(tunnelsError || templatesError) && (
            <Card className="border-destructive">
              <CardContent noOffset className="p-4 flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <span className="text-sm">{t('VPNPage.tunnelsTab.loadError')}</span>
              </CardContent>
            </Card>
          )}

          {/* Templates section */}
          <div>
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide mb-3">{t('VPNPage.tunnelsTab.templates')}</h4>
            {templatesLoading ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {[1, 2].map((i) => (
                  <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-20 w-full" /></CardContent></Card>
                ))}
              </div>
            ) : templatesData?.templates && templatesData.templates.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {templatesData.templates.map((tmpl) => (
                  <Card key={tmpl.id} className="hover:border-primary/30 transition-colors">
                    <CardContent noOffset className="p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <div className="font-medium">{tmpl.name}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {t('VPNPage.tunnelsTab.created', { date: new Date(tmpl.created_at).toLocaleDateString() })}
                          </div>
                        </div>
                        <Badge variant="outline" className={vpnTypeColors[tmpl.vpn_type] || vpnTypeColors.generic}>
                          {vpnTypeLabels[tmpl.vpn_type] || tmpl.vpn_type}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Route className="h-3 w-3" />
                        <span className="capitalize">{tmpl.topology.replace('_', ' ')}</span>
                        {tmpl.default_subnets && tmpl.default_subnets.length > 0 && (
                          <span> &middot; {t('VPNPage.tunnelsTab.subnetCount', { count: tmpl.default_subnets.length })}</span>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <Card className="p-8">
                <div className="flex flex-col items-center justify-center text-center">
                  <Settings className="h-8 w-8 text-muted-foreground/50 mb-3" />
                  <p className="text-sm text-muted-foreground">{t('VPNPage.tunnelsTab.noTemplates')}</p>
                </div>
              </Card>
            )}
          </div>

          {/* Tunnels section */}
          <div>
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide mb-3">{t('VPNPage.tunnelsTab.activeTunnels')}</h4>
            {tunnelsLoading ? (
              <div className="space-y-3">
                {[1, 2].map((i) => (
                  <Card key={i}><CardContent noOffset className="p-4"><Skeleton className="h-16 w-full" /></CardContent></Card>
                ))}
              </div>
            ) : tunnelsData?.tunnels && tunnelsData.tunnels.length > 0 ? (
              <div className="space-y-3">
                {tunnelsData.tunnels.map((tunnel) => {
                  const siteA = sites.find(s => s.id === tunnel.site_a_id);
                  const siteB = sites.find(s => s.id === tunnel.site_b_id);
                  const isActionPending = (tunnelActionMutation.isPending && tunnelActionMutation.variables?.id === tunnel.id)
                    || (teardownMutation.isPending && teardownMutation.variables === tunnel.id);

                  return (
                    <Card key={tunnel.id} className="hover:border-primary/30 transition-colors">
                      <CardContent noOffset className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2">
                              <div className="p-1.5 rounded bg-muted">
                                <MapPin className="h-3.5 w-3.5 text-muted-foreground" />
                              </div>
                              <span className="text-sm font-medium">{siteA?.name || tunnel.site_a_id.slice(0, 8)}</span>
                            </div>
                            <Route className="h-4 w-4 text-muted-foreground" />
                            <div className="flex items-center gap-2">
                              <div className="p-1.5 rounded bg-muted">
                                <MapPin className="h-3.5 w-3.5 text-muted-foreground" />
                              </div>
                              <span className="text-sm font-medium">{siteB?.name || tunnel.site_b_id.slice(0, 8)}</span>
                            </div>
                            <Badge variant="outline" className={`text-xs ${tunnelStatusColors[tunnel.status] || ''}`}>
                              {tunnel.status}
                            </Badge>
                            {tunnel.error_message && (
                              <span className="text-xs text-destructive truncate max-w-[200px]" title={tunnel.error_message}>
                                {tunnel.error_message}
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            {tunnel.status === 'disabled' || tunnel.status === 'error' ? (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => tunnelActionMutation.mutate({ id: tunnel.id, action: 'enable' })}
                                disabled={isActionPending}
                              >
                                <Play className="mr-1 h-3 w-3" />
                                {t('VPNPage.tunnelsTab.enable')}
                              </Button>
                            ) : tunnel.status === 'active' || tunnel.status === 'pending' || tunnel.status === 'provisioning' ? (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                  if (confirm(t('VPNPage.tunnelsTab.disableConfirm'))) {
                    tunnelActionMutation.mutate({ id: tunnel.id, action: 'disable' });
                  }
                }}
                                disabled={isActionPending}
                              >
                                <Square className="mr-1 h-3 w-3" />
                                {t('VPNPage.tunnelsTab.disable')}
                              </Button>
                            ) : null}
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-destructive hover:text-destructive"
                              onClick={() => {
                                if (confirm(t('VPNPage.tunnelsTab.teardownConfirm', { siteA: siteA?.name || t('VPNPage.tunnelsTab.siteA'), siteB: siteB?.name || t('VPNPage.tunnelsTab.siteB') }))) {
                                  teardownMutation.mutate(tunnel.id);
                                }
                              }}
                              disabled={isActionPending}
                              aria-label={t('VPNPage.tunnelsTab.teardownAria')}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        {tunnel.provisioned_at && (
                          <div className="mt-2 text-xs text-muted-foreground">
                            {t('VPNPage.tunnelsTab.provisioned', { date: new Date(tunnel.provisioned_at).toLocaleString() })}
                            {tunnel.last_health_check && (
                              <> &middot; {t('VPNPage.tunnelsTab.lastCheck', { date: new Date(tunnel.last_health_check).toLocaleString() })}</>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            ) : (
              <Card className="p-12">
                <div className="flex flex-col items-center justify-center text-center">
                  <Route className="h-12 w-12 text-muted-foreground/50 mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNPage.tunnelsTab.emptyTitle')}</h3>
                  <p className="text-muted-foreground max-w-md">
                    {t('VPNPage.tunnelsTab.emptyDescription')}
                  </p>
                </div>
              </Card>
            )}
          </div>
              </div>
            ),
          },
          {
            value: 'topology',
            label: t('VPNPage.tabs.topology'),
            content: (
              <div className="space-y-4">
          <Suspense fallback={<Skeleton className="h-96" />}>
            <VPNTopologyTab />
          </Suspense>
              </div>
            ),
          },
          {
            value: 'conflicts',
            label: t('VPNPage.tabs.conflicts'),
            content: (
              <div className="space-y-6">
          {conflictsLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
          ) : conflictsError ? (
            <Card className="border-destructive/50 bg-destructive/5 p-6">
              <div className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-5 w-5" />
                <span className="font-medium">{t('VPNPage.conflictsTab.loadError')}</span>
              </div>
            </Card>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <h3 className="text-lg font-semibold">{t('VPNPage.conflictsTab.heading')}</h3>
                  {conflictsData && (
                    <Badge variant="outline" className="text-xs">
                      {t('VPNPage.conflictsTab.sourcesScanned', { count: conflictsData.scanned_sources })}
                    </Badge>
                  )}
                </div>
              </div>

              {!conflictsData?.conflicts?.length ? (
                <Card className="border-success/30 bg-success/5 p-6">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="h-6 w-6 text-success" />
                    <div>
                      <h4 className="font-medium text-success">{t('VPNPage.conflictsTab.noConflictsTitle')}</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        {t('VPNPage.conflictsTab.noConflictsDescription')}
                      </p>
                    </div>
                  </div>
                </Card>
              ) : (
                <DataTable<VPNRouteConflict>
                  data={conflictsData.conflicts}
                  columns={[
                    { id: 'subnet', header: t('VPNPage.conflictsTab.colSubnet'), accessorKey: 'subnet' },
                    { id: 'source_a', header: t('VPNPage.conflictsTab.colSourceA'), accessorKey: 'source_a' },
                    { id: 'source_b', header: t('VPNPage.conflictsTab.colSourceB'), accessorKey: 'source_b' },
                    {
                      id: 'severity',
                      header: t('VPNPage.conflictsTab.colSeverity'),
                      accessorKey: 'severity',
                      cell: (row: VPNRouteConflict) => (
                        <Badge className={row.severity === 'error'
                          ? 'bg-destructive/10 text-destructive border-destructive/20'
                          : 'bg-warning/10 text-warning border-warning/20'
                        }>
                          {row.severity}
                        </Badge>
                      ),
                    },
                    {
                      id: 'overlap_type',
                      header: t('VPNPage.conflictsTab.colOverlapType'),
                      accessorKey: 'overlap_type',
                      cell: (row: VPNRouteConflict) => (
                        <Badge variant="outline">{row.overlap_type}</Badge>
                      ),
                    },
                  ]}
                />
              )}
            </div>
          )}
              </div>
            ),
          },
          {
            value: 'certificates',
            label: t('VPNPage.tabs.certificates'),
            content: (
              <div className="space-y-6">
          {certsLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
          ) : certsError ? (
            <Card className="border-destructive/50 bg-destructive/5 p-6">
              <div className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-5 w-5" />
                <span className="font-medium">{t('VPNPage.certsTab.loadError')}</span>
              </div>
            </Card>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">{t('VPNPage.certsTab.heading')}</h3>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => certScanMutation.mutate()}
                  disabled={certScanMutation.isPending}
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${certScanMutation.isPending ? 'animate-spin' : ''}`} />
                  {certScanMutation.isPending ? t('VPNPage.certsTab.scanning') : t('VPNPage.certsTab.scanCertificates')}
                </Button>
              </div>

              {!certsData?.certs?.length ? (
                <Card className="p-12">
                  <div className="flex flex-col items-center justify-center text-center">
                    <Lock className="h-12 w-12 text-muted-foreground/50 mb-4" />
                    <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNPage.certsTab.emptyTitle')}</h3>
                    <p className="text-muted-foreground max-w-md">
                      {t('VPNPage.certsTab.emptyDescription')}
                    </p>
                  </div>
                </Card>
              ) : (
                <DataTable<VPNCertExpiry>
                  data={certsData.certs}
                  columns={[
                    { id: 'site_name', header: t('VPNPage.certsTab.colSite'), accessorFn: (row: VPNCertExpiry) => row.site_name || '-' },
                    { id: 'vpn_type', header: t('VPNPage.certsTab.colVpnType'), accessorKey: 'vpn_type' },
                    { id: 'cert_subject', header: t('VPNPage.certsTab.colSubject'), accessorFn: (row: VPNCertExpiry) => row.cert_subject || '-' },
                    {
                      id: 'expires_at',
                      header: t('VPNPage.certsTab.colExpiresAt'),
                      accessorKey: 'expires_at',
                      cell: (row: VPNCertExpiry) => new Date(row.expires_at).toLocaleDateString(),
                    },
                    {
                      id: 'days_remaining',
                      header: t('VPNPage.certsTab.colDaysRemaining'),
                      accessorKey: 'days_remaining',
                      cell: (row: VPNCertExpiry) => (
                        <span className={row.days_remaining <= 7 ? 'text-destructive font-semibold' : row.days_remaining <= 30 ? 'text-warning font-medium' : ''}>
                          {row.days_remaining}
                        </span>
                      ),
                    },
                    {
                      id: 'severity',
                      header: t('VPNPage.certsTab.colSeverity'),
                      accessorKey: 'severity',
                      cell: (row: VPNCertExpiry) => {
                        const severityColors: Record<string, string> = {
                          info: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
                          warning: 'bg-warning/10 text-warning border-warning/20',
                          error: 'bg-destructive/10 text-destructive border-destructive/20',
                          critical: 'bg-destructive/10 text-destructive border-destructive/20 font-bold',
                        };
                        return (
                          <Badge className={severityColors[row.severity] || ''}>
                            {row.severity}
                          </Badge>
                        );
                      },
                    },
                  ] as DataTableColumn<VPNCertExpiry>[]}
                />
              )}
            </div>
          )}
              </div>
            ),
          },
        ] satisfies PageTab[]}
      />

      {/* ── Dialogs ── */}

      <ConnectionFormDialog
        open={connectionFormOpen}
        onOpenChange={setConnectionFormOpen}
        connection={editingConnection}
      />

      <DeleteConnectionDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        connection={deletingConnection}
      />

      {selectedSite && (
        <SiteVPNConfigDialog
          key={selectedSite.id}
          open={configDialogOpen}
          onOpenChange={setConfigDialogOpen}
          site={selectedSite}
        />
      )}

      <CreateTemplateDialog
        open={createTemplateOpen}
        onOpenChange={setCreateTemplateOpen}
      />
    </div>
  );
}
