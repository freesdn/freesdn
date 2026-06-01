// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Network Discovery Page
 *
 * Interactive VoIP device discovery with:
 * - CIDR subnet validation + common subnet presets
 * - Start / Stop (cancel) scan controls
 * - Live progress bar per scan phase (ARP → HTTP → SIP)
 * - Real-time device feed as devices are found
 * - Activity log with timestamped scan events
 * - Scan history with results drill-down & delete
 * - Toast notifications for all mutations
 * - Back navigation to VoIP dashboard
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { isValid } from 'date-fns';
import {
  Radar, Play, RefreshCw, ArrowLeft,
  Network, Upload, Eye, Monitor, CheckCircle2,
  Clock, Terminal, Phone,
  Signal, Globe, XCircle,
  ChevronRight, StopCircle, Trash2, ChevronDown,
  Lock, Unlock, PhoneCall, AlertTriangle,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  Dialog, DialogContent, DialogDescription,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useToastHelpers } from '@/components/ui/toast';
import { voipApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { ScanStatusBadge, VendorLabel, formatTimeAgo } from './components';
import type { DiscoveryScan, DiscoveredDevice, ScanStatusResponse } from './types';

// ─── Phase configuration for visual display ─────────────────────────────────

const PHASE_STEPS = [
  { key: 'init', labelKey: 'phases.init', icon: Radar, range: [0, 5] },
  { key: 'arp', labelKey: 'phases.arp', icon: Network, range: [5, 30] },
  { key: 'http', labelKey: 'phases.http', icon: Globe, range: [30, 60] },
  { key: 'sip', labelKey: 'phases.sip', icon: Signal, range: [60, 90] },
  { key: 'complete', labelKey: 'phases.complete', icon: CheckCircle2, range: [90, 100] },
] as const;

// ─── Common subnet presets ───────────────────────────────────────────────────

const SUBNET_PRESETS = [
  { label: '192.168.1.0/24', descKey: 'subnetPresets.classC254' },
  { label: '192.168.0.0/24', descKey: 'subnetPresets.classC254' },
  { label: '10.0.0.0/24', descKey: 'subnetPresets.classAPrivate254' },
  { label: '10.0.1.0/24', descKey: 'subnetPresets.classAPrivate254' },
  { label: '172.16.0.0/24', descKey: 'subnetPresets.classBPrivate254' },
  { label: '192.168.10.0/24', descKey: 'subnetPresets.classC254' },
  { label: '10.10.10.0/24', descKey: 'subnetPresets.commonVoipVlan' },
  { label: '192.168.1.0/16', descKey: 'subnetPresets.largeSweep65k' },
];

// ─── CIDR validation ─────────────────────────────────────────────────────────

const CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

function validateSubnet(value: string, t: (key: string) => string): string | null {
  if (!value) return t('VoipDiscoveryPage.validation.required');
  if (!CIDR_REGEX.test(value.trim())) return t('VoipDiscoveryPage.validation.invalidCidr');

  const [ip, prefixStr] = value.trim().split('/');
  const prefix = parseInt(prefixStr, 10);

  if (prefix < 16 || prefix > 32) return t('VoipDiscoveryPage.validation.prefixRange');

  const octets = ip.split('.').map(Number);
  if (octets.some((o) => o < 0 || o > 255 || isNaN(o))) return t('VoipDiscoveryPage.validation.invalidOctets');

  return null; // valid
}

function getActivePhaseIndex(phase: string): number {
  if (!phase || phase === 'starting' || phase === 'init') return 0;
  if (phase.startsWith('arp')) return 1;
  if (phase.startsWith('http')) return 2;
  if (phase.startsWith('sip')) return 3;
  if (phase === 'complete' || phase === 'done') return 4;
  if (phase === 'error') return -1;
  return 0;
}

// ─── Live timer hook ─────────────────────────────────────────────────────────

function useElapsedTimer(startedAt: string | null | undefined, isActive: boolean) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!startedAt || !isActive) return;
    const start = new Date(startedAt).getTime();
    const tick = () => setElapsed(Math.floor((Date.now() - start) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt, isActive]);
  return elapsed;
}

function formatElapsed(s: number): string {
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

// ═════════════════════════════════════════════════════════════════════════════
// Main Component
// ═════════════════════════════════════════════════════════════════════════════

export default function DiscoveryPage() {
  const { t } = useTranslation('voip');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const logEndRef = useRef<HTMLDivElement>(null);
  const toast = useToastHelpers();

  // ── State ──
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [showResultsDialog, setShowResultsDialog] = useState(false);
  const [selectedScan, setSelectedScan] = useState<DiscoveryScan | null>(null);
  const [showScanForm, setShowScanForm] = useState(false);
  const [subnetError, setSubnetError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DiscoveryScan | null>(null);

  const [scanForm, setScanForm] = useState({
    subnet: '192.168.1.0/24',
    scan_type: 'full',
    auto_onboard: false,
    default_template_id: '',
    use_credentials: false,
    cred_username: 'admin',
    cred_password: '',
  });

  // ── Queries ──

  // Scan history
  const { data: scansRes, isLoading: scansLoading, isError: scansError, refetch: refetchScans } = useQuery({
    queryKey: ['voip-discovery-scans'],
    queryFn: () => voipApi.getDiscoveryScans({ limit: 50 }),
    refetchInterval: activeScanId ? 5_000 : 15_000,
  });
  const scans: DiscoveryScan[] = useMemo(() => scansRes?.data?.items ?? [], [scansRes?.data?.items]);

  // Live progress poll · only when a scan is active
  const { data: statusRes } = useQuery({
    queryKey: ['voip-discovery-status', activeScanId],
    queryFn: () => voipApi.getDiscoveryScanStatus(activeScanId!),
    enabled: !!activeScanId,
    refetchInterval: 1_500,
  });
  const liveStatus: ScanStatusResponse | undefined = statusRes?.data;

  // Auto-detect running scan on mount
  useEffect(() => {
    const running = scans.find((s) => s.status === 'running' || s.status === 'pending');
    if (running && !activeScanId) {
      setActiveScanId(running.id);
    }
  }, [scans, activeScanId]);

  // Clear active scan when it completes / fails / is cancelled
  useEffect(() => {
    if (liveStatus && (liveStatus.status === 'completed' || liveStatus.status === 'failed' || liveStatus.status === 'cancelled')) {
      const timer = setTimeout(() => {
        setActiveScanId(null);
        queryClient.invalidateQueries({ queryKey: ['voip-discovery-scans'] });
      }, 3000);
      return () => clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveStatus?.status, queryClient]);

  // Auto-scroll activity log
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [liveStatus?.progress?.log?.length]);

  // Scan detail for results dialog
  const { data: scanDetailRes, isLoading: detailLoading } = useQuery({
    queryKey: ['voip-discovery-scan', selectedScan?.id],
    queryFn: () => voipApi.getDiscoveryScan(selectedScan!.id),
    enabled: !!selectedScan?.id && showResultsDialog,
  });
  const scanDetail: DiscoveryScan | undefined = scanDetailRes?.data;

  // Templates for auto-onboard
  const { data: templatesRes } = useQuery({
    queryKey: ['voip-templates-list'],
    queryFn: () => voipApi.getTemplates({ limit: 100 }),
    staleTime: 60_000,
  });
  const templates = templatesRes?.data?.items ?? [];

  // ── Mutations ──

  const triggerScanMutation = useMutation({
    mutationFn: (data: any) => voipApi.triggerDiscoveryScan(data),
    onSuccess: (res) => {
      const scanId = res?.data?.scan_id;
      if (scanId) setActiveScanId(scanId);
      queryClient.invalidateQueries({ queryKey: ['voip-discovery-scans'] });
      setShowScanForm(false);
      toast.success(
        t('VoipDiscoveryPage.toast.scanStarted.title'),
        t('VoipDiscoveryPage.toast.scanStarted.message', { subnet: scanForm.subnet || t('VoipDiscoveryPage.toast.scanStarted.autoDetect') }),
      );
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      const msg = Array.isArray(detail)
        ? detail.map((d: any) => d.msg || d).join('; ')
        : detail || t('VoipDiscoveryPage.toast.scanFailed.fallback');
      toast.error(t('VoipDiscoveryPage.toast.scanFailed.title'), msg);
    },
  });

  const cancelScanMutation = useMutation({
    mutationFn: (scanId: string) => voipApi.cancelDiscoveryScan(scanId),
    onSuccess: () => {
      setActiveScanId(null);
      queryClient.invalidateQueries({ queryKey: ['voip-discovery-scans'] });
      toast.warning(t('VoipDiscoveryPage.toast.scanCancelled.title'), t('VoipDiscoveryPage.toast.scanCancelled.message'));
    },
    onError: (err: any) => {
      toast.error(t('VoipDiscoveryPage.toast.cancelFailed.title'), err?.response?.data?.detail || t('VoipDiscoveryPage.toast.cancelFailed.fallback'));
    },
  });

  const deleteScanMutation = useMutation({
    mutationFn: (scanId: string) => voipApi.deleteDiscoveryScan(scanId),
    onSuccess: () => {
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: ['voip-discovery-scans'] });
      toast.success(t('VoipDiscoveryPage.toast.scanDeleted.title'), t('VoipDiscoveryPage.toast.scanDeleted.message'));
    },
    onError: (err: any) => {
      setDeleteTarget(null);
      toast.error(t('VoipDiscoveryPage.toast.deleteFailed.title'), err?.response?.data?.detail || t('VoipDiscoveryPage.toast.deleteFailed.fallback'));
    },
  });

  // ── Handlers ──

  const handleSubnetChange = useCallback((value: string) => {
    setScanForm((prev) => ({ ...prev, subnet: value }));
    if (subnetError) setSubnetError(null);
  }, [subnetError]);

  const handleStartScan = useCallback(() => {
    const error = validateSubnet(scanForm.subnet, t);
    if (error) {
      setSubnetError(error);
      return;
    }
    setSubnetError(null);
    const payload: any = {
      subnet: scanForm.subnet,
      scan_type: scanForm.scan_type,
      auto_onboard: scanForm.auto_onboard,
      default_template_id: scanForm.default_template_id || undefined,
    };
    if (scanForm.use_credentials) {
      payload.credentials = {
        username: scanForm.cred_username || 'admin',
        password: scanForm.cred_password || 'admin',
      };
    }
    triggerScanMutation.mutate(payload);
  }, [scanForm, triggerScanMutation, t]);

  // ── Derived state ──

  const progress = liveStatus?.progress;
  const isScanning = !!activeScanId && liveStatus?.status !== 'completed' && liveStatus?.status !== 'failed' && liveStatus?.status !== 'cancelled';
  const elapsed = useElapsedTimer(liveStatus?.started_at, isScanning);
  const activePhaseIdx = getActivePhaseIndex(progress?.phase ?? '');
  const liveDevices = progress?.devices ?? [];
  const runningScans = scans.filter((s) => s.status === 'running').length;
  const totalDevicesFound = scans.reduce((sum, s) => sum + (s.devices_found ?? 0), 0);

  // ── Scan Table Columns ──

  const scanColumns: DataTableColumn<DiscoveryScan>[] = [
    {
      id: 'status',
      header: t('VoipDiscoveryPage.columns.status'),
      cell: (row) => <ScanStatusBadge status={row.status} />,
    },
    {
      id: 'subnet',
      header: t('VoipDiscoveryPage.columns.subnet'),
      cell: (row) => <span className="font-mono text-sm">{row.subnet}</span>,
    },
    {
      id: 'scan_type',
      header: t('VoipDiscoveryPage.columns.type'),
      cell: (row) => <Badge variant="outline">{row.scan_type?.toUpperCase()}</Badge>,
    },
    {
      id: 'devices_found',
      header: t('VoipDiscoveryPage.columns.devices'),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <span className="font-semibold">{row.devices_found ?? 0}</span>
          {(row as any).new_devices != null && (row as any).new_devices > 0 && (
            <Badge variant="secondary" className="text-xs">{t('VoipDiscoveryPage.newDevicesBadge', { count: (row as any).new_devices })}</Badge>
          )}
        </div>
      ),
    },
    {
      id: 'started_at',
      header: t('VoipDiscoveryPage.columns.started'),
      cell: (row) => <span className="text-sm text-muted-foreground">{formatTimeAgo(row.started_at)}</span>,
    },
    {
      id: 'duration',
      header: t('VoipDiscoveryPage.columns.duration'),
      cell: (row) => {
        if (!row.completed_at || !row.started_at) return <span className="text-sm text-muted-foreground">--</span>;
        const ms = new Date(row.completed_at).getTime() - new Date(row.started_at).getTime();
        return <span className="text-sm">{(ms / 1000).toFixed(1)}s</span>;
      },
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={() => { setSelectedScan(row); setShowResultsDialog(true); }}>
            <Eye className="h-4 w-4 mr-1" /> {t('VoipDiscoveryPage.actions.results')}
          </Button>
          {row.status !== 'running' && row.status !== 'pending' && (
            <Button
              variant="ghost"
              size="sm"
              className="text-destructive hover:text-destructive"
              onClick={() => setDeleteTarget(row)}
              disabled={deleteScanMutation.isPending}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      ),
    },
  ];

  // ── Discovered Devices Columns (inside results dialog) ──

  const deviceColumns: DataTableColumn<DiscoveredDevice>[] = [
    {
      id: 'ip',
      header: t('VoipDiscoveryPage.deviceColumns.ipAddress'),
      cell: (row) => <span className="font-mono text-sm">{row.ip_address || row.ip}</span>,
    },
    {
      id: 'mac',
      header: t('VoipDiscoveryPage.deviceColumns.macAddress'),
      cell: (row) => <span className="font-mono text-sm">{row.mac_address || row.mac || '--'}</span>,
    },
    {
      id: 'vendor',
      header: t('VoipDiscoveryPage.deviceColumns.vendor'),
      cell: (row) => <VendorLabel vendor={row.vendor} />,
    },
    {
      id: 'model',
      header: t('VoipDiscoveryPage.deviceColumns.model'),
      cell: (row) => <span className="text-sm">{row.model || '--'}</span>,
    },
    {
      id: 'method',
      header: t('VoipDiscoveryPage.deviceColumns.method'),
      cell: (row) => {
        const methods = row.methods || (row.discovery_method ? row.discovery_method.split(',') : []);
        return (
          <div className="flex gap-1">
            {methods.map((m: string) => (
              <Badge key={m} variant="outline" className="text-xs">{m}</Badge>
            ))}
          </div>
        );
      },
    },
    {
      id: 'sip',
      header: t('VoipDiscoveryPage.deviceColumns.sipRegistration'),
      cell: (row) => {
        if (!row.sip_registered && !row.sip_account) {
          return <span className="text-sm text-muted-foreground">--</span>;
        }
        return (
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-1">
              <PhoneCall className={cn('h-3.5 w-3.5', row.sip_registered ? 'text-green-500' : 'text-amber-500')} />
              <span className={cn('text-xs font-medium', row.sip_registered ? 'text-green-600' : 'text-amber-600')}>
                {row.sip_registered ? t('VoipDiscoveryPage.sip.registered') : t('VoipDiscoveryPage.sip.configured')}
              </span>
            </div>
            {row.sip_account && (
              <span className="text-xs text-muted-foreground font-mono">{row.sip_account}</span>
            )}
            {row.sip_registrar && (
              <span className="text-xs text-muted-foreground">→ {row.sip_registrar}</span>
            )}
          </div>
        );
      },
    },
    {
      id: 'auth',
      header: t('VoipDiscoveryPage.deviceColumns.auth'),
      cell: (row) => (
        <div className="flex items-center gap-1">
          {row.authenticated ? (
            <><Unlock className="h-3.5 w-3.5 text-green-500" /><span className="text-xs text-green-600">{t('VoipDiscoveryPage.common.yes')}</span></>
          ) : (
            <><Lock className="h-3.5 w-3.5 text-muted-foreground" /><span className="text-xs text-muted-foreground">{t('VoipDiscoveryPage.common.no')}</span></>
          )}
        </div>
      ),
    },
    {
      id: 'is_new',
      header: t('VoipDiscoveryPage.deviceColumns.status'),
      cell: (row) => row.is_new
        ? <Badge className="bg-green-500/20 text-green-600 border-green-500/30">{t('VoipDiscoveryPage.deviceStatus.new')}</Badge>
        : <Badge variant="secondary">{t('VoipDiscoveryPage.deviceStatus.known')}</Badge>,
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => row.is_new ? (
        <Button size="sm" variant="outline" onClick={() => navigate('/voip/phones?action=add')}>
          <Upload className="h-3.5 w-3.5 mr-1" /> {t('VoipDiscoveryPage.actions.onboard')}
        </Button>
      ) : (
        <Button size="sm" variant="ghost" disabled={!row.phone_id} onClick={() => row.phone_id && navigate(`/voip/phones/${row.phone_id}`)}>
          <Eye className="h-3.5 w-3.5 mr-1" /> {t('VoipDiscoveryPage.actions.view')}
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* ── Header with Back Button ── */}
      <PageHeader
        icon={Radar}
        title={t('VoipDiscoveryPage.header.title')}
        description={t('VoipDiscoveryPage.header.subtitle')}
        breadcrumbs={
          <button
            type="button"
            onClick={() => navigate('/voip')}
            aria-label="VoIP"
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            VoIP
          </button>
        }
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => refetchScans()} disabled={scansLoading}>
              <RefreshCw className={cn('h-4 w-4 mr-2', scansLoading && 'animate-spin')} />
              {t('VoipDiscoveryPage.actions.refresh')}
            </Button>
            {!isScanning && (
              <Button onClick={() => setShowScanForm(true)}>
                <Play className="h-4 w-4 mr-2" /> {t('VoipDiscoveryPage.actions.newScan')}
              </Button>
            )}
          </>
        }
      />

      {scansError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('VoipDiscoveryPage.errors.loadFailed')}</span>
          </CardContent>
        </Card>
      )}

      {/* ── Stats Cards ── */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent noOffset className="pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <Radar className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{scans.length}</p>
                <p className="text-xs text-muted-foreground">{t('VoipDiscoveryPage.stats.totalScans')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="pb-3">
            <div className="flex items-center gap-3">
              <div className={cn('p-2 rounded-lg', runningScans > 0 ? 'bg-amber-500/10' : 'bg-muted')}>
                <RefreshCw className={cn('h-5 w-5', runningScans > 0 ? 'text-amber-500 animate-spin' : 'text-muted-foreground')} />
              </div>
              <div>
                <p className="text-2xl font-bold">{runningScans}</p>
                <p className="text-xs text-muted-foreground">{t('VoipDiscoveryPage.stats.runningNow')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/10 rounded-lg">
                <Network className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{totalDevicesFound}</p>
                <p className="text-xs text-muted-foreground">{t('VoipDiscoveryPage.stats.devicesFound')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/10 rounded-lg">
                <Clock className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {isScanning ? formatElapsed(elapsed) : '--'}
                </p>
                <p className="text-xs text-muted-foreground">{t('VoipDiscoveryPage.stats.scanTime')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          LIVE SCAN PANEL (shown when a scan is active)
          ══════════════════════════════════════════════════════════════════════ */}
      {activeScanId && liveStatus && (
        <Card className={cn(
          'border-2 transition-colors',
          isScanning ? 'border-blue-500/40 shadow-lg shadow-blue-500/5' : (
            liveStatus.status === 'completed' ? 'border-green-500/40' :
            liveStatus.status === 'cancelled' ? 'border-amber-500/40' :
            'border-red-500/40'
          ),
        )}>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {isScanning ? (
                  <div className="relative">
                    <Radar className="h-6 w-6 text-blue-500 animate-pulse" />
                    <span className="absolute -top-1 -right-1 h-3 w-3 bg-blue-500 rounded-full animate-ping" />
                  </div>
                ) : liveStatus.status === 'completed' ? (
                  <CheckCircle2 className="h-6 w-6 text-green-500" />
                ) : liveStatus.status === 'cancelled' ? (
                  <StopCircle className="h-6 w-6 text-amber-500" />
                ) : (
                  <XCircle className="h-6 w-6 text-red-500" />
                )}
                <div>
                  <CardTitle className="text-lg">
                    {isScanning ? t('VoipDiscoveryPage.liveScan.inProgress') : (
                      liveStatus.status === 'completed' ? t('VoipDiscoveryPage.liveScan.complete') :
                      liveStatus.status === 'cancelled' ? t('VoipDiscoveryPage.liveScan.cancelled') :
                      t('VoipDiscoveryPage.liveScan.failed')
                    )}
                  </CardTitle>
                  <CardDescription className="mt-0.5">
                    {progress?.message || t('VoipDiscoveryPage.liveScan.initializing')}
                  </CardDescription>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {isScanning && (
                  <Badge variant="outline" className="gap-1 text-blue-500 border-blue-500/30">
                    <Clock className="h-3.5 w-3.5" />
                    {formatElapsed(elapsed)}
                  </Badge>
                )}
                <Badge variant="outline" className="gap-1">
                  <Monitor className="h-3.5 w-3.5" />
                  {t('VoipDiscoveryPage.liveScan.devicesCount', { count: progress?.devices_found ?? 0 })}
                </Badge>
                {isScanning && (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => cancelScanMutation.mutate(activeScanId!)}
                    disabled={cancelScanMutation.isPending}
                  >
                    <StopCircle className="h-4 w-4 mr-1" />
                    {cancelScanMutation.isPending ? t('VoipDiscoveryPage.liveScan.stopping') : t('VoipDiscoveryPage.liveScan.stopScan')}
                  </Button>
                )}
              </div>
            </div>
          </CardHeader>

          <CardContent className="space-y-5">
            {/* ── Phase Progress Bar ── */}
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium">{t('VoipDiscoveryPage.liveScan.overallProgress')}</span>
                <span className="text-muted-foreground font-mono">{progress?.percent ?? 0}%</span>
              </div>
              <Progress
                value={progress?.percent ?? 0}
                className={cn(
                  'h-3',
                  liveStatus.status === 'completed' && '[&>div]:bg-green-500',
                  liveStatus.status === 'failed' && '[&>div]:bg-red-500',
                )}
              />

              {/* Phase Steps */}
              <div className="flex items-center justify-between">
                {PHASE_STEPS.map((step, idx) => {
                  const Icon = step.icon;
                  const isActive = idx === activePhaseIdx;
                  const isComplete = idx < activePhaseIdx || liveStatus.status === 'completed';
                  const isFailed = liveStatus.status === 'failed' && idx <= activePhaseIdx;
                  return (
                    <div key={step.key} className="flex items-center gap-1">
                      <div className={cn(
                        'flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium transition-all',
                        isActive && 'bg-blue-500/10 text-blue-500 ring-1 ring-blue-500/20',
                        isComplete && !isActive && 'text-green-500',
                        isFailed && 'text-red-500',
                        !isActive && !isComplete && !isFailed && 'text-muted-foreground',
                      )}>
                        <Icon className={cn('h-3.5 w-3.5', isActive && 'animate-pulse')} />
                        <span className="hidden sm:inline">{t(`VoipDiscoveryPage.${step.labelKey}`)}</span>
                      </div>
                      {idx < PHASE_STEPS.length - 1 && (
                        <ChevronRight className="h-3 w-3 text-muted-foreground/40 hidden sm:block" />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <Separator />

            {/* ── Two Column: Live Devices + Activity Log ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Live Device Feed */}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Phone className="h-4 w-4 text-muted-foreground" />
                  <h3 className="text-sm font-semibold">{t('VoipDiscoveryPage.liveScan.discoveredDevices')}</h3>
                  <Badge variant="secondary" className="ml-auto text-xs">{liveDevices.length}</Badge>
                </div>
                <ScrollArea className="h-[240px] rounded-md border bg-muted/20">
                  {liveDevices.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full py-12 text-muted-foreground">
                      <Network className="h-8 w-8 mb-2 opacity-40" />
                      <p className="text-sm">{t('VoipDiscoveryPage.liveScan.waitingForDevices')}</p>
                    </div>
                  ) : (
                    <div className="p-2 space-y-1">
                      {liveDevices.map((dev: any, i: number) => (
                        <div
                          key={dev.mac || dev.ip || i}
                          className={cn(
                            'flex items-center justify-between p-2 rounded-md transition-all',
                            i === liveDevices.length - 1 && isScanning
                              ? 'bg-blue-500/5 border border-blue-500/20'
                              : 'bg-background/50 border border-transparent hover:border-border',
                          )}
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="p-1.5 bg-primary/5 rounded">
                              <Monitor className="h-3.5 w-3.5 text-primary" />
                            </div>
                            <div className="min-w-0">
                              <p className="text-sm font-mono truncate">{dev.ip}</p>
                              <p className="text-xs text-muted-foreground font-mono truncate">{dev.mac || t('VoipDiscoveryPage.liveScan.macUnknown')}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <VendorLabel vendor={dev.vendor} />
                            {dev.model && (
                              <Badge variant="outline" className="text-xs">{dev.model}</Badge>
                            )}
                            {dev.sip_registered && (
                              <Badge variant="outline" className="text-xs border-green-500/30 text-green-600">
                                <PhoneCall className="h-3 w-3 mr-0.5" />SIP
                              </Badge>
                            )}
                            {dev.authenticated && (
                              <Unlock className="h-3.5 w-3.5 text-green-500" />
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </div>

              {/* Activity Log */}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Terminal className="h-4 w-4 text-muted-foreground" />
                  <h3 className="text-sm font-semibold">{t('VoipDiscoveryPage.liveScan.activityLog')}</h3>
                  <Badge variant="secondary" className="ml-auto text-xs">
                    {progress?.log?.length ?? 0}
                  </Badge>
                </div>
                <ScrollArea className="h-[240px] rounded-md border bg-zinc-950 dark:bg-zinc-950">
                  {!progress?.log?.length ? (
                    <div className="flex items-center justify-center h-full py-12 text-zinc-500">
                      <p className="text-sm">{t('VoipDiscoveryPage.liveScan.waitingForEvents')}</p>
                    </div>
                  ) : (
                    <div className="p-3 space-y-0.5 font-mono text-xs">
                      {progress.log.map((entry, i) => {
                        const phase = entry.phase ?? '';
                        return (
                        <div key={i} className="flex gap-2 leading-relaxed">
                          <span className="text-zinc-600 shrink-0">
                            {entry.ts && isValid(new Date(entry.ts))
                              ? new Date(entry.ts).toLocaleTimeString('en-US', { hour12: false })
                              : '—'}
                          </span>
                          <span className={cn(
                            phase === 'error' ? 'text-red-400' :
                            phase === 'complete' || phase === 'done' ? 'text-green-400' :
                            phase.includes('done') ? 'text-emerald-400' :
                            phase.includes('start') ? 'text-blue-400' :
                            'text-zinc-300',
                          )}>
                            {entry.message}
                          </span>
                        </div>
                        );
                      })}
                      <div ref={logEndRef} />
                    </div>
                  )}
                </ScrollArea>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          SCAN FORM (inline card, not a dialog)
          ══════════════════════════════════════════════════════════════════════ */}
      {showScanForm && !isScanning && (
        <Card className="border-dashed border-2">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Play className="h-4 w-4" />
              {t('VoipDiscoveryPage.scanForm.title')}
            </CardTitle>
            <CardDescription>
              {t('VoipDiscoveryPage.scanForm.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="space-y-2">
                <Label>{t('VoipDiscoveryPage.scanForm.subnetLabel')}</Label>
                <div className="flex gap-1">
                  <Input
                    placeholder="192.168.1.0/24"
                    value={scanForm.subnet}
                    onChange={(e) => handleSubnetChange(e.target.value)}
                    className={cn('font-mono flex-1', subnetError && 'border-destructive focus-visible:ring-destructive')}
                  />
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="icon" className="shrink-0" title={t('VoipDiscoveryPage.scanForm.commonSubnets')}>
                        <ChevronDown className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-56">
                      {SUBNET_PRESETS.map((preset) => (
                        <DropdownMenuItem
                          key={preset.label}
                          onClick={() => handleSubnetChange(preset.label)}
                        >
                          <div>
                            <p className="font-mono text-sm">{preset.label}</p>
                            <p className="text-xs text-muted-foreground">{t(`VoipDiscoveryPage.${preset.descKey}`)}</p>
                          </div>
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
                {subnetError && (
                  <p className="text-xs text-destructive">{subnetError}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label>{t('VoipDiscoveryPage.scanForm.scanTypeLabel')}</Label>
                <Select value={scanForm.scan_type} onValueChange={(v) => setScanForm({ ...scanForm, scan_type: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="arp">{t('VoipDiscoveryPage.scanTypes.arp')}</SelectItem>
                    <SelectItem value="sip">{t('VoipDiscoveryPage.scanTypes.sip')}</SelectItem>
                    <SelectItem value="http">{t('VoipDiscoveryPage.scanTypes.http')}</SelectItem>
                    <SelectItem value="full">{t('VoipDiscoveryPage.scanTypes.full')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t('VoipDiscoveryPage.scanForm.autoOnboardLabel')}</Label>
                <div className="flex items-center gap-3 h-10">
                  <Switch
                    checked={scanForm.auto_onboard}
                    onCheckedChange={(v) => setScanForm({ ...scanForm, auto_onboard: v })}
                  />
                  <span className="text-sm text-muted-foreground">
                    {scanForm.auto_onboard ? t('VoipDiscoveryPage.common.enabled') : t('VoipDiscoveryPage.common.disabled')}
                  </span>
                </div>
              </div>
              {scanForm.auto_onboard && (
                <div className="space-y-2">
                  <Label>{t('VoipDiscoveryPage.scanForm.defaultTemplateLabel')}</Label>
                  <Select
                    value={scanForm.default_template_id}
                    onValueChange={(v) => setScanForm({ ...scanForm, default_template_id: v })}
                  >
                    <SelectTrigger><SelectValue placeholder={t('VoipDiscoveryPage.scanForm.selectTemplatePlaceholder')} /></SelectTrigger>
                    <SelectContent>
                      {templates.map((t: any) => (
                        <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>

            {/* ── Phone Credentials ── */}
            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-3">
                <Switch
                  checked={scanForm.use_credentials}
                  onCheckedChange={(v) => setScanForm({ ...scanForm, use_credentials: v })}
                />
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-muted-foreground" />
                  <Label className="cursor-pointer">{t('VoipDiscoveryPage.credentials.label')}</Label>
                </div>
                <span className="text-xs text-muted-foreground">
                  {scanForm.use_credentials ? t('VoipDiscoveryPage.credentials.custom') : t('VoipDiscoveryPage.credentials.default')}
                </span>
              </div>
              {scanForm.use_credentials && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-12">
                  <div className="space-y-1">
                    <Label className="text-xs">{t('VoipDiscoveryPage.credentials.username')}</Label>
                    <Input
                      placeholder="admin"
                      value={scanForm.cred_username}
                      onChange={(e) => setScanForm({ ...scanForm, cred_username: e.target.value })}
                      autoComplete="off"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">{t('VoipDiscoveryPage.credentials.password')}</Label>
                    <Input
                      type="password"
                      placeholder="admin"
                      value={scanForm.cred_password}
                      onChange={(e) => setScanForm({ ...scanForm, cred_password: e.target.value })}
                      autoComplete="off"
                    />
                  </div>
                </div>
              )}
            </div>
            <div className="flex items-center justify-end gap-2 mt-4">
              <Button variant="outline" onClick={() => setShowScanForm(false)}>{t('VoipDiscoveryPage.common.cancel')}</Button>
              <Button
                onClick={handleStartScan}
                disabled={triggerScanMutation.isPending || !scanForm.subnet}
              >
                <Play className="h-4 w-4 mr-2" />
                {triggerScanMutation.isPending ? t('VoipDiscoveryPage.scanForm.starting') : t('VoipDiscoveryPage.scanForm.startDiscovery')}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          SCAN HISTORY
          ══════════════════════════════════════════════════════════════════════ */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">{t('VoipDiscoveryPage.history.title')}</CardTitle>
              <CardDescription>{t('VoipDiscoveryPage.history.description')}</CardDescription>
            </div>
            {!showScanForm && !isScanning && (
              <Button variant="outline" size="sm" onClick={() => setShowScanForm(true)}>
                <Play className="h-3.5 w-3.5 mr-1" /> {t('VoipDiscoveryPage.actions.newScan')}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <DataTable
            data={scans}
            columns={scanColumns}
            isLoading={scansLoading}
            embedded
            itemName={t('VoipDiscoveryPage.itemName.scans')}
            paginated
            defaultPageSize={10}
            emptyState={
              <div className="flex flex-col items-center gap-3 py-12">
                <Radar className="h-12 w-12 text-muted-foreground/30" />
                <p className="text-muted-foreground">{t('VoipDiscoveryPage.history.empty')}</p>
                <Button onClick={() => setShowScanForm(true)}>
                  <Play className="h-4 w-4 mr-2" /> {t('VoipDiscoveryPage.actions.startFirstScan')}
                </Button>
              </div>
            }
          />
        </CardContent>
      </Card>

      {/* ── Scan Results Dialog ── */}
      <Dialog open={showResultsDialog} onOpenChange={setShowResultsDialog}>
        <DialogContent className="sm:max-w-[900px] max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('VoipDiscoveryPage.resultsDialog.title')}</DialogTitle>
            <DialogDescription>
              {selectedScan && (
                <>
                  {selectedScan.subnet} · {selectedScan.scan_type?.toUpperCase()} ·{' '}
                  {t('VoipDiscoveryPage.resultsDialog.devicesFound', { count: selectedScan.devices_found ?? 0 })}
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          {detailLoading ? (
            <div className="flex items-center justify-center h-32">
              <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : scanDetail?.results?.length || scanDetail?.discovered_devices?.length ? (
            <DataTable
              data={scanDetail.discovered_devices || scanDetail.results || []}
              columns={deviceColumns}
              itemName={t('VoipDiscoveryPage.itemName.devices')}
              paginated
              defaultPageSize={10}
            />
          ) : (
            <p className="text-center text-muted-foreground py-8">{t('VoipDiscoveryPage.resultsDialog.empty')}</p>
          )}
        </DialogContent>
      </Dialog>

      {/* ── Delete Confirmation Dialog ── */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('VoipDiscoveryPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('VoipDiscoveryPage.deleteDialog.descriptionBefore')}{' '}
              <span className="font-mono font-semibold">{deleteTarget?.subnet}</span>{' '}
              {t('VoipDiscoveryPage.deleteDialog.descriptionAfter')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('VoipDiscoveryPage.common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteTarget && deleteScanMutation.mutate(deleteTarget.id)}
            >
              {deleteScanMutation.isPending ? t('VoipDiscoveryPage.deleteDialog.deleting') : t('VoipDiscoveryPage.common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
