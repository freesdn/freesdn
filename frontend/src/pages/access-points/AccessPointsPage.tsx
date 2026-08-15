/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React, { useState, useMemo, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { useToast } from '@/hooks/use-toast';
import {
  Wifi,
  Signal,
  RefreshCw,
  MoreVertical,
  Settings,
  Radio,
  Users,
  Locate,
  Edit,
  Trash2,
  ArrowUpCircle,
  Clock,
  Lightbulb,
  LightbulbOff,
  Globe,
  CheckCircle,
  WifiOff,
  Eye,
  Smartphone,
  RotateCw,
  Shield,
  MapPin,
  BarChart3,
  ShieldAlert,
  Sliders,
  Satellite,
  ArrowLeft,
  type LucideIcon,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { EmptyState, ErrorState, NoResultsState } from '@/components/ui/empty-state';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
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
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

import { accessPointsApi } from '@/lib/api';
import { controllersApi } from '@/lib/api/controllers';
import type {
  AccessPointSummary,
  AccessPointDetail,
  APRadio,
  APClient,
} from '@/lib/api';

// ─── Helper Functions ────────────────────────────────────────────────────────

const formatUptime = (seconds: number) => {
  if (!seconds) return '-';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
};

const formatBytes = (bytes: number) => {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  if (bytes < 1024 * 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  return (bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2) + ' TB';
};

const getStatusColor = (status: string) => {
  switch (status?.toLowerCase()) {
    case 'online': return 'bg-green-500';
    case 'offline': return 'bg-red-500';
    case 'adopting': return 'bg-yellow-500';
    case 'provisioning': return 'bg-blue-500';
    case 'degraded': return 'bg-orange-500';
    default: return 'bg-muted-foreground';
  }
};

const getStatusBadgeVariant = (status: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
  switch (status?.toLowerCase()) {
    case 'online': return 'default';
    case 'offline': return 'destructive';
    default: return 'secondary';
  }
};

/**
 * Normalize any band identifier (human label, hyphenated `5g-2`, mixed case)
 * to the canonical Omada radio code the apply/channel-list path expects.
 * Producers historically emit inconsistent codes (e.g. `5g-2` vs `5g2`, or the
 * human label `2.4 GHz` from the list-summary fallback), so we canonicalize on
 * read before keying the channel dropdown or PATCHing `/radios/{band}`.
 */
const RADIO_BAND_ALIASES: Record<string, string> = {
  '2g': '2g',
  '2.4g': '2g',
  '2.4 ghz': '2g',
  '2.4ghz': '2g',
  '5g': '5g',
  '5 ghz': '5g',
  '5ghz': '5g',
  '5g2': '5g2',
  '5g-2': '5g2',
  '5g_2': '5g2',
  '5 ghz-2': '5g2',
  '5ghz-2': '5g2',
  '6g': '6g',
  '6 ghz': '6g',
  '6ghz': '6g',
};

const getCanonicalBand = (band: string): string =>
  RADIO_BAND_ALIASES[String(band ?? '').trim().toLowerCase()] ?? band;

// Selectable channels per canonical band (UNII / DFS sets common to Omada APs).
const RADIO_CHANNELS: Record<string, number[]> = {
  '2g': [1, 6, 11],
  '5g': [36, 40, 44, 48, 149, 153, 157, 161, 165],
  // Second 5 GHz radio, DFS/UNII-2 set distinct from the primary 5 GHz radio.
  '5g2': [52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140],
  // 6 GHz UNII-5/6/7 PSC channels.
  '6g': [37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213],
};

const getBandLabel = (band: string) => {
  switch (getCanonicalBand(band)) {
    case '2g': return '2.4 GHz';
    case '5g': return '5 GHz';
    case '5g2': return '5 GHz-2';
    case '6g': return '6 GHz';
    default: return band;
  }
};

const getChannelWidthLabel = (width: number, _band?: string) => {
  // Omada uses internal codes: 0=20MHz, 1=40MHz, 2=20/40MHz, 3=80MHz, 4=20/40MHz(2.4G), 5=160MHz, 6=80/160MHz
  const widthMap: Record<number, string> = {
    0: '20 MHz',
    1: '40 MHz',
    2: '20/40 MHz',
    3: '80 MHz',
    4: '20/40 MHz',
    5: '160 MHz',
    6: '80/160 MHz',
    7: '320 MHz',
  };
  return widthMap[width] || `${width}`;
};

const getSecurityLabel = (security: number) => {
  const map: Record<number, string> = {
    0: 'Open',
    1: 'WEP',
    2: 'WPA',
    3: 'WPA2/WPA3',
    4: 'WPA3',
    5: 'WPA2 Enterprise',
    6: 'WPA3 Enterprise',
  };
  return map[security] || 'Unknown';
};

const getBandIcon = (band: string): LucideIcon => {
  switch (getCanonicalBand(band)) {
    case '2g':
      return Radio;
    case '5g':
    case '5g2':
      return Wifi;
    case '6g':
      return Satellite;
    default:
      return Signal;
  }
};

/** Inline band icon for use alongside band labels (h-3.5 with right margin for label spacing). */
function BandIcon({ band, className }: { band: string; className?: string }) {
  const Icon = getBandIcon(band);
  return <Icon className={className ?? 'inline h-3.5 w-3.5 mr-1'} aria-hidden="true" />;
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function AccessPointsPage() {
  const { t } = useTranslation('accessPoints');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { deviceId: deviceIdFromUrl, tab: tabFromUrl } = useParams<{ deviceId?: string; tab?: string }>();
  const navigate = useNavigate();
  const [selectedAP, setSelectedAP] = useState<AccessPointSummary | null>(null);
  const [activeTab, setActiveTab] = useState(tabFromUrl || 'overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [siteFilter, setSiteFilter] = useState<string>('all');

  const selectAP = useCallback((ap: AccessPointSummary | null) => {
    setSelectedAP(ap);
    if (ap) {
      navigate(`/access-points/${ap.id}/${activeTab}`, { replace: true });
    } else {
      navigate('/access-points', { replace: true });
      setActiveTab('overview');
    }
  }, [navigate, activeTab]);

  const switchTab = useCallback((tab: string) => {
    setActiveTab(tab);
    if (selectedAP) {
      navigate(`/access-points/${selectedAP.id}/${tab}`, { replace: true });
    }
  }, [selectedAP, navigate]);

  // Dialogs
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [renameName, setRenameName] = useState('');
  const [radioDialogOpen, setRadioDialogOpen] = useState(false);
  const [editingRadio, setEditingRadio] = useState<APRadio | null>(null);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{ action: string; apId: string; apName: string } | null>(null);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Data Fetching ────────────────────────────────────────────────────────

  const {
    data: accessPoints,
    isLoading: apLoading,
    isError: apError,
    refetch: refetchAPs,
  } = useQuery({
    queryKey: ['access-points', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await accessPointsApi.listAccessPoints({ ...(selectedSiteId ? { site_id: selectedSiteId } : {}), per_page: 200 });
      return response.data.items;
    },
    staleTime: 30000,
  });

  // Resolve /:deviceId from URL once AP list loads
  useEffect(() => {
    if (!accessPoints || !deviceIdFromUrl) return;
    if (selectedAP?.id === deviceIdFromUrl) return;
    const match = accessPoints.find((ap) => ap.id === deviceIdFromUrl);
    if (match) {
      setSelectedAP(match);
    }
  }, [accessPoints, deviceIdFromUrl, selectedAP?.id]);

  // Sync active tab from URL
  useEffect(() => {
    if (tabFromUrl && tabFromUrl !== activeTab) {
      setActiveTab(tabFromUrl);
    }
  }, [tabFromUrl, activeTab]);

  const {
    data: apDetail,
  } = useQuery({
    queryKey: ['access-point-detail', selectedAP?.id],
    queryFn: async () => {
      if (!selectedAP) return null;
      const response = await accessPointsApi.getAccessPoint(selectedAP.id);
      return response.data;
    },
    enabled: !!selectedAP,
    staleTime: 15000,
  });

  const {
    data: apClients,
    isLoading: clientsLoading,
  } = useQuery({
    queryKey: ['access-point-clients', selectedAP?.id],
    queryFn: async () => {
      if (!selectedAP) return [];
      const response = await accessPointsApi.getClients(selectedAP.id);
      return response.data;
    },
    enabled: !!selectedAP && activeTab === 'clients',
    staleTime: 15000,
  });

  // Derive controller ID from selected AP or first AP in list
  const controllerId = selectedAP?.controller_id || accessPoints?.[0]?.controller_id || null;

  const {
    data: channelUtilization,
    isLoading: channelUtilLoading,
    isError: channelUtilError,
    refetch: refetchChannelUtil,
  } = useQuery({
    queryKey: ['wifi-channel-util', controllerId],
    queryFn: async () => {
      if (!controllerId) return [];
      const response = await controllersApi.getChannelUtilization(controllerId);
      return response.data;
    },
    enabled: !!controllerId && activeTab === 'rf-health',
    staleTime: 15000,
  });

  const {
    data: rogueAps,
    isLoading: rogueLoading,
    isError: rogueError,
    refetch: refetchRogueAps,
  } = useQuery({
    queryKey: ['wifi-rogue-aps', controllerId],
    queryFn: async () => {
      if (!controllerId) return [];
      const response = await controllersApi.getRogueAps(controllerId);
      return response.data;
    },
    enabled: !!controllerId && activeTab === 'rogue-aps',
    staleTime: 30000,
  });

  const {
    data: radioSettings,
    isLoading: radioSettingsLoading,
    isError: radioSettingsError,
    refetch: refetchRadioSettings,
  } = useQuery({
    queryKey: ['wifi-radio-settings', controllerId],
    queryFn: async () => {
      if (!controllerId) return null;
      const response = await controllersApi.getRadioSettings(controllerId);
      return response.data;
    },
    enabled: !!controllerId && activeTab === 'radio-settings',
    staleTime: 30000,
  });

  // ── Mutations ────────────────────────────────────────────────────────────

  const mutationErrorHandler = (err: any) => {
    toast({ title: t('AccessPointsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AccessPointsPage.toast.operationFailed'), variant: "destructive" });
  };

  const rebootMutation = useMutation({
    mutationFn: (apId: string) => accessPointsApi.reboot(apId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-points'] });
      queryClient.invalidateQueries({ queryKey: ['access-point-detail'] });
    },
    onError: mutationErrorHandler,
  });

  const locateMutation = useMutation({
    mutationFn: (apId: string) => accessPointsApi.locate(apId),
    onError: mutationErrorHandler,
  });

  const ledMutation = useMutation({
    mutationFn: ({ apId, enabled }: { apId: string; enabled: boolean }) =>
      accessPointsApi.setLed(apId, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-point-detail'] });
    },
    onError: mutationErrorHandler,
  });

  const meshMutation = useMutation({
    mutationFn: ({ apId, enabled }: { apId: string; enabled: boolean }) =>
      accessPointsApi.setMesh(apId, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-point-detail'] });
    },
    onError: mutationErrorHandler,
  });

  const renameMutation = useMutation({
    mutationFn: ({ apId, name }: { apId: string; name: string }) =>
      accessPointsApi.rename(apId, name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-points'] });
      queryClient.invalidateQueries({ queryKey: ['access-point-detail'] });
      setRenameDialogOpen(false);
    },
    onError: mutationErrorHandler,
  });

  const upgradeMutation = useMutation({
    mutationFn: (apId: string) => accessPointsApi.upgrade(apId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-points'] });
    },
    onError: mutationErrorHandler,
  });

  const adoptMutation = useMutation({
    mutationFn: (apId: string) => accessPointsApi.adopt(apId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-points'] });
    },
    onError: mutationErrorHandler,
  });

  const forgetMutation = useMutation({
    mutationFn: (apId: string) => accessPointsApi.forget(apId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-points'] });
      selectAP(null);
    },
    onError: mutationErrorHandler,
  });

  const updateRadioMutation = useMutation({
    mutationFn: ({ apId, band, data }: { apId: string; band: string; data: Partial<APRadio> }) =>
      accessPointsApi.updateRadio(apId, band, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-point-detail'] });
      setRadioDialogOpen(false);
    },
    onError: mutationErrorHandler,
  });

  const radioSettingsMutation = useMutation({
    mutationFn: (data: Record<string, any>) => controllersApi.updateRadioSettings(controllerId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wifi-radio-settings', controllerId] });
      toast({ title: t('AccessPointsPage.toast.radioSettingsUpdated'), description: t('AccessPointsPage.toast.radioSettingsUpdatedDesc') });
    },
    onError: mutationErrorHandler,
  });
  // radioSettingsMutation is used in the Radio Settings tab for fast roaming toggles

  // ── Filters ──────────────────────────────────────────────────────────────

  // Unique sites for filter dropdown
  const uniqueSites = useMemo(() => {
    if (!accessPoints) return [];
    const sites = new Map<string, string>();
    accessPoints.forEach((ap) => {
      if (ap.site_id && ap.site_name) sites.set(ap.site_id, ap.site_name);
    });
    return Array.from(sites.entries()).map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));
  }, [accessPoints]);

  const filteredAPs = useMemo(() => {
    if (!accessPoints) return [];
    return accessPoints.filter((ap) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (
          !(ap.name ?? '').toLowerCase().includes(q) &&
          !(ap.model ?? '').toLowerCase().includes(q) &&
          !(ap.mac_address ?? '').toLowerCase().includes(q) &&
          !(ap.ip_address ?? '').toLowerCase().includes(q) &&
          !(ap.site_name || '').toLowerCase().includes(q)
        ) return false;
      }
      if (statusFilter !== 'all' && ap.status !== statusFilter) return false;
      if (siteFilter !== 'all' && ap.site_id !== siteFilter) return false;
      return true;
    });
  }, [accessPoints, searchQuery, statusFilter, siteFilter]);

  // ── Summary Stats ────────────────────────────────────────────────────────

  const stats = useMemo(() => {
    if (!accessPoints) return { total: 0, online: 0, offline: 0, clients: 0 };
    return {
      total: accessPoints.length,
      online: accessPoints.filter(a => a.status === 'online').length,
      offline: accessPoints.filter(a => a.status === 'offline').length,
      clients: accessPoints.reduce((sum, a) => sum + (a.clients || 0), 0),
    };
  }, [accessPoints]);

  // ── CSV Export ───────────────────────────────────────────────────────────

  const handleExport = useCallback(() => {
    if (filteredAPs.length === 0) {
      toast({ title: t('AccessPointsPage.toast.errorTitle'), description: t('AccessPointsPage.list.emptyTitle'), variant: "destructive" });
      return;
    }
    const headers = ['Name', 'Model', 'Vendor', 'MAC Address', 'IP Address', 'Site', 'Status', 'Firmware', 'Clients', 'Uptime (s)', 'CPU %', 'Memory %'];
    const escape = (val: unknown) => {
      const s = val === null || val === undefined ? '' : String(val);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = filteredAPs.map((ap) => [
      ap.name, ap.model, ap.vendor, ap.mac_address, ap.ip_address, ap.site_name,
      ap.status, ap.firmware_version, ap.clients, ap.uptime, ap.cpu_usage, ap.memory_usage,
    ].map(escape).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `access-points-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [filteredAPs, toast, t]);

  // ── Confirm Action Handler ───────────────────────────────────────────────

  const handleConfirmAction = () => {
    if (!confirmAction) return;
    switch (confirmAction.action) {
      case 'reboot':
        rebootMutation.mutate(confirmAction.apId);
        break;
      case 'upgrade':
        upgradeMutation.mutate(confirmAction.apId);
        break;
      case 'forget':
        forgetMutation.mutate(confirmAction.apId);
        break;
    }
    setConfirmDialogOpen(false);
    setConfirmAction(null);
  };

  const openConfirmDialog = (action: string, apId: string, apName: string) => {
    setConfirmAction({ action, apId, apName });
    setConfirmDialogOpen(true);
  };

  // ════════════════════════════════════════════════════════════════════════════
  // AP Detail View
  // ════════════════════════════════════════════════════════════════════════════

  if (selectedAP) {
    const detail = apDetail as AccessPointDetail | null;
    const radios = detail?.radios || selectedAP.radios || [];
    const ssids = detail?.ssid_overrides || [];
    const clients = Array.isArray(apClients) ? apClients : [];

    return (
      <div className="space-y-6">
        {/* Header */}
        <PageHeader
          icon={Wifi}
          title={selectedAP.name}
          description={`${selectedAP.vendor} ${selectedAP.model} • ${selectedAP.mac_address} • ${selectedAP.ip_address}`}
          breadcrumbs={
            <button
              type="button"
              onClick={() => selectAP(null)}
              className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              {t('AccessPointsPage.detail.back')}
            </button>
          }
          actions={
            <>
              <Badge variant={getStatusBadgeVariant(selectedAP.status)}>
                {selectedAP.status}
              </Badge>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  queryClient.invalidateQueries({ queryKey: ['access-point-detail', selectedAP.id] });
                  queryClient.invalidateQueries({ queryKey: ['access-point-clients', selectedAP.id] });
                }}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                {t('AccessPointsPage.detail.refresh')}
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    <MoreVertical className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={() => {
                    setRenameName(selectedAP.name);
                    setRenameDialogOpen(true);
                  }}>
                    <Edit className="mr-2 h-4 w-4" />
                    {t('AccessPointsPage.actions.rename')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => locateMutation.mutate(selectedAP.id)}>
                    <Locate className="mr-2 h-4 w-4" />
                    {t('AccessPointsPage.actions.locateFlashLed')}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => openConfirmDialog('reboot', selectedAP.id, selectedAP.name)}>
                    <RotateCw className="mr-2 h-4 w-4" />
                    {t('AccessPointsPage.actions.reboot')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => openConfirmDialog('upgrade', selectedAP.id, selectedAP.name)}>
                    <ArrowUpCircle className="mr-2 h-4 w-4" />
                    {t('AccessPointsPage.actions.upgradeFirmware')}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="text-destructive"
                    onClick={() => openConfirmDialog('forget', selectedAP.id, selectedAP.name)}
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    {t('AccessPointsPage.actions.forgetDevice')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          }
        />

        {/* Summary Cards */}
        <div className="grid gap-4 md:grid-cols-5">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('AccessPointsPage.summary.clients')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <Users className="h-5 w-5 text-blue-500" />
                <span className="text-2xl font-bold">{detail?.clients ?? selectedAP.clients ?? 0}</span>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('AccessPointsPage.summary.cpuMemory')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <span>{t('AccessPointsPage.summary.cpu')}</span>
                  <span className="font-medium">{detail?.cpu_usage ?? 0}%</span>
                </div>
                <Progress value={detail?.cpu_usage ?? 0} className="h-1.5" />
                <div className="flex items-center justify-between text-sm">
                  <span>{t('AccessPointsPage.summary.mem')}</span>
                  <span className="font-medium">{detail?.memory_usage ?? 0}%</span>
                </div>
                <Progress value={detail?.memory_usage ?? 0} className="h-1.5" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('AccessPointsPage.summary.uptime')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-muted-foreground" />
                <span className="text-xl font-bold">{formatUptime(detail?.uptime ?? 0)}</span>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('AccessPointsPage.summary.radios')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-1.5">
                {radios.map((r) => (
                  <Badge key={r.band} variant="outline" className="text-xs">
                    <BandIcon band={r.band} />{getBandLabel(r.band)}
                  </Badge>
                ))}
                {radios.length === 0 && <span className="text-sm text-muted-foreground">{t('AccessPointsPage.summary.noRadios')}</span>}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('AccessPointsPage.summary.controls')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm">{t('AccessPointsPage.summary.led')}</span>
                  <Switch
                    checked={detail?.led_enabled ?? false}
                    onCheckedChange={(checked) => ledMutation.mutate({ apId: selectedAP.id, enabled: checked })}
                    disabled={ledMutation.isPending}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">{t('AccessPointsPage.summary.mesh')}</span>
                  <Switch
                    checked={detail?.mesh_enabled ?? false}
                    onCheckedChange={(checked) => meshMutation.mutate({ apId: selectedAP.id, enabled: checked })}
                    disabled={meshMutation.isPending}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={switchTab}>
          <TabsList>
            <TabsTrigger value="overview">{t('AccessPointsPage.tabs.overview')}</TabsTrigger>
            <TabsTrigger value="radios">{t('AccessPointsPage.tabs.radios')}</TabsTrigger>
            <TabsTrigger value="ssids">{t('AccessPointsPage.tabs.ssids')}</TabsTrigger>
            <TabsTrigger value="clients">{t('AccessPointsPage.tabs.clients')}</TabsTrigger>
            <TabsTrigger value="config">{t('AccessPointsPage.tabs.configuration')}</TabsTrigger>
            <TabsTrigger value="rf-health">{t('AccessPointsPage.tabs.rfHealth')}</TabsTrigger>
            <TabsTrigger value="rogue-aps">{t('AccessPointsPage.tabs.rogueAps')}</TabsTrigger>
            <TabsTrigger value="radio-settings">{t('AccessPointsPage.tabs.radioSettings')}</TabsTrigger>
          </TabsList>

          {/* ── Overview Tab ─────────────────────────────────────────────── */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              {/* Device Info */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('AccessPointsPage.overview.deviceInformation')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-2 gap-y-3 text-sm">
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.model')}</dt>
                    <dd className="font-medium">{selectedAP.model}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.vendor')}</dt>
                    <dd className="font-medium">{selectedAP.vendor}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.macAddress')}</dt>
                    <dd className="font-mono text-xs">{selectedAP.mac_address}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.ipAddress')}</dt>
                    <dd className="font-mono text-xs">{selectedAP.ip_address}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.serialNumber')}</dt>
                    <dd className="font-mono text-xs">{(detail as AccessPointDetail)?.serial_number || '-'}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.firmware')}</dt>
                    <dd className="font-medium text-xs">{selectedAP.firmware_version || '-'}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.site')}</dt>
                    <dd className="font-medium">{selectedAP.site_name || '-'}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.overview.mesh')}</dt>
                    <dd>{detail?.mesh_enabled ? <Badge variant="default">{t('AccessPointsPage.common.enabled')}</Badge> : <Badge variant="outline">{t('AccessPointsPage.common.disabled')}</Badge>}</dd>
                  </dl>
                </CardContent>
              </Card>

              {/* Radio Summary */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('AccessPointsPage.overview.radioSummary')}</CardTitle>
                </CardHeader>
                <CardContent>
                  {radios.length === 0 ? (
                    <p className="text-muted-foreground text-sm">{t('AccessPointsPage.overview.noRadioData')}</p>
                  ) : (
                    <div className="space-y-4">
                      {radios.map((radio) => (
                        <div key={radio.band} className="rounded-lg border p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Radio className="h-4 w-4 text-blue-500" />
                              <span className="font-semibold">{getBandLabel(radio.band)}</span>
                            </div>
                            <Badge variant="outline" className="text-xs">
                              {t('AccessPointsPage.common.ch')} {radio.channel === 0 ? t('AccessPointsPage.common.auto') : radio.channel}
                            </Badge>
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                            <div>
                              <span className="text-muted-foreground">{t('AccessPointsPage.radio.width')}</span>
                              <p className="font-medium">{getChannelWidthLabel(radio.channel_width, radio.band)}</p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">{t('AccessPointsPage.radio.txPower')}</span>
                              <p className="font-medium">{radio.tx_power} dBm</p>
                            </div>
                            <div>
                              <span className="text-muted-foreground">{t('AccessPointsPage.radio.clients')}</span>
                              <p className="font-medium">{radio.clients}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* SSID Overview */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('AccessPointsPage.ssids.overridesTitle')}</CardTitle>
                <CardDescription>{t('AccessPointsPage.ssids.overridesCardDescription')}</CardDescription>
              </CardHeader>
              <CardContent>
                {ssids.length === 0 ? (
                  <p className="text-muted-foreground text-sm">{t('AccessPointsPage.ssids.noneConfigured')}</p>
                ) : (
                  <div className="grid gap-3 md:grid-cols-3">
                    {ssids.map((ssid) => (
                      <div key={ssid.index} className="rounded-lg border p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Wifi className="h-4 w-4" />
                            <span className="font-semibold text-sm">{ssid.ssid}</span>
                          </div>
                          <Badge variant={ssid.ssidEnable ? 'default' : 'secondary'} className="text-xs">
                            {ssid.ssidEnable ? t('AccessPointsPage.common.active') : t('AccessPointsPage.common.disabled')}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground">
                          <span><Shield className="inline h-3 w-3 mr-1" />{getSecurityLabel(ssid.security)}</span>
                          <span>VLAN {ssid.vlanId}</span>
                          {(ssid.supportBands ?? []).includes(0) && <Badge variant="outline" className="text-[10px] px-1">2.4G</Badge>}
                          {(ssid.supportBands ?? []).includes(1) && <Badge variant="outline" className="text-[10px] px-1">5G</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── Radios Tab ───────────────────────────────────────────────── */}
          <TabsContent value="radios" className="space-y-4">
            {radios.length === 0 ? (
              <Card>
                <CardContent noOffset className="py-8 text-center text-muted-foreground">
                  <WifiOff className="mx-auto h-12 w-12 mb-4 opacity-30" />
                  <p>{t('AccessPointsPage.radio.noDataForAp')}</p>
                </CardContent>
              </Card>
            ) : (
              radios.map((radio) => (
                <Card key={radio.band}>
                  <CardHeader className="flex flex-row items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="rounded-lg bg-blue-500/10 p-2">
                        <Radio className="h-5 w-5 text-blue-500" />
                      </div>
                      <div>
                        <CardTitle className="text-lg">{t('AccessPointsPage.radio.bandRadio', { band: getBandLabel(radio.band) })}</CardTitle>
                        <CardDescription>
                          {t('AccessPointsPage.radio.channel')} {radio.channel === 0 ? t('AccessPointsPage.common.auto') : radio.channel} • {getChannelWidthLabel(radio.channel_width, radio.band)} • {radio.tx_power} dBm
                        </CardDescription>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setEditingRadio(radio);
                        setRadioDialogOpen(true);
                      }}
                    >
                      <Settings className="mr-2 h-4 w-4" />
                      {t('AccessPointsPage.radio.configure')}
                    </Button>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="rounded-lg border p-3 text-center">
                        <p className="text-sm text-muted-foreground">{t('AccessPointsPage.radio.channel')}</p>
                        <p className="text-2xl font-bold">{radio.channel === 0 ? t('AccessPointsPage.common.auto') : radio.channel}</p>
                      </div>
                      <div className="rounded-lg border p-3 text-center">
                        <p className="text-sm text-muted-foreground">{t('AccessPointsPage.radio.width')}</p>
                        <p className="text-lg font-bold">{getChannelWidthLabel(radio.channel_width, radio.band)}</p>
                      </div>
                      <div className="rounded-lg border p-3 text-center">
                        <p className="text-sm text-muted-foreground">{t('AccessPointsPage.radio.txPower')}</p>
                        <p className="text-2xl font-bold">{radio.tx_power}<span className="text-sm text-muted-foreground ml-1">dBm</span></p>
                      </div>
                      <div className="rounded-lg border p-3 text-center">
                        <p className="text-sm text-muted-foreground">{t('AccessPointsPage.radio.clients')}</p>
                        <p className="text-2xl font-bold">{radio.clients}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>

          {/* ── SSIDs Tab ────────────────────────────────────────────────── */}
          <TabsContent value="ssids" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>{t('AccessPointsPage.ssids.overridesTitle')}</CardTitle>
                <CardDescription>
                  {t('AccessPointsPage.ssids.overridesTabDescription')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {ssids.length === 0 ? (
                  <div className="py-8 text-center text-muted-foreground">
                    <Wifi className="mx-auto h-12 w-12 mb-4 opacity-30" />
                    <p>{t('AccessPointsPage.ssids.noneForAp')}</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('AccessPointsPage.ssids.colSsid')}</TableHead>
                        <TableHead>{t('AccessPointsPage.ssids.colGlobalName')}</TableHead>
                        <TableHead>{t('AccessPointsPage.ssids.colSecurity')}</TableHead>
                        <TableHead>{t('AccessPointsPage.ssids.colBands')}</TableHead>
                        <TableHead>{t('AccessPointsPage.ssids.colVlan')}</TableHead>
                        <TableHead>{t('AccessPointsPage.ssids.colStatus')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {ssids.map((ssid) => (
                        <TableRow key={ssid.index}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Wifi className="h-4 w-4 text-blue-500" />
                              <span className="font-medium">{ssid.ssid}</span>
                            </div>
                          </TableCell>
                          <TableCell className="text-muted-foreground">{ssid.globalSsid}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-xs">
                              <Shield className="mr-1 h-3 w-3" />
                              {getSecurityLabel(ssid.security)}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1">
                              {(ssid.supportBands ?? []).includes(0) && <Badge variant="outline" className="text-xs">2.4G</Badge>}
                              {(ssid.supportBands ?? []).includes(1) && <Badge variant="outline" className="text-xs">5G</Badge>}
                            </div>
                          </TableCell>
                          <TableCell>
                            {ssid.vlanEnable ? (
                              <Badge variant="outline">{ssid.vlanId}</Badge>
                            ) : (
                              <span className="text-muted-foreground text-xs">{t('AccessPointsPage.common.default')}</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant={ssid.ssidEnable ? 'default' : 'secondary'}>
                              {ssid.ssidEnable ? t('AccessPointsPage.common.active') : t('AccessPointsPage.common.disabled')}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── Clients Tab ──────────────────────────────────────────────── */}
          <TabsContent value="clients" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>{t('AccessPointsPage.clients.title')}</CardTitle>
                <CardDescription>
                  {t('AccessPointsPage.clients.description')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {clientsLoading ? (
                  <div className="py-8 text-center text-muted-foreground">{t('AccessPointsPage.clients.loading')}</div>
                ) : clients.length === 0 ? (
                  <EmptyState
                    icon={Users}
                    title={t('AccessPointsPage.clients.emptyTitle')}
                    description={t('AccessPointsPage.clients.emptyDescription')}
                    variant="compact"
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('AccessPointsPage.clients.colName')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colMac')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colIp')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colSsid')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colBand')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colSignal')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colRate')}</TableHead>
                        <TableHead>{t('AccessPointsPage.clients.colUptime')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {clients.map((client: APClient) => (
                        <TableRow key={client.mac_address}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Smartphone className="h-4 w-4 text-muted-foreground" />
                              <span className="font-medium">{client.name || t('AccessPointsPage.common.unknown')}</span>
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{client.mac_address}</TableCell>
                          <TableCell className="font-mono text-xs">{client.ip_address || '-'}</TableCell>
                          <TableCell>{client.ssid || '-'}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-xs">{getBandLabel(client.band)}</Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1">
                              <Signal className="h-3 w-3" />
                              <span className={`text-sm ${
                                client.signal > -50 ? 'text-green-500' :
                                client.signal > -70 ? 'text-yellow-500' : 'text-red-500'
                              }`}>
                                {client.signal} dBm
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            <div>↓ {formatBytes(client.rx_rate)}/s</div>
                            <div>↑ {formatBytes(client.tx_rate)}/s</div>
                          </TableCell>
                          <TableCell className="text-sm">{formatUptime(client.uptime)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── Configuration Tab ────────────────────────────────────────── */}
          <TabsContent value="config" className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              {/* LAN Port Config */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('AccessPointsPage.config.lanPort')}</CardTitle>
                  <CardDescription>{t('AccessPointsPage.config.lanPortDescription')}</CardDescription>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-2 gap-y-3 text-sm">
                    <dt className="text-muted-foreground">{t('AccessPointsPage.config.vlanEnabled')}</dt>
                    <dd>{detail?.lan_port_vlan_enabled ? <Badge variant="default">{t('AccessPointsPage.common.yes')}</Badge> : <Badge variant="outline">{t('AccessPointsPage.common.no')}</Badge>}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.config.vlanId')}</dt>
                    <dd className="font-medium">{detail?.lan_port_vlan_id ?? '-'}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.config.poe')}</dt>
                    <dd>
                      {detail?.lan_port_poe_enabled == null ? '-' :
                        detail.lan_port_poe_enabled ? <Badge variant="default">{t('AccessPointsPage.config.powered')}</Badge> : <Badge variant="outline">{t('AccessPointsPage.common.no')}</Badge>
                      }
                    </dd>
                  </dl>
                </CardContent>
              </Card>

              {/* Location */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('AccessPointsPage.config.location')}</CardTitle>
                  <CardDescription>{t('AccessPointsPage.config.locationDescription')}</CardDescription>
                </CardHeader>
                <CardContent>
                  {detail?.location?.latitude != null ? (
                    <dl className="grid grid-cols-2 gap-y-3 text-sm">
                      <dt className="text-muted-foreground">{t('AccessPointsPage.config.latitude')}</dt>
                      <dd className="font-mono">{detail.location.latitude}</dd>
                      <dt className="text-muted-foreground">{t('AccessPointsPage.config.longitude')}</dt>
                      <dd className="font-mono">{detail.location.longitude}</dd>
                    </dl>
                  ) : (
                    <div className="py-4 text-center text-muted-foreground text-sm">
                      <Globe className="mx-auto h-8 w-8 mb-2 opacity-30" />
                      <p>{t('AccessPointsPage.config.noLocationSet')}</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Firmware */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('AccessPointsPage.config.firmware')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-2 gap-y-3 text-sm">
                    <dt className="text-muted-foreground">{t('AccessPointsPage.config.currentVersion')}</dt>
                    <dd className="font-medium text-xs">{selectedAP.firmware_version || '-'}</dd>
                    <dt className="text-muted-foreground">{t('AccessPointsPage.config.updateAvailableLabel')}</dt>
                    <dd>
                      {selectedAP.update_available ? (
                        <Badge variant="destructive" className="text-xs">
                          <ArrowUpCircle className="mr-1 h-3 w-3" />
                          {t('AccessPointsPage.config.updateAvailable')}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-xs">
                          <CheckCircle className="mr-1 h-3 w-3" />
                          {t('AccessPointsPage.config.upToDate')}
                        </Badge>
                      )}
                    </dd>
                  </dl>
                  {selectedAP.update_available && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-3"
                      onClick={() => openConfirmDialog('upgrade', selectedAP.id, selectedAP.name)}
                    >
                      <ArrowUpCircle className="mr-2 h-4 w-4" />
                      {t('AccessPointsPage.actions.upgradeFirmware')}
                    </Button>
                  )}
                </CardContent>
              </Card>

              {/* Quick Actions */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('AccessPointsPage.config.quickActions')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-2">
                    <Button variant="outline" size="sm" onClick={() => locateMutation.mutate(selectedAP.id)} disabled={locateMutation.isPending}>
                      <Locate className="mr-2 h-4 w-4" />
                      {t('AccessPointsPage.actions.locate')}
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => openConfirmDialog('reboot', selectedAP.id, selectedAP.name)}>
                      <RotateCw className="mr-2 h-4 w-4" />
                      {t('AccessPointsPage.actions.reboot')}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => ledMutation.mutate({ apId: selectedAP.id, enabled: !(detail?.led_enabled ?? false) })}
                      disabled={ledMutation.isPending}
                    >
                      {detail?.led_enabled ? <LightbulbOff className="mr-2 h-4 w-4" /> : <Lightbulb className="mr-2 h-4 w-4" />}
                      {detail?.led_enabled ? t('AccessPointsPage.actions.ledOff') : t('AccessPointsPage.actions.ledOn')}
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => adoptMutation.mutate(selectedAP.id)} disabled={adoptMutation.isPending}>
                      <CheckCircle className="mr-2 h-4 w-4" />
                      {t('AccessPointsPage.actions.reAdopt')}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* ── RF Health Tab ────────────────────────────────────────── */}
          <TabsContent value="rf-health" className="space-y-4">
            {!controllerId && (
              <Card>
                <CardContent noOffset className="py-8 text-center text-muted-foreground">
                  {t('AccessPointsPage.rfHealth.noController')}
                </CardContent>
              </Card>
            )}
            {controllerId && channelUtilLoading && (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            )}
            {controllerId && !channelUtilLoading && channelUtilError && (
              <ErrorState
                message={t('AccessPointsPage.rfHealth.loadError')}
                onRetry={() => refetchChannelUtil()}
              />
            )}
            {controllerId && !channelUtilLoading && !channelUtilError && (!channelUtilization || channelUtilization.length === 0) && (
              <EmptyState
                icon={BarChart3}
                title={t('AccessPointsPage.rfHealth.noChannelDataTitle')}
                description={t('AccessPointsPage.rfHealth.noChannelDataDescription')}
              />
            )}
            {channelUtilization && channelUtilization.length > 0 && (
              <>
                {/* Per-band summary cards */}
                <div className="grid gap-4 md:grid-cols-3">
                  {['2g', '5g', '6g'].map(band => {
                    const bandData = channelUtilization.filter((d: any) => d.band === band);
                    if (bandData.length === 0) return null;
                    const avgUtil = Math.round(bandData.reduce((s: number, d: any) => s + (d.utilization_percent || 0), 0) / bandData.length);
                    const avgInterference = Math.round(bandData.reduce((s: number, d: any) => s + (d.interference_percent || 0), 0) / bandData.length);
                    const totalClients = bandData.reduce((s: number, d: any) => s + (d.client_count || 0), 0);
                    return (
                      <Card key={band}>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <BandIcon band={band} />{getBandLabel(band)}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="text-muted-foreground">{t('AccessPointsPage.rfHealth.utilization')}</span>
                              <span className={`font-medium ${avgUtil > 70 ? 'text-red-500' : avgUtil > 40 ? 'text-yellow-500' : 'text-green-500'}`}>{avgUtil}%</span>
                            </div>
                            <Progress value={avgUtil} className="h-2" />
                          </div>
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="text-muted-foreground">{t('AccessPointsPage.rfHealth.interference')}</span>
                              <span className={`font-medium ${avgInterference > 30 ? 'text-red-500' : avgInterference > 15 ? 'text-yellow-500' : 'text-green-500'}`}>{avgInterference}%</span>
                            </div>
                            <Progress value={avgInterference} className="h-2" />
                          </div>
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">{t('AccessPointsPage.rfHealth.aps')}</span>
                            <span className="font-medium">{bandData.length}</span>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span className="text-muted-foreground">{t('AccessPointsPage.rfHealth.clients')}</span>
                            <span className="font-medium">{totalClients}</span>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>

                {/* Channel Heatmap · visual grid of APs × Channels */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">{t('AccessPointsPage.rfHealth.channelHeatmap')}</CardTitle>
                    <CardDescription>{t('AccessPointsPage.rfHealth.channelHeatmapDescription')}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {(() => {
                      // Group by band, then build AP×Channel grid
                      const bands = ['2g', '5g', '6g'] as const;
                      return bands.map(band => {
                        const bandItems = channelUtilization.filter((d: any) => d.band === band);
                        if (bandItems.length === 0) return null;

                        // Collect unique channels and APs for this band
                        const channels = [...new Set<number>(bandItems.map((d: any) => d.channel as number))].sort((a: number, b: number) => a - b);
                        const aps: [string, string][] = [...new Map<string, string>(bandItems.map((d: any) => [d.ap_mac as string, (d.ap_name || d.ap_mac) as string])).entries()];

                        // Build lookup: (ap_mac, channel) → utilization
                        const lookup = new Map<string, number>();
                        bandItems.forEach((d: any) => lookup.set(`${d.ap_mac}:${d.channel}`, d.utilization_percent || 0));

                        return (
                          <div key={band} className="mb-6 last:mb-0">
                            <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                              <BandIcon band={band} />{getBandLabel(band)}
                            </h4>
                            <div className="overflow-x-auto">
                              <div className="inline-grid gap-px bg-border rounded-lg overflow-hidden" style={{ gridTemplateColumns: `140px repeat(${channels.length}, minmax(48px, 1fr))` }}>
                                {/* Header row */}
                                <div className="bg-muted px-2 py-1.5 text-xs font-medium text-muted-foreground">{t('AccessPointsPage.rfHealth.ap')}</div>
                                {channels.map(ch => (
                                  <div key={ch} className="bg-muted px-2 py-1.5 text-xs font-medium text-center text-muted-foreground">{t('AccessPointsPage.common.ch')} {ch}</div>
                                ))}
                                {/* AP rows */}
                                {aps.map(([mac, name]) => (
                                  <React.Fragment key={mac}>
                                    <div className="bg-background px-2 py-1.5 text-xs truncate max-w-[140px]" title={String(name)}>{name}</div>
                                    {channels.map(ch => {
                                      const util = lookup.get(`${mac}:${ch}`);
                                      const hasData = util !== undefined;
                                      const bg = !hasData
                                        ? 'bg-muted/30'
                                        : util > 80 ? 'bg-red-500' : util > 60 ? 'bg-orange-500' : util > 40 ? 'bg-yellow-500' : util > 20 ? 'bg-emerald-400' : 'bg-emerald-500';
                                      const text = !hasData ? '' : util > 50 ? 'text-white' : 'text-foreground';
                                      return (
                                        <div
                                          key={`${mac}:${ch}`}
                                          className={`${bg} ${text} px-1 py-1.5 text-xs text-center font-mono transition-colors`}
                                          title={hasData ? `${name} · ${t('AccessPointsPage.common.ch')} ${ch}: ${util}%` : t('AccessPointsPage.rfHealth.noData')}
                                        >
                                          {hasData ? `${util}%` : ''}
                                        </div>
                                      );
                                    })}
                                  </React.Fragment>
                                ))}
                              </div>
                            </div>
                            {/* Legend */}
                            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                              <span>{t('AccessPointsPage.rfHealth.low')}</span>
                              <div className="flex gap-px">
                                {[{ c: 'bg-emerald-500', l: '0-20%' }, { c: 'bg-emerald-400', l: '20-40%' }, { c: 'bg-yellow-500', l: '40-60%' }, { c: 'bg-orange-500', l: '60-80%' }, { c: 'bg-red-500', l: '80%+' }].map(s => (
                                  <div key={s.l} className={`${s.c} w-8 h-3 rounded-sm`} title={s.l} />
                                ))}
                              </div>
                              <span>{t('AccessPointsPage.rfHealth.high')}</span>
                            </div>
                          </div>
                        );
                      });
                    })()}
                  </CardContent>
                </Card>

                {/* Per-AP channel utilization table */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">{t('AccessPointsPage.rfHealth.utilizationByApTitle')}</CardTitle>
                    <CardDescription>{t('AccessPointsPage.rfHealth.utilizationByApDescription')}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t('AccessPointsPage.rfHealth.ap')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.colBand')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.colChannel')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.colWidth')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.utilization')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.interference')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.noiseFloor')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rfHealth.clients')}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {channelUtilization.map((item: any, idx: number) => (
                          <TableRow key={`${item.ap_mac}-${item.band}-${idx}`}>
                            <TableCell className="font-medium">{item.ap_name || item.ap_mac}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className="text-xs">
                                <BandIcon band={item.band} />{getBandLabel(item.band)}
                              </Badge>
                            </TableCell>
                            <TableCell>{item.channel}</TableCell>
                            <TableCell>{item.channel_width ? `${item.channel_width} MHz` : '-'}</TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <div className="w-16 bg-muted rounded-full h-2">
                                  <div
                                    className={`h-2 rounded-full ${(item.utilization_percent || 0) > 70 ? 'bg-red-500' : (item.utilization_percent || 0) > 40 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                    style={{ width: `${Math.min(item.utilization_percent || 0, 100)}%` }}
                                  />
                                </div>
                                <span className="text-sm">{item.utilization_percent || 0}%</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className={`text-sm ${(item.interference_percent || 0) > 30 ? 'text-red-500' : (item.interference_percent || 0) > 15 ? 'text-yellow-500' : ''}`}>
                                {item.interference_percent || 0}%
                              </span>
                            </TableCell>
                            <TableCell className="text-sm">{item.noise_floor_dbm != null ? `${item.noise_floor_dbm} dBm` : '-'}</TableCell>
                            <TableCell>{item.client_count || 0}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* ── Rogue APs Tab ────────────────────────────────────────── */}
          <TabsContent value="rogue-aps" className="space-y-4">
            {!controllerId && (
              <Card>
                <CardContent noOffset className="py-8 text-center text-muted-foreground">
                  {t('AccessPointsPage.rogueAps.noController')}
                </CardContent>
              </Card>
            )}
            {controllerId && rogueLoading && (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            )}
            {controllerId && !rogueLoading && rogueError && (
              <ErrorState
                message={t('AccessPointsPage.rogueAps.loadError')}
                onRetry={() => refetchRogueAps()}
              />
            )}
            {controllerId && !rogueLoading && !rogueError && (!rogueAps || rogueAps.length === 0) && (
              <EmptyState
                icon={ShieldAlert}
                title={t('AccessPointsPage.rogueAps.noneTitle')}
                description={t('AccessPointsPage.rogueAps.noneDescription')}
              />
            )}
            {rogueAps && rogueAps.length > 0 && (
              <>
                {/* Summary cards */}
                <div className="grid gap-4 md:grid-cols-3">
                  <Card>
                    <CardContent noOffset>
                      <div className="text-2xl font-bold text-red-500">{(rogueAps || []).filter((r: any) => r.classification === 'rogue').length}</div>
                      <p className="text-sm text-muted-foreground">{t('AccessPointsPage.rogueAps.rogueApsLabel')}</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent noOffset>
                      <div className="text-2xl font-bold text-yellow-500">{(rogueAps || []).filter((r: any) => r.classification === 'neighbor').length}</div>
                      <p className="text-sm text-muted-foreground">{t('AccessPointsPage.rogueAps.neighborApsLabel')}</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent noOffset>
                      <div className="text-2xl font-bold text-green-500">{(rogueAps || []).filter((r: any) => r.classification === 'known').length}</div>
                      <p className="text-sm text-muted-foreground">{t('AccessPointsPage.rogueAps.knownApsLabel')}</p>
                    </CardContent>
                  </Card>
                </div>

                {/* Rogue AP table */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">{t('AccessPointsPage.rogueAps.detectedTitle')}</CardTitle>
                    <CardDescription>{t('AccessPointsPage.rogueAps.detectedDescription')}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t('AccessPointsPage.rogueAps.colClassification')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colBssid')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colSsid')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colChannel')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colBand')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colSignal')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colSecurity')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colDetectedBy')}</TableHead>
                          <TableHead>{t('AccessPointsPage.rogueAps.colLastSeen')}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {rogueAps.map((rogue: any, idx: number) => (
                          <TableRow key={`${rogue.mac_address}-${idx}`}>
                            <TableCell>
                              <Badge variant={
                                rogue.classification === 'rogue' ? 'destructive' :
                                rogue.classification === 'neighbor' ? 'secondary' : 'outline'
                              }>
                                {rogue.classification || t('AccessPointsPage.common.unknownLower')}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-xs">{rogue.mac_address}</TableCell>
                            <TableCell>{rogue.ssid || <span className="text-muted-foreground italic">{t('AccessPointsPage.rogueAps.hidden')}</span>}</TableCell>
                            <TableCell>{rogue.channel || '-'}</TableCell>
                            <TableCell>
                              {rogue.band && <Badge variant="outline" className="text-xs">{getBandLabel(rogue.band)}</Badge>}
                            </TableCell>
                            <TableCell>
                              <span className={`font-medium ${(rogue.signal || -100) > -50 ? 'text-green-500' : (rogue.signal || -100) > -70 ? 'text-yellow-500' : 'text-red-500'}`}>
                                {rogue.signal != null ? `${rogue.signal} dBm` : '-'}
                              </span>
                            </TableCell>
                            <TableCell className="text-xs">{rogue.security || '-'}</TableCell>
                            <TableCell className="text-xs">{rogue.detecting_ap_name || rogue.detecting_ap_mac || '-'}</TableCell>
                            <TableCell className="text-xs">{rogue.last_seen ? new Date(rogue.last_seen).toLocaleString() : '-'}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* ── Radio Settings Tab ───────────────────────────────────── */}
          <TabsContent value="radio-settings" className="space-y-4">
            {!controllerId && (
              <Card>
                <CardContent noOffset className="py-8 text-center text-muted-foreground">
                  {t('AccessPointsPage.radioSettings.noController')}
                </CardContent>
              </Card>
            )}
            {controllerId && radioSettingsLoading && (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            )}
            {controllerId && !radioSettingsLoading && radioSettingsError && (
              <ErrorState
                message={t('AccessPointsPage.radioSettings.loadError')}
                onRetry={() => refetchRadioSettings()}
              />
            )}
            {controllerId && !radioSettingsLoading && !radioSettingsError && !radioSettings && (
              <EmptyState
                icon={Sliders}
                title={t('AccessPointsPage.radioSettings.noneTitle')}
                description={t('AccessPointsPage.radioSettings.noneDescription')}
              />
            )}
            {radioSettings && typeof radioSettings === 'object' && (
              <>
              <div className="grid gap-4 md:grid-cols-2">
                {/* Display radio settings as read-only cards per band */}
                {Object.entries(radioSettings).map(([key, value]: [string, any]) => {
                  // Each key might be a band identifier or a general setting
                  if (typeof value !== 'object' || value === null) {
                    return (
                      <Card key={key}>
                        <CardContent noOffset>
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</span>
                            <span className="font-medium">{typeof value === 'boolean' ? (value ? t('AccessPointsPage.common.enabled') : t('AccessPointsPage.common.disabled')) : String(value ?? '-')}</span>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  }
                  // Band-level settings
                  return (
                    <Card key={key} className="col-span-1">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-base flex items-center gap-2">
                          <Sliders className="h-4 w-4" />
                          {getBandLabel(key) !== key ? getBandLabel(key) : key.replace(/_/g, ' ')}
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <dl className="space-y-2 text-sm">
                          {Object.entries(value).map(([settingKey, settingVal]: [string, any]) => (
                            <div key={settingKey} className="flex justify-between">
                              <dt className="text-muted-foreground capitalize">{settingKey.replace(/_/g, ' ')}</dt>
                              <dd className="font-medium">
                                {typeof settingVal === 'boolean'
                                  ? (settingVal ? <Badge variant="default" className="text-xs">{t('AccessPointsPage.common.enabled')}</Badge> : <Badge variant="secondary" className="text-xs">{t('AccessPointsPage.common.disabled')}</Badge>)
                                  : Array.isArray(settingVal)
                                    ? settingVal.join(', ')
                                    : String(settingVal ?? '-')
                                }
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              {/* Fast Roaming Settings */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Wifi className="h-4 w-4" />
                    {t('AccessPointsPage.radioSettings.fastRoamingTitle')}
                  </CardTitle>
                  <CardDescription>
                    {t('AccessPointsPage.radioSettings.fastRoamingDescription')}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* 802.11r - Fast BSS Transition */}
                    <div className="flex items-center justify-between py-2 border-b">
                      <div className="space-y-0.5">
                        <div className="text-sm font-medium">{t('AccessPointsPage.radioSettings.dot11rTitle')}</div>
                        <div className="text-xs text-muted-foreground">{t('AccessPointsPage.radioSettings.dot11rDescription')}</div>
                      </div>
                      <Switch
                        checked={radioSettings.fast_roaming_enabled ?? radioSettings.dot11r ?? false}
                        onCheckedChange={(checked: boolean) =>
                          radioSettingsMutation.mutate({ fast_roaming_enabled: checked, dot11r: checked })
                        }
                        disabled={radioSettingsMutation.isPending}
                      />
                    </div>

                    {/* 802.11k - Radio Resource Management */}
                    <div className="flex items-center justify-between py-2 border-b">
                      <div className="space-y-0.5">
                        <div className="text-sm font-medium">{t('AccessPointsPage.radioSettings.dot11kTitle')}</div>
                        <div className="text-xs text-muted-foreground">{t('AccessPointsPage.radioSettings.dot11kDescription')}</div>
                      </div>
                      <Switch
                        checked={radioSettings.dot11k ?? radioSettings.rrm_enabled ?? false}
                        onCheckedChange={(checked: boolean) =>
                          radioSettingsMutation.mutate({ dot11k: checked, rrm_enabled: checked })
                        }
                        disabled={radioSettingsMutation.isPending}
                      />
                    </div>

                    {/* 802.11v - BSS Transition Management */}
                    <div className="flex items-center justify-between py-2">
                      <div className="space-y-0.5">
                        <div className="text-sm font-medium">{t('AccessPointsPage.radioSettings.dot11vTitle')}</div>
                        <div className="text-xs text-muted-foreground">{t('AccessPointsPage.radioSettings.dot11vDescription')}</div>
                      </div>
                      <Switch
                        checked={radioSettings.dot11v ?? radioSettings.bss_transition ?? false}
                        onCheckedChange={(checked: boolean) =>
                          radioSettingsMutation.mutate({ dot11v: checked, bss_transition: checked })
                        }
                        disabled={radioSettingsMutation.isPending}
                      />
                    </div>

                    {radioSettingsMutation.isPending && (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground pt-2">
                        <RefreshCw className="h-3 w-3 animate-spin" />
                        {t('AccessPointsPage.radioSettings.applyingChanges')}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
              </>
            )}
          </TabsContent>
        </Tabs>

        {/* ── Rename Dialog ────────────────────────────────────────────── */}
        <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('AccessPointsPage.renameDialog.title')}</DialogTitle>
              <DialogDescription>{t('AccessPointsPage.renameDialog.description')}</DialogDescription>
            </DialogHeader>
            <div className="py-4">
              <Label htmlFor="ap-name">{t('AccessPointsPage.renameDialog.nameLabel')}</Label>
              <Input
                id="ap-name"
                value={renameName}
                onChange={(e) => setRenameName(e.target.value)}
                placeholder={t('AccessPointsPage.renameDialog.namePlaceholder')}
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setRenameDialogOpen(false)}>{t('AccessPointsPage.common.cancel')}</Button>
              <Button
                onClick={() => renameMutation.mutate({ apId: selectedAP.id, name: renameName })}
                disabled={!renameName.trim() || renameMutation.isPending}
              >
                {renameMutation.isPending ? t('AccessPointsPage.common.saving') : t('AccessPointsPage.common.save')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* ── Radio Config Dialog ──────────────────────────────────────── */}
        <Dialog open={radioDialogOpen} onOpenChange={setRadioDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('AccessPointsPage.radioDialog.title', { band: editingRadio ? getBandLabel(editingRadio.band) : '' })}</DialogTitle>
              <DialogDescription>{t('AccessPointsPage.radioDialog.description')}</DialogDescription>
            </DialogHeader>
            {editingRadio && (
              <div className="space-y-4 py-4">
                <div>
                  <Label>{t('AccessPointsPage.radio.channel')}</Label>
                  <Select
                    value={String(editingRadio.channel)}
                    onValueChange={(v) => setEditingRadio({ ...editingRadio, channel: parseInt(v) })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="0">{t('AccessPointsPage.common.auto')}</SelectItem>
                      {(RADIO_CHANNELS[getCanonicalBand(editingRadio.band)] ?? []).map(ch => (
                        <SelectItem key={ch} value={String(ch)}>{t('AccessPointsPage.radioDialog.channelOption', { ch })}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label>{t('AccessPointsPage.radioDialog.txPowerLabel')}</Label>
                  <Input
                    type="number"
                    value={editingRadio.tx_power}
                    onChange={(e) => setEditingRadio({ ...editingRadio, tx_power: parseInt(e.target.value) || 0 })}
                    min={1}
                    max={30}
                  />
                </div>
              </div>
            )}
            <DialogFooter>
              <Button variant="outline" onClick={() => setRadioDialogOpen(false)}>{t('AccessPointsPage.common.cancel')}</Button>
              <Button
                onClick={() => {
                  if (editingRadio && selectedAP) {
                    updateRadioMutation.mutate({
                      apId: selectedAP.id,
                      band: getCanonicalBand(editingRadio.band),
                      data: { channel: editingRadio.channel, tx_power: editingRadio.tx_power },
                    });
                  }
                }}
                disabled={updateRadioMutation.isPending}
              >
                {updateRadioMutation.isPending ? t('AccessPointsPage.common.applying') : t('AccessPointsPage.common.apply')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* ── Confirm Dialog ───────────────────────────────────────────── */}
        <Dialog open={confirmDialogOpen} onOpenChange={setConfirmDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {confirmAction?.action === 'reboot' && t('AccessPointsPage.confirm.rebootTitle')}
                {confirmAction?.action === 'upgrade' && t('AccessPointsPage.confirm.upgradeTitle')}
                {confirmAction?.action === 'forget' && t('AccessPointsPage.confirm.forgetTitle')}
              </DialogTitle>
              <DialogDescription>
                {confirmAction?.action === 'reboot' && t('AccessPointsPage.confirm.rebootDescription', { name: confirmAction.apName })}
                {confirmAction?.action === 'upgrade' && t('AccessPointsPage.confirm.upgradeDescription', { name: confirmAction.apName })}
                {confirmAction?.action === 'forget' && t('AccessPointsPage.confirm.forgetDescriptionDetail', { name: confirmAction.apName })}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirmDialogOpen(false)}>{t('AccessPointsPage.common.cancel')}</Button>
              <Button
                variant={confirmAction?.action === 'forget' ? 'destructive' : 'default'}
                onClick={handleConfirmAction}
              >
                {confirmAction?.action === 'reboot' && t('AccessPointsPage.actions.reboot')}
                {confirmAction?.action === 'upgrade' && t('AccessPointsPage.actions.upgrade')}
                {confirmAction?.action === 'forget' && t('AccessPointsPage.actions.forget')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  // ════════════════════════════════════════════════════════════════════════════
  // AP List View
  // ════════════════════════════════════════════════════════════════════════════

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        icon={Radio}
        title={t('AccessPointsPage.header.title')}
        description={t('AccessPointsPage.header.description')}
        onRefresh={() => refetchAPs()}
        refreshing={apLoading}
        secondaryActions={[{ label: t('AccessPointsPage.header.export'), icon: Download, onClick: handleExport }]}
      />

      {/* Query Error Banner */}
      {apError && (
        <ErrorState
          message={t('AccessPointsPage.list.loadError')}
          onRetry={() => refetchAPs()}
        />
      )}

      <StatsGrid
        columns={4}
        isLoading={apLoading}
        stats={[
          {
            title: t('AccessPointsPage.stats.totalApsTitle'),
            value: stats.total,
            icon: Wifi,
            variant: 'primary',
            description: t('AccessPointsPage.stats.totalApsDescription'),
          },
          {
            title: t('AccessPointsPage.stats.onlineTitle'),
            value: stats.online,
            icon: CheckCircle,
            variant: 'success',
            description: stats.total > 0 ? t('AccessPointsPage.stats.onlineDescription', { pct: Math.round((stats.online / stats.total) * 100) }) : t('AccessPointsPage.stats.noAps'),
          },
          {
            title: t('AccessPointsPage.stats.offlineTitle'),
            value: stats.offline,
            icon: WifiOff,
            variant: 'destructive',
            description: t('AccessPointsPage.stats.offlineDescription'),
          },
          {
            title: t('AccessPointsPage.stats.totalClientsTitle'),
            value: stats.clients,
            icon: Users,
            variant: 'info',
            description: t('AccessPointsPage.stats.totalClientsDescription'),
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          placeholder={t('AccessPointsPage.list.searchPlaceholder')}
          value={searchQuery}
          onChange={setSearchQuery}
          className="w-full sm:w-auto"
        />
        <Select value={siteFilter} onValueChange={setSiteFilter}>
          <SelectTrigger className="w-full sm:w-[180px]">
            <SelectValue placeholder={t('AccessPointsPage.list.allSitesPlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('AccessPointsPage.list.allSites')}</SelectItem>
            {uniqueSites.map((s) => (
              <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('AccessPointsPage.list.allStatusesPlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('AccessPointsPage.list.allStatuses')}</SelectItem>
            <SelectItem value="online">{t('AccessPointsPage.status.online')}</SelectItem>
            <SelectItem value="offline">{t('AccessPointsPage.status.offline')}</SelectItem>
            <SelectItem value="adopting">{t('AccessPointsPage.status.adopting')}</SelectItem>
          </SelectContent>
        </Select>
        {(searchQuery || siteFilter !== 'all' || statusFilter !== 'all') && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearchQuery('');
              setSiteFilter('all');
              setStatusFilter('all');
            }}
          >
            {t('AccessPointsPage.list.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* AP List */}
      {apLoading ? (
        <Card>
          <CardContent noOffset className="py-12 text-center text-muted-foreground">
            <RefreshCw className="mx-auto h-8 w-8 animate-spin mb-4" />
            {t('AccessPointsPage.list.loading')}
          </CardContent>
        </Card>
      ) : filteredAPs.length === 0 ? (
        searchQuery ? (
          <NoResultsState searchQuery={searchQuery} onClear={() => setSearchQuery('')} />
        ) : (
          <EmptyState
            icon={Wifi}
            title={t('AccessPointsPage.list.emptyTitle')}
            description={t('AccessPointsPage.list.emptyDescription')}
            variant="card"
          />
        )
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filteredAPs.map((ap) => (
            <Card
              key={ap.id}
              className="cursor-pointer transition-all hover:shadow-md hover:border-primary/50"
              onClick={() => selectAP(ap)}
            >
              <CardContent noOffset className="p-5">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`rounded-full p-2 ${ap.status === 'online' ? 'bg-success/10' : 'bg-destructive/10'}`}>
                      <Wifi className={`h-5 w-5 ${ap.status === 'online' ? 'text-success' : 'text-destructive'}`} />
                    </div>
                    <div className="min-w-0">
                      <h3 className="font-semibold truncate">{ap.name}</h3>
                      <p className="text-xs text-muted-foreground">{ap.model} • {ap.ip_address}</p>
                    </div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                      <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                        <MoreVertical className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
                      <DropdownMenuItem onClick={() => selectAP(ap)}>
                        <Eye className="mr-2 h-4 w-4" />
                        {t('AccessPointsPage.actions.viewDetails')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => locateMutation.mutate(ap.id)}>
                        <Locate className="mr-2 h-4 w-4" />
                        {t('AccessPointsPage.actions.locate')}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => openConfirmDialog('reboot', ap.id, ap.name)}>
                        <RotateCw className="mr-2 h-4 w-4" />
                        {t('AccessPointsPage.actions.reboot')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => openConfirmDialog('upgrade', ap.id, ap.name)}>
                        <ArrowUpCircle className="mr-2 h-4 w-4" />
                        {t('AccessPointsPage.actions.upgrade')}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem className="text-destructive" onClick={() => openConfirmDialog('forget', ap.id, ap.name)}>
                        <Trash2 className="mr-2 h-4 w-4" />
                        {t('AccessPointsPage.actions.forget')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>

                {/* Status + Site */}
                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <Badge variant={getStatusBadgeVariant(ap.status)} className="text-xs">
                    <div className={`w-1.5 h-1.5 rounded-full mr-1.5 ${getStatusColor(ap.status)}`} />
                    {ap.status}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{ap.mac_address}</span>
                  {ap.site_name && (
                    <Badge variant="secondary" className="text-[10px] ml-auto">
                      <MapPin className="h-2.5 w-2.5 mr-1" />
                      {ap.site_name}
                    </Badge>
                  )}
                </div>

                {/* Stats row */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-center border-t pt-3">
                  <div>
                    <div className="flex items-center justify-center gap-1">
                      <Users className="h-3 w-3 text-muted-foreground" />
                      <span className="text-lg font-semibold">{ap.clients}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground">{t('AccessPointsPage.card.clients')}</p>
                  </div>
                  <div>
                    <div className="flex items-center justify-center gap-1">
                      <Radio className="h-3 w-3 text-muted-foreground" />
                      <span className="text-lg font-semibold">{ap.radios?.length || 0}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground">{t('AccessPointsPage.card.radios')}</p>
                  </div>
                  <div>
                    <div className="flex items-center justify-center gap-1">
                      <Clock className="h-3 w-3 text-muted-foreground" />
                      <span className="text-sm font-semibold">{formatUptime(ap.uptime)}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground">{t('AccessPointsPage.card.uptime')}</p>
                  </div>
                </div>

                {/* Radio bands */}
                {ap.radios && ap.radios.length > 0 && (
                  <div className="flex gap-1.5 mt-3 flex-wrap">
                    {ap.radios.map((r) => (
                      <Badge key={r.band} variant="outline" className="text-[10px] gap-1">
                        <BandIcon band={r.band} />{r.band}, {t('AccessPointsPage.common.ch')} {r.channel === 0 ? t('AccessPointsPage.common.auto') : r.channel}
                        {r.channel_width ? ` / ${r.channel_width}MHz` : ''}
                        {r.clients > 0 && <span className="text-primary font-semibold">({r.clients})</span>}
                      </Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* ── Confirm Dialog (List level) ──────────────────────────────────── */}
      <Dialog open={confirmDialogOpen} onOpenChange={setConfirmDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {confirmAction?.action === 'reboot' && t('AccessPointsPage.confirm.rebootTitle')}
              {confirmAction?.action === 'upgrade' && t('AccessPointsPage.confirm.upgradeTitle')}
              {confirmAction?.action === 'forget' && t('AccessPointsPage.confirm.forgetTitle')}
            </DialogTitle>
            <DialogDescription>
              {confirmAction?.action === 'reboot' && t('AccessPointsPage.confirm.rebootDescription', { name: confirmAction.apName })}
              {confirmAction?.action === 'upgrade' && t('AccessPointsPage.confirm.upgradeDescription', { name: confirmAction.apName })}
              {confirmAction?.action === 'forget' && t('AccessPointsPage.confirm.forgetDescription', { name: confirmAction.apName })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDialogOpen(false)}>{t('AccessPointsPage.common.cancel')}</Button>
            <Button
              variant={confirmAction?.action === 'forget' ? 'destructive' : 'default'}
              onClick={handleConfirmAction}
            >
              {confirmAction?.action === 'reboot' && t('AccessPointsPage.actions.reboot')}
              {confirmAction?.action === 'upgrade' && t('AccessPointsPage.actions.upgrade')}
              {confirmAction?.action === 'forget' && t('AccessPointsPage.actions.forget')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
