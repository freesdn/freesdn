// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Phone Detail Page
 *
 * Single-device view with:
 *  - Overview, Config, Provisioning, Network, Actions tabs
 *  - Lifecycle controls (onboard / decommission / maintenance)
 *  - Config template assignment & XML preview
 *  - Health metrics (CPU, memory, uptime)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft, RefreshCw, Settings, Upload,
  Wrench, XCircle, CheckCircle, Copy, AlertTriangle,
  Activity, HardDrive, Cpu, Clock, FileText,
  Shield, Code, Link2, Unlock, Eye, EyeOff,
  Phone as PhoneIcon,
  Power, RotateCcw, Send, Loader2, MapPin,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { voipApi, sitesApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import {
  PhoneStatusBadge, LifecycleBadge, ProvisionBadge, SIPIndicator,
  formatTimeAgo, formatUptime,
} from './components';
import type { VoIPPhone, PhoneConnectionTestResult } from './types';

function InfoRow({ label, value, mono }: { label: string; value?: string | number | null; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 border-b last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={cn('text-sm', mono && 'font-mono')}>{value ?? '-'}</span>
    </div>
  );
}

const VALID_PHONE_TABS = new Set(['overview', 'config', 'provisioning', 'network', 'actions']);

export default function PhoneDetailPage() {
  const { t } = useTranslation('voip');
  const { id, tab } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const activeTab = tab && VALID_PHONE_TABS.has(tab) ? tab : 'overview';
  const setActiveTab = useCallback((value: string) => {
    navigate(
      value === 'overview' ? `/voip/phones/${id}` : `/voip/phones/${id}/${value}`,
      { replace: true },
    );
  }, [id, navigate]);

  const [showOnboardDialog, setShowOnboardDialog] = useState(false);
  const [onboardData, setOnboardData] = useState({ name: '', config_template_id: '', location: '' });

  // Connection test state
  const [connUsername, setConnUsername] = useState('admin');
  const [connPassword, setConnPassword] = useState('');
  const [showConnPassword, setShowConnPassword] = useState(false);
  const [saveCredsOnSuccess, setSaveCredsOnSuccess] = useState(true);
  const [connTestResult, setConnTestResult] = useState<PhoneConnectionTestResult | null>(null);

  // ── Queries ──

  const { data: phoneRes, isLoading, isError: phoneError, refetch } = useQuery({
    queryKey: ['voip-phone', id],
    queryFn: () => voipApi.getPhoneById(id!),
    enabled: !!id,
    refetchInterval: 15_000,
  });

  const phone: VoIPPhone | undefined = phoneRes?.data;

  const { data: configPreviewRes, isLoading: configPreviewLoading, isError: configPreviewError, refetch: refetchPreview } = useQuery({
    queryKey: ['voip-phone-config-preview', id],
    queryFn: () => voipApi.previewPhoneConfig(id!),
    enabled: !!id && activeTab === 'config',
    staleTime: 30_000,
  });

  const configPreview = typeof configPreviewRes?.data === 'string'
    ? configPreviewRes.data
    : (configPreviewRes?.data?.config ?? '');

  const { data: templatesRes, isError: templatesError } = useQuery({
    queryKey: ['voip-templates-list'],
    queryFn: () => voipApi.getTemplates({ limit: 100 }),
    staleTime: 60_000,
  });
  const templates = templatesRes?.data?.items ?? [];

  // ── Mutations ──

  const invalidatePhone = () => {
    queryClient.invalidateQueries({ queryKey: ['voip-phone', id] });
    queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
  };

  const onboardMutation = useMutation({
    mutationFn: (data: any) => voipApi.onboardPhone(id!, data),
    onSuccess: () => { invalidatePhone(); setShowOnboardDialog(false); },
    onError: (err: any) => console.error('Onboard failed:', err?.response?.data?.detail || err.message),
  });

  const decommissionMutation = useMutation({
    mutationFn: () => voipApi.decommissionPhone(id!),
    onSuccess: invalidatePhone,
    onError: (err: any) => console.error('Decommission failed:', err?.response?.data?.detail || err.message),
  });

  const maintenanceMutation = useMutation({
    mutationFn: (enabled: boolean) => voipApi.toggleMaintenance(id!, enabled),
    onSuccess: invalidatePhone,
    onError: (err: any) => console.error('Maintenance toggle failed:', err?.response?.data?.detail || err.message),
  });

  const provisionMutation = useMutation({
    mutationFn: () => voipApi.provisionPhone(id!, { force: true }),
    onSuccess: invalidatePhone,
    onError: (err: any) => console.error('Provision failed:', err?.response?.data?.detail || err.message),
  });

  const connTestMutation = useMutation({
    mutationFn: (data: { username: string; password: string; save_credentials: boolean }) =>
      voipApi.testPhoneConnection(id!, data),
    onSuccess: (res) => {
      setConnTestResult(res.data);
      if (res.data?.authenticated) {
        invalidatePhone();
      }
    },
    onError: (err: any) => {
      setConnTestResult({
        success: false,
        status: 'error',
        ip_address: phone?.ip_address || '',
        authenticated: false,
        sip_registered: false,
        error: err?.response?.data?.detail || err.message || t('PhoneDetailPage.connTest.testFailed'),
      });
    },
  });

  // ── Push SIP Config dialog state + mutation ─────────────────────
  const [showPushSipDialog, setShowPushSipDialog] = useState(false);
  const [pushSipPassword, setPushSipPassword] = useState('');
  const [pushSipPreview, setPushSipPreview] = useState<any>(null);

  const pushSipDryRunMutation = useMutation({
    mutationFn: () => voipApi.pushSipConfigToPhone(id!, {
      sip_password: pushSipPassword || 'placeholder-for-preview',
      dry_run: true,
    }),
    onSuccess: (res) => setPushSipPreview(res.data),
    onError: (err: any) => toast({
      title: t('PhoneDetailPage.toasts.previewFailed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });
  const pushSipMutation = useMutation({
    mutationFn: () => voipApi.pushSipConfigToPhone(id!, {
      sip_password: pushSipPassword,
      dry_run: false,
    }),
    onSuccess: (res) => {
      toast({
        title: res.data?.status === 'success' ? t('PhoneDetailPage.toasts.sipConfigPushed') : t('PhoneDetailPage.toasts.pushFailed'),
        description: res.data?.message,
        variant: res.data?.status === 'success' ? 'default' : 'destructive',
      });
      if (res.data?.status === 'success') {
        setShowPushSipDialog(false);
        setPushSipPassword('');
        setPushSipPreview(null);
        invalidatePhone();
      }
    },
    onError: (err: any) => toast({
      title: t('PhoneDetailPage.toasts.pushFailed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });

  // ── Migrate dialog state + mutation ─────────────────────────────
  // Moves the phone to a different site. ``follow_links`` tries to
  // rebind PBX/extension at the new site if equivalent resources
  // exist there; otherwise the operator runs auto-link after.
  const [showMigrateDialog, setShowMigrateDialog] = useState(false);
  const [migrateTargetSite, setMigrateTargetSite] = useState<string>('');
  const [migrateFollowLinks, setMigrateFollowLinks] = useState(false);
  const [migratePreview, setMigratePreview] = useState<any>(null);

  // Other sites in the user's org (everything except the phone's
  // current site). Pulled via the same site list the global picker uses.
  const { data: sitesRes } = useQuery({
    queryKey: ['sites-for-migrate'],
    queryFn: () => sitesApi.getAll({ per_page: 100 }),
    enabled: showMigrateDialog,
    staleTime: 60_000,
  });
  const candidateSites: Array<{ id: string; name: string }> =
    (sitesRes?.data?.items || sitesRes?.data || [])
      .filter((s: any) => s.id !== phone?.site_id);

  const migrateDryRunMutation = useMutation({
    mutationFn: () => voipApi.migratePhone(id!, {
      target_site_id: migrateTargetSite,
      follow_links: migrateFollowLinks,
      dry_run: true,
    }),
    onSuccess: (res) => setMigratePreview(res.data),
    onError: (err: any) => toast({
      title: t('PhoneDetailPage.toasts.migrationPreviewFailed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });
  const migrateMutation = useMutation({
    mutationFn: () => voipApi.migratePhone(id!, {
      target_site_id: migrateTargetSite,
      follow_links: migrateFollowLinks,
      dry_run: false,
    }),
    onSuccess: (res) => {
      toast({
        title: t('PhoneDetailPage.toasts.phoneMigrated'),
        description: res.data?.message,
      });
      setShowMigrateDialog(false);
      setMigrateTargetSite('');
      setMigratePreview(null);
      invalidatePhone();
      // The phones-list query is keyed by site_id so invalidate it too
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
    },
    onError: (err: any) => toast({
      title: t('PhoneDetailPage.toasts.migrationFailed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });

  // ── Power action mutations ──────────────────────────────────────
  const [showRebootDialog, setShowRebootDialog] = useState(false);
  const [showFactoryResetDialog, setShowFactoryResetDialog] = useState(false);

  const rebootMutation = useMutation({
    mutationFn: () => voipApi.rebootPhone(id!),
    onSuccess: (res) => {
      toast({ title: t('PhoneDetailPage.toasts.rebootSent'), description: res.data?.message });
      setShowRebootDialog(false);
      invalidatePhone();
    },
    onError: (err: any) => toast({
      title: t('PhoneDetailPage.toasts.rebootFailed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });
  const factoryResetMutation = useMutation({
    mutationFn: () => voipApi.factoryResetPhone(id!),
    onSuccess: (res) => {
      toast({ title: t('PhoneDetailPage.toasts.factoryResetSent'), description: res.data?.message });
      setShowFactoryResetDialog(false);
      invalidatePhone();
    },
    onError: (err: any) => toast({
      title: t('PhoneDetailPage.toasts.factoryResetFailed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });

  // ── Live status (5s polling) ────────────────────────────────────
  // Cheap probe of the phone's current line state, only enabled when
  // the phone has saved admin creds, otherwise we'd 400 every 5 s.
  const hasAdminCreds = !!(phone?.settings as any)?.web_password;
  const { data: liveStatusRes } = useQuery({
    queryKey: ['voip-phone-live', id],
    queryFn: () => voipApi.getPhoneLiveStatus(id!),
    enabled: !!id && !!phone && hasAdminCreds,
    refetchInterval: 5_000,
    staleTime: 2_000,
    retry: false, // surface 400/timeout immediately, don't pile up
  });
  const liveStatus: any = liveStatusRes?.data ?? null;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!phone) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <p className="text-muted-foreground">{t('PhoneDetailPage.notFound.title')}</p>
        <Button variant="outline" onClick={() => navigate('/voip/phones')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.notFound.back')}
        </Button>
      </div>
    );
  }

  const hasQueryError = phoneError || configPreviewError || templatesError;

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={PhoneIcon}
        title={phone.name}
        description={[phone.vendor, phone.model, phone.mac_address].filter(Boolean).join(' · ')}
        breadcrumbs={
          <Link to="/voip/phones" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" /> {t('PhoneDetailPage.notFound.back')}
          </Link>
        }
        actions={
          <>
            <PhoneStatusBadge status={phone.status} />
            <LifecycleBadge state={phone.lifecycle_state} />
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.actions.refresh')}
            </Button>
            {phone.lifecycle_state === 'discovered' && (
              <Button size="sm" onClick={() => {
                setOnboardData({ name: phone.name || '', config_template_id: '', location: phone.location || '' });
                setShowOnboardDialog(true);
              }}>
                <Upload className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.actions.onboard')}
              </Button>
            )}
            {phone.lifecycle_state === 'managed' && (
              <Button size="sm" onClick={() => provisionMutation.mutate()}>
                <Settings className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.actions.provision')}
              </Button>
            )}
          </>
        }
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('PhoneDetailPage.errorBanner')}</span>
          </CardContent>
        </Card>
      )}

      {/* Live state strip, only when we have creds + the probe came
          back. Auto-refreshes every 5 s via the useQuery refetch
          interval set up above. */}
      {hasAdminCreds && liveStatus && (() => {
        const state = String(liveStatus.phone_state || 'unknown').toLowerCase();
        const lines: any[] = liveStatus.active_lines || [];
        const isBusy = state === 'in_call' || state === 'ringing' || lines.length > 0;
        const dotClass =
          state === 'in_call' ? 'bg-warning animate-pulse' :
          state === 'ringing' ? 'bg-primary animate-pulse' :
          state === 'available' ? 'bg-success' :
          'bg-muted-foreground/40';
        return (
          <Card className={cn('border-l-4', isBusy ? 'border-l-warning' : 'border-l-success')}>
            <CardContent noOffset className="p-3 flex items-center gap-4">
              <div className={cn('h-2.5 w-2.5 rounded-full shrink-0', dotClass)} />
              <div className="flex-1 flex items-center gap-6 flex-wrap text-sm">
                <div>
                  <span className="text-muted-foreground mr-2">{t('PhoneDetailPage.liveState.label')}</span>
                  <span className="font-medium capitalize">{state.replace('_',' ')}</span>
                </div>
                <div>
                  <span className="text-muted-foreground mr-2">{t('PhoneDetailPage.liveState.lines')}</span>
                  <span className="font-mono">{t('PhoneDetailPage.liveState.linesValue', { active: lines.length, total: liveStatus.total_lines || 0 })}</span>
                </div>
                {liveStatus.lockout && liveStatus.lockout !== 'ok' && (
                  <div className="text-destructive font-medium">
                    {t('PhoneDetailPage.liveState.lockout', { lockout: liveStatus.lockout })}
                  </div>
                )}
                {lines.length > 0 && (
                  <div className="text-xs text-muted-foreground">
                    {lines.map((l: any) =>
                      `L${l.line}: ${l.state}${l.remote_number ? ` ↔ ${l.remote_number}` : ''}`
                    ).join('  ·  ')}
                  </div>
                )}
              </div>
              <span className="text-[10px] text-muted-foreground">{t('PhoneDetailPage.liveState.refresh')}</span>
            </CardContent>
          </Card>
        );
      })()}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">{t('PhoneDetailPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="config">{t('PhoneDetailPage.tabs.config')}</TabsTrigger>
          <TabsTrigger value="provisioning">{t('PhoneDetailPage.tabs.provisioning')}</TabsTrigger>
          <TabsTrigger value="network">{t('PhoneDetailPage.tabs.network')}</TabsTrigger>
          <TabsTrigger value="actions">{t('PhoneDetailPage.tabs.actions')}</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Device Info */}
            <Card>
              <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.overview.deviceInfo')}</CardTitle></CardHeader>
              <CardContent>
                <InfoRow label={t('PhoneDetailPage.fields.name')} value={phone.name} />
                <InfoRow label={t('PhoneDetailPage.fields.vendor')} value={phone.vendor} />
                <InfoRow label={t('PhoneDetailPage.fields.model')} value={phone.model} />
                <InfoRow label={t('PhoneDetailPage.fields.macAddress')} value={phone.mac_address} mono />
                <InfoRow label={t('PhoneDetailPage.fields.serialNumber')} value={phone.serial_number} mono />
                <InfoRow label={t('PhoneDetailPage.fields.firmware')} value={phone.firmware_version} mono />
                <InfoRow label={t('PhoneDetailPage.fields.location')} value={phone.location} />
              </CardContent>
            </Card>

            {/* Status & Health */}
            <Card>
              <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.overview.statusHealth')}</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('PhoneDetailPage.fields.status')}</span>
                  <PhoneStatusBadge status={phone.status} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('PhoneDetailPage.fields.lifecycle')}</span>
                  <LifecycleBadge state={phone.lifecycle_state} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('PhoneDetailPage.fields.sipRegistration')}</span>
                  <SIPIndicator registered={phone.sip_registered} />
                </div>
                <Separator />
                {phone.uptime_seconds != null && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5" /> {t('PhoneDetailPage.fields.uptime')}
                    </span>
                    <span className="text-sm font-mono">{formatUptime(phone.uptime_seconds)}</span>
                  </div>
                )}
                {phone.cpu_usage != null && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground flex items-center gap-1.5">
                        <Cpu className="h-3.5 w-3.5" /> {t('PhoneDetailPage.fields.cpu')}
                      </span>
                      <span>{phone.cpu_usage.toFixed(1)}%</span>
                    </div>
                    <Progress value={phone.cpu_usage} />
                  </div>
                )}
                {phone.memory_usage != null && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground flex items-center gap-1.5">
                        <HardDrive className="h-3.5 w-3.5" /> {t('PhoneDetailPage.fields.memory')}
                      </span>
                      <span>{phone.memory_usage.toFixed(1)}%</span>
                    </div>
                    <Progress value={phone.memory_usage} />
                  </div>
                )}
                <InfoRow label={t('PhoneDetailPage.fields.lastSeen')} value={formatTimeAgo(phone.last_seen)} />
                <InfoRow label={t('PhoneDetailPage.fields.lastPolled')} value={formatTimeAgo(phone.last_polled)} />
              </CardContent>
            </Card>

            {/* PBX Association */}
            <Card>
              <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.overview.pbxAssociation')}</CardTitle></CardHeader>
              <CardContent>
                <InfoRow label={t('PhoneDetailPage.fields.pbxSystem')} value={phone.pbx_system_name || phone.pbx_system_id} />
                <InfoRow label={t('PhoneDetailPage.fields.extension')} value={phone.extension} />
                <InfoRow label={t('PhoneDetailPage.fields.sipUser')} value={phone.sip_user} mono />
              </CardContent>
            </Card>

            {/* Tags & Metadata */}
            <Card>
              <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.overview.tagsMetadata')}</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap gap-1.5">
                  {phone.tags && phone.tags.length > 0 ? (
                    phone.tags.map((tag: string) => (
                      <Badge key={tag} variant="secondary">{tag}</Badge>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">{t('PhoneDetailPage.overview.noTags')}</span>
                  )}
                </div>
                <Separator />
                <InfoRow label={t('PhoneDetailPage.fields.discoveryMethod')} value={phone.discovery_method} />
                <InfoRow label={t('PhoneDetailPage.fields.created')} value={phone.created_at ? new Date(phone.created_at).toLocaleDateString() : null} />
                <InfoRow label={t('PhoneDetailPage.fields.updated')} value={phone.updated_at ? new Date(phone.updated_at).toLocaleDateString() : null} />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Config Tab */}
        <TabsContent value="config" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="space-y-4">
              <Card>
                <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.config.templateAssignment')}</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-2">
                    <Label>{t('PhoneDetailPage.fields.configTemplate')}</Label>
                    <Select value={phone.config_template_id || ''} disabled>
                      <SelectTrigger><SelectValue placeholder={t('PhoneDetailPage.config.noTemplateAssigned')} /></SelectTrigger>
                      <SelectContent>
                        {templates.map((tpl: any) => (
                          <SelectItem key={tpl.id} value={tpl.id}>{tpl.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <Button variant="outline" className="w-full" onClick={() => navigate('/voip/templates')}>
                    <FileText className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.config.manageTemplates')}
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.config.provisioningInfo')}</CardTitle></CardHeader>
                <CardContent>
                  <InfoRow label={t('PhoneDetailPage.fields.status')} value={phone.provision_status} />
                  <InfoRow label={t('PhoneDetailPage.fields.configTemplate')} value={phone.config_template_id ? t('PhoneDetailPage.values.assigned') : t('PhoneDetailPage.values.none')} />
                  <InfoRow label={t('PhoneDetailPage.fields.vendor')} value={phone.vendor} />
                  <InfoRow label={t('PhoneDetailPage.fields.model')} value={phone.model} />
                </CardContent>
              </Card>
            </div>

            <div className="lg:col-span-2">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0">
                  <div>
                    <CardTitle className="text-base">{t('PhoneDetailPage.config.configPreview')}</CardTitle>
                    <CardDescription>{t('PhoneDetailPage.config.configPreviewDesc')}</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => refetchPreview()}>
                      <RefreshCw className="h-3.5 w-3.5 mr-1" /> {t('PhoneDetailPage.actions.refresh')}
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(configPreview)}>
                      <Copy className="h-3.5 w-3.5 mr-1" /> {t('PhoneDetailPage.actions.copy')}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {configPreviewLoading ? (
                    <div className="flex items-center justify-center h-48">
                      <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
                    </div>
                  ) : configPreview ? (
                    <pre className="p-4 bg-muted rounded-lg text-xs font-mono overflow-auto max-h-[500px] whitespace-pre-wrap">
                      {configPreview}
                    </pre>
                  ) : (
                    <div className="text-center text-muted-foreground py-12">
                      <Code className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p>{t('PhoneDetailPage.config.noTemplateAssigned')}</p>
                      <p className="text-xs">{t('PhoneDetailPage.config.assignTemplateHint')}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* Provisioning Tab */}
        <TabsContent value="provisioning" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('PhoneDetailPage.provisioning.statusTitle')}</CardTitle>
                <CardDescription>{t('PhoneDetailPage.provisioning.statusDesc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm">{t('PhoneDetailPage.fields.currentStatus')}</span>
                  <ProvisionBadge status={phone.provision_status} />
                </div>
                <Separator />
                <InfoRow label={t('PhoneDetailPage.fields.autoProvisionUrl')} value={phone.mac_address ? `/provisioning/cfg${phone.mac_address?.replace(/:/g, '')}.xml` : null} mono />
                <InfoRow label={t('PhoneDetailPage.fields.template')} value={phone.config_template_id || t('PhoneDetailPage.values.none')} />
                <Separator />
                <Button className="w-full" onClick={() => provisionMutation.mutate()} disabled={provisionMutation.isPending}>
                  <Settings className="h-4 w-4 mr-2" />
                  {provisionMutation.isPending ? t('PhoneDetailPage.provisioning.provisioning') : t('PhoneDetailPage.provisioning.provisionNow')}
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('PhoneDetailPage.provisioning.firmware')}</CardTitle>
                <CardDescription>{t('PhoneDetailPage.provisioning.firmwareDesc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <InfoRow label={t('PhoneDetailPage.fields.currentVersion')} value={phone.firmware_version} mono />
                <InfoRow label={t('PhoneDetailPage.fields.vendor')} value={phone.vendor} />
                <InfoRow label={t('PhoneDetailPage.fields.model')} value={phone.model} />
                <Separator />
                <Button variant="outline" className="w-full" onClick={() => navigate('/voip/firmware')}>
                  <Shield className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.actions.firmwareManagement')}
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Network Tab */}
        <TabsContent value="network" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.network.detailsTitle')}</CardTitle></CardHeader>
              <CardContent>
                <InfoRow label={t('PhoneDetailPage.fields.ipAddress')} value={phone.ip_address} mono />
                <InfoRow label={t('PhoneDetailPage.fields.macAddress')} value={phone.mac_address} mono />
                <InfoRow label={t('PhoneDetailPage.fields.subnet')} value={phone.subnet} mono />
                <InfoRow label={t('PhoneDetailPage.fields.vlan')} value={phone.vlan_id} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-base">{t('PhoneDetailPage.fields.sipRegistration')}</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('PhoneDetailPage.fields.status')}</span>
                  <SIPIndicator registered={phone.sip_registered} />
                </div>
                <InfoRow label={t('PhoneDetailPage.fields.sipUser')} value={phone.sip_user || (phone.settings as any)?.sip_user_id} mono />
                <InfoRow label={t('PhoneDetailPage.fields.extension')} value={phone.extension} />
                <InfoRow label={t('PhoneDetailPage.fields.sipRegistrar')} value={(phone.settings as any)?.sip_registrar} mono />
                <InfoRow label={t('PhoneDetailPage.fields.pbx')} value={phone.pbx_system_name || phone.pbx_system_id} />
              </CardContent>
            </Card>
          </div>

          {/* Connection Test */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Link2 className="h-4 w-4" /> {t('PhoneDetailPage.connTest.title')}
              </CardTitle>
              <CardDescription>
                {t('PhoneDetailPage.connTest.description')}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label className="text-sm">{t('PhoneDetailPage.connTest.username')}</Label>
                  <Input
                    value={connUsername}
                    onChange={(e) => setConnUsername(e.target.value)}
                    placeholder="admin"
                    autoComplete="off"
                  />
                </div>
                <div className="grid gap-2">
                  <Label className="text-sm">{t('PhoneDetailPage.connTest.password')}</Label>
                  <div className="relative">
                    <Input
                      type={showConnPassword ? 'text' : 'password'}
                      value={connPassword}
                      onChange={(e) => setConnPassword(e.target.value)}
                      placeholder="admin"
                      autoComplete="off"
                    />
                    <Button
                      variant="ghost" size="icon"
                      className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                      onClick={() => setShowConnPassword(!showConnPassword)}
                    >
                      {showConnPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </Button>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Switch
                    id="save-creds"
                    checked={saveCredsOnSuccess}
                    onCheckedChange={setSaveCredsOnSuccess}
                  />
                  <Label htmlFor="save-creds" className="text-sm cursor-pointer">
                    {t('PhoneDetailPage.connTest.saveCreds')}
                  </Label>
                </div>
                <Button
                  onClick={() => connTestMutation.mutate({
                    username: connUsername,
                    password: connPassword,
                    save_credentials: saveCredsOnSuccess,
                  })}
                  disabled={connTestMutation.isPending || !phone.ip_address}
                >
                  {connTestMutation.isPending ? (
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Link2 className="h-4 w-4 mr-2" />
                  )}
                  {connTestMutation.isPending ? t('PhoneDetailPage.connTest.testing') : t('PhoneDetailPage.connTest.testConnection')}
                </Button>
              </div>

              {/* Connection Test Result */}
              {connTestResult && (
                <div className="space-y-3 pt-2">
                  <Card className={cn(
                    'border',
                    connTestResult.authenticated
                      ? 'border-emerald-500/30 bg-emerald-500/5'
                      : connTestResult.api_accessible
                        ? 'border-blue-500/30 bg-blue-500/5'
                        : connTestResult.success
                          ? 'border-amber-500/30 bg-amber-500/5'
                          : 'border-red-500/30 bg-red-500/5'
                  )}>
                    <CardContent noOffset className="py-3">
                      <div className="flex items-center gap-3 mb-3">
                        {connTestResult.authenticated ? (
                          <CheckCircle className="h-5 w-5 text-emerald-500 shrink-0" />
                        ) : connTestResult.api_accessible ? (
                          <CheckCircle className="h-5 w-5 text-blue-500 shrink-0" />
                        ) : connTestResult.success ? (
                          <Unlock className="h-5 w-5 text-amber-500 shrink-0" />
                        ) : (
                          <XCircle className="h-5 w-5 text-red-500 shrink-0" />
                        )}
                        <div>
                          <p className="text-sm font-medium">
                            {connTestResult.authenticated
                              ? t('PhoneDetailPage.connTest.result.authenticated')
                              : connTestResult.status === 'identified' && connTestResult.api_accessible
                                ? t('PhoneDetailPage.connTest.result.configReadable')
                                : connTestResult.status === 'identified'
                                  ? t('PhoneDetailPage.connTest.result.identified')
                                  : connTestResult.status === 'reachable'
                                    ? t('PhoneDetailPage.connTest.result.reachable')
                                    : connTestResult.status === 'locked_out'
                                      ? t('PhoneDetailPage.connTest.result.lockedOut')
                                      : connTestResult.status === 'unreachable'
                                        ? t('PhoneDetailPage.connTest.result.unreachable')
                                        : t('PhoneDetailPage.connTest.result.error', { error: connTestResult.error || t('PhoneDetailPage.values.unknown') })}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {t('PhoneDetailPage.connTest.result.statusIp', { status: connTestResult.status, ip: connTestResult.ip_address })}
                            {connTestResult.api_accessible && !connTestResult.authenticated && t('PhoneDetailPage.connTest.result.apiAccessibleSuffix')}
                          </p>
                          {connTestResult.auth_note && (
                            <p className="text-xs text-muted-foreground mt-0.5 italic">
                              {connTestResult.auth_note}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* Device Info Grid */}
                      {(connTestResult.mac_address || connTestResult.model || connTestResult.firmware_version) && (
                        <>
                          <Separator className="my-2" />
                          <div className="grid grid-cols-2 gap-2 text-sm">
                            {connTestResult.vendor && (
                              <div>
                                <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.vendor')}</span>{' '}
                                <span className="capitalize">{connTestResult.vendor}</span>
                              </div>
                            )}
                            {connTestResult.model && (
                              <div>
                                <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.model')}</span>{' '}
                                <span className="font-mono">{connTestResult.model}</span>
                              </div>
                            )}
                            {connTestResult.mac_address && (
                              <div>
                                <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.mac')}</span>{' '}
                                <span className="font-mono">{connTestResult.mac_address}</span>
                              </div>
                            )}
                            {connTestResult.firmware_version && (
                              <div>
                                <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.firmware')}</span>{' '}
                                <span className="font-mono">{connTestResult.firmware_version}</span>
                              </div>
                            )}
                            {connTestResult.config_items != null && (
                              <div>
                                <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.configItems')}</span>{' '}
                                <span>{connTestResult.config_items.toLocaleString()}</span>
                              </div>
                            )}
                            {connTestResult.lockout_status && (
                              <div>
                                <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.lockout')}</span>{' '}
                                <Badge variant={connTestResult.lockout_status === 'ok' ? 'secondary' : 'destructive'} className="ml-1 text-xs">
                                  {connTestResult.lockout_status === 'ok' ? t('PhoneDetailPage.connTest.result.notLocked') : connTestResult.lockout_status}
                                </Badge>
                              </div>
                            )}
                          </div>
                        </>
                      )}

                      {/* Network Info */}
                      {connTestResult.network_info && Object.keys(connTestResult.network_info).length > 0 && (
                        <>
                          <Separator className="my-2" />
                          <div className="grid grid-cols-2 gap-2 text-sm">
                            {Object.entries(connTestResult.network_info).map(([key, value]) => (
                              <div key={key}>
                                <span className="text-muted-foreground capitalize">{key.replace(/_/g, ' ')}:</span>{' '}
                                <span className="font-mono">{value}</span>
                              </div>
                            ))}
                          </div>
                        </>
                      )}

                      {/* SIP Info */}
                      {(connTestResult.sip_account || connTestResult.sip_registered || (connTestResult.sip_accounts && connTestResult.sip_accounts.length > 0)) ? (
                        <>
                          <Separator className="my-2" />
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-2 text-sm">
                              <PhoneIcon className="h-3.5 w-3.5 text-muted-foreground" />
                              <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.sip')}</span>
                              {connTestResult.sip_registered ? (
                                <Badge className="bg-emerald-500/10 text-emerald-500 text-xs">{t('PhoneDetailPage.connTest.result.registered')}</Badge>
                              ) : (
                                <Badge variant="secondary" className="text-xs">{t('PhoneDetailPage.connTest.result.notRegistered')}</Badge>
                              )}
                              {connTestResult.sip_account && (
                                <span className="font-mono text-sm">
                                  {connTestResult.sip_account}
                                  {connTestResult.sip_registrar ? ` @ ${connTestResult.sip_registrar}` : ''}
                                </span>
                              )}
                            </div>
                            {connTestResult.sip_accounts && connTestResult.sip_accounts.length > 0 && (
                              <div className="pl-5 space-y-1">
                                {connTestResult.sip_accounts.map((acct, i) => (
                                  <div key={i} className="text-xs text-muted-foreground">
                                    {t('PhoneDetailPage.connTest.result.account', { account: acct.account || i + 1 })}
                                    {acct.user_id && <span className="font-mono ml-1">{acct.user_id}</span>}
                                    {acct.server && <span className="ml-1">@ {acct.server}</span>}
                                    {acct.active === '1' && <Badge className="ml-1 bg-emerald-500/10 text-emerald-500 text-[10px] py-0">{t('PhoneDetailPage.connTest.result.active')}</Badge>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </>
                      ) : connTestResult.api_accessible && (
                        <>
                          <Separator className="my-2" />
                          <div className="flex items-center gap-2 text-sm">
                            <PhoneIcon className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="text-muted-foreground">{t('PhoneDetailPage.connTest.result.sip')}</span>
                            <Badge variant="outline" className="text-xs">{t('PhoneDetailPage.connTest.result.notConfigured')}</Badge>
                          </div>
                        </>
                      )}

                      {/* Raw data toggle */}
                      {connTestResult.raw_data && Object.keys(connTestResult.raw_data).length > 0 && (
                        <>
                          <Separator className="my-2" />
                          <details className="text-xs">
                            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                              {t('PhoneDetailPage.connTest.result.rawPValues', { count: Object.keys(connTestResult.raw_data).length })}
                            </summary>
                            <pre className="mt-2 p-2 bg-muted/50 rounded text-xs font-mono overflow-x-auto max-h-40 overflow-y-auto">
                              {JSON.stringify(connTestResult.raw_data, null, 2)}
                            </pre>
                          </details>
                        </>
                      )}
                    </CardContent>
                  </Card>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Actions Tab */}
        <TabsContent value="actions" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Lifecycle */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('PhoneDetailPage.lifecycle.title')}</CardTitle>
                <CardDescription>{t('PhoneDetailPage.lifecycle.description')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {phone.lifecycle_state === 'discovered' && (
                  <Button className="w-full justify-start" onClick={() => {
                    setOnboardData({ name: phone.name || '', config_template_id: '', location: phone.location || '' });
                    setShowOnboardDialog(true);
                  }}>
                    <Upload className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.lifecycle.onboardDevice')}
                  </Button>
                )}
                {phone.lifecycle_state === 'managed' && (
                  <Button variant="outline" className="w-full justify-start"
                    onClick={() => maintenanceMutation.mutate(true)}>
                    <Wrench className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.lifecycle.enterMaintenance')}
                  </Button>
                )}
                {phone.lifecycle_state === 'maintenance' && (
                  <Button variant="outline" className="w-full justify-start"
                    onClick={() => maintenanceMutation.mutate(false)}>
                    <CheckCircle className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.lifecycle.exitMaintenance')}
                  </Button>
                )}
                {phone.lifecycle_state !== 'decommissioned' && (
                  <Button variant="destructive" className="w-full justify-start"
                    onClick={() => decommissionMutation.mutate()}>
                    <XCircle className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.lifecycle.decommissionDevice')}
                  </Button>
                )}
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('PhoneDetailPage.quickActions.title')}</CardTitle>
                <CardDescription>{t('PhoneDetailPage.quickActions.description')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button variant="outline" className="w-full justify-start"
                  onClick={() => {
                    setActiveTab('network');
                    setConnTestResult(null);
                  }}>
                  <Link2 className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.testConnection')}
                </Button>

                {/* Push SIP from PBX, only meaningful when the phone
                    is linked to an extension. The button is always
                    rendered (so the operator sees it exists) but
                    disabled when no link is present with a helpful
                    tooltip-friendly label. */}
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  disabled={!phone.extension_id || !phone.pbx_id}
                  title={
                    phone.extension_id
                      ? t('PhoneDetailPage.quickActions.pushSipTooltipLinked', { extension: phone.extension || '' })
                      : t('PhoneDetailPage.quickActions.pushSipTooltipUnlinked')
                  }
                  onClick={() => {
                    setPushSipPreview(null);
                    setPushSipPassword('');
                    setShowPushSipDialog(true);
                  }}>
                  <Send className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.pushSipConfig')}
                </Button>

                <Button variant="outline" className="w-full justify-start"
                  onClick={() => provisionMutation.mutate()}>
                  <Settings className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.reprovisionConfig')}
                </Button>

                {/* Power actions, destructive, guarded behind a
                    confirmation dialog. Reboot is fine to allow
                    without saved creds, but the actual REST call
                    will 400 with a helpful message in that case. */}
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => setShowRebootDialog(true)}>
                  <Power className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.rebootPhone')}
                </Button>
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => {
                    setMigratePreview(null);
                    setMigrateTargetSite('');
                    setMigrateFollowLinks(false);
                    setShowMigrateDialog(true);
                  }}>
                  <MapPin className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.moveToSite')}
                </Button>
                <Button
                  variant="outline"
                  className="w-full justify-start text-destructive hover:text-destructive"
                  onClick={() => setShowFactoryResetDialog(true)}>
                  <RotateCcw className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.factoryReset')}
                </Button>

                <Button variant="outline" className="w-full justify-start"
                  onClick={() => navigate('/voip/discovery')}>
                  <Activity className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.discoveryScans')}
                </Button>
                <Button variant="outline" className="w-full justify-start"
                  onClick={() => navigate('/voip/templates')}>
                  <FileText className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.configTemplates')}
                </Button>
                <Button variant="outline" className="w-full justify-start"
                  onClick={() => navigate('/voip/firmware')}>
                  <Shield className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.actions.firmwareManagement')}
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* ── Push SIP Config Dialog ─────────────────────────────────
           Pulls the bound extension's identity from FreePBX and pushes
           it to the phone as Account 1 P-values. The SIP password is
           NEVER stored in FreeSDN, operator types it once per push,
           the server forwards it straight to the phone's config_update
           endpoint and discards it. */}
      <Dialog open={showPushSipDialog} onOpenChange={setShowPushSipDialog}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle>{t('PhoneDetailPage.pushSip.title')}</DialogTitle>
            <DialogDescription>
              {t('PhoneDetailPage.pushSip.descPrefix')}{' '}
              <span className="font-mono font-semibold">{phone.extension || '-'}</span>
              {phone.extension_display && (
                <> ({phone.extension_display})</>
              )}
              {' '}{t('PhoneDetailPage.pushSip.descFrom')}{' '}
              <span className="font-semibold">{phone.pbx_system_name || t('PhoneDetailPage.pushSip.linkedPbx')}</span>
              {' '}{t('PhoneDetailPage.pushSip.descSuffix')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label>{t('PhoneDetailPage.pushSip.passwordLabel')}</Label>
              <div className="relative">
                <Input
                  type="password"
                  value={pushSipPassword}
                  onChange={(e) => setPushSipPassword(e.target.value)}
                  placeholder={t('PhoneDetailPage.pushSip.passwordPlaceholder')}
                  className="font-mono"
                />
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {t('PhoneDetailPage.pushSip.secretHint', { extension: phone.extension })}
              </p>
            </div>

            {pushSipPreview && (
              <div className="rounded border bg-muted/30 p-3 space-y-1">
                <div className="text-sm font-medium">{t('PhoneDetailPage.pushSip.plan')}</div>
                <pre className="text-xs font-mono whitespace-pre-wrap">
{JSON.stringify(pushSipPreview.plan, null, 2)}
                </pre>
                <div className="text-xs text-muted-foreground mt-2">
                  {pushSipPreview.message}
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowPushSipDialog(false)}>
              {t('PhoneDetailPage.common.cancel')}
            </Button>
            <Button
              variant="outline"
              onClick={() => pushSipDryRunMutation.mutate()}
              disabled={pushSipDryRunMutation.isPending}>
              {pushSipDryRunMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {t('PhoneDetailPage.common.previewPlan')}
            </Button>
            <Button
              onClick={() => pushSipMutation.mutate()}
              disabled={!pushSipPassword || pushSipMutation.isPending}>
              {pushSipMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <Send className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.pushSip.pushToPhone')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Migrate to Site dialog ──────────────────────────────────
           Moves the phone (and its shadow inventory row + firmware
           history) to a different site. Site-scoped FreePBX links
           are cleared by default, operator runs auto-link after
           migration to bind to the new site's PBX. */}
      <Dialog open={showMigrateDialog} onOpenChange={setShowMigrateDialog}>
        <DialogContent className="sm:max-w-[520px]">
          <DialogHeader>
            <DialogTitle>{t('PhoneDetailPage.migrate.title')}</DialogTitle>
            <DialogDescription>
              {t('PhoneDetailPage.migrate.description', { ip: phone.ip_address, model: phone.model || phone.vendor })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label>{t('PhoneDetailPage.migrate.destinationSite')}</Label>
              <select
                value={migrateTargetSite}
                onChange={(e) => { setMigrateTargetSite(e.target.value); setMigratePreview(null); }}
                className="w-full px-3 py-2 border rounded-md text-sm bg-background">
                <option value="">{t('PhoneDetailPage.migrate.pickSite')}</option>
                {candidateSites.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
              {candidateSites.length === 0 && (
                <p className="text-xs text-muted-foreground mt-1">
                  {t('PhoneDetailPage.migrate.noOtherSites')}
                </p>
              )}
            </div>

            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={migrateFollowLinks}
                onChange={(e) => { setMigrateFollowLinks(e.target.checked); setMigratePreview(null); }}
                className="mt-1"
              />
              <span className="text-sm">
                <span className="font-medium">{t('PhoneDetailPage.migrate.followLinks')}</span>
                <span className="block text-xs text-muted-foreground">
                  {t('PhoneDetailPage.migrate.followLinksHint')}
                </span>
              </span>
            </label>

            {migratePreview && (
              <div className="rounded border bg-muted/30 p-3 space-y-1 text-xs">
                <div className="font-medium text-sm">{t('PhoneDetailPage.migrate.planTitle')}</div>
                <div>{t('PhoneDetailPage.migrate.fromTo')} <span className="font-mono">{phone.site_id?.slice(0, 8)} → {migratePreview.target_site_name}</span></div>
                <div>{t('PhoneDetailPage.migrate.shadowDeviceRow')} {migratePreview.shadow_device_updated ? t('PhoneDetailPage.migrate.willFollow') : t('PhoneDetailPage.migrate.notPresent')}</div>
                <div>{t('PhoneDetailPage.migrate.firmwareHistoryRows')} {migratePreview.firmware_records_updated}</div>
                <div>{t('PhoneDetailPage.migrate.pbxLink')} {migratePreview.pbx_rebound ? t('PhoneDetailPage.migrate.rebound') : (migratePreview.pbx_unlinked ? t('PhoneDetailPage.migrate.willBeCleared') : t('PhoneDetailPage.migrate.noneDash'))}</div>
                <div>{t('PhoneDetailPage.migrate.extensionLink')} {migratePreview.extension_rebound ? t('PhoneDetailPage.migrate.rebound') : (migratePreview.extension_unlinked ? t('PhoneDetailPage.migrate.willBeCleared') : t('PhoneDetailPage.migrate.noneDash'))}</div>
                <div>{t('PhoneDetailPage.migrate.configTemplate')} {migratePreview.template_unlinked ? t('PhoneDetailPage.migrate.willBeCleared') : t('PhoneDetailPage.migrate.noneDash')}</div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowMigrateDialog(false)}>
              {t('PhoneDetailPage.common.cancel')}
            </Button>
            <Button
              variant="outline"
              onClick={() => migrateDryRunMutation.mutate()}
              disabled={!migrateTargetSite || migrateDryRunMutation.isPending}>
              {migrateDryRunMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {t('PhoneDetailPage.common.previewPlan')}
            </Button>
            <Button
              onClick={() => migrateMutation.mutate()}
              disabled={!migrateTargetSite || migrateMutation.isPending}>
              {migrateMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <MapPin className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.migrate.movePhone')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Reboot Confirmation ───────────────────────────────────── */}
      <Dialog open={showRebootDialog} onOpenChange={setShowRebootDialog}>
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle>{t('PhoneDetailPage.reboot.title')}</DialogTitle>
            <DialogDescription>
              {t('PhoneDetailPage.reboot.description', { ip: phone.ip_address, model: phone.model || phone.vendor })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowRebootDialog(false)}>
              {t('PhoneDetailPage.common.cancel')}
            </Button>
            <Button
              onClick={() => rebootMutation.mutate()}
              disabled={rebootMutation.isPending}>
              {rebootMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <Power className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.reboot.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Factory Reset Confirmation (destructive) ─────────────── */}
      <Dialog open={showFactoryResetDialog} onOpenChange={setShowFactoryResetDialog}>
        <DialogContent className="sm:max-w-[460px]">
          <DialogHeader>
            <DialogTitle className="text-destructive">{t('PhoneDetailPage.factoryReset.title')}</DialogTitle>
            <DialogDescription>
              <strong className="text-destructive">{t('PhoneDetailPage.factoryReset.destructive')}</strong>{' '}
              {t('PhoneDetailPage.factoryReset.description', { ip: phone.ip_address })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowFactoryResetDialog(false)}>
              {t('PhoneDetailPage.common.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() => factoryResetMutation.mutate()}
              disabled={factoryResetMutation.isPending}>
              {factoryResetMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              <RotateCcw className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.quickActions.factoryReset')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Onboard Dialog */}
      <Dialog open={showOnboardDialog} onOpenChange={setShowOnboardDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>{t('PhoneDetailPage.onboard.title')}</DialogTitle>
            <DialogDescription>
              {t('PhoneDetailPage.onboard.description', { name: phone.name || phone.mac_address })}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label>{t('PhoneDetailPage.onboard.deviceName')}</Label>
              <Input value={onboardData.name}
                onChange={(e) => setOnboardData({ ...onboardData, name: e.target.value })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PhoneDetailPage.fields.configTemplate')}</Label>
              <Select value={onboardData.config_template_id}
                onValueChange={(v) => setOnboardData({ ...onboardData, config_template_id: v })}>
                <SelectTrigger><SelectValue placeholder={t('PhoneDetailPage.onboard.selectTemplate')} /></SelectTrigger>
                <SelectContent>
                  {templates.map((tpl: any) => (
                    <SelectItem key={tpl.id} value={tpl.id}>{tpl.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label>{t('PhoneDetailPage.fields.location')}</Label>
              <Input value={onboardData.location}
                onChange={(e) => setOnboardData({ ...onboardData, location: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowOnboardDialog(false)}>{t('PhoneDetailPage.common.cancel')}</Button>
            <Button onClick={() => onboardMutation.mutate(onboardData)}>
              <Upload className="h-4 w-4 mr-2" /> {t('PhoneDetailPage.onboard.title')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
