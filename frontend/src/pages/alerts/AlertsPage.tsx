// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Unified Alerts Console
 * ======================================
 *
 * Enterprise-grade alert management page aggregating three sources:
 *   1. Alert Rule engine alerts  (AlertInstance)
 *   2. Correlation engine incidents (Incident)
 *   3. Security audit events  (SecurityEvent)
 *
 * Features:
 *   - Deep-link tabs: /alerts, /alerts/rules, /alerts/incidents, /alerts/security
 *   - Full-width search bar
 *   - Severity & status filters
 *   - Bulk actions: acknowledge, resolve, suppress
 *   - Mark all as read (clears sidebar badge)
 *   - Detail dialog with source-specific panels
 *   - Connected to Alert Rules engine (/alert-rules)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Bell,
  AlertCircle,
  CheckCircle,
  Shield,
  ShieldAlert,
  Search,
  Eye,
  Check,
  Zap,
  Play,
  Layers,
  Siren,
  BellOff,
  CheckSquare,
  Settings,
  ArrowRight,
  AlertTriangle,
} from 'lucide-react';
import { formatDistanceToNow, format, isValid } from 'date-fns';
import { PageHeader } from '@/components/layout';
import { DataTable, type DataTableColumn, type SelectionInfo } from '@/components/ui/data-table';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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
import { EmptyState } from '@/components/ui/empty-state';
import {
  api,
  alertRulesApi,
  correlationApi,
  notificationApi,
  type AlertInstance,
  type AlertRuleStats,
  type Incident,
  type IncidentEvent,
  type CorrelationStats,
} from '@/lib/api';
import { useAlertBadgeStore } from '@/stores/alertBadgeStore';
import { useToast } from '@/hooks/use-toast';

// ─── Types ──────────────────────────────────────────────────────────────

interface SecurityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  user_id?: string;
  user_email?: string;
  ip_address?: string;
  success: boolean;
  risk_score: number;
  details: Record<string, any>;
}

/** Unified alert row that normalizes across all three sources */
interface UnifiedAlert {
  id: string;
  source: 'rule' | 'incident' | 'security';
  severity: string;
  title: string;
  description: string;
  status: string;
  timestamp: string;
  raw: AlertInstance | Incident | SecurityEvent;
}

// ─── API helpers ────────────────────────────────────────────────────────

const securityApi = {
  getAll: (params?: any) => api.get('/audit/security', { params }),
  // NOTE: there is no backend route to review/acknowledge a security event yet.
  // SecurityEventRecord HAS the reviewed/reviewed_by/reviewed_at fields, but a
  // properly-scoped endpoint isn't implemented (it's a global, no-org_id table,
  // needs careful authz). The UI disables the action instead of firing a 404.
  // TODO(post-launch): PATCH /audit/security/{id}/review (super_admin).
};

// ─── Display helpers ────────────────────────────────────────────────────
// Map domain values to StatusBadge tone variants · themes correctly in light/dark.

const SEVERITY_VARIANT: Record<string, StatusVariant> = {
  critical: 'severity_critical',
  high: 'severity_high',
  medium: 'severity_medium',
  warning: 'warning',
  low: 'severity_low',
  info: 'info',
};

const STATUS_VARIANT: Record<string, StatusVariant> = {
  firing: 'error',
  acknowledged: 'warning',
  resolved: 'success',
  suppressed: 'neutral',
  open: 'error',
  investigating: 'warning',
  mitigating: 'warning',
  closed: 'neutral',
  failed: 'error',
  success: 'success',
};

const SOURCE_LABELS: Record<string, { labelKey: string; variant: StatusVariant }> = {
  rule:     { labelKey: 'sources.rule',     variant: 'info' },
  incident: { labelKey: 'sources.incident', variant: 'info' },
  security: { labelKey: 'sources.security', variant: 'error' },
};

const SECURITY_EVENT_LABELS: Record<string, string> = {
  login_failed: 'Failed Login',
  login_success: 'Successful Login',
  password_reset: 'Password Reset',
  password_change: 'Password Change',
  mfa_failed: 'MFA Failed',
  mfa_disabled: 'MFA Disabled',
  mfa_enabled: 'MFA Enabled',
  suspicious_activity: 'Suspicious Activity',
  account_locked: 'Account Locked',
  permission_denied: 'Permission Denied',
  api_abuse: 'API Abuse Detected',
  brute_force: 'Brute Force Attempt',
  brute_force_attempt: 'Brute Force Attempt',
  session_hijack: 'Session Hijacking',
  unauthorized_access: 'Unauthorized Access',
  vpn_disconnect: 'VPN Disconnect',
};

// ─── Normalizers ────────────────────────────────────────────────────────

function normalizeAlertInstance(a: AlertInstance): UnifiedAlert {
  return {
    id: `rule:${a.id}`,
    source: 'rule',
    severity: a.severity,
    title: a.title,
    description: a.message,
    status: a.suppressed ? 'suppressed' : a.status,
    timestamp: a.fired_at,
    raw: a,
  };
}

function normalizeIncident(i: Incident): UnifiedAlert {
  return {
    id: `incident:${i.id}`,
    source: 'incident',
    severity: i.severity,
    title: i.title,
    description: i.description || `Incident with ${i.event_count} correlated events`,
    status: i.status,
    timestamp: i.opened_at,
    raw: i,
  };
}

function normalizeSecurityEvent(e: SecurityEvent): UnifiedAlert {
  const severity = e.risk_score >= 80 ? 'critical' : e.risk_score >= 60 ? 'high' : e.risk_score >= 30 ? 'medium' : 'low';
  return {
    id: `security:${e.id}`,
    source: 'security',
    severity,
    title: SECURITY_EVENT_LABELS[e.event_type] || e.event_type,
    description: `${e.user_email || 'Unknown user'} from ${e.ip_address || 'unknown IP'} · risk ${e.risk_score}`,
    status: e.success ? 'success' : 'failed',
    timestamp: e.timestamp,
    raw: e,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, warning: 2, medium: 2, low: 3, info: 4,
};

function isActiveStatus(status: string) {
  return ['firing', 'open', 'investigating', 'mitigating', 'failed'].includes(status);
}

const ALERT_TABS = ['all', 'rules', 'incidents', 'security'] as const;
type AlertTab = (typeof ALERT_TABS)[number];

function tabToPath(tab: AlertTab) {
  return tab === 'all' ? '/alerts' : `/alerts/${tab}`;
}

// ═════════════════════════════════════════════════════════════════════════
//  AlertsPage
// ═════════════════════════════════════════════════════════════════════════

export default function AlertsPage() {
  const { t } = useTranslation('alerts');
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const markAllReviewed = useAlertBadgeStore((s) => s.markAllReviewed);
  const { toast } = useToast();

  // Deep-link tab from URL path
  const activeTab: AlertTab = ALERT_TABS.includes(urlTab as AlertTab) ? (urlTab as AlertTab) : 'all';
  const setActiveTab = (t: string) => {
    navigate(tabToPath(t as AlertTab), { replace: true });
  };

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedUnified, setSelectedUnified] = useState<UnifiedAlert | null>(null);

  // Bulk selection
  const [selectedAlerts, setSelectedAlerts] = useState<UnifiedAlert[]>([]);
  const [selectionInfo, setSelectionInfo] = useState<SelectionInfo<UnifiedAlert> | null>(null);

  const handleSelectionChange = useCallback((rows: UnifiedAlert[], info?: SelectionInfo<UnifiedAlert>) => {
    setSelectedAlerts(rows);
    setSelectionInfo(info || null);
  }, []);

  // ── Site Context ──
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Data Queries ──

  const alertRuleStatsQuery = useQuery({
    queryKey: ['alert-rules-stats', { siteId: selectedSiteId }],
    queryFn: async () => (await alertRulesApi.getStats(selectedSiteId ? { site_id: selectedSiteId } : {})).data,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const alertInstancesQuery = useQuery({
    queryKey: ['alert-instances-all', { siteId: selectedSiteId }],
    queryFn: async () => (await alertRulesApi.listAlerts({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) })).data,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  const correlationStatsQuery = useQuery({
    queryKey: ['correlation-stats', { siteId: selectedSiteId }],
    queryFn: async () => (await correlationApi.getStats(selectedSiteId ? { site_id: selectedSiteId } : {})).data,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const incidentsQuery = useQuery({
    queryKey: ['incidents-all', { siteId: selectedSiteId }],
    queryFn: async () => (await correlationApi.listIncidents({ limit: 200, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) })).data,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  const securityQuery = useQuery({
    queryKey: ['security-events', { siteId: selectedSiteId }],
    queryFn: async () => {
      const res = await securityApi.getAll({ page: 1, per_page: 200 });
      return res.data;
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const incidentEventsQuery = useQuery({
    queryKey: ['incident-events', selectedUnified?.source === 'incident' ? (selectedUnified.raw as Incident).id : null],
    queryFn: async () => (await correlationApi.getIncidentEvents((selectedUnified!.raw as Incident).id)).data,
    enabled: selectedUnified?.source === 'incident',
  });

  // ── Mutations ──

  const acknowledgeAlertMutation = useMutation({
    mutationFn: (id: string) => alertRulesApi.acknowledgeAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances-all'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  const resolveAlertMutation = useMutation({
    mutationFn: (id: string) => alertRulesApi.resolveAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances-all'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  const suppressAlertMutation = useMutation({
    mutationFn: ({ id, minutes, reason }: { id: string; minutes: number; reason?: string }) =>
      alertRulesApi.suppressAlert(id, { suppress_minutes: minutes, reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances-all'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  const evaluateMutation = useMutation({
    mutationFn: () => alertRulesApi.triggerEvaluation(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances-all'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  const updateIncidentMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Incident> }) =>
      correlationApi.updateIncident(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents-all'] });
      queryClient.invalidateQueries({ queryKey: ['correlation-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  const triggerCorrelationMutation = useMutation({
    mutationFn: () => correlationApi.trigger({}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents-all'] });
      queryClient.invalidateQueries({ queryKey: ['correlation-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  const markAllReadMutation = useMutation({
    mutationFn: () => notificationApi.markAllAsRead(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts-count-rules'] });
      queryClient.invalidateQueries({ queryKey: ['alerts-count-correlation'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
      queryClient.invalidateQueries({ queryKey: ['correlation-stats'] });
      queryClient.invalidateQueries({ queryKey: ['security-events'] });
      queryClient.invalidateQueries({ queryKey: ['alert-instances-all'] });
      queryClient.invalidateQueries({ queryKey: ['incidents-all'] });
    },
    onError: (err: any) => {
      toast({ title: t('AlertsPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertsPage.toast.operationFailed'), variant: "destructive" });
    },
  });

  // ── Extracted data ──

  const ruleStats: AlertRuleStats | null = alertRuleStatsQuery.data || null;
  const correlationStats: CorrelationStats | null = correlationStatsQuery.data || null;

  // ── Build unified list ──

  const unifiedAlerts: UnifiedAlert[] = useMemo(() => {
    const alertInstances: AlertInstance[] = alertInstancesQuery.data?.alerts ?? [];
    const incidents: Incident[] = incidentsQuery.data?.incidents ?? [];
    const securityEvents: SecurityEvent[] = (Array.isArray(securityQuery.data) ? securityQuery.data : securityQuery.data?.items ?? []) as SecurityEvent[];

    const all: UnifiedAlert[] = [
      ...alertInstances.map(normalizeAlertInstance),
      ...incidents.map(normalizeIncident),
      ...securityEvents.map(normalizeSecurityEvent),
    ];
    all.sort((a, b) => {
      const sevA = SEVERITY_ORDER[a.severity] ?? 5;
      const sevB = SEVERITY_ORDER[b.severity] ?? 5;
      if (sevA !== sevB) return sevA - sevB;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
    return all;
  }, [alertInstancesQuery.data?.alerts, incidentsQuery.data?.incidents, securityQuery.data]);

  // ── Filters ──

  function filterAlerts(list: UnifiedAlert[]): UnifiedAlert[] {
    return list.filter((a) => {
      if (severityFilter !== 'all') {
        const sev = a.severity;
        if (severityFilter === 'warning') {
          if (sev !== 'warning' && sev !== 'medium') return false;
        } else if (sev !== severityFilter) return false;
      }
      if (statusFilter === 'active' && !isActiveStatus(a.status)) return false;
      if (statusFilter === 'resolved' && !['resolved', 'closed', 'suppressed', 'success'].includes(a.status)) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          a.title.toLowerCase().includes(q) ||
          a.description.toLowerCase().includes(q) ||
          a.source.includes(q)
        );
      }
      return true;
    });
  }

  const tabData: Record<AlertTab, UnifiedAlert[]> = {
    all: filterAlerts(unifiedAlerts),
    rules: filterAlerts(unifiedAlerts.filter((a) => a.source === 'rule')),
    incidents: filterAlerts(unifiedAlerts.filter((a) => a.source === 'incident')),
    security: filterAlerts(unifiedAlerts.filter((a) => a.source === 'security')),
  };

  // ── Stats ──

  const totalActive = unifiedAlerts.filter((a) => isActiveStatus(a.status)).length;
  const totalCritical = unifiedAlerts.filter((a) => a.severity === 'critical' && isActiveStatus(a.status)).length;
  const firingRuleAlerts = ruleStats?.firing_alerts || 0;
  const openIncidents = correlationStats?.open_incidents || 0;
  const failedSecurity = ((Array.isArray(securityQuery.data) ? securityQuery.data : securityQuery.data?.items ?? []) as SecurityEvent[]).filter((e) => !e.success).length;

  const isLoading = alertInstancesQuery.isLoading && incidentsQuery.isLoading && securityQuery.isLoading;
  const isRefreshing = alertInstancesQuery.isFetching || incidentsQuery.isFetching || securityQuery.isFetching;
  const hasQueryError = alertRuleStatsQuery.isError || alertInstancesQuery.isError || correlationStatsQuery.isError || incidentsQuery.isError || securityQuery.isError;

  const refetchAll = () => {
    alertRuleStatsQuery.refetch();
    alertInstancesQuery.refetch();
    correlationStatsQuery.refetch();
    incidentsQuery.refetch();
    securityQuery.refetch();
  };

  // ── Column definition ──

  const unifiedColumns: DataTableColumn<UnifiedAlert>[] = [
    {
      id: 'severity',
      header: t('AlertsPage.columns.severity'),
      accessorKey: 'severity',
      sortable: true,
      cell: (row) => (
        <StatusBadge variant={SEVERITY_VARIANT[row.severity] || 'info'} hideIcon size="sm">
          {row.severity}
        </StatusBadge>
      ),
    },
    {
      id: 'source',
      header: t('AlertsPage.columns.source'),
      accessorKey: 'source',
      sortable: true,
      cell: (row) => {
        const s = SOURCE_LABELS[row.source];
        return <StatusBadge variant={s.variant} hideIcon size="sm">{t(`AlertsPage.${s.labelKey}`)}</StatusBadge>;
      },
    },
    {
      id: 'title',
      header: t('AlertsPage.columns.title'),
      accessorKey: 'title',
      cell: (row) => (
        <div className="max-w-md">
          <span className="font-medium">{row.title}</span>
          <p className="text-xs text-muted-foreground truncate mt-0.5">{row.description}</p>
        </div>
      ),
    },
    {
      id: 'status',
      header: t('AlertsPage.columns.status'),
      accessorKey: 'status',
      sortable: true,
      cell: (row) => (
        <StatusBadge variant={STATUS_VARIANT[row.status] || 'neutral'} hideIcon size="sm">
          {row.status}
        </StatusBadge>
      ),
    },
    {
      id: 'time',
      header: t('AlertsPage.columns.time'),
      accessorKey: 'timestamp',
      sortable: true,
      cell: (row) => (
        <span className="text-sm text-muted-foreground whitespace-nowrap">
          {row.timestamp && isValid(new Date(row.timestamp))
            ? formatDistanceToNow(new Date(row.timestamp), { addSuffix: true })
            : '—'}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <Button variant="ghost" size="sm" onClick={() => setSelectedUnified(row)}>
          <Eye className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  // ── Bulk Actions ──

  function handleBulkAcknowledge() {
    for (const alert of selectedAlerts) {
      if (alert.source === 'rule' && (alert.raw as AlertInstance).status === 'firing') {
        acknowledgeAlertMutation.mutate((alert.raw as AlertInstance).id);
      } else if (alert.source === 'incident' && (alert.raw as Incident).status === 'open') {
        updateIncidentMutation.mutate({ id: (alert.raw as Incident).id, data: { status: 'investigating' } });
      }
      // security-source events are skipped in bulk: no review endpoint yet.
    }
    setSelectedAlerts([]);
  }

  function handleBulkResolve() {
    for (const alert of selectedAlerts) {
      if (alert.source === 'rule' && ['firing', 'acknowledged'].includes((alert.raw as AlertInstance).status)) {
        resolveAlertMutation.mutate((alert.raw as AlertInstance).id);
      } else if (alert.source === 'incident' && ['open', 'investigating', 'mitigating'].includes((alert.raw as Incident).status)) {
        updateIncidentMutation.mutate({ id: (alert.raw as Incident).id, data: { status: 'resolved' } });
      }
    }
    setSelectedAlerts([]);
  }

  function handleBulkSuppress() {
    for (const alert of selectedAlerts) {
      if (alert.source === 'rule' && !(alert.raw as AlertInstance).suppressed) {
        suppressAlertMutation.mutate({ id: (alert.raw as AlertInstance).id, minutes: 60 });
      }
    }
    setSelectedAlerts([]);
  }

  // ── Single Actions ──

  function handleAcknowledge(alert: UnifiedAlert) {
    // Security-source events are intentionally not acknowledgeable from the UI
    // (no backend review endpoint yet), so canAcknowledge never fires for them
    // and this handler only handles rule/incident sources.
    if (alert.source === 'rule') {
      acknowledgeAlertMutation.mutate((alert.raw as AlertInstance).id);
    } else if (alert.source === 'incident') {
      updateIncidentMutation.mutate({
        id: (alert.raw as Incident).id,
        data: { status: 'investigating' },
      });
    }
    setSelectedUnified(null);
  }

  function handleResolve(alert: UnifiedAlert) {
    if (alert.source === 'rule') {
      resolveAlertMutation.mutate((alert.raw as AlertInstance).id);
    } else if (alert.source === 'incident') {
      updateIncidentMutation.mutate({
        id: (alert.raw as Incident).id,
        data: { status: 'resolved' },
      });
    }
    setSelectedUnified(null);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Render
  // ═══════════════════════════════════════════════════════════════════════

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <PageHeader
          title={t('AlertsPage.header.title')}
          description={t('AlertsPage.header.description')}
          icon={Bell}
          onRefresh={refetchAll}
          refreshing={isRefreshing}
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  markAllReadMutation.mutate();
                  markAllReviewed();
                }}
                disabled={markAllReadMutation.isPending || totalActive === 0}
              >
                <CheckSquare className="h-4 w-4 mr-2" />
                {t('AlertsPage.actions.markAllRead')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => evaluateMutation.mutate()}
                disabled={evaluateMutation.isPending}
              >
                <Play className="h-4 w-4 mr-2" />
                {t('AlertsPage.actions.evaluateRules')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => triggerCorrelationMutation.mutate()}
                disabled={triggerCorrelationMutation.isPending}
              >
                <Zap className="h-4 w-4 mr-2" />
                {t('AlertsPage.actions.correlate')}
              </Button>
              <Button size="sm" onClick={() => navigate('/alert-rules')}>
                <Settings className="h-4 w-4 mr-2" />
                {t('AlertsPage.actions.manageRules')}
              </Button>
            </div>
          }
        />
      </motion.div>

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('AlertsPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats Row */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          { title: t('AlertsPage.stats.activeAlerts'), value: totalActive, icon: Siren, variant: 'destructive' },
          { title: t('AlertsPage.stats.critical'), value: totalCritical, icon: AlertCircle, variant: 'destructive' },
          { title: t('AlertsPage.stats.firingRules'), value: firingRuleAlerts, icon: ShieldAlert, variant: 'primary', linkTo: '/alert-rules' },
          { title: t('AlertsPage.stats.openIncidents'), value: openIncidents, icon: Layers, variant: 'info', linkTo: '/alerts/incidents' },
          { title: t('AlertsPage.stats.failedSecurity'), value: failedSecurity, icon: Shield, variant: 'destructive', linkTo: '/alerts/security' },
        ]}
      />

      {/* Full-width search */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder={t('AlertsPage.search.placeholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <div className="flex flex-wrap gap-3">
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('AlertsPage.filters.severityPlaceholder')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('AlertsPage.filters.allSeverities')}</SelectItem>
                <SelectItem value="critical">{t('AlertsPage.filters.critical')}</SelectItem>
                <SelectItem value="high">{t('AlertsPage.filters.high')}</SelectItem>
                <SelectItem value="warning">{t('AlertsPage.filters.warningMedium')}</SelectItem>
                <SelectItem value="low">{t('AlertsPage.filters.low')}</SelectItem>
                <SelectItem value="info">{t('AlertsPage.filters.info')}</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('AlertsPage.filters.statusPlaceholder')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('AlertsPage.filters.allStatus')}</SelectItem>
                <SelectItem value="active">{t('AlertsPage.filters.active')}</SelectItem>
                <SelectItem value="resolved">{t('AlertsPage.filters.resolved')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </motion.div>

      {/* Bulk Actions Bar */}
      <BulkActionsBar
        selectedCount={selectedAlerts.length}
        onClear={() => selectionInfo?.clearSelection()}
        itemName={t('AlertsPage.bulk.itemName')}
        totalCount={tabData[activeTab].length}
        isAllPageSelected={selectionInfo?.isAllPageSelected}
        onSelectAll={selectionInfo?.selectAll}
        actions={[
          {
            label: t('AlertsPage.bulk.acknowledge'),
            icon: Check,
            onClick: handleBulkAcknowledge,
          },
          {
            label: t('AlertsPage.bulk.resolve'),
            icon: CheckCircle,
            onClick: handleBulkResolve,
          },
          {
            label: t('AlertsPage.bulk.suppress1h'),
            icon: BellOff,
            onClick: handleBulkSuppress,
          },
        ]}
      />

      {/* Tabbed Alert Table */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="all">{t('AlertsPage.tabs.all', { count: tabData.all.length })}</TabsTrigger>
            <TabsTrigger value="rules">{t('AlertsPage.tabs.rules', { count: tabData.rules.length })}</TabsTrigger>
            <TabsTrigger value="incidents">{t('AlertsPage.tabs.incidents', { count: tabData.incidents.length })}</TabsTrigger>
            <TabsTrigger value="security">{t('AlertsPage.tabs.security', { count: tabData.security.length })}</TabsTrigger>
          </TabsList>

          {ALERT_TABS.map((tab) => (
            <TabsContent key={tab} value={tab} className="mt-4">
              <DataTable
                columns={unifiedColumns}
                data={tabData[tab]}
                searchable={false}
                selectable
                onSelectionChange={handleSelectionChange}
                paginated
                defaultPageSize={25}
                itemName={t('AlertsPage.dataTable.itemName')}
                getRowId={(row) => row.id}
                isLoading={isLoading}
                emptyState={
                  <EmptyState
                    icon={CheckCircle}
                    title={t('AlertsPage.empty.title')}
                    description={
                      search || severityFilter !== 'all' || statusFilter !== 'all'
                        ? t('AlertsPage.empty.filtered')
                        : t('AlertsPage.empty.none')
                    }
                  />
                }
              />
            </TabsContent>
          ))}
        </Tabs>
      </motion.div>

      {/* Quick link to Alert Rules */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
        <Card className="border-dashed border-muted-foreground/30 hover:border-primary/50 transition-colors cursor-pointer" onClick={() => navigate('/alert-rules')}>
          <CardContent noOffset className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Settings className="h-5 w-5 text-muted-foreground" />
                <div>
                  <p className="font-medium text-sm">{t('AlertsPage.engineCard.title')}</p>
                  <p className="text-xs text-muted-foreground">
                    {t('AlertsPage.engineCard.description')}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3 text-muted-foreground">
                <span className="text-sm">{t('AlertsPage.engineCard.activeRules', { count: ruleStats?.active_rules || 0 })}</span>
                <ArrowRight className="h-4 w-4" />
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Detail Dialog */}
      <UnifiedAlertDetail
        alert={selectedUnified}
        onClose={() => setSelectedUnified(null)}
        onAcknowledge={handleAcknowledge}
        onResolve={handleResolve}
        onSuppress={(alert, minutes, reason) => {
          if (alert.source === 'rule') {
            suppressAlertMutation.mutate({ id: (alert.raw as AlertInstance).id, minutes, reason });
          }
          setSelectedUnified(null);
        }}
        incidentEvents={incidentEventsQuery.data || []}
        incidentEventsLoading={incidentEventsQuery.isLoading}
      />
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════
//  Unified Alert Detail Dialog
// ═════════════════════════════════════════════════════════════════════════

function UnifiedAlertDetail({
  alert, onClose, onAcknowledge, onResolve, onSuppress, incidentEvents, incidentEventsLoading,
}: {
  alert: UnifiedAlert | null;
  onClose: () => void;
  onAcknowledge: (a: UnifiedAlert) => void;
  onResolve: (a: UnifiedAlert) => void;
  onSuppress: (a: UnifiedAlert, minutes: number, reason?: string) => void;
  incidentEvents: IncidentEvent[];
  incidentEventsLoading: boolean;
}) {
  const { t } = useTranslation('alerts');
  const [suppressMinutes, setSuppressMinutes] = useState(60);
  const [suppressReason, setSuppressReason] = useState('');
  const [showSuppress, setShowSuppress] = useState(false);

  if (!alert) return null;

  const raw = alert.raw;
  const sourceInfo = SOURCE_LABELS[alert.source];

  // Security-source events have NO backend review/acknowledge endpoint yet, so we
  // do NOT surface an Acknowledge affordance for them (firing one would be a no-op).
  // TODO(post-launch): re-enable once PATCH /audit/security/{id}/review ships.
  const canAcknowledge =
    (alert.source === 'rule' && (raw as AlertInstance).status === 'firing') ||
    (alert.source === 'incident' && (raw as Incident).status === 'open');

  const canResolve =
    (alert.source === 'rule' && ['firing', 'acknowledged'].includes((raw as AlertInstance).status)) ||
    (alert.source === 'incident' && ['open', 'investigating', 'mitigating'].includes((raw as Incident).status));

  const canSuppress = alert.source === 'rule' && !(raw as AlertInstance).suppressed;

  return (
    <Dialog open={!!alert} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 flex-wrap">
            <StatusBadge variant={SEVERITY_VARIANT[alert.severity] || 'info'} hideIcon size="sm">
              {alert.severity}
            </StatusBadge>
            <StatusBadge variant={sourceInfo.variant} hideIcon size="sm">{t(`AlertsPage.${sourceInfo.labelKey}`)}</StatusBadge>
            <span className="text-lg">{alert.title}</span>
          </DialogTitle>
          <DialogDescription>
            {alert.timestamp && isValid(new Date(alert.timestamp))
              ? `${format(new Date(alert.timestamp), 'PPpp')} · ${formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}`
              : '—'}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <Label className="text-muted-foreground">{t('AlertsPage.detail.status')}</Label>
              <div className="mt-1">
                <StatusBadge variant={STATUS_VARIANT[alert.status] || 'neutral'} hideIcon size="sm">
                  {alert.status}
                </StatusBadge>
              </div>
            </div>
            <div>
              <Label className="text-muted-foreground">{t('AlertsPage.detail.source')}</Label>
              <div className="mt-1">
                <StatusBadge variant={sourceInfo.variant} hideIcon size="sm">{t(`AlertsPage.${sourceInfo.labelKey}`)}</StatusBadge>
              </div>
            </div>
          </div>

          {alert.description && (
            <div>
              <Label className="text-muted-foreground">{t('AlertsPage.detail.description')}</Label>
              <p className="mt-1 text-sm">{alert.description}</p>
            </div>
          )}

          {alert.source === 'rule' && <AlertRuleDetail instance={raw as AlertInstance} />}
          {alert.source === 'incident' && <IncidentDetail incident={raw as Incident} events={incidentEvents} eventsLoading={incidentEventsLoading} />}
          {alert.source === 'security' && <SecurityDetail event={raw as SecurityEvent} />}

          {showSuppress && (
            <div className="p-3 border rounded-lg space-y-3">
              <h4 className="text-sm font-medium">{t('AlertsPage.suppress.title')}</h4>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>{t('AlertsPage.suppress.durationLabel')}</Label>
                  <Input type="number" value={suppressMinutes} onChange={(e) => setSuppressMinutes(Number(e.target.value))} min={5} max={43200} />
                </div>
                <div>
                  <Label>{t('AlertsPage.suppress.reasonLabel')}</Label>
                  <Input value={suppressReason} onChange={(e) => setSuppressReason(e.target.value)} placeholder={t('AlertsPage.suppress.reasonPlaceholder')} />
                </div>
              </div>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={() => setShowSuppress(false)}>{t('AlertsPage.suppress.cancel')}</Button>
                <Button size="sm" onClick={() => { onSuppress(alert, Math.min(43200, Math.max(5, Math.round(suppressMinutes) || 5)), suppressReason || undefined); setShowSuppress(false); }}>
                  {t('AlertsPage.suppress.confirm')}
                </Button>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="flex-wrap gap-2">
          {canSuppress && !showSuppress && (
            <Button variant="outline" size="sm" onClick={() => setShowSuppress(true)}>
              <BellOff className="h-4 w-4 mr-2" />{t('AlertsPage.detail.suppress')}
            </Button>
          )}
          {canAcknowledge && (
            <Button variant="outline" size="sm" onClick={() => onAcknowledge(alert)}>
              <Check className="h-4 w-4 mr-2" />{alert.source === 'incident' ? t('AlertsPage.detail.investigate') : t('AlertsPage.detail.acknowledge')}
            </Button>
          )}
          {canResolve && (
            <Button size="sm" onClick={() => onResolve(alert)}>
              <CheckCircle className="h-4 w-4 mr-2" />{t('AlertsPage.detail.resolve')}
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={onClose}>{t('AlertsPage.detail.close')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Source-specific detail sub-components ───────────────────────────────

function AlertRuleDetail({ instance }: { instance: AlertInstance }) {
  const { t } = useTranslation('alerts');
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.occurrences')}</Label>
          <p className="mt-1 font-mono">{instance.occurrence_count}</p>
        </div>
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.notificationsSent')}</Label>
          <p className="mt-1 font-mono">{instance.notifications_sent}</p>
        </div>
        {instance.acknowledged_at && isValid(new Date(instance.acknowledged_at)) && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.acknowledged')}</Label>
            <p className="mt-1">{format(new Date(instance.acknowledged_at), 'PPpp')}</p>
          </div>
        )}
        {instance.resolved_at && isValid(new Date(instance.resolved_at)) && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.resolved')}</Label>
            <p className="mt-1">{format(new Date(instance.resolved_at), 'PPpp')}</p>
          </div>
        )}
        {instance.suppressed && instance.suppressed_until && isValid(new Date(instance.suppressed_until)) && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.suppressedUntil')}</Label>
            <p className="mt-1">{format(new Date(instance.suppressed_until), 'PPpp')}</p>
          </div>
        )}
      </div>
      {instance.tags && instance.tags.length > 0 && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.tags')}</Label>
          <div className="flex flex-wrap gap-1 mt-1">
            {instance.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
          </div>
        </div>
      )}
      {Object.keys(instance.details || {}).length > 0 && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.ruleDetail.details')}</Label>
          <pre className="mt-1 p-3 bg-muted rounded-lg text-xs overflow-auto max-h-48">
            {JSON.stringify(instance.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function IncidentDetail({ incident, events, eventsLoading }: { incident: Incident; events: IncidentEvent[]; eventsLoading: boolean }) {
  const { t } = useTranslation('alerts');
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.eventCount')}</Label>
          <p className="mt-1 font-mono">{incident.event_count}</p>
        </div>
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.affectedDevices')}</Label>
          <p className="mt-1">{incident.affected_devices?.length || 0}</p>
        </div>
        {incident.assigned_to && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.assignedTo')}</Label>
            <p className="mt-1">{incident.assigned_to}</p>
          </div>
        )}
        {incident.resolved_at && isValid(new Date(incident.resolved_at)) && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.resolved')}</Label>
            <p className="mt-1">{format(new Date(incident.resolved_at), 'PPpp')}</p>
          </div>
        )}
      </div>
      {incident.root_cause && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.rootCause')}</Label>
          <p className="mt-1 text-sm">{incident.root_cause}</p>
        </div>
      )}
      {incident.resolution_notes && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.resolutionNotes')}</Label>
          <p className="mt-1 text-sm">{incident.resolution_notes}</p>
        </div>
      )}
      {incident.tags && incident.tags.length > 0 && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.incidentDetail.tags')}</Label>
          <div className="flex flex-wrap gap-1 mt-1">
            {incident.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
          </div>
        </div>
      )}
      <div>
        <Label className="text-muted-foreground mb-2 block">{t('AlertsPage.incidentDetail.linkedEvents')}</Label>
        {eventsLoading ? (
          <Skeleton className="h-20" />
        ) : events.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('AlertsPage.incidentDetail.noLinkedEvents')}</p>
        ) : (
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {events.map((ev) => (
              <div key={ev.id} className="flex items-center gap-2 text-sm border rounded p-2">
                <Badge variant="outline">{ev.event_type || t('AlertsPage.incidentDetail.unknownEventType')}</Badge>
                <span className="text-muted-foreground">{ev.event_timestamp && isValid(new Date(ev.event_timestamp)) ? format(new Date(ev.event_timestamp), 'PPpp') : ''}</span>
                {ev.matched_pattern && <span className="ml-auto text-xs text-muted-foreground">{t('AlertsPage.incidentDetail.pattern', { pattern: ev.matched_pattern })}</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SecurityDetail({ event }: { event: SecurityEvent }) {
  const { t } = useTranslation('alerts');
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.eventType')}</Label>
          <p className="mt-1 font-mono">{event.event_type}</p>
        </div>
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.status')}</Label>
          <StatusBadge variant={event.success ? 'success' : 'error'} hideIcon size="sm">
            {event.success ? t('AlertsPage.securityDetail.success') : t('AlertsPage.securityDetail.failed')}
          </StatusBadge>
        </div>
        {event.user_email && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.userEmail')}</Label>
            <p className="mt-1">{event.user_email}</p>
          </div>
        )}
        {event.ip_address && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.ipAddress')}</Label>
            <p className="mt-1 font-mono">{event.ip_address}</p>
          </div>
        )}
        {event.user_id && (
          <div>
            <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.userId')}</Label>
            <p className="mt-1 font-mono text-xs">{event.user_id}</p>
          </div>
        )}
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.timestamp')}</Label>
          <p className="mt-1">{event.timestamp && isValid(new Date(event.timestamp)) ? format(new Date(event.timestamp), 'PPpp') : '—'}</p>
        </div>
      </div>
      {event.risk_score !== undefined && event.risk_score !== null && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.riskScore')}</Label>
          <div className="flex items-center gap-2 mt-1">
            <div className="flex-1 bg-secondary rounded-full h-2">
              <div
                className={`h-2 rounded-full ${event.risk_score >= 80 ? 'bg-red-500' : event.risk_score >= 50 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                style={{ width: `${event.risk_score}%` }}
              />
            </div>
            <span className="font-bold text-sm">{event.risk_score}%</span>
          </div>
        </div>
      )}
      {Object.keys(event.details || {}).length > 0 && (
        <div>
          <Label className="text-muted-foreground">{t('AlertsPage.securityDetail.additionalDetails')}</Label>
          <pre className="mt-1 p-3 bg-muted rounded-lg text-xs overflow-auto max-h-48">
            {JSON.stringify(event.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
