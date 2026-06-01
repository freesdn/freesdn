// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Alert Rules Engine
 * =============================================
 *
 * Full-featured alert rule configuration page:
 *   - CRUD for alert rules with threshold / pattern / anomaly types
 *   - Notification channel configuration per rule (Email, Slack, SMS, Webhook, Teams)
 *   - Channel-specific settings (webhook URL, Slack channel, email recipients)
 *   - Severity threshold for notifications
 *   - Overview of firing alerts from rules
 *   - Connected navigation to /alerts console
 *   - Provider management (configured notification providers)
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { useToast } from '@/hooks/use-toast';
import { motion } from 'framer-motion';
import {
  alertRulesApi,
  notificationApi,
  type AlertRule,
  type AlertRuleCreate,
  type AlertInstance,
  type AlertRuleStats,
  type NotificationProvider,
  type ProviderType,
} from '@/lib/api';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { SearchBar } from '@/components/ui/search-bar';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { PageSkeleton } from '@/components/ui/page-skeleton';
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
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { EmptyState } from '@/components/ui/empty-state';
import { formatDistanceToNow, format, isValid } from 'date-fns';
import {
  AlertTriangle,
  ArrowLeft,
  Bell,
  BellOff,
  Check,
  CheckCircle,
  Eye,
  Globe,
  Mail,
  MessageSquare,
  Phone,
  Play,
  Plus,
  Settings,
  Shield,
  ShieldAlert,
  Hash,
  Trash2,
  Webhook,
  Zap,
} from 'lucide-react';

// ─── Constants ──────────────────────────────────────────────────────────

const PAGE_TABS = ['rules', 'alerts', 'channels'] as const;
type PageTab = (typeof PAGE_TABS)[number];

const SEVERITY_VARIANT: Record<string, StatusVariant> = {
  critical: 'severity_critical',
  high: 'severity_high',
  warning: 'severity_medium',
  medium: 'severity_medium',
  low: 'severity_low',
  info: 'severity_info',
};

const ALERT_STATUS_VARIANT: Record<string, StatusVariant> = {
  firing: 'error',
  acknowledged: 'warning',
  resolved: 'success',
  suppressed: 'neutral',
};

const CHANNEL_ICONS: Record<string, React.ElementType> = {
  email: Mail,
  slack: Hash,
  sms: Phone,
  webhook: Webhook,
  teams: MessageSquare,
  in_app: Bell,
};

// Channel keys that drive the channel-label/summary UI. Labels are
// translated at the render site via ``buildChannelLabels(t)`` because
// module-scope cannot call the i18n hook.
const CHANNEL_KEYS = ['email', 'slack', 'sms', 'webhook', 'teams', 'in_app'] as const;

const buildChannelLabels = (t: (key: string) => string): Record<string, string> => ({
  email: t('AlertRulesPage.channels.email'),
  slack: t('AlertRulesPage.channels.slack'),
  sms: t('AlertRulesPage.channels.sms'),
  webhook: t('AlertRulesPage.channels.webhook'),
  teams: t('AlertRulesPage.channels.teams'),
  in_app: t('AlertRulesPage.channels.inApp'),
});

// ═════════════════════════════════════════════════════════════════════════
//  AlertRulesPage
// ═════════════════════════════════════════════════════════════════════════

export default function AlertRulesPage() {
  const { t } = useTranslation('enterprise');
  const channelLabels = useMemo(() => buildChannelLabels(t), [t]);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const tab: PageTab = PAGE_TABS.includes(urlTab as PageTab) ? (urlTab as PageTab) : 'rules';
  const setTab = (v: string) =>
    navigate(v === 'rules' ? '/alert-rules' : `/alert-rules/${v}`, { replace: true });

  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [showCreate, setShowCreate] = useState(false);
  const [editingRule, setEditingRule] = useState<AlertRule | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertInstance | null>(null);
  const [selectedRules, setSelectedRules] = useState<AlertRule[]>([]);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // ── Queries ──

  const siteFilter = selectedSiteId ? { site_id: selectedSiteId } : {};

  const statsQuery = useQuery({
    queryKey: ['alert-rules-stats', { siteId: selectedSiteId }],
    queryFn: async () => (await alertRulesApi.getStats(siteFilter)).data,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const rulesQuery = useQuery({
    queryKey: ['alert-rules', { siteId: selectedSiteId }],
    queryFn: async () => (await alertRulesApi.listRules(siteFilter)).data,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const alertsQuery = useQuery({
    queryKey: ['alert-instances', { siteId: selectedSiteId }],
    queryFn: async () => (await alertRulesApi.listAlerts({ limit: 200, ...siteFilter })).data,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  // Notification providers + provider-types are org-scoped; including
  // ``siteId`` in the queryKey only fragmented the cache without
  // changing the response (the API call doesn't forward site_id).
  const providersQuery = useQuery({
    queryKey: ['notification-providers'],
    queryFn: async () => (await notificationApi.getProviders()).data,
  });

  const providerTypesQuery = useQuery({
    queryKey: ['notification-provider-types'],
    queryFn: async () => (await notificationApi.getProviderTypes()).data,
  });

  // ── Mutations ──

  const createRuleMutation = useMutation({
    mutationFn: (data: AlertRuleCreate) => alertRulesApi.createRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
      setShowCreate(false);
    },
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.createFailed'), variant: "destructive" }); },
  });

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => alertRulesApi.updateRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
      setEditingRule(null);
    },
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.updateFailed'), variant: "destructive" }); },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => alertRulesApi.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-rules'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.deleteFailed'), variant: "destructive" }); },
  });

  const toggleRuleMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      alertRulesApi.updateRule(id, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alert-rules'] }),
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.toggleFailed'), variant: "destructive" }); },
  });

  const acknowledgeAlertMutation = useMutation({
    mutationFn: (id: string) => alertRulesApi.acknowledgeAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.acknowledgeFailed'), variant: "destructive" }); },
  });

  const resolveAlertMutation = useMutation({
    mutationFn: (id: string) => alertRulesApi.resolveAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.resolveFailed'), variant: "destructive" }); },
  });

  const evaluateMutation = useMutation({
    mutationFn: () => alertRulesApi.triggerEvaluation(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert-instances'] });
      queryClient.invalidateQueries({ queryKey: ['alert-rules-stats'] });
    },
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.evaluationFailed'), variant: "destructive" }); },
  });

  // The Channels tab's row-level "Test" button is a connectivity check,
  // does the provider's credentials work, can we reach the upstream? It
  // does NOT send a real notification. The full "send a real message
  // to a given recipient" flow lives in NotificationProvidersPage's
  // testing tab. The previous version called ``testProvider(id)``
  // without a recipient and the backend 400-ed every click with
  // "test_email query param required", switching to ``verifyProvider``
  // matches what the button promises.
  const testProviderMutation = useMutation({
    mutationFn: (providerId: string) => notificationApi.verifyProvider(providerId),
    onSuccess: () => toast({ title: t('AlertRulesPage.toast.providerVerifiedTitle'), description: t('AlertRulesPage.toast.providerVerifiedDesc') }),
    onError: (err: any) => { toast({ title: t('AlertRulesPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('AlertRulesPage.toast.verificationFailed'), variant: "destructive" }); },
  });

  // ── Data ──

  const stats: AlertRuleStats | null = statsQuery.data || null;
  const rules: AlertRule[] = useMemo(() => rulesQuery.data?.rules ?? [], [rulesQuery.data?.rules]);
  const alerts: AlertInstance[] = useMemo(() => alertsQuery.data?.alerts ?? [], [alertsQuery.data?.alerts]);
  const providers: NotificationProvider[] = providersQuery.data || [];
  const providerTypes: ProviderType[] = providerTypesQuery.data || [];

  // ── Filtered data ──

  const filteredRules = useMemo(() => {
    let list = rules;
    if (statusFilter !== 'all') list = list.filter((r) => r.status === statusFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.rule_type.toLowerCase().includes(q) ||
          r.severity.toLowerCase().includes(q)
      );
    }
    return list;
  }, [rules, search, statusFilter]);

  const hasActiveFilters = search !== '' || statusFilter !== 'all';

  const filteredAlerts = useMemo(() => {
    if (!search) return alerts;
    const q = search.toLowerCase();
    return alerts.filter(
      (a) =>
        a.title.toLowerCase().includes(q) ||
        a.message.toLowerCase().includes(q) ||
        a.severity.toLowerCase().includes(q)
    );
  }, [alerts, search]);

  // ── Rule columns ──

  const ruleColumns: DataTableColumn<AlertRule>[] = [
    {
      id: 'name',
      header: t('AlertRulesPage.ruleColumns.rule'),
      accessorKey: 'name',
      cell: (row) => (
        <div className="max-w-xs">
          <span className="font-medium">{row.name}</span>
          {row.description && (
            <p className="text-xs text-muted-foreground truncate">{row.description}</p>
          )}
        </div>
      ),
    },
    {
      id: 'type',
      header: t('AlertRulesPage.ruleColumns.type'),
      accessorKey: 'rule_type',
      sortable: true,
      cell: (row) => <TypeBadge type={row.rule_type} />,
    },
    {
      id: 'severity',
      header: t('AlertRulesPage.ruleColumns.severity'),
      accessorKey: 'severity',
      sortable: true,
      cell: (row) => (
        <StatusBadge variant={SEVERITY_VARIANT[row.severity] || 'severity_info'} />
      ),
    },
    {
      id: 'status',
      header: t('AlertRulesPage.ruleColumns.status'),
      accessorKey: 'status',
      sortable: true,
      cell: (row) => (
        <StatusBadge variant={row.status === 'active' ? 'success' : 'neutral'}>
          {row.status}
        </StatusBadge>
      ),
    },
    {
      id: 'channels',
      header: t('AlertRulesPage.ruleColumns.channels'),
      cell: (row) => {
        const channels = Object.keys(row.notification_channels || {}).filter(
          (key) => row.notification_channels[key]?.enabled
        );
        if (channels.length === 0) return <span className="text-muted-foreground text-xs">{t('AlertRulesPage.common.none')}</span>;
        return (
          <div className="flex gap-1">
            {channels.map((ch) => {
              const Icon = CHANNEL_ICONS[ch] || Bell;
              return (
                <span key={ch} title={channelLabels[ch] || ch} className="text-muted-foreground">
                  <Icon className="h-4 w-4" />
                </span>
              );
            })}
          </div>
        );
      },
    },
    {
      id: 'scope',
      header: t('AlertRulesPage.ruleColumns.scope'),
      accessorKey: 'scope',
      cell: (row) => <span className="capitalize text-sm">{row.scope}</span>,
    },
    {
      id: 'fire_count',
      header: t('AlertRulesPage.ruleColumns.fired'),
      accessorKey: 'fire_count',
      sortable: true,
      cell: (row) => <span className="font-mono text-sm">{row.fire_count}</span>,
    },
    {
      id: 'last_evaluated',
      header: t('AlertRulesPage.ruleColumns.lastEvaluated'),
      accessorKey: 'last_evaluated_at',
      sortable: true,
      cell: (row) =>
        row.last_evaluated_at ? (
          <span className="text-sm text-muted-foreground whitespace-nowrap">
            {formatDistanceToNow(new Date(row.last_evaluated_at), { addSuffix: true })}
          </span>
        ) : (
          <span className="text-muted-foreground text-xs">{t('AlertRulesPage.common.never')}</span>
        ),
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <div className="flex gap-1">
          <Button variant="ghost" size="sm" onClick={() => setEditingRule(row)} title={t('AlertRulesPage.actions.editRule')}>
            <Settings className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() =>
              toggleRuleMutation.mutate({
                id: row.id,
                status: row.status === 'active' ? 'disabled' : 'active',
              })
            }
          >
            {row.status === 'active' ? (
              <BellOff className="h-4 w-4" />
            ) : (
              <Bell className="h-4 w-4" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              if (confirm(t('AlertRulesPage.confirm.deleteRule', { name: row.name }))) {
                deleteRuleMutation.mutate(row.id);
              }
            }}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  // ── Alert columns ──

  const alertColumns: DataTableColumn<AlertInstance>[] = [
    {
      id: 'severity',
      header: t('AlertRulesPage.alertColumns.severity'),
      accessorKey: 'severity',
      sortable: true,
      cell: (row) => (
        <StatusBadge variant={SEVERITY_VARIANT[row.severity] || 'severity_info'} />
      ),
    },
    {
      id: 'title',
      header: t('AlertRulesPage.alertColumns.title'),
      accessorKey: 'title',
      cell: (row) => (
        <div className="max-w-sm">
          <span className="font-medium">{row.title}</span>
          <p className="text-xs text-muted-foreground truncate">{row.message}</p>
        </div>
      ),
    },
    {
      id: 'status',
      header: t('AlertRulesPage.alertColumns.status'),
      accessorKey: 'status',
      sortable: true,
      cell: (row) => {
        const s = row.suppressed ? 'suppressed' : row.status;
        return (
          <StatusBadge variant={ALERT_STATUS_VARIANT[s] || 'neutral'}>
            {s}
          </StatusBadge>
        );
      },
    },
    {
      id: 'occurrences',
      header: t('AlertRulesPage.alertColumns.count'),
      accessorKey: 'occurrence_count',
      sortable: true,
      cell: (row) => <span className="font-mono text-sm">{row.occurrence_count}</span>,
    },
    {
      id: 'notified',
      header: t('AlertRulesPage.alertColumns.notified'),
      accessorKey: 'notifications_sent',
      cell: (row) => <span className="font-mono text-sm">{row.notifications_sent}</span>,
    },
    {
      id: 'fired_at',
      header: t('AlertRulesPage.alertColumns.fired'),
      accessorKey: 'fired_at',
      sortable: true,
      cell: (row) => (
        <span className="text-sm text-muted-foreground whitespace-nowrap">
          {formatDistanceToNow(new Date(row.fired_at), { addSuffix: true })}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <div className="flex gap-1">
          <Button variant="ghost" size="sm" onClick={() => setSelectedAlert(row)}>
            <Eye className="h-4 w-4" />
          </Button>
          {row.status === 'firing' && (
            <Button variant="ghost" size="sm" onClick={() => acknowledgeAlertMutation.mutate(row.id)}>
              <Check className="h-4 w-4" />
            </Button>
          )}
          {row.status !== 'resolved' && (
            <Button variant="ghost" size="sm" onClick={() => resolveAlertMutation.mutate(row.id)}>
              <CheckCircle className="h-4 w-4" />
            </Button>
          )}
        </div>
      ),
    },
  ];

  // ── Loading ──

  if (statsQuery.isLoading) {
    return <PageSkeleton variant="list" statsCount={4} />;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Render
  // ═══════════════════════════════════════════════════════════════════════

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <PageHeader
          icon={ShieldAlert}
          title={t('AlertRulesPage.header.title')}
          description={t('AlertRulesPage.header.description')}
          onRefresh={() => {
            statsQuery.refetch();
            rulesQuery.refetch();
            alertsQuery.refetch();
            providersQuery.refetch();
          }}
          refreshing={statsQuery.isFetching || rulesQuery.isFetching}
          actions={
            <div className="flex gap-2">
              <Button variant="outline" size="sm" asChild>
                <Link to="/alerts">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  {t('AlertRulesPage.actions.alertsConsole')}
                </Link>
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => evaluateMutation.mutate()}
                disabled={evaluateMutation.isPending}
              >
                <Play className="h-4 w-4 mr-2" />
                {t('AlertRulesPage.actions.evaluateNow')}
              </Button>
              <Button size="sm" onClick={() => setShowCreate(true)}>
                <Plus className="h-4 w-4 mr-2" />
                {t('AlertRulesPage.actions.newRule')}
              </Button>
            </div>
          }
        />
      </motion.div>

      {/* Query Error Banner, also surfaces notification-channel
          query failures (previously silent: the Channels tab just
          showed an empty list with no signal). */}
      {(statsQuery.isError || rulesQuery.isError || alertsQuery.isError
        || providersQuery.isError || providerTypesQuery.isError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('AlertRulesPage.errorBanner.message')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
        {stats && (
          <StatsGrid
            stats={[
              { title: t('AlertRulesPage.stats.activeRules'), value: stats.active_rules, icon: Shield },
              { title: t('AlertRulesPage.stats.firingAlerts'), value: stats.firing_alerts, icon: ShieldAlert },
              { title: t('AlertRulesPage.stats.alerts24h'), value: stats.alerts_last_24h, icon: Bell },
              { title: t('AlertRulesPage.stats.criticalFiring'), value: stats.critical_firing, icon: AlertTriangle },
            ]}
          />
        )}
      </motion.div>

      {/* Toolbar */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}>
        <PageToolbar>
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder={t('AlertRulesPage.toolbar.searchPlaceholder')}
            className="w-full sm:w-auto"
          />
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('AlertRulesPage.toolbar.allStatuses')} /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('AlertRulesPage.toolbar.allStatuses')}</SelectItem>
              <SelectItem value="active">{t('AlertRulesPage.toolbar.active')}</SelectItem>
              <SelectItem value="disabled">{t('AlertRulesPage.toolbar.disabled')}</SelectItem>
            </SelectContent>
          </Select>
          {hasActiveFilters && (
            <Button variant="ghost" size="sm" onClick={() => { setSearch(''); setStatusFilter('all'); }}>
              {t('AlertRulesPage.toolbar.clearFilters')}
            </Button>
          )}
        </PageToolbar>
      </motion.div>

      {/* Tabs */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="rules">{t('AlertRulesPage.tabs.rules', { count: rules.length })}</TabsTrigger>
            <TabsTrigger value="alerts">{t('AlertRulesPage.tabs.alerts', { count: alerts.length })}</TabsTrigger>
            <TabsTrigger value="channels">
              {t('AlertRulesPage.tabs.channels', { count: providers.length })}
            </TabsTrigger>
          </TabsList>

          {/* ── Rules Tab ── */}
          <TabsContent value="rules" className="mt-4 space-y-4">
            <DataTable
              columns={ruleColumns}
              data={filteredRules}
              selectable
              onSelectionChange={setSelectedRules}
              searchable={false}
              paginated
              defaultPageSize={20}
              itemName={t('AlertRulesPage.itemNames.rules')}
              getRowId={(r) => r.id}
              emptyState={
                <EmptyState
                  icon={Bell}
                  title={t('AlertRulesPage.emptyRules.title')}
                  description={search ? t('AlertRulesPage.emptyRules.searchDescription') : t('AlertRulesPage.emptyRules.description')}
                  action={!search ? { label: t('AlertRulesPage.actions.newRule'), onClick: () => setShowCreate(true), icon: Plus } : undefined}
                />
              }
            />
            <BulkActionsBar
              selectedCount={selectedRules.length}
              itemName={t('AlertRulesPage.itemNames.rule')}
              onClear={() => setSelectedRules([])}
              actions={[
                {
                  label: t('AlertRulesPage.bulkActions.enable'),
                  icon: Bell,
                  onClick: () => {
                    selectedRules.forEach((r) => toggleRuleMutation.mutate({ id: r.id, status: 'active' }));
                    setSelectedRules([]);
                  },
                },
                {
                  label: t('AlertRulesPage.bulkActions.disable'),
                  icon: BellOff,
                  onClick: () => {
                    selectedRules.forEach((r) => toggleRuleMutation.mutate({ id: r.id, status: 'disabled' }));
                    setSelectedRules([]);
                  },
                },
                {
                  label: t('AlertRulesPage.bulkActions.delete'),
                  icon: Trash2,
                  variant: 'destructive',
                  onClick: () => {
                    if (confirm(t('AlertRulesPage.confirm.deleteRules', { count: selectedRules.length }))) {
                      selectedRules.forEach((r) => deleteRuleMutation.mutate(r.id));
                      setSelectedRules([]);
                    }
                  },
                },
              ]}
            />
          </TabsContent>

          {/* ── Alerts Tab ── */}
          <TabsContent value="alerts" className="mt-4">
            <DataTable
              columns={alertColumns}
              data={filteredAlerts}
              searchable={false}
              paginated
              defaultPageSize={25}
              itemName={t('AlertRulesPage.itemNames.alerts')}
              emptyState={
                <div className="text-center py-16">
                  <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                  <h3 className="text-lg font-medium">{t('AlertRulesPage.emptyAlerts.title')}</h3>
                  <p className="text-muted-foreground mt-1">{t('AlertRulesPage.emptyAlerts.description')}</p>
                </div>
              }
            />
          </TabsContent>

          {/* ── Channels Tab ── */}
          <TabsContent value="channels" className="mt-4">
            <ChannelsTab
              providers={providers}
              providerTypes={providerTypes}
              search={search}
              onTest={(id) => testProviderMutation.mutate(id)}
              testPending={testProviderMutation.isPending}
            />
          </TabsContent>
        </Tabs>
      </motion.div>

      {/* Alert Detail Dialog */}
      <AlertDetailDialog
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAcknowledge={(id) => {
          acknowledgeAlertMutation.mutate(id);
          setSelectedAlert(null);
        }}
        onResolve={(id) => {
          resolveAlertMutation.mutate(id);
          setSelectedAlert(null);
        }}
      />

      {/* Create Rule Dialog */}
      <RuleFormDialog
        open={showCreate}
        onOpenChange={setShowCreate}
        onSubmit={(data) => createRuleMutation.mutate(data)}
        isPending={createRuleMutation.isPending}
        providers={providers}
        title={t('AlertRulesPage.dialog.createTitle')}
      />

      {/* Edit Rule Dialog */}
      <RuleFormDialog
        open={!!editingRule}
        onOpenChange={(open) => !open && setEditingRule(null)}
        onSubmit={(data) => {
          if (editingRule) {
            updateRuleMutation.mutate({ id: editingRule.id, data });
          }
        }}
        isPending={updateRuleMutation.isPending}
        providers={providers}
        title={t('AlertRulesPage.dialog.editTitle')}
        initialData={editingRule || undefined}
      />
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════
//  Notification Channels Tab
// ═════════════════════════════════════════════════════════════════════════

function ChannelsTab({
  providers,
  providerTypes,
  search,
  onTest,
  testPending,
}: {
  providers: NotificationProvider[];
  providerTypes: ProviderType[];
  search: string;
  onTest: (id: string) => void;
  testPending: boolean;
}) {
  const { t } = useTranslation('enterprise');
  const channelLabels = useMemo(() => buildChannelLabels(t), [t]);
  const filtered = useMemo(() => {
    if (!search) return providers;
    const q = search.toLowerCase();
    return providers.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.provider_type.toLowerCase().includes(q) ||
        p.channel.toLowerCase().includes(q)
    );
  }, [providers, search]);

  // Group by channel
  const channelGroups = useMemo(() => {
    const groups: Record<string, NotificationProvider[]> = {};
    for (const p of filtered) {
      const ch = p.channel || 'other';
      if (!groups[ch]) groups[ch] = [];
      groups[ch].push(p);
    }
    return groups;
  }, [filtered]);

  const availableChannels = [...CHANNEL_KEYS];

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {availableChannels.map((ch) => {
          const Icon = CHANNEL_ICONS[ch] || Bell;
          const count = (channelGroups[ch] || []).length;
          const enabled = (channelGroups[ch] || []).filter((p) => p.is_enabled).length;
          return (
            <Card key={ch} className={count > 0 ? 'border-primary/30' : 'border-dashed'}>
              <CardContent noOffset className="pb-3 text-center">
                <Icon className={`h-6 w-6 mx-auto mb-2 ${count > 0 ? 'text-primary' : 'text-muted-foreground'}`} />
                <p className="text-sm font-medium">{channelLabels[ch]}</p>
                <p className="text-xs text-muted-foreground">
                  {count === 0 ? t('AlertRulesPage.channelsTab.notConfigured') : t('AlertRulesPage.channelsTab.activeCount', { enabled, count })}
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Provider list */}
      {filtered.length === 0 ? (
        <Card>
          <CardContent noOffset className="py-12 text-center">
            <Bell className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-medium">{t('AlertRulesPage.channelsTab.noProvidersTitle')}</h3>
            <p className="text-muted-foreground mt-1 mb-4 max-w-md mx-auto">
              {t('AlertRulesPage.channelsTab.noProvidersDescription')}
            </p>
            <Button variant="outline" asChild>
              <Link to="/settings/notifications">
                <Settings className="h-4 w-4 mr-2" />
                {t('AlertRulesPage.channelsTab.configureProviders')}
              </Link>
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {Object.entries(channelGroups).map(([channel, channelProviders]) => (
            <Card key={channel}>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  {(() => {
                    const Icon = CHANNEL_ICONS[channel] || Bell;
                    return <Icon className="h-5 w-5" />;
                  })()}
                  {channelLabels[channel] || channel}
                  <Badge variant="secondary" className="ml-auto">
                    {t('AlertRulesPage.channelsTab.providerCount', { count: channelProviders.length })}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="space-y-3">
                  {channelProviders.map((provider) => (
                    <div
                      key={provider.id}
                      className="flex items-center justify-between p-3 border rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`h-2 w-2 rounded-full ${
                            provider.is_enabled ? 'bg-green-500' : 'bg-muted-foreground'
                          }`}
                        />
                        <div>
                          <p className="font-medium text-sm">{provider.name}</p>
                          <p className="text-xs text-muted-foreground">{provider.provider_type}</p>
                        </div>
                        {provider.is_default && (
                          <Badge variant="outline" className="text-xs">
                            {t('AlertRulesPage.channelsTab.default')}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => onTest(provider.id)}
                          disabled={testPending || !provider.is_enabled}
                        >
                          <Zap className="h-3 w-3 mr-1" />
                          {t('AlertRulesPage.channelsTab.test')}
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Available provider types */}
      {providerTypes.length > 0 && (
        <Card className="border-dashed">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-muted-foreground">{t('AlertRulesPage.channelsTab.availableTypesTitle')}</CardTitle>
            <CardDescription>
              {t('AlertRulesPage.channelsTab.availableTypesDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex flex-wrap gap-2">
              {providerTypes.map((pt) => (
                <Badge key={pt.type} variant="outline" className="py-1.5 px-3">
                  {(() => {
                    const Icon = CHANNEL_ICONS[pt.channel] || Globe;
                    return <Icon className="h-3 w-3 mr-1.5" />;
                  })()}
                  {pt.name}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════
//  Create / Edit Rule Dialog
// ═════════════════════════════════════════════════════════════════════════

function RuleFormDialog({
  open,
  onOpenChange,
  onSubmit,
  isPending,
  providers,
  title,
  initialData,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: AlertRuleCreate) => void;
  isPending: boolean;
  providers: NotificationProvider[];
  title: string;
  initialData?: AlertRule;
}) {
  const { t } = useTranslation('enterprise');
  const [name, setName] = useState(initialData?.name || '');
  const [description, setDescription] = useState(initialData?.description || '');
  const [ruleType, setRuleType] = useState(initialData?.rule_type || 'threshold');
  const [severity, setSeverity] = useState(initialData?.severity || 'warning');
  const [scope, setScope] = useState(initialData?.scope || 'organization');
  const [autoResolve, setAutoResolve] = useState(initialData?.auto_resolve ?? true);
  const [notifyOnResolve, setNotifyOnResolve] = useState(initialData?.notify_on_resolve ?? false);
  const [checkInterval, setCheckInterval] = useState(String(initialData?.check_interval_seconds || 180));
  const [forDuration, setForDuration] = useState(String(initialData?.for_duration_seconds || 0));
  const [cooldown, setCooldown] = useState(String(initialData?.cooldown_seconds || 300));
  const [dedupeWindow, setDedupeWindow] = useState(String(initialData?.dedupe_window_seconds || 3600));
  const [tags, setTags] = useState(initialData?.tags?.join(', ') || '');

  // Conditions based on type
  const initConditions = initialData?.conditions || {};
  const [metric, setMetric] = useState(initConditions.metric || '');
  const [operator, setOperator] = useState(initConditions.operator || '>');
  const [threshold, setThreshold] = useState(String(initConditions.value || ''));
  const [eventType, setEventType] = useState(initConditions.event_type || '');
  const [minCount, setMinCount] = useState(String(initConditions.min_count || 3));
  const [timeWindow, setTimeWindow] = useState(String(initConditions.time_window_seconds || 300));
  const [stdDevThreshold, setStdDevThreshold] = useState(String(initConditions.std_dev_threshold || 3));

  // Notification channels
  const [channels, setChannels] = useState<Record<string, { enabled: boolean; config: Record<string, any> }>>(
    () => {
      const existing = initialData?.notification_channels || {};
      const result: Record<string, { enabled: boolean; config: Record<string, any> }> = {};
      for (const ch of ['email', 'slack', 'sms', 'webhook', 'teams', 'in_app']) {
        result[ch] = {
          enabled: existing[ch]?.enabled || false,
          config: existing[ch] || {},
        };
      }
      return result;
    }
  );

  const toggleChannel = (ch: string) => {
    setChannels((prev) => ({
      ...prev,
      [ch]: { ...prev[ch], enabled: !prev[ch].enabled },
    }));
  };

  const updateChannelConfig = (ch: string, key: string, value: any) => {
    setChannels((prev) => ({
      ...prev,
      [ch]: { ...prev[ch], config: { ...prev[ch].config, [key]: value } },
    }));
  };

  const handleSubmit = () => {
    const conditions: Record<string, any> = {};
    if (ruleType === 'threshold') {
      conditions.metric = metric;
      conditions.operator = operator;
      conditions.value = parseFloat(threshold);
    } else if (ruleType === 'pattern') {
      conditions.event_type = eventType;
      conditions.min_count = parseInt(minCount, 10);
      conditions.time_window_seconds = parseInt(timeWindow, 10);
    } else if (ruleType === 'anomaly') {
      // Backend evaluate_anomaly_rule z-scores this metric against its
      // recent baseline in analytics.metric_data and fires when the
      // latest sample deviates by more than std_dev_threshold sigmas.
      conditions.metric = metric;
      const sigma = parseFloat(stdDevThreshold);
      conditions.std_dev_threshold = Number.isFinite(sigma) && sigma > 0 ? sigma : 3.0;
    }

    // Build notification_channels
    const notifChannels: Record<string, any> = {};
    for (const [ch, cfg] of Object.entries(channels)) {
      if (cfg.enabled) {
        notifChannels[ch] = { enabled: true, ...cfg.config };
      }
    }

    onSubmit({
      name,
      description: description || undefined,
      rule_type: ruleType,
      severity,
      scope,
      conditions,
      auto_resolve: autoResolve,
      notify_on_resolve: notifyOnResolve,
      notification_channels: notifChannels,
      check_interval_seconds: parseInt(checkInterval, 10) || 180,
      for_duration_seconds: parseInt(forDuration, 10) || 0,
      cooldown_seconds: parseInt(cooldown, 10) || 300,
      dedupe_window_seconds: parseInt(dedupeWindow, 10) || 3600,
      tags: tags
        ? tags
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean)
        : undefined,
    });
  };

  // Reset form when initialData changes
  const key = initialData?.id || 'new';

  return (
    <Dialog open={open} onOpenChange={onOpenChange} key={key}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {t('AlertRulesPage.form.dialogDescription')}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* ── Basic Info ── */}
          <div className="space-y-4">
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              {t('AlertRulesPage.form.basicInformation')}
            </h4>
            <div>
              <Label>{t('AlertRulesPage.form.ruleName')}</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('AlertRulesPage.form.ruleNamePlaceholder')} />
            </div>
            <div>
              <Label>{t('AlertRulesPage.form.description')}</Label>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={t('AlertRulesPage.form.descriptionPlaceholder')}
                rows={2}
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <Label>{t('AlertRulesPage.form.type')}</Label>
                <Select value={ruleType} onValueChange={setRuleType}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="threshold">{t('AlertRulesPage.ruleTypes.threshold')}</SelectItem>
                    <SelectItem value="pattern">{t('AlertRulesPage.ruleTypes.pattern')}</SelectItem>
                    {/* Anomaly detection is now wired in the backend evaluator
                        (services/alert_rules.py evaluate_anomaly_rule): it
                        z-scores the configured metric against its recent
                        baseline in analytics.metric_data. */}
                    <SelectItem value="anomaly">{t('AlertRulesPage.ruleTypes.anomaly')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>{t('AlertRulesPage.form.severity')}</Label>
                {/* Backend severity pattern is ^(info|warning|critical)$;
                    low/high previously round-tripped to a 422 on submit. */}
                <Select value={severity} onValueChange={setSeverity}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="info">{t('AlertRulesPage.severities.info')}</SelectItem>
                    <SelectItem value="warning">{t('AlertRulesPage.severities.warning')}</SelectItem>
                    <SelectItem value="critical">{t('AlertRulesPage.severities.critical')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>{t('AlertRulesPage.form.scope')}</Label>
                <Select value={scope} onValueChange={setScope}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="organization">{t('AlertRulesPage.scopes.organization')}</SelectItem>
                    <SelectItem value="site">{t('AlertRulesPage.scopes.site')}</SelectItem>
                    <SelectItem value="device_group">{t('AlertRulesPage.scopes.deviceGroup')}</SelectItem>
                    <SelectItem value="device">{t('AlertRulesPage.scopes.device')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <Separator />

          {/* ── Conditions ── */}
          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              {t('AlertRulesPage.form.conditions')}
            </h4>

            {ruleType === 'threshold' && (
              <div className="p-4 border rounded-lg space-y-3 bg-muted/30">
                <div>
                  <Label>{t('AlertRulesPage.form.metric')}</Label>
                  <Input value={metric} onChange={(e) => setMetric(e.target.value)} placeholder={t('AlertRulesPage.form.metricThresholdPlaceholder')} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>{t('AlertRulesPage.form.operator')}</Label>
                    <Select value={operator} onValueChange={setOperator}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value=">">{'>'} {t('AlertRulesPage.operators.greaterThan')}</SelectItem>
                        <SelectItem value=">=">{'≥'} {t('AlertRulesPage.operators.greaterOrEqual')}</SelectItem>
                        <SelectItem value="<">{'<'} {t('AlertRulesPage.operators.lessThan')}</SelectItem>
                        <SelectItem value="<=">{'≤'} {t('AlertRulesPage.operators.lessOrEqual')}</SelectItem>
                        <SelectItem value="==">{'='} {t('AlertRulesPage.operators.equal')}</SelectItem>
                        <SelectItem value="!=">{'≠'} {t('AlertRulesPage.operators.notEqual')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>{t('AlertRulesPage.form.thresholdValue')}</Label>
                    <Input type="number" value={threshold} onChange={(e) => setThreshold(e.target.value)} placeholder="90" />
                  </div>
                </div>
              </div>
            )}

            {ruleType === 'pattern' && (
              <div className="p-4 border rounded-lg space-y-3 bg-muted/30">
                <div>
                  <Label>{t('AlertRulesPage.form.eventType')}</Label>
                  <Input value={eventType} onChange={(e) => setEventType(e.target.value)} placeholder={t('AlertRulesPage.form.eventTypePlaceholder')} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>{t('AlertRulesPage.form.minimumCount')}</Label>
                    <Input type="number" value={minCount} onChange={(e) => setMinCount(e.target.value)} placeholder="3" />
                  </div>
                  <div>
                    <Label>{t('AlertRulesPage.form.timeWindow')}</Label>
                    <Input type="number" value={timeWindow} onChange={(e) => setTimeWindow(e.target.value)} placeholder="300" />
                  </div>
                </div>
              </div>
            )}

            {ruleType === 'anomaly' && (
              <div className="p-4 border rounded-lg bg-muted/30">
                <p className="text-sm text-muted-foreground">
                  {t('AlertRulesPage.form.anomalyDescription')}
                </p>
                <div className="mt-3 grid grid-cols-2 gap-3">
                  <div>
                    <Label>{t('AlertRulesPage.form.metric')}</Label>
                    <Input value={metric} onChange={(e) => setMetric(e.target.value)} placeholder={t('AlertRulesPage.form.metricAnomalyPlaceholder')} />
                  </div>
                  <div>
                    <Label>{t('AlertRulesPage.form.thresholdValue')}</Label>
                    <Input
                      type="number"
                      min="0"
                      step="0.5"
                      value={stdDevThreshold}
                      onChange={(e) => setStdDevThreshold(e.target.value)}
                      placeholder="3"
                    />
                  </div>
                </div>
              </div>
            )}
          </div>

          <Separator />

          {/* ── Timing ── */}
          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              {t('AlertRulesPage.form.timingBehavior')}
            </h4>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>{t('AlertRulesPage.form.checkInterval')}</Label>
                <Input type="number" value={checkInterval} onChange={(e) => setCheckInterval(e.target.value)} placeholder="180" />
                <p className="text-xs text-muted-foreground mt-1">{t('AlertRulesPage.form.checkIntervalHint')}</p>
              </div>
              <div>
                <Label>{t('AlertRulesPage.form.forDuration')}</Label>
                <Input type="number" value={forDuration} onChange={(e) => setForDuration(e.target.value)} placeholder="0" />
                <p className="text-xs text-muted-foreground mt-1">{t('AlertRulesPage.form.forDurationHint')}</p>
              </div>
              <div>
                <Label>{t('AlertRulesPage.form.cooldown')}</Label>
                <Input type="number" value={cooldown} onChange={(e) => setCooldown(e.target.value)} placeholder="300" />
                <p className="text-xs text-muted-foreground mt-1">{t('AlertRulesPage.form.cooldownHint')}</p>
              </div>
              <div>
                <Label>{t('AlertRulesPage.form.dedupeWindow')}</Label>
                <Input type="number" value={dedupeWindow} onChange={(e) => setDedupeWindow(e.target.value)} placeholder="3600" />
                <p className="text-xs text-muted-foreground mt-1">{t('AlertRulesPage.form.dedupeWindowHint')}</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Switch checked={autoResolve} onCheckedChange={setAutoResolve} />
                <Label className="cursor-pointer">{t('AlertRulesPage.form.autoResolve')}</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={notifyOnResolve} onCheckedChange={setNotifyOnResolve} />
                <Label className="cursor-pointer">{t('AlertRulesPage.form.notifyOnResolve')}</Label>
              </div>
            </div>
          </div>

          <Separator />

          {/* ── Notification Channels ── */}
          <div className="space-y-4">
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              {t('AlertRulesPage.form.notificationChannels')}
            </h4>
            <p className="text-sm text-muted-foreground">
              {t('AlertRulesPage.form.notificationChannelsHint')}
            </p>

            <div className="space-y-3">
              {/* Email */}
              <ChannelConfigCard
                channel="email"
                label={t('AlertRulesPage.channels.email')}
                icon={Mail}
                enabled={channels.email?.enabled}
                onToggle={() => toggleChannel('email')}
                hasProviders={providers.some((p) => p.channel === 'email' && p.is_enabled)}
              >
                <div>
                  <Label>{t('AlertRulesPage.form.recipients')}</Label>
                  <Input
                    value={channels.email?.config?.recipients || ''}
                    onChange={(e) => updateChannelConfig('email', 'recipients', e.target.value)}
                    placeholder="ops@example.com, devops@example.com"
                  />
                </div>
                <div>
                  <Label>{t('AlertRulesPage.form.minSeverityEmail')}</Label>
                  <Select
                    value={channels.email?.config?.min_severity || 'warning'}
                    onValueChange={(v) => updateChannelConfig('email', 'min_severity', v)}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="info">{t('AlertRulesPage.severities.info')}</SelectItem>
                      <SelectItem value="warning">{t('AlertRulesPage.severities.warning')}</SelectItem>
                      <SelectItem value="critical">{t('AlertRulesPage.severities.critical')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </ChannelConfigCard>

              {/* Slack */}
              <ChannelConfigCard
                channel="slack"
                label={t('AlertRulesPage.channels.slack')}
                icon={Hash}
                enabled={channels.slack?.enabled}
                onToggle={() => toggleChannel('slack')}
                hasProviders={providers.some((p) => p.channel === 'slack' && p.is_enabled)}
              >
                <div>
                  <Label>{t('AlertRulesPage.form.slackChannel')}</Label>
                  <Input
                    value={channels.slack?.config?.channel || ''}
                    onChange={(e) => updateChannelConfig('slack', 'channel', e.target.value)}
                    placeholder="#alerts or #incident-room"
                  />
                </div>
                <div>
                  <Label>{t('AlertRulesPage.form.mention')}</Label>
                  <Input
                    value={channels.slack?.config?.mention || ''}
                    onChange={(e) => updateChannelConfig('slack', 'mention', e.target.value)}
                    placeholder={t('AlertRulesPage.form.mentionPlaceholder')}
                  />
                </div>
              </ChannelConfigCard>

              {/* SMS */}
              <ChannelConfigCard
                channel="sms"
                label={t('AlertRulesPage.channels.sms')}
                icon={Phone}
                enabled={channels.sms?.enabled}
                onToggle={() => toggleChannel('sms')}
                hasProviders={providers.some((p) => p.channel === 'sms' && p.is_enabled)}
              >
                <div>
                  <Label>{t('AlertRulesPage.form.phoneNumbers')}</Label>
                  <Input
                    value={channels.sms?.config?.phone_numbers || ''}
                    onChange={(e) => updateChannelConfig('sms', 'phone_numbers', e.target.value)}
                    placeholder="+1234567890, +9876543210"
                  />
                </div>
                <div>
                  <Label>{t('AlertRulesPage.form.minSeveritySms')}</Label>
                  <Select
                    value={channels.sms?.config?.min_severity || 'critical'}
                    onValueChange={(v) => updateChannelConfig('sms', 'min_severity', v)}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="warning">{t('AlertRulesPage.severities.warning')}</SelectItem>
                      <SelectItem value="high">{t('AlertRulesPage.severities.high')}</SelectItem>
                      <SelectItem value="critical">{t('AlertRulesPage.severities.criticalOnly')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </ChannelConfigCard>

              {/* Webhook */}
              <ChannelConfigCard
                channel="webhook"
                label={t('AlertRulesPage.channels.webhook')}
                icon={Webhook}
                enabled={channels.webhook?.enabled}
                onToggle={() => toggleChannel('webhook')}
                hasProviders={providers.some((p) => p.channel === 'webhook' && p.is_enabled)}
              >
                <div>
                  <Label>{t('AlertRulesPage.form.webhookUrl')}</Label>
                  <Input
                    value={channels.webhook?.config?.url || ''}
                    onChange={(e) => updateChannelConfig('webhook', 'url', e.target.value)}
                    placeholder="https://hooks.example.com/alerts"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>{t('AlertRulesPage.form.httpMethod')}</Label>
                    <Select
                      value={channels.webhook?.config?.method || 'POST'}
                      onValueChange={(v) => updateChannelConfig('webhook', 'method', v)}
                    >
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="POST">POST</SelectItem>
                        <SelectItem value="PUT">PUT</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>{t('AlertRulesPage.form.secretHeader')}</Label>
                    <Input
                      value={channels.webhook?.config?.secret || ''}
                      onChange={(e) => updateChannelConfig('webhook', 'secret', e.target.value)}
                      placeholder={t('AlertRulesPage.form.secretHeaderPlaceholder')}
                      type="password"
                    />
                  </div>
                </div>
                <div>
                  <Label>{t('AlertRulesPage.form.customHeaders')}</Label>
                  <Input
                    value={channels.webhook?.config?.headers || ''}
                    onChange={(e) => updateChannelConfig('webhook', 'headers', e.target.value)}
                    placeholder='{"Authorization": "Bearer ..."}'
                  />
                </div>
              </ChannelConfigCard>

              {/* Teams */}
              <ChannelConfigCard
                channel="teams"
                label={t('AlertRulesPage.channels.teams')}
                icon={MessageSquare}
                enabled={channels.teams?.enabled}
                onToggle={() => toggleChannel('teams')}
                hasProviders={providers.some((p) => p.channel === 'teams' && p.is_enabled)}
              >
                <div>
                  <Label>{t('AlertRulesPage.form.teamsWebhookUrl')}</Label>
                  <Input
                    value={channels.teams?.config?.webhook_url || ''}
                    onChange={(e) => updateChannelConfig('teams', 'webhook_url', e.target.value)}
                    placeholder="https://outlook.office.com/webhook/..."
                  />
                </div>
              </ChannelConfigCard>

              {/* In-App */}
              <ChannelConfigCard
                channel="in_app"
                label={t('AlertRulesPage.channels.inAppNotifications')}
                icon={Bell}
                enabled={channels.in_app?.enabled}
                onToggle={() => toggleChannel('in_app')}
                hasProviders={true}
              >
                <p className="text-sm text-muted-foreground">
                  {t('AlertRulesPage.form.inAppHint')}
                </p>
              </ChannelConfigCard>
            </div>
          </div>

          <Separator />

          {/* ── Tags ── */}
          <div>
            <Label>{t('AlertRulesPage.form.tags')}</Label>
            <Input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="network, critical-path, production"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('AlertRulesPage.actions.cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={!name || isPending}>
            {isPending ? t('AlertRulesPage.actions.saving') : initialData ? t('AlertRulesPage.actions.updateRule') : t('AlertRulesPage.actions.createRule')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═════════════════════════════════════════════════════════════════════════
//  Channel Configuration Card
// ═════════════════════════════════════════════════════════════════════════

function ChannelConfigCard({
  channel,
  label,
  icon: Icon,
  enabled,
  onToggle,
  hasProviders,
  children,
}: {
  channel: string;
  label: string;
  icon: React.ElementType;
  enabled: boolean;
  onToggle: () => void;
  hasProviders: boolean;
  children: React.ReactNode;
}) {
  const { t } = useTranslation('enterprise');
  return (
    <div className={`border rounded-lg transition-colors ${enabled ? 'border-primary/40 bg-primary/5' : ''}`}>
      <div className="flex items-center justify-between p-3">
        <div className="flex items-center gap-3">
          <Icon className={`h-5 w-5 ${enabled ? 'text-primary' : 'text-muted-foreground'}`} />
          <div>
            <span className="font-medium text-sm">{label}</span>
            {!hasProviders && channel !== 'in_app' && (
              <p className="text-xs text-amber-600 dark:text-amber-400">{t('AlertRulesPage.form.noProviderConfigured')}</p>
            )}
          </div>
        </div>
        <Switch checked={enabled} onCheckedChange={onToggle} />
      </div>
      {enabled && (
        <div className="px-3 pb-3 space-y-3 border-t pt-3">
          {children}
        </div>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════
//  Alert Detail Dialog
// ═════════════════════════════════════════════════════════════════════════

function AlertDetailDialog({
  alert,
  onClose,
  onAcknowledge,
  onResolve,
}: {
  alert: AlertInstance | null;
  onClose: () => void;
  onAcknowledge: (id: string) => void;
  onResolve: (id: string) => void;
}) {
  const { t } = useTranslation('enterprise');
  if (!alert) return null;

  return (
    <Dialog open={!!alert} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-lg max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <StatusBadge variant={SEVERITY_VARIANT[alert.severity] || 'severity_info'} />
            {alert.title}
          </DialogTitle>
          <DialogDescription>
            {format(new Date(alert.fired_at), 'PPpp')} -{' '}
            {formatDistanceToNow(new Date(alert.fired_at), { addSuffix: true })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <Label className="text-muted-foreground">{t('AlertRulesPage.detail.status')}</Label>
              <p className="mt-1 capitalize">{alert.suppressed ? 'suppressed' : alert.status}</p>
            </div>
            <div>
              <Label className="text-muted-foreground">{t('AlertRulesPage.detail.occurrences')}</Label>
              <p className="mt-1 font-mono">{alert.occurrence_count}</p>
            </div>
            <div>
              <Label className="text-muted-foreground">{t('AlertRulesPage.detail.notificationsSent')}</Label>
              <p className="mt-1 font-mono">{alert.notifications_sent}</p>
            </div>
            {alert.last_notified_at && isValid(new Date(alert.last_notified_at)) && (
              <div>
                <Label className="text-muted-foreground">{t('AlertRulesPage.detail.lastNotified')}</Label>
                <p className="mt-1">{format(new Date(alert.last_notified_at), 'PPpp')}</p>
              </div>
            )}
            {alert.acknowledged_at && isValid(new Date(alert.acknowledged_at)) && (
              <div>
                <Label className="text-muted-foreground">{t('AlertRulesPage.detail.acknowledged')}</Label>
                <p className="mt-1">{format(new Date(alert.acknowledged_at), 'PPpp')}</p>
              </div>
            )}
            {alert.resolved_at && isValid(new Date(alert.resolved_at)) && (
              <div>
                <Label className="text-muted-foreground">{t('AlertRulesPage.detail.resolved')}</Label>
                <p className="mt-1">{format(new Date(alert.resolved_at), 'PPpp')}</p>
              </div>
            )}
          </div>

          {alert.message && (
            <div>
              <Label className="text-muted-foreground">{t('AlertRulesPage.detail.message')}</Label>
              <p className="mt-1 text-sm">{alert.message}</p>
            </div>
          )}

          {alert.tags && alert.tags.length > 0 && (
            <div>
              <Label className="text-muted-foreground">{t('AlertRulesPage.detail.tags')}</Label>
              <div className="flex flex-wrap gap-1 mt-1">
                {alert.tags.map((tag) => (
                  <Badge key={tag} variant="outline">{tag}</Badge>
                ))}
              </div>
            </div>
          )}

          {Object.keys(alert.details || {}).length > 0 && (
            <div>
              <Label className="text-muted-foreground">{t('AlertRulesPage.detail.details')}</Label>
              <pre className="mt-1 p-3 bg-muted rounded-lg text-xs overflow-auto max-h-48">
                {JSON.stringify(alert.details, null, 2)}
              </pre>
            </div>
          )}
        </div>

        <DialogFooter className="gap-2">
          {alert.status === 'firing' && (
            <Button variant="outline" size="sm" onClick={() => onAcknowledge(alert.id)}>
              <Check className="h-4 w-4 mr-2" />
              {t('AlertRulesPage.actions.acknowledge')}
            </Button>
          )}
          {alert.status !== 'resolved' && (
            <Button size="sm" onClick={() => onResolve(alert.id)}>
              <CheckCircle className="h-4 w-4 mr-2" />
              {t('AlertRulesPage.actions.resolve')}
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={onClose}>
            {t('AlertRulesPage.actions.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
