/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Gateway Orchestration Page
 *
 * Unified gateway orchestration with URL-based tab routing.
 * Manages canonical VLANs, distribution engine, drift detection,
 * VLAN templates, and imported resource dashboards.
 *
 * Tabs:
 *   /gateway                → Dashboard overview
 *   /gateway/vlans          → Canonical VLAN management
 *   /gateway/distribution   → Distribution log
 *   /gateway/drift          → Drift detection events
 *   /gateway/templates      → VLAN templates
 *   /gateway/firewall-rules → Imported firewall rules (read-only)
 *   /gateway/nat            → Imported NAT rules (read-only)
 *   /gateway/vpn            → Imported VPN tunnels (read-only)
 *   /gateway/interfaces     → Imported interfaces (read-only)
 *   /gateway/dhcp           → Imported DHCP leases (read-only)
 */

import { useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { useToast } from '@/hooks/use-toast';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Router,
  BarChart3,
  Network,
  ArrowRightLeft,
  AlertTriangle,
  FileStack,
  Shield,
  Globe,
  Lock,
  Cable,
  Server,
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
  Play,
  RotateCcw,
  MoreHorizontal,
  Upload,
  ArrowDownToLine,
  RefreshCw,
  Undo2,
  ChevronDown,
  ChevronRight,
  Loader2,
  Search,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Badge } from '@/components/ui/badge';
import { StatsGrid } from '@/components/ui/stats-grid';
import { FormDialog } from '@/components/ui/form-dialog';
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import { useSiteStore } from '@/stores/siteStore';
import {
  gatewayOrchApi,
  sitesApiV2,
  type CanonicalVLANResponse,
  type CanonicalVLANCreate,
  type DistributionResponse,
  type DriftEventResponse,
  type DriftSummaryResponse,
  type GatewayDashboardOverview,
  type VLANTemplateResponse,
  type VLANTemplateCreate,
  type ImportedFirewallRuleResponse,
  type ImportedNATRuleResponse,
  type ImportedVPNTunnelResponse,
  type ImportedInterfaceResponse,
  type ImportedDHCPLeaseResponse,
  type Site,
} from '@/lib/api';

// =============================================================================
// Tab ↔ URL mapping
// =============================================================================

const BASE_PATH = '/firewall/orchestration';

const TAB_PATHS: Record<string, string> = {
  dashboard: BASE_PATH,
  vlans: `${BASE_PATH}/vlans`,
  distribution: `${BASE_PATH}/distribution`,
  drift: `${BASE_PATH}/drift`,
  templates: `${BASE_PATH}/templates`,
  reconciliation: `${BASE_PATH}/reconciliation`,
  'firewall-rules': `${BASE_PATH}/firewall-rules`,
  nat: `${BASE_PATH}/nat`,
  vpn: `${BASE_PATH}/vpn`,
  interfaces: `${BASE_PATH}/interfaces`,
  dhcp: `${BASE_PATH}/dhcp`,
};

const PATH_TO_TAB: Record<string, string> = {};
for (const [tab, path] of Object.entries(TAB_PATHS)) {
  PATH_TO_TAB[path] = tab;
}

function resolveTabFromPath(pathname: string): string {
  const clean = pathname.replace(/\/+$/, '') || BASE_PATH;
  if (PATH_TO_TAB[clean]) return PATH_TO_TAB[clean];
  return 'dashboard';
}

// =============================================================================
// Helpers
// =============================================================================

type TFunc = (key: string, options?: Record<string, unknown>) => string;

function timeAgo(t: TFunc, dateStr?: string | null): string {
  if (!dateStr) return t('GatewayPage.time.never');
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return t('GatewayPage.time.justNow');
  if (mins < 60) return t('GatewayPage.time.minutesAgo', { n: mins });
  const hours = Math.floor(mins / 60);
  if (hours < 24) return t('GatewayPage.time.hoursAgo', { n: hours });
  const days = Math.floor(hours / 24);
  return t('GatewayPage.time.daysAgo', { n: days });
}

function severityBadge(severity: string) {
  const map: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/20',
    warning: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    info: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  };
  return map[severity] || 'bg-muted text-muted-foreground';
}

function statusBadge(t: TFunc, status: string) {
  const map: Record<string, { cls: string; label: string }> = {
    pending: { cls: 'bg-yellow-500/10 text-yellow-500', label: t('GatewayPage.status.pending') },
    executing: { cls: 'bg-blue-500/10 text-blue-500', label: t('GatewayPage.status.executing') },
    completed: { cls: 'bg-green-500/10 text-green-500', label: t('GatewayPage.status.completed') },
    failed: { cls: 'bg-red-500/10 text-red-500', label: t('GatewayPage.status.failed') },
    rolled_back: { cls: 'bg-orange-500/10 text-orange-500', label: t('GatewayPage.status.rolledBack') },
  };
  return map[status] || { cls: 'bg-muted text-muted-foreground', label: status };
}

function purposeBadge(purpose: string) {
  const map: Record<string, string> = {
    general: 'bg-muted-foreground/10 text-muted-foreground',
    management: 'bg-purple-500/10 text-purple-400',
    iot: 'bg-cyan-500/10 text-cyan-400',
    guest: 'bg-amber-500/10 text-amber-400',
    voip: 'bg-green-500/10 text-green-400',
    security: 'bg-red-500/10 text-red-400',
  };
  return map[purpose] || 'bg-muted text-muted-foreground';
}

// =============================================================================
// Main Page
// =============================================================================

export default function GatewayPage() {
  const { t } = useTranslation('gateway');
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // ── Site context (global) ────────────────────────────────────────────
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const siteFilter = selectedSiteId ?? 'all';

  // ── State ────────────────────────────────────────────────────────────
  const [showCreateVlan, setShowCreateVlan] = useState(false);
  const [showCreateTemplate, setShowCreateTemplate] = useState(false);
  const [applyingTemplate, setApplyingTemplate] = useState<VLANTemplateResponse | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [driftSeverityFilter, setDriftSeverityFilter] = useState<string>('all');
  const [driftResolutionFilter, setDriftResolutionFilter] = useState<string>('all');
  const [expandedDistId, setExpandedDistId] = useState<string | null>(null);

  // Derive active tab from URL
  const activeTab = resolveTabFromPath(location.pathname);
  const handleTabChange = useCallback(
    (tab: string) => navigate(TAB_PATHS[tab] || BASE_PATH),
    [navigate],
  );

  const siteParam = siteFilter !== 'all' ? siteFilter : undefined;

  // ── Sites (for VLAN create dialog) ──────────────────────────────────
  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApiV2.list();
      return response.data;
    },
  });
  const sites: Site[] = sitesData?.items ?? [];

  // ── Dashboard ────────────────────────────────────────────────────────
  const { data: overviewRes, isLoading: overviewLoading, isError: overviewError } = useQuery({
    queryKey: ['gateway', 'overview', siteParam],
    queryFn: () => gatewayOrchApi.getDashboardOverview({ site_id: siteParam }),
    enabled: activeTab === 'dashboard',
  });
  const overview: GatewayDashboardOverview = overviewRes?.data ?? {
    total_vlans: 0,
    total_role_maps: 0,
    total_distributions: 0,
    open_drift_events: 0,
  };

  const { data: driftSummaryRes } = useQuery({
    queryKey: ['gateway', 'drift-summary', siteParam],
    queryFn: () => gatewayOrchApi.getDriftSummary({ site_id: siteParam }),
    enabled: activeTab === 'dashboard' || activeTab === 'drift',
  });
  const driftSummary: DriftSummaryResponse = driftSummaryRes?.data ?? {
    total: 0, critical: 0, warning: 0, info: 0, pending: 0, resolved: 0,
  };

  // ── Canonical VLANs ──────────────────────────────────────────────────
  const { data: vlansRes, isLoading: vlansLoading, isError: vlansError } = useQuery({
    queryKey: ['gateway', 'vlans', siteParam],
    queryFn: () => gatewayOrchApi.getVlans({ site_id: siteParam, limit: 200 }),
    enabled: activeTab === 'vlans',
  });
  const vlans: CanonicalVLANResponse[] = vlansRes?.data?.items ?? [];

  // ── Distribution Records ─────────────────────────────────────────────
  const { data: distRes, isLoading: distLoading, isError: distError } = useQuery({
    queryKey: ['gateway', 'distribution', siteParam],
    queryFn: () => gatewayOrchApi.getDistributions({ site_id: siteParam, limit: 100 }),
    enabled: activeTab === 'distribution',
  });
  const distributions: DistributionResponse[] = distRes?.data?.items ?? [];

  // ── Drift Events ─────────────────────────────────────────────────────
  const { data: driftRes, isLoading: driftLoading, isError: driftError } = useQuery({
    queryKey: ['gateway', 'drift-events', siteParam],
    queryFn: () => gatewayOrchApi.getDriftEvents({ site_id: siteParam, limit: 100 }),
    enabled: activeTab === 'drift',
  });
  const driftEvents: DriftEventResponse[] = driftRes?.data?.items ?? [];

  // ── Templates ────────────────────────────────────────────────────────
  const { data: templatesRes, isLoading: templatesLoading, isError: templatesError } = useQuery({
    queryKey: ['gateway', 'templates'],
    queryFn: () => gatewayOrchApi.getTemplates({ limit: 200 }),
    enabled: activeTab === 'templates',
  });
  const templates: VLANTemplateResponse[] = templatesRes?.data?.items ?? [];

  // ── Imported Resources (dashboard tabs) ──────────────────────────────
  const { data: fwRulesRes, isLoading: fwRulesLoading, isError: fwRulesError } = useQuery({
    queryKey: ['gateway', 'firewall-rules', siteParam],
    queryFn: () => gatewayOrchApi.getFirewallRules({ site_id: siteParam }),
    enabled: activeTab === 'firewall-rules',
  });
  const fwRules: ImportedFirewallRuleResponse[] = fwRulesRes?.data?.items ?? [];

  const { data: natRes, isLoading: natLoading, isError: natError } = useQuery({
    queryKey: ['gateway', 'nat-rules', siteParam],
    queryFn: () => gatewayOrchApi.getNatRules({ site_id: siteParam }),
    enabled: activeTab === 'nat',
  });
  const natRules: ImportedNATRuleResponse[] = natRes?.data?.items ?? [];

  const { data: vpnRes, isLoading: vpnLoading, isError: vpnError } = useQuery({
    queryKey: ['gateway', 'vpn-tunnels', siteParam],
    queryFn: () => gatewayOrchApi.getVpnTunnels({ site_id: siteParam }),
    enabled: activeTab === 'vpn',
  });
  const vpnTunnels: ImportedVPNTunnelResponse[] = vpnRes?.data?.items ?? [];

  const { data: ifacesRes, isLoading: ifacesLoading, isError: ifacesError } = useQuery({
    queryKey: ['gateway', 'interfaces', siteParam],
    queryFn: () => gatewayOrchApi.getInterfaces({ site_id: siteParam }),
    enabled: activeTab === 'interfaces',
  });
  const interfaces: ImportedInterfaceResponse[] = ifacesRes?.data?.items ?? [];

  const { data: dhcpRes, isLoading: dhcpLoading, isError: dhcpError } = useQuery({
    queryKey: ['gateway', 'dhcp-leases', siteParam],
    queryFn: () => gatewayOrchApi.getDhcpLeases({ site_id: siteParam }),
    enabled: activeTab === 'dhcp',
  });
  const dhcpLeases: ImportedDHCPLeaseResponse[] = dhcpRes?.data?.items ?? [];

  // ── Reconciliation ──────────────────────────────────────────────────
  const { data: alignmentRes, isLoading: alignmentLoading, isError: alignmentError, refetch: refetchAlignment } = useQuery({
    queryKey: ['gateway', 'alignment', siteParam],
    queryFn: () => gatewayOrchApi.checkAlignment(siteParam!),
    enabled: activeTab === 'reconciliation' && !!siteParam,
  });
  const alignment = alignmentRes?.data;

  const hasQueryError = overviewError || vlansError || fwRulesError || distError
    || driftError || templatesError || natError || vpnError || ifacesError || dhcpError || alignmentError;

  // ── Reconciliation Mutations ─────────────────────────────────────────
  const importFromBrainMutation = useMutation({
    mutationFn: ({ siteId, dryRun }: { siteId: string; dryRun: boolean }) =>
      gatewayOrchApi.importFromBrain(siteId, dryRun),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'vlans'] });
      queryClient.invalidateQueries({ queryKey: ['gateway', 'alignment'] });
      toast({ title: t('GatewayPage.toast.importComplete.title'), description: t('GatewayPage.toast.importComplete.description') });
    },
    onError: () => toast({ title: t('GatewayPage.toast.importFailed.title'), description: t('GatewayPage.toast.importFailed.description'), variant: 'destructive' }),
  });

  const distributeToLimbsMutation = useMutation({
    mutationFn: ({ siteId, vlanIds, dryRun }: { siteId: string; vlanIds?: number[]; dryRun?: boolean }) =>
      gatewayOrchApi.distributeToLimbs(siteId, { vlan_ids: vlanIds, dry_run: dryRun }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'alignment'] });
      toast({ title: t('GatewayPage.toast.distributionComplete.title'), description: t('GatewayPage.toast.distributionComplete.description') });
    },
    onError: () => toast({ title: t('GatewayPage.toast.distributionFailed.title'), description: t('GatewayPage.toast.distributionFailed.description'), variant: 'destructive' }),
  });

  // ── Mutations ────────────────────────────────────────────────────────
  const createVlanMutation = useMutation({
    mutationFn: (data: CanonicalVLANCreate) => gatewayOrchApi.createVlan(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'vlans'] });
      queryClient.invalidateQueries({ queryKey: ['gateway', 'overview'] });
      setShowCreateVlan(false);
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.createVlanFailed'), variant: 'destructive' }),
  });

  const deleteVlanMutation = useMutation({
    mutationFn: (id: string) => gatewayOrchApi.deleteVlan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'vlans'] });
      queryClient.invalidateQueries({ queryKey: ['gateway', 'overview'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.deleteVlanFailed'), variant: 'destructive' }),
  });

  const triggerDistMutation = useMutation({
    mutationFn: (data: { vlan_id: string; site_id: string }) =>
      gatewayOrchApi.triggerDistribution(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'distribution'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.triggerDistributionFailed'), variant: 'destructive' }),
  });

  const resolveDriftMutation = useMutation({
    mutationFn: ({ id, resolution }: { id: string; resolution: 'reapply' | 'accept' | 'ignore' }) =>
      gatewayOrchApi.resolveDriftEvent(id, { resolution }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'drift'] });
      queryClient.invalidateQueries({ queryKey: ['gateway', 'overview'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.resolveDriftFailed'), variant: 'destructive' }),
  });

  const createTemplateMutation = useMutation({
    mutationFn: (data: VLANTemplateCreate) => gatewayOrchApi.createTemplate(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'templates'] });
      setShowCreateTemplate(false);
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.createTemplateFailed'), variant: 'destructive' }),
  });

  const deleteTemplateMutation = useMutation({
    mutationFn: (id: string) => gatewayOrchApi.deleteTemplate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'templates'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.deleteTemplateFailed'), variant: 'destructive' }),
  });

  const applyTemplateMutation = useMutation({
    mutationFn: ({ templateId, siteId }: { templateId: string; siteId: string }) =>
      gatewayOrchApi.applyTemplate(templateId, siteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'vlans'] });
      setApplyingTemplate(null);
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.createVlanFailed'), variant: 'destructive' }),
  });

  const triggerDriftCheckMutation = useMutation({
    mutationFn: (siteId: string) => gatewayOrchApi.triggerDriftCheck(siteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'drift'] });
      queryClient.invalidateQueries({ queryKey: ['gateway', 'drift-summary'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.triggerDriftCheckFailed'), variant: 'destructive' }),
  });

  const retryDistMutation = useMutation({
    mutationFn: (id: string) => gatewayOrchApi.retryDistribution(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'distribution'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.retryDistributionFailed'), variant: 'destructive' }),
  });

  const rollbackDistMutation = useMutation({
    mutationFn: (id: string) => gatewayOrchApi.rollbackDistribution(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateway', 'distribution'] });
    },
    onError: () => toast({ title: t('GatewayPage.toast.error'), description: t('GatewayPage.toast.rollbackDistributionFailed'), variant: 'destructive' }),
  });

  // =====================================================================
  // Render: Dashboard
  // =====================================================================

  function renderDashboard() {
    if (overviewLoading) {
      return (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
      );
    }

    return (
      <div className="space-y-6">
        {/* Stats */}
        <StatsGrid
          columns={4}
          stats={[
            {
              title: t('GatewayPage.dashboard.stats.canonicalVlans'),
              value: overview.total_vlans,
              icon: Network,
              variant: 'primary',
            },
            {
              title: t('GatewayPage.dashboard.stats.siteRoleMaps'),
              value: overview.total_role_maps,
              icon: Server,
              variant: 'primary',
            },
            {
              title: t('GatewayPage.dashboard.stats.distributions'),
              value: overview.total_distributions,
              icon: ArrowRightLeft,
              variant: 'primary',
            },
            {
              title: t('GatewayPage.dashboard.stats.openDriftEvents'),
              value: overview.open_drift_events,
              icon: AlertTriangle,
              variant: overview.open_drift_events > 0 ? 'warning' : 'default',
            },
          ]}
        />

        {/* Drift Summary */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">{t('GatewayPage.dashboard.driftSummary.title')}</CardTitle>
            <CardDescription>{t('GatewayPage.dashboard.driftSummary.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
              {([
                [t('GatewayPage.driftSummary.total'), driftSummary.total, 'text-foreground'],
                [t('GatewayPage.driftSummary.critical'), driftSummary.critical, 'text-red-500'],
                [t('GatewayPage.driftSummary.warning'), driftSummary.warning, 'text-yellow-500'],
                [t('GatewayPage.driftSummary.info'), driftSummary.info, 'text-blue-500'],
                [t('GatewayPage.driftSummary.pending'), driftSummary.pending, 'text-orange-500'],
                [t('GatewayPage.driftSummary.resolved'), driftSummary.resolved, 'text-green-500'],
              ] as const).map(([label, val, color]) => (
                <div key={label} className="text-center">
                  <p className={cn('text-2xl font-bold', color)}>{val}</p>
                  <p className="text-xs text-muted-foreground">{label}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">{t('GatewayPage.dashboard.quickActions.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Button variant="outline" size="sm" onClick={() => handleTabChange('vlans')}>
                <Network className="h-4 w-4 mr-2" />
                {t('GatewayPage.dashboard.quickActions.manageVlans')}
              </Button>
              <Button variant="outline" size="sm" asChild>
                <Link to="/firewall/orchestration/import">
                  <Upload className="h-4 w-4 mr-2" />
                  {t('GatewayPage.dashboard.quickActions.importWizard')}
                </Link>
              </Button>
              <Button variant="outline" size="sm" onClick={() => handleTabChange('templates')}>
                <FileStack className="h-4 w-4 mr-2" />
                {t('GatewayPage.dashboard.quickActions.vlanTemplates')}
              </Button>
              <Button variant="outline" size="sm" onClick={() => handleTabChange('drift')}>
                <AlertTriangle className="h-4 w-4 mr-2" />
                {t('GatewayPage.dashboard.quickActions.driftEvents')}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // =====================================================================
  // Render: Canonical VLANs
  // =====================================================================

  const vlanColumns: DataTableColumn<CanonicalVLANResponse>[] = useMemo(
    () => [
      {
        id: 'vlan_id',
        header: t('GatewayPage.vlanColumns.vlan'),
        cell: (row: CanonicalVLANResponse) => (
          <span className="font-mono font-medium">{row.vlan_id}</span>
        ),
        sortable: true,
      },
      {
        id: 'name',
        header: t('GatewayPage.vlanColumns.name'),
        cell: (row: CanonicalVLANResponse) => (
          <div>
            <p className="font-medium">{row.name}</p>
            {row.description && (
              <p className="text-xs text-muted-foreground truncate max-w-[200px]">{row.description}</p>
            )}
          </div>
        ),
        sortable: true,
      },
      {
        id: 'subnet',
        header: t('GatewayPage.vlanColumns.subnet'),
        cell: (row: CanonicalVLANResponse) => <span className="font-mono text-sm">{row.subnet}</span>,
      },
      {
        id: 'gateway_ip',
        header: t('GatewayPage.vlanColumns.gateway'),
        cell: (row: CanonicalVLANResponse) => <span className="font-mono text-sm">{row.gateway_ip}</span>,
      },
      {
        id: 'purpose',
        header: t('GatewayPage.vlanColumns.purpose'),
        cell: (row: CanonicalVLANResponse) => (
          <Badge variant="outline" className={cn('capitalize', purposeBadge(row.purpose))}>
            {row.purpose}
          </Badge>
        ),
      },
      {
        id: 'dhcp_enabled',
        header: t('GatewayPage.vlanColumns.dhcp'),
        cell: (row: CanonicalVLANResponse) =>
          row.dhcp_enabled ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-500">{t('GatewayPage.common.on')}</Badge>
          ) : (
            <Badge variant="outline" className="bg-muted text-muted-foreground">{t('GatewayPage.common.off')}</Badge>
          ),
      },
      {
        id: 'management_state',
        header: t('GatewayPage.vlanColumns.state'),
        cell: (row: CanonicalVLANResponse) => (
          <Badge variant="outline" className="capitalize">{row.management_state}</Badge>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: (row: CanonicalVLANResponse) => (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => triggerDistMutation.mutate({ vlan_id: row.id, site_id: row.site_id })}>
                <Play className="h-4 w-4 mr-2" />
                {t('GatewayPage.vlanActions.distribute')}
              </DropdownMenuItem>
              {/* Retract is performed per-distribution from the Distributions
                  tab's Rollback action (POST /distribution/{id}/rollback, which
                  the backend implements as retract_vlan). The old VLAN-row
                  retract posted to a nonexistent /distribution/retract route. */}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive"
                onClick={() => {
                  if (confirm(t('GatewayPage.vlanActions.deleteConfirm'))) {
                    deleteVlanMutation.mutate(row.id);
                  }
                }}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('GatewayPage.vlanActions.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ),
      },
    ],
    [t, triggerDistMutation, deleteVlanMutation],
  );

  function renderVlans() {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Input
              placeholder={t('GatewayPage.vlans.searchPlaceholder')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-64"
            />
          </div>
          <Button onClick={() => setShowCreateVlan(true)}>
            <Plus className="h-4 w-4 mr-2" />
            {t('GatewayPage.vlans.createVlan')}
          </Button>
        </div>

        <DataTable
          columns={vlanColumns}
          data={vlans.filter(
            (v) =>
              !searchQuery ||
              (v.name ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
              String(v.vlan_id).includes(searchQuery),
          )}
          isLoading={vlansLoading}
        />
      </div>
    );
  }

  // =====================================================================
  // Render: Distribution Log
  // =====================================================================

  const distColumns: DataTableColumn<DistributionResponse>[] = useMemo(
    () => [
      {
        id: 'expand',
        header: '',
        cell: (row: DistributionResponse) => (
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={(e) => { e.stopPropagation(); setExpandedDistId(expandedDistId === row.id ? null : row.id); }}
          >
            {expandedDistId === row.id ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          </Button>
        ),
      },
      {
        id: 'resource_type',
        header: t('GatewayPage.distColumns.resource'),
        cell: (row: DistributionResponse) => (
          <Badge variant="outline" className="capitalize">{row.resource_type}</Badge>
        ),
      },
      {
        id: 'action',
        header: t('GatewayPage.distColumns.action'),
        cell: (row: DistributionResponse) => (
          <span className="capitalize font-medium">{row.action}</span>
        ),
      },
      {
        id: 'status',
        header: t('GatewayPage.distColumns.status'),
        cell: (row: DistributionResponse) => {
          const s = statusBadge(t, row.status);
          return <Badge variant="outline" className={s.cls}>{s.label}</Badge>;
        },
      },
      {
        id: 'started_at',
        header: t('GatewayPage.distColumns.started'),
        cell: (row: DistributionResponse) => (
          <span className="text-sm text-muted-foreground">{timeAgo(t, row.started_at)}</span>
        ),
        sortable: true,
      },
      {
        id: 'completed_at',
        header: t('GatewayPage.distColumns.completed'),
        cell: (row: DistributionResponse) => (
          <span className="text-sm text-muted-foreground">{timeAgo(t, row.completed_at)}</span>
        ),
      },
      {
        id: 'error_message',
        header: t('GatewayPage.distColumns.error'),
        cell: (row: DistributionResponse) =>
          row.error_message ? (
            <span className="text-xs text-red-500 truncate max-w-[200px] block">{row.error_message}</span>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'actions',
        header: '',
        cell: (row: DistributionResponse) => {
          if (row.status === 'failed') {
            return (
              <Button variant="ghost" size="sm" onClick={() => retryDistMutation.mutate(row.id)}>
                <RefreshCw className="h-3.5 w-3.5 mr-1" /> {t('GatewayPage.distActions.retry')}
              </Button>
            );
          }
          if (row.status === 'completed') {
            return (
              <Button variant="ghost" size="sm" onClick={() => rollbackDistMutation.mutate(row.id)}>
                <Undo2 className="h-3.5 w-3.5 mr-1" /> {t('GatewayPage.distActions.rollback')}
              </Button>
            );
          }
          return null;
        },
      },
    ],
    [t, expandedDistId, retryDistMutation, rollbackDistMutation],
  );

  function renderDistribution() {
    return (
      <div className="space-y-4">
        <DataTable
          columns={distColumns}
          data={distributions}
          isLoading={distLoading}
        />

        {/* Expanded step details */}
        {expandedDistId && (() => {
          const dist = distributions.find((d) => d.id === expandedDistId);
          if (!dist?.step_results?.length) return null;
          return (
            <Card className="border-dashed">
              <CardHeader className="py-3 px-4">
                <CardTitle className="text-sm">{t('GatewayPage.distribution.stepDetails', { action: dist.action, resource: dist.resource_type })}</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <div className="space-y-2">
                  {dist.step_results.map((step, i) => (
                    <div key={i} className="flex items-center gap-3 text-sm border rounded-md px-3 py-2">
                      <Badge variant="outline" className="font-mono text-xs">T{step.tier}</Badge>
                      <span className="font-medium capitalize">{(step.action ?? '').replace(/_/g, ' ')}</span>
                      <span className="text-xs text-muted-foreground font-mono truncate max-w-[120px]">{step.device_id}</span>
                      <Badge variant="outline" className={cn('ml-auto', statusBadge(t, step.status).cls)}>
                        {statusBadge(t, step.status).label}
                      </Badge>
                      {step.duration_ms != null && (
                        <span className="text-xs text-muted-foreground">{step.duration_ms}ms</span>
                      )}
                      {step.error && (
                        <span className="text-xs text-red-500 truncate max-w-[150px]">{step.error}</span>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          );
        })()}
      </div>
    );
  }

  // =====================================================================
  // Render: Drift Events
  // =====================================================================

  const driftColumns: DataTableColumn<DriftEventResponse>[] = useMemo(
    () => [
      {
        id: 'severity',
        header: t('GatewayPage.driftColumns.severity'),
        cell: (row: DriftEventResponse) => (
          <Badge variant="outline" className={cn('capitalize', severityBadge(row.severity))}>
            {row.severity}
          </Badge>
        ),
        sortable: true,
      },
      {
        id: 'drift_type',
        header: t('GatewayPage.driftColumns.type'),
        cell: (row: DriftEventResponse) => (
          <span className="text-sm capitalize">{(row.drift_type ?? '').replace(/_/g, ' ')}</span>
        ),
      },
      {
        id: 'resource_type',
        header: t('GatewayPage.driftColumns.resource'),
        cell: (row: DriftEventResponse) => (
          <Badge variant="outline" className="capitalize">{row.resource_type}</Badge>
        ),
      },
      {
        id: 'message',
        header: t('GatewayPage.driftColumns.message'),
        cell: (row: DriftEventResponse) => (
          <p className="text-sm truncate max-w-[300px]">{row.message}</p>
        ),
      },
      {
        id: 'resolution',
        header: t('GatewayPage.driftColumns.resolution'),
        cell: (row: DriftEventResponse) => {
          if (row.resolution === 'pending') {
            return <Badge variant="outline" className="bg-yellow-500/10 text-yellow-500">{t('GatewayPage.status.pending')}</Badge>;
          }
          return <Badge variant="outline" className="bg-green-500/10 text-green-500 capitalize">{(row.resolution ?? '').replace(/_/g, ' ')}</Badge>;
        },
      },
      {
        id: 'created_at',
        header: t('GatewayPage.driftColumns.detected'),
        cell: (row: DriftEventResponse) => (
          <span className="text-sm text-muted-foreground">{timeAgo(t, row.created_at)}</span>
        ),
        sortable: true,
      },
      {
        id: 'actions',
        header: '',
        cell: (row: DriftEventResponse) =>
          row.resolution === 'pending' ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => resolveDriftMutation.mutate({ id: row.id, resolution: 'reapply' })}>
                  <RotateCcw className="h-4 w-4 mr-2" />
                  {t('GatewayPage.driftActions.reapply')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => resolveDriftMutation.mutate({ id: row.id, resolution: 'accept' })}>
                  <CheckCircle className="h-4 w-4 mr-2" />
                  {t('GatewayPage.driftActions.accept')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => resolveDriftMutation.mutate({ id: row.id, resolution: 'ignore' })}>
                  <XCircle className="h-4 w-4 mr-2" />
                  {t('GatewayPage.driftActions.ignore')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : null,
      },
    ],
    [t, resolveDriftMutation],
  );

  function renderDrift() {
    const filteredDriftEvents = driftEvents.filter((e) => {
      if (driftSeverityFilter !== 'all' && e.severity !== driftSeverityFilter) return false;
      if (driftResolutionFilter === 'pending' && e.resolution !== 'pending') return false;
      if (driftResolutionFilter === 'resolved' && e.resolution === 'pending') return false;
      return true;
    });

    return (
      <div className="space-y-4">
        {/* Header with drift check button */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Select value={driftSeverityFilter} onValueChange={setDriftSeverityFilter}>
              <SelectTrigger className="w-[130px]">
                <SelectValue placeholder={t('GatewayPage.drift.severityPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('GatewayPage.drift.allSeverity')}</SelectItem>
                <SelectItem value="critical">{t('GatewayPage.driftSummary.critical')}</SelectItem>
                <SelectItem value="warning">{t('GatewayPage.driftSummary.warning')}</SelectItem>
                <SelectItem value="info">{t('GatewayPage.driftSummary.info')}</SelectItem>
              </SelectContent>
            </Select>
            <Select value={driftResolutionFilter} onValueChange={setDriftResolutionFilter}>
              <SelectTrigger className="w-[130px]">
                <SelectValue placeholder={t('GatewayPage.drift.resolutionPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('GatewayPage.drift.allStatus')}</SelectItem>
                <SelectItem value="pending">{t('GatewayPage.status.pending')}</SelectItem>
                <SelectItem value="resolved">{t('GatewayPage.driftSummary.resolved')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button
            onClick={() => {
              if (siteFilter !== 'all') {
                triggerDriftCheckMutation.mutate(siteFilter);
              }
            }}
            disabled={siteFilter === 'all' || triggerDriftCheckMutation.isPending}
            variant="outline"
          >
            {triggerDriftCheckMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Search className="h-4 w-4 mr-2" />
            )}
            {t('GatewayPage.drift.runDriftCheck')}
          </Button>
        </div>

        {/* Drift summary mini-cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {([
            [t('GatewayPage.driftSummary.total'), driftSummary.total, 'text-foreground'],
            [t('GatewayPage.driftSummary.critical'), driftSummary.critical, 'text-red-500'],
            [t('GatewayPage.driftSummary.warning'), driftSummary.warning, 'text-yellow-500'],
            [t('GatewayPage.driftSummary.info'), driftSummary.info, 'text-blue-500'],
            [t('GatewayPage.driftSummary.pending'), driftSummary.pending, 'text-orange-500'],
            [t('GatewayPage.driftSummary.resolved'), driftSummary.resolved, 'text-green-500'],
          ] as const).map(([label, val, color]) => (
            <Card key={label}>
              <CardContent noOffset className="p-3 text-center">
                <p className={cn('text-xl font-bold', color)}>{val}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {siteFilter === 'all' && (
          <p className="text-xs text-muted-foreground text-center">{t('GatewayPage.drift.selectSiteHint')}</p>
        )}

        <DataTable
          columns={driftColumns}
          data={filteredDriftEvents}
          isLoading={driftLoading}
        />
      </div>
    );
  }

  // =====================================================================
  // Render: VLAN Templates
  // =====================================================================

  const templateColumns: DataTableColumn<VLANTemplateResponse>[] = useMemo(
    () => [
      {
        id: 'name',
        header: t('GatewayPage.templateColumns.name'),
        cell: (row: VLANTemplateResponse) => (
          <div>
            <p className="font-medium">{row.name}</p>
            {row.description && (
              <p className="text-xs text-muted-foreground truncate max-w-[200px]">{row.description}</p>
            )}
          </div>
        ),
        sortable: true,
      },
      {
        id: 'vlan_id',
        header: t('GatewayPage.templateColumns.vlanId'),
        cell: (row: VLANTemplateResponse) => <span className="font-mono">{row.vlan_id}</span>,
        sortable: true,
      },
      {
        id: 'subnet_template',
        header: t('GatewayPage.templateColumns.subnetTemplate'),
        cell: (row: VLANTemplateResponse) => <span className="font-mono text-sm">{row.subnet_template}</span>,
      },
      {
        id: 'purpose',
        header: t('GatewayPage.templateColumns.purpose'),
        cell: (row: VLANTemplateResponse) => (
          <Badge variant="outline" className={cn('capitalize', purposeBadge(row.purpose))}>
            {row.purpose}
          </Badge>
        ),
      },
      {
        id: 'dhcp_enabled',
        header: t('GatewayPage.templateColumns.dhcp'),
        cell: (row: VLANTemplateResponse) =>
          row.dhcp_enabled ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-500">{t('GatewayPage.common.on')}</Badge>
          ) : (
            <Badge variant="outline" className="bg-muted text-muted-foreground">{t('GatewayPage.common.off')}</Badge>
          ),
      },
      {
        id: 'actions',
        header: '',
        cell: (row: VLANTemplateResponse) => (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setApplyingTemplate(row)}>
                <ArrowDownToLine className="h-4 w-4 mr-2" />
                {t('GatewayPage.reconciliation.selectSiteTitle')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive"
                onClick={() => {
                  if (confirm(t('GatewayPage.templateActions.deleteConfirm'))) {
                    deleteTemplateMutation.mutate(row.id);
                  }
                }}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('GatewayPage.templateActions.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ),
      },
    ],
    [t, deleteTemplateMutation],
  );

  function renderTemplates() {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-end">
          <Button onClick={() => setShowCreateTemplate(true)}>
            <Plus className="h-4 w-4 mr-2" />
            {t('GatewayPage.templates.createTemplate')}
          </Button>
        </div>

        <DataTable
          columns={templateColumns}
          data={templates}
          isLoading={templatesLoading}

        />
      </div>
    );
  }

  // =====================================================================
  // Render: Imported Firewall Rules (read-only)
  // =====================================================================

  const fwRuleColumns: DataTableColumn<ImportedFirewallRuleResponse>[] = useMemo(
    () => [
      {
        id: 'rule_index',
        header: t('GatewayPage.fwRuleColumns.index'),
        cell: (row: ImportedFirewallRuleResponse) => <span className="font-mono text-xs">{row.rule_index}</span>,
        sortable: true,
      },
      {
        id: 'name',
        header: t('GatewayPage.fwRuleColumns.name'),
        cell: (row: ImportedFirewallRuleResponse) => (
          <div>
            <p className="font-medium text-sm">{row.name}</p>
            {row.description && (
              <p className="text-xs text-muted-foreground truncate max-w-[180px]">{row.description}</p>
            )}
          </div>
        ),
      },
      {
        id: 'direction',
        header: t('GatewayPage.fwRuleColumns.dir'),
        cell: (row: ImportedFirewallRuleResponse) => <Badge variant="outline" className="capitalize text-xs">{row.direction}</Badge>,
      },
      {
        id: 'action',
        header: t('GatewayPage.fwRuleColumns.action'),
        cell: (row: ImportedFirewallRuleResponse) => {
          const color = row.action === 'pass' || row.action === 'allow'
            ? 'bg-green-500/10 text-green-500'
            : row.action === 'block' || row.action === 'deny'
              ? 'bg-red-500/10 text-red-500'
              : 'bg-muted text-muted-foreground';
          return <Badge variant="outline" className={cn('capitalize text-xs', color)}>{row.action}</Badge>;
        },
      },
      {
        id: 'protocol',
        header: t('GatewayPage.fwRuleColumns.proto'),
        cell: (row: ImportedFirewallRuleResponse) => <span className="font-mono text-xs uppercase">{row.protocol}</span>,
      },
      {
        id: 'is_enabled',
        header: t('GatewayPage.fwRuleColumns.enabled'),
        cell: (row: ImportedFirewallRuleResponse) =>
          row.is_enabled ? (
            <CheckCircle className="h-4 w-4 text-green-500" />
          ) : (
            <XCircle className="h-4 w-4 text-muted-foreground" />
          ),
      },
      {
        id: 'hit_count',
        header: t('GatewayPage.fwRuleColumns.hits'),
        cell: (row: ImportedFirewallRuleResponse) => <span className="font-mono text-xs">{(row.hit_count ?? 0).toLocaleString()}</span>,
        sortable: true,
      },
      {
        id: 'last_synced_at',
        header: t('GatewayPage.fwRuleColumns.synced'),
        cell: (row: ImportedFirewallRuleResponse) => <span className="text-xs text-muted-foreground">{timeAgo(t, row.last_synced_at)}</span>,
      },
    ],
    [t],
  );

  function renderFirewallRules() {
    return (
      <DataTable
        columns={fwRuleColumns}
        data={fwRules}
        isLoading={fwRulesLoading}

      />
    );
  }

  // =====================================================================
  // Render: Imported NAT Rules (read-only)
  // =====================================================================

  const natColumns: DataTableColumn<ImportedNATRuleResponse>[] = useMemo(
    () => [
      {
        id: 'name',
        header: t('GatewayPage.natColumns.name'),
        cell: (row: ImportedNATRuleResponse) => <span className="font-medium text-sm">{row.name}</span>,
      },
      {
        id: 'nat_type',
        header: t('GatewayPage.natColumns.type'),
        cell: (row: ImportedNATRuleResponse) => <Badge variant="outline" className="capitalize text-xs">{row.nat_type}</Badge>,
      },
      {
        id: 'is_enabled',
        header: t('GatewayPage.natColumns.enabled'),
        cell: (row: ImportedNATRuleResponse) =>
          row.is_enabled ? (
            <CheckCircle className="h-4 w-4 text-green-500" />
          ) : (
            <XCircle className="h-4 w-4 text-muted-foreground" />
          ),
      },
      {
        id: 'last_synced_at',
        header: t('GatewayPage.natColumns.synced'),
        cell: (row: ImportedNATRuleResponse) => <span className="text-xs text-muted-foreground">{timeAgo(t, row.last_synced_at)}</span>,
      },
    ],
    [t],
  );

  function renderNAT() {
    return (
      <DataTable
        columns={natColumns}
        data={natRules}
        isLoading={natLoading}

      />
    );
  }

  // =====================================================================
  // Render: Imported VPN Tunnels (read-only)
  // =====================================================================

  const vpnColumns: DataTableColumn<ImportedVPNTunnelResponse>[] = useMemo(
    () => [
      {
        id: 'name',
        header: t('GatewayPage.vpnColumns.name'),
        cell: (row: ImportedVPNTunnelResponse) => <span className="font-medium text-sm">{row.name}</span>,
      },
      {
        id: 'vpn_type',
        header: t('GatewayPage.vpnColumns.type'),
        cell: (row: ImportedVPNTunnelResponse) => <Badge variant="outline" className="uppercase text-xs">{row.vpn_type}</Badge>,
      },
      {
        id: 'status',
        header: t('GatewayPage.vpnColumns.status'),
        cell: (row: ImportedVPNTunnelResponse) => {
          const up = row.status === 'up' || row.status === 'connected';
          return (
            <Badge variant="outline" className={cn('capitalize', up ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500')}>
              {row.status}
            </Badge>
          );
        },
      },
      {
        id: 'last_synced_at',
        header: t('GatewayPage.vpnColumns.synced'),
        cell: (row: ImportedVPNTunnelResponse) => <span className="text-xs text-muted-foreground">{timeAgo(t, row.last_synced_at)}</span>,
      },
    ],
    [t],
  );

  function renderVPN() {
    return (
      <DataTable
        columns={vpnColumns}
        data={vpnTunnels}
        isLoading={vpnLoading}

      />
    );
  }

  // =====================================================================
  // Render: Imported Interfaces (read-only)
  // =====================================================================

  const ifaceColumns: DataTableColumn<ImportedInterfaceResponse>[] = useMemo(
    () => [
      {
        id: 'name',
        header: t('GatewayPage.ifaceColumns.name'),
        cell: (row: ImportedInterfaceResponse) => (
          <div>
            <p className="font-mono text-sm">{row.name}</p>
            {row.description && (
              <p className="text-xs text-muted-foreground truncate max-w-[160px]">{row.description}</p>
            )}
          </div>
        ),
      },
      {
        id: 'if_type',
        header: t('GatewayPage.ifaceColumns.type'),
        cell: (row: ImportedInterfaceResponse) => <span className="text-xs">{row.if_type ?? '-'}</span>,
      },
      {
        id: 'ipv4_address',
        header: t('GatewayPage.ifaceColumns.ipv4'),
        cell: (row: ImportedInterfaceResponse) => (
          <span className="font-mono text-xs">{row.ipv4_address ?? '-'}</span>
        ),
      },
      {
        id: 'vlan_tag',
        header: t('GatewayPage.ifaceColumns.vlan'),
        cell: (row: ImportedInterfaceResponse) =>
          row.vlan_tag ? <span className="font-mono">{row.vlan_tag}</span> : <span className="text-muted-foreground">-</span>,
      },
      {
        id: 'is_up',
        header: t('GatewayPage.ifaceColumns.status'),
        cell: (row: ImportedInterfaceResponse) =>
          row.is_up ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-500">{t('GatewayPage.common.up')}</Badge>
          ) : (
            <Badge variant="outline" className="bg-red-500/10 text-red-500">{t('GatewayPage.common.down')}</Badge>
          ),
      },
      {
        id: 'mac_address',
        header: t('GatewayPage.ifaceColumns.mac'),
        cell: (row: ImportedInterfaceResponse) => <span className="font-mono text-xs">{row.mac_address ?? '-'}</span>,
      },
    ],
    [t],
  );

  function renderInterfaces() {
    return (
      <DataTable
        columns={ifaceColumns}
        data={interfaces}
        isLoading={ifacesLoading}

      />
    );
  }

  // =====================================================================
  // Render: Imported DHCP Leases (read-only)
  // =====================================================================

  const dhcpColumns: DataTableColumn<ImportedDHCPLeaseResponse>[] = useMemo(
    () => [
      {
        id: 'ip_address',
        header: t('GatewayPage.dhcpColumns.ipAddress'),
        cell: (row: ImportedDHCPLeaseResponse) => <span className="font-mono text-sm">{row.ip_address}</span>,
        sortable: true,
      },
      {
        id: 'mac_address',
        header: t('GatewayPage.dhcpColumns.macAddress'),
        cell: (row: ImportedDHCPLeaseResponse) => <span className="font-mono text-xs">{row.mac_address}</span>,
      },
      {
        id: 'hostname',
        header: t('GatewayPage.dhcpColumns.hostname'),
        cell: (row: ImportedDHCPLeaseResponse) => <span className="text-sm">{row.hostname ?? '-'}</span>,
      },
      {
        id: 'interface',
        header: t('GatewayPage.dhcpColumns.interface'),
        cell: (row: ImportedDHCPLeaseResponse) => <span className="font-mono text-xs">{row.interface ?? '-'}</span>,
      },
      {
        id: 'status',
        header: t('GatewayPage.dhcpColumns.status'),
        cell: (row: ImportedDHCPLeaseResponse) =>
          row.status ? (
            <Badge variant="outline" className="capitalize text-xs">{row.status}</Badge>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
    ],
    [t],
  );

  function renderDHCP() {
    return (
      <DataTable
        columns={dhcpColumns}
        data={dhcpLeases}
        isLoading={dhcpLoading}

      />
    );
  }

  function renderReconciliation() {
    if (!siteParam) {
      return (
        <Card>
          <CardContent noOffset className="p-8 text-center text-muted-foreground">
            <RefreshCw className="h-8 w-8 mx-auto mb-3 opacity-50" />
            <p className="font-medium">{t('GatewayPage.reconciliation.selectSiteTitle')}</p>
            <p className="text-sm mt-1">{t('GatewayPage.reconciliation.selectSiteDescription')}</p>
          </CardContent>
        </Card>
      );
    }

    if (alignmentLoading) {
      return (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-24 rounded-xl" />
            ))}
          </div>
          <Skeleton className="h-[280px] rounded-xl" />
        </div>
      );
    }

    const score = alignment?.score ?? 0;
    const scoreColor = score >= 90 ? 'text-green-500' : score >= 60 ? 'text-yellow-500' : 'text-red-500';

    return (
      <div className="space-y-6">
        {/* Actions Bar */}
        <div className="flex items-center gap-3">
          <button
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-sm font-medium disabled:opacity-50"
            onClick={() => importFromBrainMutation.mutate({ siteId: siteParam, dryRun: false })}
            disabled={importFromBrainMutation.isPending}
          >
            {importFromBrainMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
            {t('GatewayPage.reconciliation.importFromBrain')}
          </button>
          <button
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-secondary text-secondary-foreground hover:bg-secondary/80 text-sm font-medium disabled:opacity-50"
            onClick={() => distributeToLimbsMutation.mutate({ siteId: siteParam })}
            disabled={distributeToLimbsMutation.isPending}
          >
            {distributeToLimbsMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowDownToLine className="h-4 w-4" />}
            {t('GatewayPage.reconciliation.distributeToLimbs')}
          </button>
          <button
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md border hover:bg-accent text-sm font-medium"
            onClick={() => refetchAlignment()}
          >
            <RefreshCw className="h-4 w-4" />
            {t('GatewayPage.reconciliation.refresh')}
          </button>
        </div>

        {/* Score Card */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card>
            <CardContent noOffset className="p-4 text-center">
              <p className="text-sm text-muted-foreground">{t('GatewayPage.reconciliation.alignmentScore')}</p>
              <p className={`text-3xl font-bold ${scoreColor}`}>{score}%</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="p-4 text-center">
              <p className="text-sm text-muted-foreground">{t('GatewayPage.reconciliation.totalVlans')}</p>
              <p className="text-2xl font-semibold">{alignment?.total_vlans ?? 0}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="p-4 text-center">
              <p className="text-sm text-muted-foreground">{t('GatewayPage.reconciliation.aligned')}</p>
              <p className="text-2xl font-semibold text-green-500">{alignment?.aligned ?? 0}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="p-4 text-center">
              <p className="text-sm text-muted-foreground">{t('GatewayPage.reconciliation.missing')}</p>
              <p className="text-2xl font-semibold text-red-500">{alignment?.missing ?? 0}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent noOffset className="p-4 text-center">
              <p className="text-sm text-muted-foreground">{t('GatewayPage.reconciliation.extra')}</p>
              <p className="text-2xl font-semibold text-yellow-500">{alignment?.extra ?? 0}</p>
            </CardContent>
          </Card>
        </div>

        {/* Alignment Detail Table */}
        {alignment?.items && alignment.items.length > 0 && (
          <Card>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left p-3 font-medium">{t('GatewayPage.alignmentTable.vlan')}</th>
                    <th className="text-left p-3 font-medium">{t('GatewayPage.alignmentTable.name')}</th>
                    <th className="text-left p-3 font-medium">{t('GatewayPage.alignmentTable.device')}</th>
                    <th className="text-left p-3 font-medium">{t('GatewayPage.alignmentTable.role')}</th>
                    <th className="text-left p-3 font-medium">{t('GatewayPage.alignmentTable.status')}</th>
                  </tr>
                </thead>
                <tbody>
                  {alignment.items.map((item: any, idx: number) => (
                    <tr key={idx} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="p-3 font-mono">{item.vlan_id}</td>
                      <td className="p-3">{item.vlan_name}</td>
                      <td className="p-3 font-mono text-xs">{item.device_id?.slice(0, 8)}...</td>
                      <td className="p-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          item.device_role === 'brain'
                            ? 'bg-purple-500/10 text-purple-500'
                            : 'bg-blue-500/10 text-blue-500'
                        }`}>
                          {item.device_role}
                        </span>
                      </td>
                      <td className="p-3">
                        {item.status === 'aligned' && <CheckCircle className="h-4 w-4 text-green-500 inline" />}
                        {item.status === 'missing' && <XCircle className="h-4 w-4 text-red-500 inline" />}
                        {item.status === 'extra' && <AlertTriangle className="h-4 w-4 text-yellow-500 inline" />}
                        <span className="ml-1.5">{item.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        )}

        {alignment?.errors && alignment.errors.length > 0 && (
          <Card className="border-destructive">
            <CardContent noOffset className="p-4 space-y-1">
              {alignment.errors.map((err: string, i: number) => (
                <p key={i} className="text-sm text-destructive">{err}</p>
              ))}
            </CardContent>
          </Card>
        )}
      </div>
    );
  }

  // =====================================================================
  // Page Layout
  // =====================================================================

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Router}
        title={t('GatewayPage.header.title')}
        subtitle={t('GatewayPage.header.subtitle')}
        actions={<></>}
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('GatewayPage.error.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="dashboard" className="gap-1.5">
            <BarChart3 className="h-4 w-4" />
            {t('GatewayPage.tabs.dashboard')}
          </TabsTrigger>
          <TabsTrigger value="vlans" className="gap-1.5">
            <Network className="h-4 w-4" />
            {t('GatewayPage.tabs.vlans')}
            {vlans.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-5 min-w-5 p-0 flex items-center justify-center text-xs">
                {vlans.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="distribution" className="gap-1.5">
            <ArrowRightLeft className="h-4 w-4" />
            {t('GatewayPage.tabs.distribution')}
          </TabsTrigger>
          <TabsTrigger value="drift" className="gap-1.5">
            <AlertTriangle className="h-4 w-4" />
            {t('GatewayPage.tabs.drift')}
            {driftSummary.pending > 0 && (
              <Badge variant="destructive" className="ml-1 h-5 min-w-5 p-0 flex items-center justify-center text-xs">
                {driftSummary.pending > 99 ? '99+' : driftSummary.pending}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="templates" className="gap-1.5">
            <FileStack className="h-4 w-4" />
            {t('GatewayPage.tabs.templates')}
          </TabsTrigger>
          <TabsTrigger value="firewall-rules" className="gap-1.5">
            <Shield className="h-4 w-4" />
            {t('GatewayPage.tabs.fwRules')}
          </TabsTrigger>
          <TabsTrigger value="nat" className="gap-1.5">
            <Globe className="h-4 w-4" />
            {t('GatewayPage.tabs.nat')}
          </TabsTrigger>
          <TabsTrigger value="vpn" className="gap-1.5">
            <Lock className="h-4 w-4" />
            {t('GatewayPage.tabs.vpn')}
          </TabsTrigger>
          <TabsTrigger value="interfaces" className="gap-1.5">
            <Cable className="h-4 w-4" />
            {t('GatewayPage.tabs.interfaces')}
          </TabsTrigger>
          <TabsTrigger value="dhcp" className="gap-1.5">
            <Server className="h-4 w-4" />
            {t('GatewayPage.tabs.dhcpLeases')}
          </TabsTrigger>
          <TabsTrigger value="reconciliation" className="gap-1.5">
            <RefreshCw className="h-4 w-4" />
            {t('GatewayPage.tabs.reconciliation')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="mt-6">{renderDashboard()}</TabsContent>
        <TabsContent value="vlans" className="mt-6">{renderVlans()}</TabsContent>
        <TabsContent value="distribution" className="mt-6">{renderDistribution()}</TabsContent>
        <TabsContent value="drift" className="mt-6">{renderDrift()}</TabsContent>
        <TabsContent value="templates" className="mt-6">{renderTemplates()}</TabsContent>
        <TabsContent value="firewall-rules" className="mt-6">{renderFirewallRules()}</TabsContent>
        <TabsContent value="nat" className="mt-6">{renderNAT()}</TabsContent>
        <TabsContent value="vpn" className="mt-6">{renderVPN()}</TabsContent>
        <TabsContent value="interfaces" className="mt-6">{renderInterfaces()}</TabsContent>
        <TabsContent value="dhcp" className="mt-6">{renderDHCP()}</TabsContent>
        <TabsContent value="reconciliation" className="mt-6">{renderReconciliation()}</TabsContent>
      </Tabs>

      {/* ─── Create VLAN Dialog ──────────────────────────────── */}
      <CreateVlanDialog
        open={showCreateVlan}
        onOpenChange={setShowCreateVlan}
        onSubmit={(data) => createVlanMutation.mutateAsync(data)}
        sites={sites}
      />

      {/* ─── Create Template Dialog ──────────────────────────── */}
      <CreateTemplateDialog
        open={showCreateTemplate}
        onOpenChange={setShowCreateTemplate}
        onSubmit={(data) => createTemplateMutation.mutateAsync(data)}
      />

      {/* ─── Apply Template to Site Dialog ───────────────────── */}
      {applyingTemplate && (
        <ApplyTemplateDialog
          open={!!applyingTemplate}
          onOpenChange={(v) => { if (!v) setApplyingTemplate(null); }}
          template={applyingTemplate}
          sites={sites}
          onSubmit={(siteId) =>
            applyTemplateMutation.mutateAsync({ templateId: applyingTemplate.id, siteId })}
        />
      )}
    </div>
  );
}

// =============================================================================
// Create VLAN Dialog
// =============================================================================

const createVlanSchema = z.object({
  site_id: z.string().min(1, 'Site is required'),
  vlan_id: z.coerce.number().int().min(1, 'VLAN ID must be 1-4094').max(4094, 'VLAN ID must be 1-4094'),
  name: z.string().trim().min(1, 'Name is required'),
  subnet: z.string().trim().min(1, 'Subnet is required'),
  gateway_ip: z.string().trim().min(1, 'Gateway IP is required'),
  purpose: z.string(),
  dhcp_enabled: z.boolean(),
  dhcp_range_start: z.string(),
  dhcp_range_end: z.string(),
  distribute: z.boolean(),
});
type CreateVlanFormValues = z.infer<typeof createVlanSchema>;

function CreateVlanDialog({
  open,
  onOpenChange,
  onSubmit,
  sites,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSubmit: (data: CanonicalVLANCreate) => Promise<unknown> | unknown;
  isSubmitting?: boolean; // accepted for backward-compat; FormDialog handles its own state
  sites: Site[];
}) {
  const { t } = useTranslation('gateway');
  return (
    <FormDialog<CreateVlanFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('GatewayPage.createVlanDialog.title')}
      description={t('GatewayPage.createVlanDialog.description')}
      schema={createVlanSchema}
      defaultValues={{
        site_id: '',
        vlan_id: 0,
        name: '',
        subnet: '',
        gateway_ip: '',
        purpose: 'general',
        dhcp_enabled: true,
        dhcp_range_start: '',
        dhcp_range_end: '',
        distribute: true,
      }}
      submitLabel={t('GatewayPage.createVlanDialog.submitLabel')}
      contentClassName="max-w-lg"
      onSubmit={async (values) => {
        await onSubmit(values as CanonicalVLANCreate);
      }}
    >
      {(form) => {
        const dhcpEnabled = form.watch('dhcp_enabled');
        return (
          <>
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="site_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('GatewayPage.createVlanDialog.site')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger><SelectValue placeholder={t('GatewayPage.createVlanDialog.selectSite')} /></SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {sites.map((s) => (
                          <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="vlan_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('GatewayPage.createVlanDialog.vlanId')}</FormLabel>
                    <FormControl>
                      <Input type="number" min={1} max={4094} placeholder={t('GatewayPage.createVlanDialog.vlanIdPlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('GatewayPage.createVlanDialog.name')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('GatewayPage.createVlanDialog.namePlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="subnet"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('GatewayPage.createVlanDialog.subnet')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('GatewayPage.createVlanDialog.subnetPlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="gateway_ip"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('GatewayPage.createVlanDialog.gatewayIp')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('GatewayPage.createVlanDialog.gatewayIpPlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="purpose"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('GatewayPage.createVlanDialog.purpose')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {['general', 'management', 'iot', 'guest', 'voip', 'security'].map((p) => (
                          <SelectItem key={p} value={p} className="capitalize">{p}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="dhcp_enabled"
                render={({ field }) => (
                  <FormItem className="flex items-end space-x-2 pb-1 space-y-0">
                    <FormControl>
                      <input
                        type="checkbox"
                        id="dhcp_enabled"
                        checked={field.value}
                        onChange={(e) => field.onChange(e.target.checked)}
                        className="h-4 w-4 rounded border-input"
                      />
                    </FormControl>
                    <Label htmlFor="dhcp_enabled">{t('GatewayPage.createVlanDialog.enableDhcp')}</Label>
                  </FormItem>
                )}
              />
            </div>

            {dhcpEnabled && (
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="dhcp_range_start"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('GatewayPage.createVlanDialog.dhcpRangeStart')}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('GatewayPage.createVlanDialog.dhcpRangeStartPlaceholder')} {...field} />
                      </FormControl>
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="dhcp_range_end"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('GatewayPage.createVlanDialog.dhcpRangeEnd')}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('GatewayPage.createVlanDialog.dhcpRangeEndPlaceholder')} {...field} />
                      </FormControl>
                    </FormItem>
                  )}
                />
              </div>
            )}
          </>
        );
      }}
    </FormDialog>
  );
}

// =============================================================================
// Create Template Dialog
// =============================================================================

const createTemplateSchema = z.object({
  name: z.string().trim().min(1, 'Name is required'),
  description: z.string(),
  vlan_id: z.coerce.number().int().min(1, 'VLAN ID must be 1-4094').max(4094, 'VLAN ID must be 1-4094'),
  subnet_template: z.string().trim().min(1, 'Subnet template is required'),
  purpose: z.string(),
  dhcp_enabled: z.boolean(),
});
type CreateTemplateFormValues = z.infer<typeof createTemplateSchema>;

function CreateTemplateDialog({
  open,
  onOpenChange,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSubmit: (data: VLANTemplateCreate) => Promise<unknown> | unknown;
  isSubmitting?: boolean;
}) {
  const { t } = useTranslation('gateway');
  return (
    <FormDialog<CreateTemplateFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('GatewayPage.createTemplateDialog.title')}
      description={t('GatewayPage.createTemplateDialog.description')}
      schema={createTemplateSchema}
      defaultValues={{
        name: '',
        description: '',
        vlan_id: 0,
        subnet_template: '',
        purpose: 'general',
        dhcp_enabled: true,
      }}
      submitLabel={t('GatewayPage.createTemplateDialog.submitLabel')}
      contentClassName="max-w-lg"
      onSubmit={async (values) => {
        await onSubmit(values as VLANTemplateCreate);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('GatewayPage.createTemplateDialog.name')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('GatewayPage.createTemplateDialog.namePlaceholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('GatewayPage.createTemplateDialog.descriptionLabel')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('GatewayPage.createTemplateDialog.descriptionPlaceholder')} {...field} />
                </FormControl>
              </FormItem>
            )}
          />
          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="vlan_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('GatewayPage.createTemplateDialog.vlanId')}</FormLabel>
                  <FormControl>
                    <Input type="number" min={1} max={4094} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="subnet_template"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('GatewayPage.createTemplateDialog.subnetTemplate')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('GatewayPage.createTemplateDialog.subnetTemplatePlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="purpose"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('GatewayPage.createTemplateDialog.purpose')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {['general', 'management', 'iot', 'guest', 'voip', 'security'].map((p) => (
                        <SelectItem key={p} value={p} className="capitalize">{p}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="dhcp_enabled"
              render={({ field }) => (
                <FormItem className="flex items-end space-x-2 pb-1 space-y-0">
                  <FormControl>
                    <input
                      type="checkbox"
                      id="tmpl_dhcp"
                      checked={field.value}
                      onChange={(e) => field.onChange(e.target.checked)}
                      className="h-4 w-4 rounded border-input"
                    />
                  </FormControl>
                  <Label htmlFor="tmpl_dhcp">{t('GatewayPage.createTemplateDialog.enableDhcp')}</Label>
                </FormItem>
              )}
            />
          </div>
        </>
      )}
    </FormDialog>
  );
}

// =============================================================================
// Apply Template to Site Dialog
// =============================================================================

const applyTemplateSchema = z.object({
  site_id: z.string().min(1, 'Site is required'),
});
type ApplyTemplateFormValues = z.infer<typeof applyTemplateSchema>;

function ApplyTemplateDialog({
  open,
  onOpenChange,
  template,
  sites,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  template: VLANTemplateResponse;
  sites: Site[];
  onSubmit: (siteId: string) => Promise<unknown> | unknown;
}) {
  const { t } = useTranslation('gateway');
  return (
    <FormDialog<ApplyTemplateFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={`${t('GatewayPage.reconciliation.selectSiteTitle')} · ${template.name}`}
      description={t('GatewayPage.reconciliation.selectSiteDescription')}
      schema={applyTemplateSchema}
      defaultValues={{ site_id: '' }}
      submitLabel={t('GatewayPage.reconciliation.distributeToLimbs')}
      onSubmit={async (values) => {
        await onSubmit(values.site_id);
      }}
    >
      {(form) => (
        <FormField
          control={form.control}
          name="site_id"
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('GatewayPage.createVlanDialog.site')}</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <FormControl>
                  <SelectTrigger><SelectValue placeholder={t('GatewayPage.createVlanDialog.selectSite')} /></SelectTrigger>
                </FormControl>
                <SelectContent>
                  {sites.map((s) => (
                    <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
      )}
    </FormDialog>
  );
}
