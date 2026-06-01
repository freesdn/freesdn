// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Organization Detail / Dashboard Page
 * ====================================================
 *
 * Enterprise org drill-down with tabs: Overview · Sites · Users · Settings.
 * Fetches the rich /organizations/{id}/dashboard payload.
 */

import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isValid } from 'date-fns';
import {
  Building2,
  MapPin,
  Users,
  Server,
  Wifi,
  Activity,
  Settings,
  ChevronLeft,
  CheckCircle,
  XCircle,
  Mail,
  Phone,
  ExternalLink,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';

/* ============================================================
   Types
   ============================================================ */

interface SiteWithStats {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  address: string | null;
  city: string | null;
  country: string | null;
  timezone: string;
  is_active: boolean;
  organization_id: string;
  controller_count: number;
  device_count: number;
  online_device_count: number;
  created_at: string;
  updated_at: string;
}

interface OrgDashboard {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  contact_email: string | null;
  contact_phone: string | null;
  is_active: boolean;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  site_count: number;
  user_count: number;
  controller_count: number;
  device_count: number;
  online_device_count: number;
  recent_sites: SiteWithStats[];
}


/* ============================================================
   Helpers
   ============================================================ */

function StatusDot({ active }: { active: boolean }) {
  return (
    <span
      className={cn(
        'inline-block h-2 w-2 rounded-full',
        active ? 'bg-emerald-500' : 'bg-muted-foreground',
      )}
    />
  );
}


/* ============================================================
   Sub-components
   ============================================================ */

function RecentSiteRow({ site }: { site: SiteWithStats }) {
  const navigate = useNavigate();
  const healthPct =
    site.device_count > 0
      ? Math.round((site.online_device_count / site.device_count) * 100)
      : null;
  const healthColor =
    healthPct === null
      ? 'text-muted-foreground'
      : healthPct >= 90
        ? 'text-emerald-600'
        : healthPct >= 70
          ? 'text-amber-500'
          : 'text-red-500';

  return (
    <button
      className="flex w-full items-center gap-4 rounded-lg border p-3 text-left transition-colors hover:bg-muted/30"
      onClick={() => navigate(`/sites/${site.id}`)}
    >
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
        <Building2 className="h-5 w-5 text-primary" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 font-medium">
          <StatusDot active={site.is_active} />
          <span className="truncate">{site.name}</span>
        </div>
        <div className="truncate text-xs text-muted-foreground">
          {[site.city, site.country].filter(Boolean).join(', ') || site.slug}
        </div>
      </div>
      {/* Mini stats */}
      <div className="hidden sm:flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <Server className="h-3 w-3" /> {site.controller_count}
        </span>
        <span className="flex items-center gap-1">
          <Wifi className="h-3 w-3" /> {site.device_count}
        </span>
        {healthPct !== null && (
          <span className={cn('font-medium tabular-nums', healthColor)}>{healthPct}%</span>
        )}
      </div>
      <ExternalLink className="h-4 w-4 shrink-0 text-muted-foreground" />
    </button>
  );
}


function OrgInfoCard({ dashboard }: { dashboard: OrgDashboard }) {
  const { t } = useTranslation('organizations');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const plan = (dashboard.settings as any)?.plan ?? 'free';
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('OrganizationDetailPage.info.title')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">{t('OrganizationDetailPage.info.slug')}</span>
          <code className="rounded bg-muted px-2 py-0.5 text-xs">{dashboard.slug}</code>
        </div>
        <Separator />
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">{t('OrganizationDetailPage.info.plan')}</span>
          <Badge variant="outline" className="capitalize">{plan}</Badge>
        </div>
        <Separator />
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">{t('OrganizationDetailPage.info.status')}</span>
          <Badge
            variant="outline"
            className={cn(
              'gap-1',
              dashboard.is_active
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600'
                : 'border-red-500/30 bg-red-500/10 text-red-500',
            )}
          >
            {dashboard.is_active ? (
              <CheckCircle className="h-3 w-3" />
            ) : (
              <XCircle className="h-3 w-3" />
            )}
            {dashboard.is_active ? t('OrganizationDetailPage.status.active') : t('OrganizationDetailPage.status.inactive')}
          </Badge>
        </div>
        {dashboard.contact_email && (
          <>
            <Separator />
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground flex items-center gap-1">
                <Mail className="h-3.5 w-3.5" /> {t('OrganizationDetailPage.info.email')}
              </span>
              <span>{dashboard.contact_email}</span>
            </div>
          </>
        )}
        {dashboard.contact_phone && (
          <>
            <Separator />
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground flex items-center gap-1">
                <Phone className="h-3.5 w-3.5" /> {t('OrganizationDetailPage.info.phone')}
              </span>
              <span>{dashboard.contact_phone}</span>
            </div>
          </>
        )}
        {dashboard.description && (
          <>
            <Separator />
            <p className="text-muted-foreground leading-relaxed">{dashboard.description}</p>
          </>
        )}
        <Separator />
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{t('OrganizationDetailPage.info.created')}</span>
          <span>
            {dashboard.created_at && isValid(new Date(dashboard.created_at))
              ? new Date(dashboard.created_at).toLocaleDateString()
              : '—'}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}


/* ============================================================
   Overview Tab
   ============================================================ */

function OverviewTab({ dashboard }: { dashboard: OrgDashboard }) {
  const navigate = useNavigate();
  const { t } = useTranslation('organizations');
  const recentSites = Array.isArray(dashboard.recent_sites) ? dashboard.recent_sites : [];
  const healthPct =
    dashboard.device_count > 0
      ? Math.round((dashboard.online_device_count / dashboard.device_count) * 100)
      : null;

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('OrganizationDetailPage.stats.sites'), value: dashboard.site_count, icon: MapPin, variant: 'primary' },
          { title: t('OrganizationDetailPage.stats.users'), value: dashboard.user_count, icon: Users, variant: 'primary' },
          { title: t('OrganizationDetailPage.stats.controllers'), value: dashboard.controller_count, icon: Server, variant: 'primary' },
          {
            title: t('OrganizationDetailPage.stats.devices'),
            value: dashboard.device_count,
            icon: Wifi,
            variant: 'primary',
            description: healthPct !== null ? t('OrganizationDetailPage.stats.percentOnline', { pct: healthPct }) : undefined,
          },
          { title: t('OrganizationDetailPage.stats.online'), value: dashboard.online_device_count, icon: Activity, variant: 'success' },
        ]}
      />

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Recent Sites */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-base">{t('OrganizationDetailPage.recentSites.title')}</CardTitle>
              <CardDescription>{t('OrganizationDetailPage.recentSites.description')}</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate(`/sites`)}>
              {t('OrganizationDetailPage.recentSites.viewAll')}
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentSites.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                {t('OrganizationDetailPage.recentSites.empty')}
              </p>
            ) : (
              recentSites.map((site) => (
                <RecentSiteRow key={site.id} site={site} />
              ))
            )}
          </CardContent>
        </Card>

        {/* Org info */}
        <OrgInfoCard dashboard={dashboard} />
      </div>
    </div>
  );
}


/* ============================================================
   Sites Tab (compact list · links to /sites filtered)
   ============================================================ */

function SitesTab({ dashboard }: { dashboard: OrgDashboard }) {
  const { t } = useTranslation('organizations');
  const { data: allSites = [], isLoading } = useQuery<SiteWithStats[]>({
    queryKey: ['org-sites', dashboard.id],
    queryFn: async () => {
      const r = await api.get('/sites/', {
        params: { organization_id: dashboard.id, per_page: 100 },
      });
      return r.data.items ?? [];
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {allSites.length === 0 ? (
        <Card>
          <EmptyState
            icon={MapPin}
            title={t('OrganizationDetailPage.sitesTab.emptyTitle')}
            description={t('OrganizationDetailPage.sitesTab.emptyDescription')}
          />
        </Card>
      ) : (
        allSites.map((site) => <RecentSiteRow key={site.id} site={site} />)
      )}
    </div>
  );
}


/* ============================================================
   Users Tab (placeholder · links to /users filtered)
   ============================================================ */

function UsersTab() {
  const navigate = useNavigate();
  const { t } = useTranslation('organizations');
  return (
    <Card>
      <EmptyState
        icon={Users}
        title={t('OrganizationDetailPage.usersTab.title')}
        description={t('OrganizationDetailPage.usersTab.description')}
        action={{
          label: t('OrganizationDetailPage.usersTab.action'),
          icon: Users,
          onClick: () => navigate('/users'),
        }}
      />
    </Card>
  );
}


/* ============================================================
   Settings Tab (edit form · PATCH /organizations/{id})
   ============================================================ */

function SettingsTab({ dashboard }: { dashboard: OrgDashboard }) {
  const { t } = useTranslation('organizations');
  const { t: tc } = useTranslation();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [name, setName] = useState(dashboard.name);
  const [description, setDescription] = useState(dashboard.description ?? '');
  const [contactEmail, setContactEmail] = useState(dashboard.contact_email ?? '');
  const [contactPhone, setContactPhone] = useState(dashboard.contact_phone ?? '');
  const [isActive, setIsActive] = useState(dashboard.is_active);

  const mutation = useMutation({
    mutationFn: async () => {
      const r = await api.patch(`/organizations/${dashboard.id}`, {
        name: name.trim(),
        description: description.trim() || null,
        contact_email: contactEmail.trim() || null,
        contact_phone: contactPhone.trim() || null,
        is_active: isActive,
      });
      return r.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['org-dashboard', dashboard.id] });
      toast({ title: tc('common.success'), description: dashboard.name });
    },
    onError: (err: unknown) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const detail = (err as any)?.response?.data?.detail;
      toast({
        title: tc('common.error'),
        description: typeof detail === 'string' ? detail : tc('common.error'),
        variant: 'destructive',
      });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('OrganizationDetailPage.settingsTab.title')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{tc('organizations.fields.name')} *</label>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{tc('organizations.fields.ownerEmail')}</label>
          <Input
            type="email"
            value={contactEmail}
            onChange={(e) => setContactEmail(e.target.value)}
            placeholder={tc('organizations.placeholders.ownerEmail')}
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{t('OrganizationDetailPage.info.phone')}</label>
          <Input value={contactPhone} onChange={(e) => setContactPhone(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{tc('organizations.fields.description')}</label>
          <Textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={tc('organizations.placeholders.description')}
          />
        </div>
        <div className="flex items-center justify-between rounded-lg border p-3">
          <span className="text-sm font-medium">{t('OrganizationDetailPage.info.status')}</span>
          <div className="flex items-center gap-2">
            <Switch checked={isActive} onCheckedChange={setIsActive} />
            <span className="text-sm text-muted-foreground">
              {isActive
                ? t('OrganizationDetailPage.status.active')
                : t('OrganizationDetailPage.status.inactive')}
            </span>
          </div>
        </div>
        <div className="flex justify-end">
          <Button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || name.trim().length === 0}
          >
            {mutation.isPending ? tc('common.saving') : tc('common.save')}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}


/* ============================================================
   Page
   ============================================================ */

export default function OrganizationDetailPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const { t } = useTranslation('organizations');
  const activeTab = tab || 'overview';

  const {
    data: dashboard,
    isLoading,
    isError,
    refetch,
  } = useQuery<OrgDashboard>({
    queryKey: ['org-dashboard', orgId],
    queryFn: async () => {
      const r = await api.get(`/organizations/${orgId}/dashboard`);
      return r.data;
    },
    enabled: !!orgId,
    refetchInterval: 30_000,
  });

  // Error first, otherwise the `!dashboard` skeleton guard below would
  // swallow the error case (data is undefined on error) and the ErrorState
  // would be unreachable.
  if (isError) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" onClick={() => navigate('/organizations')}>
          <ChevronLeft className="mr-2 h-4 w-4" /> {t('OrganizationDetailPage.backToOrganizations')}
        </Button>
        <ErrorState
          message={t('OrganizationDetailPage.error.loadFailed')}
          onRetry={() => {
            void refetch();
          }}
        />
      </div>
    );
  }

  if (isLoading || !dashboard) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Building2}
        title={dashboard.name}
        breadcrumbs={
          <button
            onClick={() => navigate('/organizations')}
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            {t('OrganizationDetailPage.backToOrganizations')}
          </button>
        }
        description={`${dashboard.slug} · ${dashboard.site_count === 1
          ? t('OrganizationDetailPage.header.siteCount_one', { count: dashboard.site_count })
          : t('OrganizationDetailPage.header.siteCount_other', { count: dashboard.site_count })} · ${dashboard.user_count === 1
          ? t('OrganizationDetailPage.header.userCount_one', { count: dashboard.user_count })
          : t('OrganizationDetailPage.header.userCount_other', { count: dashboard.user_count })}`}
      />

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onValueChange={(v) =>
          navigate(v === 'overview' ? `/organizations/${orgId}` : `/organizations/${orgId}/${v}`, { replace: true })
        }
      >
        <TabsList>
          <TabsTrigger value="overview" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" /> {t('OrganizationDetailPage.tabs.overview')}
          </TabsTrigger>
          <TabsTrigger value="sites" className="gap-1.5">
            <MapPin className="h-3.5 w-3.5" /> {t('OrganizationDetailPage.tabs.sites')}
          </TabsTrigger>
          <TabsTrigger value="users" className="gap-1.5">
            <Users className="h-3.5 w-3.5" /> {t('OrganizationDetailPage.tabs.users')}
          </TabsTrigger>
          <TabsTrigger value="settings" className="gap-1.5">
            <Settings className="h-3.5 w-3.5" /> {t('OrganizationDetailPage.tabs.settings')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-6">
          <OverviewTab dashboard={dashboard} />
        </TabsContent>
        <TabsContent value="sites" className="mt-6">
          <SitesTab dashboard={dashboard} />
        </TabsContent>
        <TabsContent value="users" className="mt-6">
          <UsersTab />
        </TabsContent>
        <TabsContent value="settings" className="mt-6">
          <SettingsTab dashboard={dashboard} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export { OrganizationDetailPage };
