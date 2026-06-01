// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Plugin Marketplace Page
 *
 * Browse, search, and install third-party plugins from the FreeSDN marketplace.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Search,
  Star,
  Download,
  CheckCircle,
  ShieldCheck,
  Loader2,
  Package,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';

import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { EmptyState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
// Gate marketplace installs behind an explicit AlertDialog confirmation,
// the /install endpoint downloads third-party code and runs it with full
// backend privileges. Both the card and the detail page must enforce this
// supply-chain acknowledgement.
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface MarketplacePlugin {
  plugin_id: string;
  slug: string;
  name: string;
  short_description: string;
  author_name: string;
  category: string;
  tags: string[];
  latest_version: string;
  icon_url: string | null;
  download_count: number;
  rating: number;
  rating_count: number;
  is_verified: boolean;
  is_featured: boolean;
  status: string;
}

interface BrowseResponse {
  plugins: MarketplacePlugin[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

interface InstalledPlugin {
  plugin_id: string;
  status: string;
}

// NOTE: Radix Select forbids empty-string SelectItem values, so we use
// 'all' as a sentinel and translate to undefined at the API boundary.
const ALL_CATEGORIES = 'all';
const CATEGORIES = [
  { value: ALL_CATEGORIES, labelKey: 'categories.all' },
  { value: 'monitoring', labelKey: 'categories.monitoring' },
  { value: 'security', labelKey: 'categories.security' },
  { value: 'automation', labelKey: 'categories.automation' },
  { value: 'integration', labelKey: 'categories.integration' },
  { value: 'analytics', labelKey: 'categories.analytics' },
  { value: 'device', labelKey: 'categories.device' },
  { value: 'reporting', labelKey: 'categories.reporting' },
];


// ─────────────────────────────────────────────────────────────────────────────
// Star rating display
// ─────────────────────────────────────────────────────────────────────────────

function StarRating({ rating, count }: { rating: number; count: number }) {
  return (
    <div className="flex items-center gap-1">
      <Star className="h-3.5 w-3.5 fill-yellow-400 text-yellow-400" />
      <span className="text-xs font-medium">{rating.toFixed(1)}</span>
      <span className="text-xs text-muted-foreground">({count})</span>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Plugin card
// ─────────────────────────────────────────────────────────────────────────────

function PluginCard({
  plugin,
  isInstalled,
  onInstall,
  installing,
  canInstall,
}: {
  plugin: MarketplacePlugin;
  isInstalled: boolean;
  onInstall: () => void;
  installing: boolean;
  // Install hard-gates on is_superuser server-side (403 otherwise); only
  // render the control for superusers. Browse stays visible to everyone.
  canInstall: boolean;
}) {
  const { t } = useTranslation('marketplace');
  return (
    <Card className="transition-shadow hover:shadow-md">
      <CardContent noOffset className="flex flex-col p-4">
        <div className="flex items-start gap-3">
          {plugin.icon_url ? (
            <img src={plugin.icon_url} alt="" className="h-10 w-10 rounded-md" />
          ) : (
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-muted">
              <Package className="h-5 w-5 text-muted-foreground" />
            </div>
          )}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              <Link
                to={`/marketplace/${plugin.slug}`}
                className="font-semibold hover:underline truncate"
              >
                {plugin.name}
              </Link>
              {plugin.is_verified && (
                <span title={t('MarketplacePage.card.verifiedTooltip')}><ShieldCheck className="h-3.5 w-3.5 flex-shrink-0 text-blue-500" /></span>
              )}
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t('MarketplacePage.card.byAuthor', { author: plugin.author_name })}
            </p>
          </div>
        </div>

        <p className="mt-3 flex-1 text-sm text-muted-foreground line-clamp-2">
          {plugin.short_description}
        </p>

        <div className="mt-3 flex flex-wrap gap-1">
          <Badge variant="secondary" className="text-xs">{plugin.category}</Badge>
          {plugin.tags.slice(0, 2).map((t) => (
            <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
          ))}
        </div>

        <div className="mt-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <StarRating rating={plugin.rating} count={plugin.rating_count} />
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Download className="h-3 w-3" />
              {plugin.download_count.toLocaleString()}
            </div>
          </div>

          {isInstalled ? (
            <Button size="sm" variant="outline" disabled>
              <CheckCircle className="mr-1.5 h-3.5 w-3.5 text-green-600" />
              {t('MarketplacePage.card.installed')}
            </Button>
          ) : !canInstall ? null : (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button size="sm" disabled={installing}>
                  {installing ? (
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Download className="mr-1.5 h-3.5 w-3.5" />
                  )}
                  {t('MarketplacePage.card.install')}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    {t('PluginDetailPage.installDialog.title')}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {t('PluginDetailPage.installDialog.warning')}
                    <br />
                    <br />
                    {t('PluginDetailPage.installDialog.pluginLabel')}{' '}
                    <strong>{plugin.name}</strong> v{plugin.latest_version} {t('PluginDetailPage.by')} {plugin.author_name}
                    {plugin.is_verified ? null : (
                      <>
                        <br />
                        <br />
                        <span className="text-destructive font-medium">
                          {t('PluginDetailPage.installDialog.notVerified')}
                        </span>
                      </>
                    )}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>{t('PluginDetailPage.installDialog.cancel')}</AlertDialogCancel>
                  <AlertDialogAction onClick={onInstall}>
                    {t('PluginDetailPage.installDialog.confirm')}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
        </div>
      </CardContent>
    </Card>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────

export default function MarketplacePage() {
  const { t } = useTranslation('marketplace');
  const queryClient = useQueryClient();
  // Install + Sync Registry hard-gate on is_superuser server-side (403 for
  // everyone else). Hide the controls for non-superusers; browse stays open.
  const isSuperuser = useAuthStore((s) => s.user?.is_superuser ?? false);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>(ALL_CATEGORIES);
  const [sort, setSort] = useState('downloads');
  const [page, setPage] = useState(1);
  const [installingSlug, setInstallingSlug] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery<BrowseResponse>({
    queryKey: ['marketplace-plugins', search, category, sort, page],
    queryFn: () =>
      api
        .get('/marketplace/plugins', {
          params: {
            q: search || undefined,
            // Translate sentinel to "no filter" at API boundary
            category: category && category !== ALL_CATEGORIES ? category : undefined,
            sort,
            page,
          },
        })
        .then((r) => r.data),
  });

  const { data: installed = [] } = useQuery<InstalledPlugin[]>({
    queryKey: ['plugins'],
    queryFn: () => api.get('/plugins').then((r) => r.data),
  });

  const installedSet = new Set(installed.map((p) => p.plugin_id));

  const installMutation = useMutation({
    mutationFn: (slug: string) =>
      api.post(`/marketplace/plugins/${slug}/install`).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      queryClient.invalidateQueries({ queryKey: ['marketplace-plugins'] });
      setInstallingSlug(null);
    },
    onError: () => setInstallingSlug(null),
  });

  const handleInstall = (slug: string) => {
    setInstallingSlug(slug);
    installMutation.mutate(slug);
  };

  const syncMutation = useMutation({
    mutationFn: () => api.post('/marketplace/plugins/sync'),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['marketplace-plugins'] }),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Package}
        title={t('MarketplacePage.header.title')}
        subtitle={t('MarketplacePage.header.subtitle')}
        actions={
          isSuperuser ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
            >
              {syncMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="mr-2 h-4 w-4" />
              )}
              {t('MarketplacePage.actions.syncRegistry')}
            </Button>
          ) : undefined
        }
      />

      {/* Search + Filters */}
      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t('MarketplacePage.filters.searchPlaceholder')}
            className="pl-9"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          />
        </div>
        <Select value={category} onValueChange={(v) => { setCategory(v); setPage(1); }}>
          <SelectTrigger className="w-full sm:w-48">
            <SelectValue placeholder={t('MarketplacePage.categories.all')} />
          </SelectTrigger>
          <SelectContent>
            {CATEGORIES.map((c) => (
              <SelectItem key={c.value} value={c.value}>{t(`MarketplacePage.${c.labelKey}`)}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={sort} onValueChange={setSort}>
          <SelectTrigger className="w-full sm:w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="downloads">{t('MarketplacePage.sort.downloads')}</SelectItem>
            <SelectItem value="rating">{t('MarketplacePage.sort.rating')}</SelectItem>
            <SelectItem value="newest">{t('MarketplacePage.sort.newest')}</SelectItem>
            <SelectItem value="name">{t('MarketplacePage.sort.name')}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{t('MarketplacePage.errors.loadFailed')}</AlertDescription>
        </Alert>
      )}

      {syncMutation.isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>            {(syncMutation.error as any)?.response?.data?.detail || t('MarketplacePage.errors.loadFailed')}
          </AlertDescription>
        </Alert>
      )}

      {installMutation.isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>            {(installMutation.error as any)?.response?.data?.detail || t('MarketplacePage.errors.installFailed')}
          </AlertDescription>
        </Alert>
      )}

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
        </div>
      ) : (
        <>
          {data && data.total > 0 && (
            <p className="text-sm text-muted-foreground">
              {data.total === 1
                ? t('MarketplacePage.results.countOne', { count: data.total })
                : t('MarketplacePage.results.countOther', { count: data.total })}
            </p>
          )}

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {data?.plugins.map((plugin) => (
              <PluginCard
                key={plugin.slug}
                plugin={plugin}
                isInstalled={installedSet.has(plugin.plugin_id)}
                onInstall={() => handleInstall(plugin.slug)}
                installing={installingSlug === plugin.slug}
                canInstall={isSuperuser}
              />
            ))}
          </div>

          {data && data.pages > 1 && (
            <div className="flex items-center justify-center gap-2 pt-4">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 1}
                onClick={() => setPage((p) => p - 1)}
              >
                {t('MarketplacePage.pagination.previous')}
              </Button>
              <span className="text-sm text-muted-foreground">
                {t('MarketplacePage.pagination.pageOf', { page, total: data.pages })}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page === data.pages}
                onClick={() => setPage((p) => p + 1)}
              >
                {t('MarketplacePage.pagination.next')}
              </Button>
            </div>
          )}

          {data?.plugins.length === 0 && (
            <EmptyState
              icon={Package}
              title={t('MarketplacePage.empty.title')}
              description={t('MarketplacePage.empty.description')}
            />
          )}
        </>
      )}
    </div>
  );
}
