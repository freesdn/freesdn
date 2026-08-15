// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, Module Detail Page
 *
 * Enterprise-grade integration detail page.
 * Shows full module information with enable / disable / reload controls.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useMemo, useState, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  RefreshCw,
  Shield,
  Puzzle,
  Globe,
  Lock,
  Cpu,
  LayoutDashboard,
  PackageOpen,
  FileText,
  ExternalLink,
  Info,
  Layers,
  Navigation,
  Boxes,
  ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader, PageTabs } from '@/components/layout';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { cn, safeExternalUrl } from '@/lib/utils';
import { useModuleStore } from '@/stores/moduleStore';
import { useAuthStore } from '@/stores/authStore';
import { useModuleToggle, moduleQueryKeys } from '@/hooks/useModules';
import { modulesApi } from '@/lib/api';
import { resolveIcon } from '@/utils/lucide-icon-map';
import type { ModuleManifest } from '@/stores/moduleStore';

// ────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────

const CATEGORY_COLORS: Record<string, string> = {
  core: 'bg-blue-500/10 text-blue-600 border-blue-500/20',
  surveillance: 'bg-purple-500/10 text-purple-600 border-purple-500/20',
  security: 'bg-red-500/10 text-red-600 border-red-500/20',
  communication: 'bg-green-500/10 text-green-600 border-green-500/20',
  system: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20',
};

function getCategoryClasses(category: string) {
  return CATEGORY_COLORS[category?.toLowerCase()] || 'bg-muted text-muted-foreground border-border';
}

// ────────────────────────────────────────────────────────────
// Info Row, key / value pair
// ────────────────────────────────────────────────────────────

function InfoRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between py-2.5 gap-6">
      <span className="text-sm text-muted-foreground shrink-0">{label}</span>
      <span className={cn('text-sm text-right', mono && 'font-mono text-xs')}>{value || '-'}</span>
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// Section wrapper
// ────────────────────────────────────────────────────────────

function Section({
  title,
  icon: Icon,
  children,
  emptyText,
  isEmpty,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  emptyText?: string;
  isEmpty?: boolean;
}) {
  const { t } = useTranslation('settings');
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        {isEmpty ? (
          <p className="text-sm text-muted-foreground italic">{emptyText || t('ModuleDetailPage.section.noneConfigured')}</p>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}

// ────────────────────────────────────────────────────────────
// Main page
// ────────────────────────────────────────────────────────────

export default function ModuleDetailPage() {
  const { t } = useTranslation('settings');
  const { moduleId } = useParams<{ moduleId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const orgId = user?.organization_id;

  const { modules: storeModules, enabledModules, orgModules: storeOrgModules, setModules, setOrgModules } = useModuleStore();
  const { toggleModule, isToggling, toggleError, resetError } = useModuleToggle();

  // ── Direct data fetching (shares cache with useModulesInit) ──
  const { data: fetchedModules, isLoading: modulesLoading, isError: modulesError } = useQuery({
    queryKey: moduleQueryKeys.all,
    queryFn: async () => {
      const res = await modulesApi.getAll();
      const d = res.data;
      if (Array.isArray(d)) return d as ModuleManifest[];
      if (d && typeof d === 'object' && Array.isArray((d as any).modules)) return (d as any).modules as ModuleManifest[];
      return [] as ModuleManifest[];
    },
    staleTime: 5 * 60 * 1000,
  });

  const { data: fetchedOrgModules, isError: orgModulesError } = useQuery({
    queryKey: moduleQueryKeys.org(orgId ?? undefined),
    queryFn: async () => {
      const res = await modulesApi.getOrgModules(orgId!, true);
      const d = res.data;
      if (Array.isArray(d)) return d;
      if (d && typeof d === 'object' && Array.isArray((d as any).modules)) return (d as any).modules;
      return [];
    },
    enabled: !!orgId,
    staleTime: 30 * 1000,
  });

  // Sync fetched data to store
  useEffect(() => {
    if (fetchedModules && fetchedModules.length > 0 && storeModules.length === 0) {
      setModules(fetchedModules);
    }
  }, [fetchedModules, storeModules.length, setModules]);

  useEffect(() => {
    if (fetchedOrgModules && fetchedOrgModules.length > 0) {
      setOrgModules(fetchedOrgModules);
    }
  }, [fetchedOrgModules, setOrgModules]);

  const allModules = (fetchedModules && fetchedModules.length > 0) ? fetchedModules : storeModules;
  const allOrgModules = (fetchedOrgModules && fetchedOrgModules.length > 0) ? fetchedOrgModules : storeOrgModules;

  const module = useMemo(
    () => allModules.find((m) => m.id === moduleId),
    [allModules, moduleId],
  );

  const orgModule = useMemo(
    () => allOrgModules.find((om: any) => om.module_id === moduleId),
    [allOrgModules, moduleId],
  );

  const isEnabled = enabledModules.includes(moduleId || '');

  // Dependent modules (modules that require this one)
  const dependents = useMemo(() => {
    if (!moduleId) return [];
    return allModules.filter(
      (m) =>
        m.dependencies?.some((d) => d.module_id === moduleId && !d.optional) &&
        enabledModules.includes(m.id),
    );
  }, [allModules, moduleId, enabledModules]);

  // Missing dependencies for this module
  const missingDeps = useMemo(() => {
    if (!module) return [];
    return (module.dependencies || [])
      .filter((d) => !d.optional && !enabledModules.includes(d.module_id))
      .map((d) => {
        const depMod = allModules.find((m) => m.id === d.module_id);
        return { ...d, name: depMod?.name || d.module_id };
      });
  }, [module, allModules, enabledModules]);

  // ── Toggle confirm dialog ───────────────────────────────
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [togglingLocal, setTogglingLocal] = useState(false);

  const handleToggleClick = useCallback(() => {
    if (module?.is_core && isEnabled) return; // Can't disable core
    if (module?.coming_soon) return; // Preview module — not enableable yet
    setConfirmOpen(true);
  }, [module, isEnabled]);

  const executeToggle = async () => {
    if (!moduleId) return;
    setTogglingLocal(true);
    resetError();
    try {
      await toggleModule(moduleId, isEnabled);
    } catch (err) {
      console.error('Failed to toggle module:', err);
    } finally {
      setTogglingLocal(false);
      setConfirmOpen(false);
    }
  };

  const handleRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.all });
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.states });
    if (orgId) {
      queryClient.invalidateQueries({ queryKey: moduleQueryKeys.org(orgId) });
      queryClient.invalidateQueries({ queryKey: moduleQueryKeys.navigation(orgId) });
    }
  }, [queryClient, orgId]);

  // ──────────────────────────────────────────────────────────
  // Loading
  // ──────────────────────────────────────────────────────────

  if (modulesLoading && !module) {
    return (
      <div className="container max-w-5xl py-8">
        <div className="flex items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  // ──────────────────────────────────────────────────────────
  // 404
  // ──────────────────────────────────────────────────────────

  if (!module) {
    return (
      <div className="container max-w-5xl py-8">
        <Button variant="ghost" size="sm" className="gap-1.5 mb-6" onClick={() => navigate('/settings/modules')}>
          <ArrowLeft className="h-4 w-4" />
          {t('ModuleDetailPage.backToModules')}
        </Button>
        <Card>
          <EmptyState
            icon={Puzzle}
            title={t('ModuleDetailPage.notFound.title')}
            description={t('ModuleDetailPage.notFound.description', { moduleId })}
          />
        </Card>
      </div>
    );
  }

  const catClasses = getCategoryClasses(module.category);
  const ModuleIcon = resolveIcon(module.icon);
  const comingSoon = !!module.coming_soon;

  // ──────────────────────────────────────────────────────────
  // Render
  // ──────────────────────────────────────────────────────────

  return (
    <div className="container max-w-5xl py-6 space-y-6">
      {/* ── Page header (icon + name + breadcrumb + controls) ── */}
      <PageHeader
        icon={ModuleIcon}
        title={module.name}
        description={module.description}
        breadcrumbs={
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 shrink-0 h-8"
              onClick={() => navigate('/settings/modules')}
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              {t('ModuleDetailPage.breadcrumb.modules')}
            </Button>
            <Separator orientation="vertical" className="h-4" />
            <nav className="flex items-center gap-1.5 text-sm text-muted-foreground min-w-0">
              <Link to="/settings/modules" className="hover:text-foreground transition-colors">
                {t('ModuleDetailPage.breadcrumb.settings')}
              </Link>
              <ChevronRight className="h-3.5 w-3.5 shrink-0" />
              <Link to="/settings/modules" className="hover:text-foreground transition-colors">
                {t('ModuleDetailPage.breadcrumb.modules')}
              </Link>
              <ChevronRight className="h-3.5 w-3.5 shrink-0" />
              <span className="text-foreground font-medium truncate">{module.name}</span>
            </nav>
          </div>
        }
        actions={
          <>
            {/* Status indicator */}
            <div className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border',
              isEnabled
                ? 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20'
                : 'bg-muted text-muted-foreground border-border',
            )}>
              {isEnabled ? (
                <CheckCircle2 className="h-3.5 w-3.5" />
              ) : (
                <XCircle className="h-3.5 w-3.5" />
              )}
              {isEnabled ? t('ModuleDetailPage.status.enabled') : t('ModuleDetailPage.status.disabled')}
            </div>

            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={handleRefresh}>
                    <RefreshCw className="h-3.5 w-3.5" />
                    {t('ModuleDetailPage.actions.reload')}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{t('ModuleDetailPage.actions.reloadTooltip')}</TooltipContent>
              </Tooltip>
            </TooltipProvider>

            {comingSoon ? (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    {/* span wrapper: disabled buttons don't emit the pointer
                        events the tooltip listens for */}
                    <span className="inline-flex">
                      <Button variant="default" size="sm" className="h-8 gap-1.5" disabled>
                        {t('ModuleDetailPage.actions.enable')}
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>
                    {t('ModuleDetailPage.actions.comingSoonTooltip', 'This module is a preview and cannot be enabled yet.')}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ) : (
              <Button
                variant={isEnabled ? 'destructive' : 'default'}
                size="sm"
                className="h-8 gap-1.5"
                onClick={handleToggleClick}
                disabled={
                  (module.is_core && isEnabled) || isToggling || togglingLocal
                }
              >
                {(isToggling || togglingLocal) && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                )}
                {isEnabled ? t('ModuleDetailPage.actions.disable') : t('ModuleDetailPage.actions.enable')}
              </Button>
            )}
          </>
        }
      />

      {/* ── Module metadata badges ─────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        <Badge variant="outline" className="text-xs font-mono h-5">
          v{module.version}
        </Badge>
        <Badge variant="outline" className={cn('text-xs h-5 border', catClasses)}>
          {module.category}
        </Badge>
        {module.is_core && (
          <Badge variant="secondary" className="text-xs h-5 gap-1">
            <Shield className="h-3 w-3" />
            {t('ModuleDetailPage.badges.core')}
          </Badge>
        )}
        {comingSoon && (
          <Badge variant="outline" className="text-xs h-5 border-sky-500/50 text-sky-600 dark:text-sky-400">
            {t('ModuleDetailPage.badges.comingSoon', 'Coming soon')}
          </Badge>
        )}
        {module.is_beta && (
          <Badge variant="outline" className="text-xs h-5 border-amber-500/50 text-amber-600">
            {t('ModuleDetailPage.badges.beta')}
          </Badge>
        )}
        {module.is_premium && (
          <Badge variant="outline" className="text-xs h-5 border-yellow-500/50 text-yellow-600">
            {t('ModuleDetailPage.badges.premium')}
          </Badge>
        )}
        {module.author && (
          <span className="text-xs text-muted-foreground">{t('ModuleDetailPage.byAuthor', { author: module.author })}</span>
        )}
      </div>

      {/* ── Preview / coming-soon banner ───────────────── */}
      {comingSoon && (
        <div className="flex items-start gap-2 p-3 rounded-lg border border-sky-500/30 bg-sky-500/5 text-sm">
          <Info className="h-4 w-4 text-sky-500 shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-sky-600 dark:text-sky-400">{t('ModuleDetailPage.banners.comingSoon.title', 'Coming soon')}</p>
            <p className="text-muted-foreground mt-0.5">
              {t('ModuleDetailPage.banners.comingSoon.body', 'This module is a preview and is not yet available to enable. It is included so you can review its capabilities ahead of general availability.')}
            </p>
          </div>
        </div>
      )}

      {/* ── Error / warning banners ────────────────────── */}
      {(modulesError || orgModulesError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('ModuleDetailPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}
      {toggleError && (
        <div className="flex items-center gap-2 p-3 rounded-lg border border-destructive/30 bg-destructive/5 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span className="flex-1">{t('ModuleDetailPage.errors.toggleFailed', { error: String(toggleError) })}</span>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={resetError}>
            {t('ModuleDetailPage.actions.dismiss')}
          </Button>
        </div>
      )}

      {missingDeps.length > 0 && !isEnabled && (
        <div className="flex items-start gap-2 p-3 rounded-lg border border-amber-500/30 bg-amber-500/5 text-sm">
          <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-amber-600">{t('ModuleDetailPage.banners.missingDeps.title')}</p>
            <p className="text-muted-foreground mt-0.5">
              {t('ModuleDetailPage.banners.missingDeps.body')}{' '}
              {missingDeps.map((d, i) => (
                <span key={d.module_id}>
                  {i > 0 && ', '}
                  <Link
                    to={`/settings/modules/${d.module_id}`}
                    className="underline underline-offset-2 hover:text-foreground"
                  >
                    {d.name}
                  </Link>
                  <span className="text-xs text-muted-foreground ml-1">{t('ModuleDetailPage.minVersion', { version: d.min_version })}</span>
                </span>
              ))}
            </p>
          </div>
        </div>
      )}

      {dependents.length > 0 && isEnabled && (
        <div className="flex items-start gap-2 p-3 rounded-lg border border-blue-500/30 bg-blue-500/5 text-sm">
          <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-blue-600">{dependents.length === 1 ? t('ModuleDetailPage.banners.requiredBy.one', { count: dependents.length }) : t('ModuleDetailPage.banners.requiredBy.other', { count: dependents.length })}</p>
            <p className="text-muted-foreground mt-0.5">
              {dependents.map((d, i) => (
                <span key={d.id}>
                  {i > 0 && ', '}
                  <Link
                    to={`/settings/modules/${d.id}`}
                    className="underline underline-offset-2 hover:text-foreground"
                  >
                    {d.name}
                  </Link>
                </span>
              ))}
            </p>
          </div>
        </div>
      )}

      {/* ── Detail tabs ────────────────────────────────── */}
      <PageTabs
        basePath={`/settings/modules/${module.id}`}
        tabs={[
          {
            value: 'overview',
            label: (
              <span className="inline-flex items-center gap-1.5 text-xs">
                <Info className="h-3.5 w-3.5" />
                {t('ModuleDetailPage.tabs.overview')}
              </span>
            ),
            content: (
              <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Section title={t('ModuleDetailPage.sections.moduleInfo')} icon={FileText}>
              <div className="divide-y">
                <InfoRow label={t('ModuleDetailPage.fields.moduleId')} value={module.id} mono />
                <InfoRow label={t('ModuleDetailPage.fields.version')} value={module.version} mono />
                <InfoRow label={t('ModuleDetailPage.fields.category')} value={module.category} />
                <InfoRow label={t('ModuleDetailPage.fields.author')} value={module.author} />
                <InfoRow label={t('ModuleDetailPage.fields.license')} value={module.license} />
                {module.min_core_version && (
                  <InfoRow label={t('ModuleDetailPage.fields.minCoreVersion')} value={module.min_core_version} mono />
                )}
                {safeExternalUrl(module.docs_url) && (
                  <InfoRow
                    label={t('ModuleDetailPage.fields.documentation')}
                    value={
                      <a
                        href={safeExternalUrl(module.docs_url)!}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-primary hover:underline"
                      >
                        {t('ModuleDetailPage.actions.viewDocs')}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    }
                  />
                )}
              </div>
            </Section>

            <Section title={t('ModuleDetailPage.sections.statusActivation')} icon={CheckCircle2}>
              <div className="divide-y">
                <InfoRow
                  label={t('ModuleDetailPage.fields.state')}
                  value={
                    <Badge variant={isEnabled ? 'default' : 'secondary'} className="text-xs">
                      {isEnabled ? t('ModuleDetailPage.status.enabled') : t('ModuleDetailPage.status.disabled')}
                    </Badge>
                  }
                />
                <InfoRow label={t('ModuleDetailPage.fields.coreModule')} value={module.is_core ? t('ModuleDetailPage.yes') : t('ModuleDetailPage.no')} />
                <InfoRow label={t('ModuleDetailPage.fields.beta')} value={module.is_beta ? t('ModuleDetailPage.yes') : t('ModuleDetailPage.no')} />
                <InfoRow label={t('ModuleDetailPage.fields.premium')} value={module.is_premium ? t('ModuleDetailPage.yes') : t('ModuleDetailPage.no')} />
                {orgModule?.enabled_at && (
                  <InfoRow
                    label={t('ModuleDetailPage.fields.enabledAt')}
                    value={new Date(orgModule.enabled_at).toLocaleString()}
                  />
                )}
                {orgModule?.disabled_at && !isEnabled && (
                  <InfoRow
                    label={t('ModuleDetailPage.fields.disabledAt')}
                    value={new Date(orgModule.disabled_at).toLocaleString()}
                  />
                )}
              </div>
            </Section>
          </div>

          {/* Widgets */}
          {module.widgets && module.widgets.length > 0 && (
            <Section title={t('ModuleDetailPage.sections.dashboardWidgets')} icon={LayoutDashboard}>
              <div className="grid gap-3 sm:grid-cols-2">
                {module.widgets.map((w) => (
                  <div key={w.id} className="flex items-start gap-3 p-3 rounded-lg border bg-muted/30">
                    <LayoutDashboard className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
                    <div className="space-y-0.5 min-w-0">
                      <p className="text-sm font-medium">{w.name}</p>
                      <p className="text-xs text-muted-foreground">{w.description}</p>
                      <div className="flex items-center gap-2 pt-1">
                        <Badge variant="outline" className="text-[10px] h-4">{w.default_size}</Badge>
                        {w.supports_refresh && (
                          <Badge variant="outline" className="text-[10px] h-4 gap-0.5">
                            <RefreshCw className="h-2.5 w-2.5" />
                            {t('ModuleDetailPage.widgets.autoRefresh')}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}
              </div>
            ),
          },
          {
            value: 'capabilities',
            label: (
              <span className="inline-flex items-center gap-1.5 text-xs">
                <Layers className="h-3.5 w-3.5" />
                {t('ModuleDetailPage.tabs.capabilities')}
              </span>
            ),
            content: (
              <Section
                title={t('ModuleDetailPage.sections.capabilities')}
                icon={Layers}
                isEmpty={!module.capabilities?.length}
                emptyText={t('ModuleDetailPage.empty.capabilities')}
              >
                <div className="flex flex-wrap gap-2">
                  {(module.capabilities || []).map((cap) => (
                    <Badge key={cap} variant="secondary" className="text-xs font-mono">
                      {cap}
                    </Badge>
                  ))}
                </div>
              </Section>
            ),
          },
          {
            value: 'permissions',
            label: (
              <span className="inline-flex items-center gap-1.5 text-xs">
                <Lock className="h-3.5 w-3.5" />
                {t('ModuleDetailPage.tabs.permissions')}
              </span>
            ),
            content: (
              <Section
                title={t('ModuleDetailPage.sections.permissions')}
                icon={Lock}
                isEmpty={!module.permissions?.length}
                emptyText={t('ModuleDetailPage.empty.permissions')}
              >
                <div className="divide-y">
                  {(module.permissions || []).map((perm) => (
                    <div key={perm.code} className="py-3 first:pt-0 last:pb-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">{perm.code}</code>
                        {perm.resource && (
                          <Badge variant="outline" className="text-[10px] h-4">{perm.resource}</Badge>
                        )}
                        {perm.action && (
                          <Badge variant="outline" className="text-[10px] h-4">{perm.action}</Badge>
                        )}
                      </div>
                      <p className="text-sm font-medium">{perm.name}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{perm.description}</p>
                    </div>
                  ))}
                </div>
              </Section>
            ),
          },
          {
            value: 'devices',
            label: (
              <span className="inline-flex items-center gap-1.5 text-xs">
                <Cpu className="h-3.5 w-3.5" />
                {t('ModuleDetailPage.tabs.deviceTypes')}
              </span>
            ),
            content: (
              <Section
                title={t('ModuleDetailPage.sections.supportedDeviceTypes')}
                icon={Cpu}
                isEmpty={!module.device_types?.length}
                emptyText={t('ModuleDetailPage.empty.deviceTypes')}
              >
                <div className="flex flex-wrap gap-2">
                  {(module.device_types || []).map((dt) => (
                    <Badge key={dt} variant="outline" className="text-xs font-mono">
                      {dt}
                    </Badge>
                  ))}
                </div>
              </Section>
            ),
          },
          {
            value: 'navigation',
            label: (
              <span className="inline-flex items-center gap-1.5 text-xs">
                <Navigation className="h-3.5 w-3.5" />
                {t('ModuleDetailPage.tabs.navigation')}
              </span>
            ),
            content: (
              <Section
                title={t('ModuleDetailPage.sections.navigationItems')}
                icon={Navigation}
                isEmpty={!module.nav_items?.length}
                emptyText={t('ModuleDetailPage.empty.navigationItems')}
              >
                <div className="divide-y">
                  {(module.nav_items || []).map((nav) => {
                    const NavIcon = resolveIcon(nav.icon, Globe);
                    return (
                      <div key={nav.path} className="flex items-center justify-between py-2.5 gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                          <NavIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                          <div>
                            <p className="text-sm font-medium">{nav.label}</p>
                            <code className="text-xs text-muted-foreground font-mono">{nav.path}</code>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <Badge variant="outline" className="text-[10px] h-4">
                            {t('ModuleDetailPage.nav.order', { order: nav.order })}
                          </Badge>
                          {nav.parent && (
                            <Badge variant="outline" className="text-[10px] h-4">
                              {t('ModuleDetailPage.nav.parent', { parent: nav.parent })}
                            </Badge>
                          )}
                          {nav.permission && (
                            <Badge variant="outline" className="text-[10px] h-4">
                              <Lock className="h-2.5 w-2.5 mr-0.5" />
                              {nav.permission}
                            </Badge>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Section>
            ),
          },
          {
            value: 'dependencies',
            label: (
              <span className="inline-flex items-center gap-1.5 text-xs">
                <Boxes className="h-3.5 w-3.5" />
                {t('ModuleDetailPage.tabs.dependencies')}
              </span>
            ),
            content: (
              <div className="space-y-4">
          <Section
            title={t('ModuleDetailPage.sections.requiredDependencies')}
            icon={PackageOpen}
            isEmpty={!module.dependencies?.length}
            emptyText={t('ModuleDetailPage.empty.dependencies')}
          >
            <div className="divide-y">
              {(module.dependencies || []).map((dep) => {
                const depMod = allModules.find((m) => m.id === dep.module_id);
                const depEnabled = enabledModules.includes(dep.module_id);
                return (
                  <div key={dep.module_id} className="flex items-center justify-between py-2.5 gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={cn(
                        'h-2 w-2 rounded-full shrink-0',
                        depEnabled ? 'bg-emerald-500' : dep.optional ? 'bg-amber-400' : 'bg-red-500',
                      )} />
                      <div>
                        <Link
                          to={`/settings/modules/${dep.module_id}`}
                          className="text-sm font-medium hover:underline underline-offset-2"
                        >
                          {depMod?.name || dep.module_id}
                        </Link>
                        <p className="text-xs text-muted-foreground font-mono">{t('ModuleDetailPage.dep.minVersionMono', { version: dep.min_version })}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {dep.optional && (
                        <Badge variant="outline" className="text-[10px] h-4">{t('ModuleDetailPage.dep.optional')}</Badge>
                      )}
                      <Badge
                        variant={depEnabled ? 'default' : 'destructive'}
                        className="text-[10px] h-4"
                      >
                        {depEnabled ? t('ModuleDetailPage.dep.installed') : t('ModuleDetailPage.dep.missing')}
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          </Section>

          {/* Reverse dependencies · who depends on this module */}
          <Section
            title={t('ModuleDetailPage.sections.usedBy')}
            icon={Boxes}
            isEmpty={dependents.length === 0}
            emptyText={t('ModuleDetailPage.empty.usedBy')}
          >
            <div className="divide-y">
              {dependents.map((dep) => (
                <div key={dep.id} className="flex items-center justify-between py-2.5 gap-4">
                  <div className="flex items-center gap-3">
                    <div className="h-2 w-2 rounded-full bg-emerald-500 shrink-0" />
                    <Link
                      to={`/settings/modules/${dep.id}`}
                      className="text-sm font-medium hover:underline underline-offset-2"
                    >
                      {dep.name}
                    </Link>
                  </div>
                  <Badge variant="outline" className="text-[10px] h-4 font-mono">
                    v{dep.version}
                  </Badge>
                </div>
                  ))}
                </div>
              </Section>
              </div>
            ),
          },
        ]}
      />

      {/* ── Toggle confirmation dialog ─────────────────── */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {isEnabled
                ? t('ModuleDetailPage.dialog.disableTitle', { name: module.name })
                : t('ModuleDetailPage.dialog.enableTitle', { name: module.name })}
            </DialogTitle>
            <DialogDescription>
              {isEnabled
                ? t('ModuleDetailPage.dialog.disableDescription')
                : t('ModuleDetailPage.dialog.enableDescription')}
            </DialogDescription>
          </DialogHeader>

          {/* Warnings */}
          {isEnabled && dependents.length > 0 && (
            <div className="flex items-start gap-2 p-3 rounded-md bg-amber-500/10 text-sm">
              <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
              <span>
                {t('ModuleDetailPage.dialog.dependentsWarningPrefix')} <strong>{module.name}</strong>{t('ModuleDetailPage.dialog.dependentsWarningSuffix')}{' '}
                {dependents.map((d) => d.name).join(', ')}
              </span>
            </div>
          )}
          {!isEnabled && missingDeps.length > 0 && (
            <div className="flex items-start gap-2 p-3 rounded-md bg-amber-500/10 text-sm">
              <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
              <span>
                {t('ModuleDetailPage.dialog.missingDepsWarning', { deps: missingDeps.map((d) => d.name).join(', ') })}
              </span>
            </div>
          )}

          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              {t('ModuleDetailPage.actions.cancel')}
            </Button>
            <Button
              variant={isEnabled ? 'destructive' : 'default'}
              onClick={executeToggle}
              disabled={togglingLocal || isToggling}
            >
              {(togglingLocal || isToggling) && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              {isEnabled ? t('ModuleDetailPage.actions.disableModule') : t('ModuleDetailPage.actions.enableModule')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
