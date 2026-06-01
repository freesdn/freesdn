// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Modules Settings Tab
 * 
 * Enterprise-grade module management table.
 * Clicking a row navigates to the full module detail page.
 */
import { useState, useMemo, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Search,
  RefreshCw,
  Shield,
  Puzzle,
  ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { SearchBar } from '@/components/ui/search-bar';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { modulesApi } from '@/lib/api';
import { useModuleStore, type ModuleManifest } from '@/stores/moduleStore';
import { useAuthStore } from '@/stores/authStore';
import { useModuleToggle, moduleQueryKeys } from '@/hooks/useModules';

// ────────────────────────────────────────────────────────────
// Category config
// ────────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<string, { labelKey: string; variant: 'default' | 'secondary' | 'outline' | 'destructive' }> = {
  core: { labelKey: 'core', variant: 'default' },
  network: { labelKey: 'network', variant: 'default' },
  surveillance: { labelKey: 'surveillance', variant: 'secondary' },
  security: { labelKey: 'security', variant: 'secondary' },
  communication: { labelKey: 'communication', variant: 'secondary' },
  monitoring: { labelKey: 'monitoring', variant: 'secondary' },
  system: { labelKey: 'system', variant: 'outline' },
};

function getCategoryBadge(category: string): { labelKey: string | null; fallback: string; variant: 'default' | 'secondary' | 'outline' | 'destructive' } {
  const cfg = CATEGORY_CONFIG[category?.toLowerCase()];
  if (cfg) return { labelKey: cfg.labelKey, fallback: category, variant: cfg.variant };
  return { labelKey: null, fallback: category || 'Other', variant: 'outline' };
}

// ────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────

interface ConfirmDialogData {
  open: boolean;
  moduleId: string;
  moduleName: string;
  action: 'enable' | 'disable';
  warnings: string[];
}

const EMPTY_CONFIRM: ConfirmDialogData = {
  open: false,
  moduleId: '',
  moduleName: '',
  action: 'enable',
  warnings: [],
};

// ────────────────────────────────────────────────────────────
// Module Row
// ────────────────────────────────────────────────────────────

function ModuleRow({
  module,
  isEnabled,
  isToggling,
  enabledModules,
  allModules,
  onToggle,
  onNavigate,
}: {
  module: ModuleManifest;
  isEnabled: boolean;
  isToggling: boolean;
  enabledModules: string[];
  allModules: ModuleManifest[];
  onToggle: (moduleId: string, enabled: boolean) => void;
  onNavigate: (moduleId: string) => void;
}) {
  const { t } = useTranslation('settings');
  const cat = getCategoryBadge(module.category);
  const catLabel = cat.labelKey
    ? t(`ModulesSettingsTab.categories.${cat.labelKey}`)
    : cat.fallback;
  const comingSoon = !!module.coming_soon;

  const missingDeps = (module.dependencies || [])
    .filter((d) => !d.optional && !enabledModules.includes(d.module_id));
  const hasMissingDeps = missingDeps.length > 0 && !isEnabled && !comingSoon;

  const dependentCount = allModules.filter(
    (m) => m.dependencies?.some((d) => d.module_id === module.id && !d.optional) && enabledModules.includes(m.id)
  ).length;

  // Badges rendered next to the module name (shared between the mobile card
  // and the desktop grid row).
  const nameBadges = (
    <>
      {module.is_core && (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Shield className="h-3.5 w-3.5 text-blue-500 shrink-0" />
            </TooltipTrigger>
            <TooltipContent side="right"><p className="text-xs">{t('ModulesSettingsTab.row.coreModule')}</p></TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
      {comingSoon ? (
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-sky-500/60 text-sky-600 dark:text-sky-400 h-4 whitespace-nowrap shrink-0">
          {t('ModulesSettingsTab.row.comingSoon', 'Coming soon')}
        </Badge>
      ) : module.is_beta ? (
        <Badge variant="outline" className="text-[10px] px-1 py-0 border-amber-500 text-amber-600 h-4 whitespace-nowrap shrink-0">
          {t('ModulesSettingsTab.row.beta')}
        </Badge>
      ) : null}
      {hasMissingDeps && (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <AlertTriangle className="h-3.5 w-3.5 text-amber-500 shrink-0" />
            </TooltipTrigger>
            <TooltipContent side="right">
              <p className="text-xs">{t('ModulesSettingsTab.row.missingDeps', { deps: missingDeps.map(d => d.module_id).join(', ') })}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
    </>
  );

  // The enablement control: a live Switch, a spinner mid-toggle, or a
  // disabled Switch for preview ("coming soon") modules.
  const control = comingSoon ? (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex">
            <Switch
              checked={false}
              disabled
              aria-label={t('ModulesSettingsTab.row.comingSoonAria', 'Coming soon — not yet available')}
              className="scale-90"
            />
          </span>
        </TooltipTrigger>
        <TooltipContent side="left">
          <p className="text-xs">{t('ModulesSettingsTab.row.comingSoonTooltip', 'This module is a preview and cannot be enabled yet.')}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  ) : isToggling ? (
    <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
  ) : (
    <Switch
      checked={isEnabled}
      onCheckedChange={() => onToggle(module.id, isEnabled)}
      disabled={module.is_core && isEnabled}
      className="scale-90"
    />
  );

  return (
    <div
      className="group border-b text-sm transition-colors cursor-pointer hover:bg-muted/50"
      onClick={() => onNavigate(module.id)}
    >
      {/* ── Card layout (narrow columns) ── */}
      <div className="@4xl:hidden flex items-start gap-3 p-4">
        <div className={cn(
          'h-2 w-2 rounded-full shrink-0 mt-1.5',
          isEnabled ? 'bg-emerald-500' : 'bg-muted-foreground/30'
        )} />
        <div className="flex flex-col min-w-0 flex-1 gap-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium truncate">{module.name}</span>
            {nameBadges}
          </div>
          {module.description && (
            <span className="text-xs text-muted-foreground line-clamp-2">{module.description}</span>
          )}
          <div className="flex items-center gap-x-3 gap-y-1 flex-wrap pt-0.5">
            <Badge variant={cat.variant} className="text-[10px] h-5">{catLabel}</Badge>
            <span className="text-[11px] text-muted-foreground font-mono">v{module.version}</span>
            <span className="text-[11px] text-muted-foreground">
              {t('ModulesSettingsTab.row.capsCount', { count: module.capabilities?.length || 0, defaultValue: '{{count}} caps' })}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
          {control}
          <ChevronRight className="h-4 w-4 text-muted-foreground/50" />
        </div>
      </div>

      {/* ── Table row (wide columns) ── */}
      <div className="hidden @4xl:grid grid-cols-[1fr_100px_100px_64px_64px_56px_28px] items-center gap-4 px-4 py-3">
        {/* Module name + meta */}
        <div className="flex items-center gap-3 min-w-0">
          <div className={cn(
            'h-2 w-2 rounded-full shrink-0',
            isEnabled ? 'bg-emerald-500' : 'bg-muted-foreground/30'
          )} />
          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium truncate">{module.name}</span>
              {nameBadges}
            </div>
            <span className="text-xs text-muted-foreground truncate max-w-[400px]">{module.description}</span>
          </div>
        </div>

        {/* Category */}
        <div>
          <Badge variant={cat.variant} className="text-[10px] h-5">
            {catLabel}
          </Badge>
        </div>

        {/* Version */}
        <div className="text-xs text-muted-foreground font-mono">{module.version}</div>

        {/* Capabilities count */}
        <div className="text-xs text-muted-foreground text-center">
          {module.capabilities?.length || 0}
        </div>

        {/* Dependents */}
        <div className="text-xs text-muted-foreground text-center">
          {dependentCount > 0 ? dependentCount : '-'}
        </div>

        {/* Toggle */}
        <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
          {control}
        </div>

        {/* Arrow */}
        <div className="flex items-center justify-center">
          <ChevronRight className="h-4 w-4 text-muted-foreground/50 group-hover:text-muted-foreground transition-colors" />
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// Main component
// ────────────────────────────────────────────────────────────

export function ModulesSettingsTab() {
  const { t } = useTranslation('settings');
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState<ConfirmDialogData>(EMPTY_CONFIRM);

  const { user } = useAuthStore();
  const { modules: storeModules, enabledModules, setModules, setOrgModules } = useModuleStore();
  const { toggleModule, toggleError, resetError } = useModuleToggle();
  const queryClient = useQueryClient();
  const orgId = user?.organization_id;

  // Fetch modules directly · shares cache with useModulesInit() via same query key
  const {
    data: fetchedModules,
    isLoading: modulesLoading,
    isError: modulesError,
    isFetching: modulesFetching,
  } = useQuery({
    queryKey: moduleQueryKeys.all,
    queryFn: async () => {
      const res = await modulesApi.getAll();
      const d = res.data;
      if (Array.isArray(d)) return d as ModuleManifest[];
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (d && typeof d === 'object' && Array.isArray((d as any).modules)) return (d as any).modules as ModuleManifest[];
      return [] as ModuleManifest[];
    },
    staleTime: 5 * 60 * 1000,
  });

  // Fetch org modules for enablement state
  const {
    data: fetchedOrgModules,
    isLoading: orgModulesLoading,
    isError: orgModulesError,
    isFetching: orgModulesFetching,
  } = useQuery({
    queryKey: moduleQueryKeys.org(orgId ?? undefined),
    queryFn: async () => {
      const res = await modulesApi.getOrgModules(orgId!, true);
      const d = res.data;
      if (Array.isArray(d)) return d;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (d && typeof d === 'object' && Array.isArray((d as any).modules)) return (d as any).modules;
      return [];
    },
    enabled: !!orgId,
    staleTime: 30 * 1000,
  });

  // Sync fetched data to store (keeps store in sync for other consumers)
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

  // Use fetched data with store as fallback
  const allModules = (fetchedModules && fetchedModules.length > 0) ? fetchedModules : storeModules;
  const currentEnabledModules = enabledModules;
  const storeLoading = modulesLoading || orgModulesLoading;

  const categories = useMemo(() => {
    const cats = new Set(allModules.map((m) => m.category?.toLowerCase() || 'other'));
    return ['all', ...Array.from(cats).sort()];
  }, [allModules]);

  const filteredModules = useMemo(() => {
    return allModules.filter((m) => {
      const matchSearch =
        !search ||
        (m.name?.toLowerCase() ?? '').includes(search.toLowerCase()) ||
        (m.description?.toLowerCase() ?? '').includes(search.toLowerCase()) ||
        (m.id?.toLowerCase() ?? '').includes(search.toLowerCase());
      const matchCategory =
        categoryFilter === 'all' ||
        (m.category?.toLowerCase() || 'other') === categoryFilter;
      return matchSearch && matchCategory;
    });
  }, [allModules, search, categoryFilter]);

  const totalModules = allModules.length;
  const enabledCount = currentEnabledModules.length;
  const coreCount = allModules.filter((m) => m.is_core).length;

  const handleRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.all });
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.states });
    if (orgId) {
      queryClient.invalidateQueries({ queryKey: moduleQueryKeys.org(orgId) });
      queryClient.invalidateQueries({ queryKey: moduleQueryKeys.navigation(orgId) });
    }
  }, [queryClient, orgId]);

  const handleNavigate = useCallback((moduleId: string) => {
    navigate(`/settings/modules/${moduleId}`);
  }, [navigate]);

  const executeToggle = useCallback(async (moduleId: string, isCurrentlyEnabled: boolean) => {
    setTogglingId(moduleId);
    resetError();
    try {
      await toggleModule(moduleId, isCurrentlyEnabled);
    } catch (err: unknown) {
      console.error('Failed to toggle module:', err);
    } finally {
      setTogglingId(null);
    }
    setConfirmDialog(EMPTY_CONFIRM);
  }, [resetError, toggleModule]);

  const handleToggle = useCallback((moduleId: string, isCurrentlyEnabled: boolean) => {
    const mod = allModules.find((m) => m.id === moduleId);
    if (!mod || mod.coming_soon) return;

    const warnings: string[] = [];

    if (isCurrentlyEnabled) {
      const dependents = allModules.filter(
        (m) =>
          m.dependencies?.some((d) => d.module_id === moduleId && !d.optional) &&
          currentEnabledModules.includes(m.id)
      );
      if (dependents.length > 0) {
        warnings.push(t('ModulesSettingsTab.warnings.dependents', { module: mod.name, dependents: dependents.map(d => d.name).join(', ') }));
      }
      setConfirmDialog({
        open: true,
        moduleId,
        moduleName: mod.name,
        action: 'disable',
        warnings,
      });
    } else {
      const missingDeps = (mod.dependencies || [])
        .filter((d) => !d.optional && !currentEnabledModules.includes(d.module_id));

      if (missingDeps.length > 0) {
        const depNames = missingDeps.map((d) => {
          const depMod = allModules.find((m) => m.id === d.module_id);
          return depMod?.name || d.module_id;
        });
        warnings.push(t('ModulesSettingsTab.warnings.missingRequired', { deps: depNames.join(', ') }));
      }

      if (warnings.length > 0) {
        setConfirmDialog({
          open: true,
          moduleId,
          moduleName: mod.name,
          action: 'enable',
          warnings,
        });
      } else {
        executeToggle(moduleId, isCurrentlyEnabled);
      }
    }
  }, [allModules, currentEnabledModules, executeToggle, t]);

  if (storeLoading && allModules.length === 0) {
    return (
      <div className="space-y-4">
        {/* Stats grid skeleton */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-lg" />
          ))}
        </div>
        {/* Toolbar skeleton */}
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-1">
            <Skeleton className="h-8 w-64 rounded-md" />
            <Skeleton className="h-8 w-40 rounded-md" />
          </div>
          <Skeleton className="h-8 w-24 rounded-md" />
        </div>
        {/* Table skeleton */}
        <div className="border rounded-lg overflow-hidden bg-card">
          <Skeleton className="h-10 w-full rounded-none" />
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3 border-t">
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-12" />
              <Skeleton className="h-4 w-12" />
              <Skeleton className="h-5 w-9 rounded-full" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    // @container: the table/stats below switch on the actual content-column
    // width (which shrinks when both the app sidebar and the settings nav are
    // present), not the viewport — so nothing is cramped mid-range.
    <div className="@container space-y-4">
      {(modulesError || orgModulesError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('ModulesSettingsTab.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats · 2-up until the content column itself is wide enough for 4
          (container-query, so it never clips regardless of the sidebars) */}
      <StatsGrid
        columns={2}
        className="@2xl:grid-cols-4"
        stats={[
          { title: t('ModulesSettingsTab.stats.total'), value: totalModules, icon: Puzzle, variant: 'primary' },
          {
            title: t('ModulesSettingsTab.stats.enabled'),
            value: enabledCount,
            icon: CheckCircle2,
            variant: 'success',
            description: t('ModulesSettingsTab.stats.ofTotal', { total: totalModules }),
          },
          { title: t('ModulesSettingsTab.stats.core'), value: coreCount, icon: Shield, variant: 'primary' },
          { title: t('ModulesSettingsTab.stats.disabled'), value: totalModules - enabledCount, icon: XCircle, variant: 'default' },
        ]}
      />

      {/* Toolbar · stacks when the column is narrow, single row once it widens */}
      <div className="flex flex-col @xl:flex-row @xl:items-center @xl:justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <div className="relative flex-1 @xl:max-w-xs">
            <SearchBar
              value={search}
              onChange={setSearch}
              placeholder={t('ModulesSettingsTab.toolbar.searchPlaceholder')}
            />
          </div>
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="w-[120px] @xl:w-[160px] h-8 text-sm shrink-0">
              <SelectValue placeholder={t('ModulesSettingsTab.toolbar.categoryPlaceholder')} />
            </SelectTrigger>
            <SelectContent>
              {categories.map((cat) => (
                <SelectItem key={cat} value={cat} className="text-sm">
                  {cat === 'all'
                    ? t('ModulesSettingsTab.toolbar.allCategories')
                    : t(`ModulesSettingsTab.categories.${cat}`, { defaultValue: cat.charAt(0).toUpperCase() + cat.slice(1) })}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1.5"
          onClick={handleRefresh}
          disabled={modulesFetching || orgModulesFetching}
        >
          <RefreshCw
            className={cn('h-3.5 w-3.5', (modulesFetching || orgModulesFetching) && 'animate-spin')}
          />
          {t('ModulesSettingsTab.toolbar.refresh')}
        </Button>
      </div>

      {/* Error banner */}
      {toggleError && (
        <div className="flex items-center gap-2 p-2.5 rounded-md border border-destructive/30 bg-destructive/5 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span className="flex-1">{t('ModulesSettingsTab.errors.toggleFailed', { error: String(toggleError) })}</span>
          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={resetError}>{t('ModulesSettingsTab.actions.dismiss')}</Button>
        </div>
      )}

      {/* Table */}
      <div className="border rounded-lg overflow-hidden bg-card">
        {/* Header (table layout only — the card layout is self-describing) */}
        <div className="hidden @4xl:grid grid-cols-[1fr_100px_100px_64px_64px_56px_28px] items-center gap-4 px-4 py-2 border-b bg-muted/40 text-xs font-medium text-muted-foreground uppercase tracking-wider select-none">
          <div>{t('ModulesSettingsTab.columns.module')}</div>
          <div>{t('ModulesSettingsTab.columns.category')}</div>
          <div>{t('ModulesSettingsTab.columns.version')}</div>
          <div className="text-center">{t('ModulesSettingsTab.columns.caps')}</div>
          <div className="text-center">{t('ModulesSettingsTab.columns.usedBy')}</div>
          <div className="text-right">{t('ModulesSettingsTab.columns.active')}</div>
          <div />
        </div>

        {/* Rows */}
        {filteredModules.length === 0 ? (
          <EmptyState
            variant="card"
            icon={Search}
            title={t('ModulesSettingsTab.empty.title')}
            description={t('ModulesSettingsTab.empty.description')}
          />
        ) : (
          filteredModules.map((module) => (
            <ModuleRow
              key={module.id}
              module={module}
              isEnabled={currentEnabledModules.includes(module.id)}
              isToggling={togglingId === module.id}
              enabledModules={currentEnabledModules}
              allModules={allModules}
              onToggle={handleToggle}
              onNavigate={handleNavigate}
            />
          ))
        )}

        {/* Footer */}
        <div className="px-4 py-2 border-t bg-muted/20 text-xs text-muted-foreground">
          {t('ModulesSettingsTab.footer.count', { shown: filteredModules.length, total: totalModules })}
          {search || categoryFilter !== 'all' ? ' ' + t('ModulesSettingsTab.footer.filtered') : ''}
        </div>
      </div>

      {/* Confirmation Dialog */}
      <Dialog open={confirmDialog.open} onOpenChange={(open) => { if (!open) setConfirmDialog(EMPTY_CONFIRM); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {confirmDialog.action === 'disable'
                ? t('ModulesSettingsTab.dialog.titleDisable', { module: confirmDialog.moduleName })
                : t('ModulesSettingsTab.dialog.titleEnable', { module: confirmDialog.moduleName })}
            </DialogTitle>
            <DialogDescription>
              {confirmDialog.action === 'disable'
                ? t('ModulesSettingsTab.dialog.descriptionDisable')
                : t('ModulesSettingsTab.dialog.descriptionEnable')}
            </DialogDescription>
          </DialogHeader>
          {confirmDialog.warnings.length > 0 && (
            <div className="space-y-2">
              {confirmDialog.warnings.map((warning, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 rounded-md bg-amber-500/10 text-sm">
                  <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}
          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={() => setConfirmDialog(EMPTY_CONFIRM)}>{t('ModulesSettingsTab.actions.cancel')}</Button>
            <Button
              variant={confirmDialog.action === 'disable' ? 'destructive' : 'default'}
              onClick={() => executeToggle(confirmDialog.moduleId, confirmDialog.action === 'disable')}
              disabled={togglingId !== null}
            >
              {togglingId !== null && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {confirmDialog.action === 'disable'
                ? t('ModulesSettingsTab.actions.disableModule')
                : t('ModulesSettingsTab.actions.enableModule')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default ModulesSettingsTab;
