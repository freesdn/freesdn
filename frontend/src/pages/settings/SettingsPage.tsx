// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Settings Page
 *
 * Enterprise settings with categorized sidebar navigation and content area.
 * Layout: LEFT sidebar with grouped nav items, RIGHT content panel.
 */

import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { SUPPORTED_LOCALES, changeLanguage, type SupportedLocale } from '@/lib/i18n';

import {
  Settings,
  Bell,
  Palette,
  Database,
  Server,
  Save,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Moon,
  Sun,
  Monitor,
  Puzzle,
  Key,
  KeyRound,
  AppWindow,
  Brain,
  Clock,
  Activity,
  Layers,
  Cpu,
  Info,
  ShieldCheck,
  Eye,
  type LucideIcon,
} from 'lucide-react';
import { ModulesSettingsTab } from './ModulesSettingsTab';
import { NotificationsSettingsTab } from './NotificationsSettingsTab';
import { AboutSettingsTab } from './AboutSettingsTab';
import { APIKeysTab } from './APIKeysTab';
import { OAuth2AppsTab } from './OAuth2AppsTab';
// PluginsPage moved to top-level /plugins route
import AISettingsPage from './AISettingsPage';
import SSOSettingsPage from './SSOSettingsPage';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import { Skeleton } from '@/components/ui/skeleton';
import { useUIStore, ACCENT_PRESETS } from '@/stores';
import { useToast } from '@/hooks/use-toast';
import { useToastHelpers } from '@/components/ui/toast';
import { api, systemApi, getApiErrorMessage } from '@/lib/api';

// ---------------------------------------------------------------------------
// Sidebar section / item types
// ---------------------------------------------------------------------------
interface SettingsItem {
  id: string;
  label: string;
  icon: LucideIcon;
}

interface SettingsCategory {
  category: string;
  items: SettingsItem[];
}

// Accepts either i18next options or a string default value (the inline
// fallback form ``t('key', 'Default')``) so nav labels can ship before
// their locale entries land.
type TFunc = (key: string, options?: Record<string, unknown> | string) => string;

function buildSettingsSections(t: TFunc): SettingsCategory[] {
  return [
    {
      category: t('SettingsPage.nav.categories.organization'),
      items: [
        { id: 'general', label: t('SettingsPage.nav.items.general'), icon: Settings },
        { id: 'appearance', label: t('SettingsPage.nav.items.appearance'), icon: Palette },
      ],
    },
    {
      category: t('SettingsPage.nav.categories.securityAccess'),
      items: [
        { id: 'access', label: t('SettingsPage.nav.items.access', 'Read-only / Write access'), icon: ShieldCheck },
        { id: 'sso', label: t('SettingsPage.nav.items.sso'), icon: KeyRound },
        { id: 'api-keys', label: t('SettingsPage.nav.items.apiKeys'), icon: Key },
        { id: 'oauth2-apps', label: t('SettingsPage.nav.items.oauth2Apps'), icon: AppWindow },
      ],
    },
    {
      category: t('SettingsPage.nav.categories.integrations'),
      items: [
        { id: 'ai', label: t('SettingsPage.nav.items.ai'), icon: Brain },
        { id: 'notifications', label: t('SettingsPage.nav.items.notifications'), icon: Bell },
      ],
    },
    {
      category: t('SettingsPage.nav.categories.system'),
      items: [
        { id: 'modules', label: t('SettingsPage.nav.items.modules'), icon: Puzzle },
        { id: 'system', label: t('SettingsPage.nav.items.system'), icon: Server },
        { id: 'about', label: t('SettingsPage.nav.items.about'), icon: Info },
      ],
    },
  ];
}

const VALID_TABS = ['general', 'appearance', 'access', 'sso', 'api-keys', 'oauth2-apps', 'ai', 'notifications', 'modules', 'system', 'about'];

// ---------------------------------------------------------------------------
// Shared helper components
// ---------------------------------------------------------------------------
function SettingSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium">{title}</h3>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function SettingRow({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
      <div className="space-y-0.5">
        <Label className="text-base">{label}</Label>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// General Settings Tab
// ---------------------------------------------------------------------------
function GeneralSettingsTab() {
  const { t } = useTranslation('settings');
  const { toast } = useToast();
  const [isSaving, setIsSaving] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [settings, setSettings] = useState({
    siteName: 'FreeSDN',
    siteDescription: 'Unified network management platform',
    timezone: 'UTC',
    dateFormat: 'MM/DD/YYYY',
    language: 'en',
  });

  const timezones = [
    { value: 'UTC', label: t('SettingsPage.timezones.utc') },
    { value: 'America/New_York', label: t('SettingsPage.timezones.easternUs') },
    { value: 'America/Chicago', label: t('SettingsPage.timezones.centralUs') },
    { value: 'America/Denver', label: t('SettingsPage.timezones.mountainUs') },
    { value: 'America/Los_Angeles', label: t('SettingsPage.timezones.pacificUs') },
    { value: 'Europe/London', label: t('SettingsPage.timezones.london') },
    { value: 'Europe/Paris', label: t('SettingsPage.timezones.paris') },
    { value: 'Asia/Tokyo', label: t('SettingsPage.timezones.tokyo') },
    { value: 'Asia/Shanghai', label: t('SettingsPage.timezones.shanghai') },
  ];

  useEffect(() => {
    const loadSettings = async () => {
      try {
        setLoadError(null);
        const meResponse = await api.get('/auth/me');
        const me = meResponse.data;
        if (!me.organization_id) {
          return;
        }

        const orgResponse = await api.get(`/organizations/${me.organization_id}`);
        const org = orgResponse.data;
        setSettings({
          siteName: org.name ?? 'FreeSDN',
          siteDescription: org.description ?? '',
          timezone: org.settings?.timezone ?? 'UTC',
          dateFormat: org.settings?.date_format ?? 'MM/DD/YYYY',
          language: org.settings?.language ?? 'en',
        });
      } catch (err) {
        setLoadError(err instanceof Error ? err.message : t('messages.loadFailed'));
      }
    };

    void loadSettings();
  }, [t]);

  const handleSave = async () => {
    setIsSaving(true);
    setLoadError(null);
    try {
      const meResponse = await api.get('/auth/me');
      const me = meResponse.data;
      if (!me.organization_id) {
        throw new Error(t('messages.noOrganization'));
      }

      await api.patch(`/organizations/${me.organization_id}`, {
        name: settings.siteName,
        description: settings.siteDescription || null,
        settings: {
          timezone: settings.timezone,
          date_format: settings.dateFormat,
          language: settings.language,
        },
      });
      toast({ title: t('common:success') });
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : t('messages.saveFailed'));
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <SettingSection title={t('generalPage.siteInformation.title')} description={t('generalPage.siteInformation.description')}>
        <div className="grid gap-4">
          <div className="grid gap-2">
              <Label htmlFor="siteName">{t('generalPage.siteInformation.nameLabel')}</Label>
              <Input
                id="siteName"
                value={settings.siteName}
                onChange={(e) => setSettings((prev) => ({ ...prev, siteName: e.target.value }))}
                placeholder={t('generalPage.siteInformation.namePlaceholder')}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="siteDescription">{t('generalPage.siteInformation.descriptionLabel')}</Label>
              <Textarea
                id="siteDescription"
                placeholder={t('generalPage.siteInformation.descriptionPlaceholder')}
                value={settings.siteDescription}
                onChange={(e) => setSettings((prev) => ({ ...prev, siteDescription: e.target.value }))}
              />
            </div>
          </div>
      </SettingSection>

      <SettingSection title={t('generalPage.regional.title')} description={t('generalPage.regional.description')}>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="timezone">{t('generalPage.regional.timezone')}</Label>
            <Select
              value={settings.timezone}
              onValueChange={(value) => setSettings((prev) => ({ ...prev, timezone: value }))}
            >
              <SelectTrigger>
                <SelectValue placeholder={t('SettingsPage.regional.selectTimezonePlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {timezones.map(tz => (
                  <SelectItem key={tz.value} value={tz.value}>{tz.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="dateFormat">{t('generalPage.regional.dateFormat')}</Label>
            <Select
              value={settings.dateFormat}
              onValueChange={(value) => setSettings((prev) => ({ ...prev, dateFormat: value }))}
            >
              <SelectTrigger>
                <SelectValue placeholder={t('SettingsPage.regional.selectFormatPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="MM/DD/YYYY">MM/DD/YYYY</SelectItem>
                <SelectItem value="DD/MM/YYYY">DD/MM/YYYY</SelectItem>
                <SelectItem value="YYYY-MM-DD">YYYY-MM-DD</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="language">{t('generalPage.regional.language')}</Label>
            <Select
              value={settings.language}
              onValueChange={(value) => {
                // Persist the preference AND apply it immediately. changeLanguage
                // switches i18next live and caches to localStorage (freesdn_locale),
                // so the choice survives reloads via the language detector.
                setSettings((prev) => ({ ...prev, language: value }));
                void changeLanguage(value as SupportedLocale);
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder={t('SettingsPage.regional.selectLanguagePlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {SUPPORTED_LOCALES.map((loc) => (
                  <SelectItem key={loc.code} value={loc.code}>
                    {loc.nativeName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </SettingSection>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={isSaving}>
          {isSaving ? (
            <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-2 h-4 w-4" />
          )}
          {t('saveChanges')}
        </Button>
      </div>
      {loadError && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-500">
          {loadError}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Appearance Settings Tab
// ---------------------------------------------------------------------------
function AppearanceSettingsTab() {
  const { t } = useTranslation('settings');
  const { theme, setTheme, accentColor, setAccentColor, animationsEnabled, setAnimationsEnabled } = useUIStore();

  const themeOptions = [
    { value: 'light' as const, label: t('SettingsPage.appearance.theme.light.label'), icon: Sun, desc: t('SettingsPage.appearance.theme.light.desc') },
    { value: 'dark' as const, label: t('SettingsPage.appearance.theme.dark.label'), icon: Moon, desc: t('SettingsPage.appearance.theme.dark.desc') },
    { value: 'system' as const, label: t('SettingsPage.appearance.theme.system.label'), icon: Monitor, desc: t('SettingsPage.appearance.theme.system.desc') },
  ];

  return (
    <div className="space-y-8">
      {/* Theme mode */}
      <SettingSection title={t('SettingsPage.appearance.theme.title')} description={t('SettingsPage.appearance.theme.description')}>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
          {themeOptions.map(option => (
            <button
              key={option.value}
              onClick={() => setTheme(option.value)}
              className={cn(
                'group flex flex-col items-center gap-2 rounded-lg border-2 p-4 transition-all',
                theme === option.value
                  ? 'border-primary bg-primary/5 shadow-sm'
                  : 'border-muted hover:border-muted-foreground/30'
              )}
            >
              <option.icon className={cn('h-6 w-6 transition-colors', theme === option.value ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')} />
              <span className="text-sm font-medium">{option.label}</span>
              <span className="text-[11px] text-muted-foreground leading-tight">{option.desc}</span>
            </button>
          ))}
        </div>
      </SettingSection>

      {/* Accent color */}
      <SettingSection title={t('SettingsPage.appearance.accent.title')} description={t('SettingsPage.appearance.accent.description')}>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {ACCENT_PRESETS.map(preset => {
            const isActive = accentColor === preset.id;
            return (
              <button
                key={preset.id}
                onClick={() => setAccentColor(preset.id)}
                className={cn(
                  'group relative flex flex-col items-center gap-2 rounded-lg border-2 p-3 transition-all',
                  isActive
                    ? 'border-primary bg-primary/5 shadow-sm'
                    : 'border-muted hover:border-muted-foreground/30',
                )}
              >
                {/* Color swatch */}
                <div className={cn('h-8 w-8 rounded-full ring-2 ring-offset-2 ring-offset-background transition-all', preset.swatch, isActive ? 'ring-primary scale-110' : 'ring-transparent group-hover:ring-muted-foreground/30')} />
                <span className={cn('text-xs font-medium transition-colors', isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')}>
                  {preset.label}
                </span>
                {/* Active indicator */}
                {isActive && (
                  <div className="absolute -top-1.5 -right-1.5 h-4 w-4 rounded-full bg-primary flex items-center justify-center">
                    <CheckCircle className="h-3 w-3 text-primary-foreground" />
                  </div>
                )}
              </button>
            );
          })}
        </div>
        {/* Live preview strip */}
        <Card className="mt-4">
          <CardContent noOffset className="p-4">
            <p className="text-xs text-muted-foreground mb-3 uppercase tracking-wider font-medium">{t('SettingsPage.appearance.preview.title')}</p>
            <div className="flex items-center gap-3 flex-wrap">
              <Button size="sm">{t('SettingsPage.appearance.preview.primaryButton')}</Button>
              <Button size="sm" variant="outline">{t('SettingsPage.appearance.preview.outline')}</Button>
              <Button size="sm" variant="secondary">{t('SettingsPage.appearance.preview.secondary')}</Button>
              <Badge>{t('SettingsPage.appearance.preview.activeBadge')}</Badge>
              <Badge variant="outline">{t('SettingsPage.appearance.preview.outlineBadge')}</Badge>
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-primary" />
                <span className="text-sm text-primary font-medium">{t('SettingsPage.appearance.preview.primaryText')}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </SettingSection>

      {/* Display options */}
      <SettingSection title={t('SettingsPage.appearance.display.title')} description={t('SettingsPage.appearance.display.description')}>
        <SettingRow
          label={t('SettingsPage.appearance.display.animationsLabel')}
          description={t('SettingsPage.appearance.display.animationsDescription')}
        >
          <Switch checked={animationsEnabled} onCheckedChange={setAnimationsEnabled} />
        </SettingRow>
      </SettingSection>

      {/* Saved automatically via Zustand persist */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-2">
        <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
        <span>{t('SettingsPage.appearance.autoSaveNote')}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Access Settings Tab · adapter read-only / write mode
// ---------------------------------------------------------------------------
function AccessSettingsTab() {
  const { t } = useTranslation('settings');
  const toast = useToastHelpers();
  const readOnlyMode = useUIStore((state) => state.readOnlyMode);
  const setReadOnlyMode = useUIStore((state) => state.setReadOnlyMode);
  const [isSaving, setIsSaving] = useState(false);

  const handleToggle = async (nextReadOnly: boolean) => {
    setIsSaving(true);
    try {
      const res = await systemApi.setAdapterReadOnly(nextReadOnly);
      const applied = res.data.read_only;
      setReadOnlyMode(applied);
      if (applied) {
        toast.success(
          t('SettingsPage.access.toast.readOnlyTitle', 'Read-only mode enabled'),
          t('SettingsPage.access.toast.readOnlyDesc', 'Device writes are now disabled platform-wide.'),
        );
      } else {
        toast.success(
          t('SettingsPage.access.toast.writeTitle', 'Write access enabled'),
          t('SettingsPage.access.toast.writeDesc', 'Devices can now be managed and configured.'),
        );
      }
    } catch (err) {
      toast.error(
        t('SettingsPage.access.toast.errorTitle', 'Failed to update mode'),
        getApiErrorMessage(err, t('messages.saveFailed')),
      );
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <SettingSection
        title={t('SettingsPage.access.title', 'Read-only / Write access')}
        description={t(
          'SettingsPage.access.description',
          'Control whether FreeSDN can write to your devices. Read-only mode is the safe, monitor-only posture, all device writes are refused platform-wide.',
        )}
      >
        <SettingRow
          label={
            readOnlyMode
              ? t('SettingsPage.access.row.labelReadOnly', 'Read-only mode (monitor only)')
              : t('SettingsPage.access.row.labelWrite', 'Read-write mode (manage)')
          }
          description={
            readOnlyMode
              ? t('SettingsPage.access.row.descReadOnly', 'Device writes are disabled. Turn this off to manage and configure devices.')
              : t('SettingsPage.access.row.descWrite', 'Device writes are enabled. Turn this on to lock the platform to monitor-only.')
          }
        >
          <Switch
            checked={readOnlyMode}
            onCheckedChange={handleToggle}
            disabled={isSaving}
            aria-label={t('SettingsPage.access.row.toggleAria', 'Toggle read-only mode')}
          />
        </SettingRow>

        <div
          className={cn(
            'flex items-start gap-3 rounded-lg border p-4 text-sm',
            readOnlyMode
              ? 'border-warning/30 bg-warning/10 text-warning'
              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
          )}
        >
          {readOnlyMode ? (
            <Eye className="mt-0.5 h-4 w-4 shrink-0" />
          ) : (
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
          )}
          <span>
            {readOnlyMode
              ? t('SettingsPage.access.status.readOnly', 'Read-only mode is ON. FreeSDN will not write to any device.')
              : t('SettingsPage.access.status.write', 'Write access is ON. FreeSDN can apply changes to managed devices.')}
          </span>
        </div>
      </SettingSection>
    </div>
  );
}

// ---------------------------------------------------------------------------
// System Settings Tab · live infrastructure health
// ---------------------------------------------------------------------------

interface InfraComponent {
  name: string;
  status: string;
  latency_ms?: number;
  details?: Record<string, unknown>;
}

interface PlatformVersionInfo {
  app_version: string;
  python_version: string;
  fastapi_version: string;
  sqlalchemy_version: string;
  pydantic_version: string;
  cryptography_version: string;
  node_version: string | null;
  redis_version: string | null;
  postgres_version: string | null;
}

interface InfraHealthData {
  status: string;
  uptime_seconds: number;
  components: InfraComponent[];
  platform: PlatformVersionInfo | null;
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === 'healthy'
      ? 'bg-emerald-500'
      : status === 'degraded'
        ? 'bg-amber-500'
        : 'bg-red-500';
  return <span className={cn('inline-block h-2.5 w-2.5 rounded-full shrink-0', color)} />;
}

function InfoRow({ label, value, icon }: { label: string; value: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2.5 px-1">
      <span className="text-sm text-muted-foreground flex items-center gap-2">
        {icon}
        {label}
      </span>
      <span className="text-sm font-medium text-right">{value}</span>
    </div>
  );
}

function InfoCard({ title, icon, children, isLoading }: { title: string; icon: React.ReactNode; children: React.ReactNode; isLoading?: boolean }) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center justify-between">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-20" />
              </div>
            ))}
          </div>
        ) : (
          <div className="divide-y divide-border">{children}</div>
        )}
      </CardContent>
    </Card>
  );
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function SystemSettingsTab() {
  const { t } = useTranslation('settings');
  const { data: infraHealth, isLoading: infraLoading, isError: infraError } = useQuery<InfraHealthData>({
    queryKey: ['infra-health'],
    queryFn: () => api.get('/enterprise/health/infrastructure').then((r) => r.data),
    refetchInterval: 30_000,
    retry: 1,
  });

  const dbComp = infraHealth?.components?.find((c) => c.name === 'database');
  const redisComp = infraHealth?.components?.find((c) => c.name === 'redis');
  const celeryComp = infraHealth?.components?.find((c) => c.name === 'celery');

  return (
    <div className="space-y-6">
      {infraError && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-600 dark:text-amber-400 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {t('SettingsPage.system.fetchError')}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Platform */}
        <InfoCard title={t('SettingsPage.system.platform.title')} icon={<Server className="h-4 w-4 text-primary" />} isLoading={infraLoading}>
          <InfoRow
            label={t('SettingsPage.system.platform.version')}
            value={<Badge variant="secondary">{infraHealth?.platform?.app_version ?? '-'}</Badge>}
          />
          <InfoRow label="Python" value={infraHealth?.platform?.python_version ?? '-'} />
          <InfoRow label="FastAPI" value={infraHealth?.platform?.fastapi_version ?? '-'} />
          <InfoRow label="SQLAlchemy" value={infraHealth?.platform?.sqlalchemy_version ?? '-'} />
          <InfoRow label="Pydantic" value={infraHealth?.platform?.pydantic_version ?? '-'} />
          <InfoRow label="Cryptography" value={infraHealth?.platform?.cryptography_version ?? '-'} />
          <InfoRow label={t('SettingsPage.system.platform.license')} value="AGPL-3.0-only" />
          <InfoRow
            label={t('SettingsPage.system.platform.about')}
            value={
              <Link to="/settings/about" className="text-primary hover:underline">
                {t('SettingsPage.system.platform.aboutLink')}
              </Link>
            }
          />
        </InfoCard>

        {/* Database */}
        <InfoCard title={t('SettingsPage.system.database.title')} icon={<Database className="h-4 w-4 text-primary" />} isLoading={infraLoading}>
          <InfoRow
            label="PostgreSQL"
            value={
              <span className="flex items-center gap-2">
                <StatusDot status={dbComp?.status ?? 'unhealthy'} />
                {dbComp?.status === 'healthy' ? t('SettingsPage.system.status.connected') : dbComp?.status ?? t('SettingsPage.system.status.unknown')}
                {dbComp?.latency_ms != null && (
                  <span className="text-xs text-muted-foreground">({dbComp.latency_ms}ms)</span>
                )}
              </span>
            }
          />
          {infraHealth?.platform?.postgres_version && (
            <InfoRow label={t('SettingsPage.system.database.postgresVersion')} value={infraHealth.platform.postgres_version} />
          )}
          <InfoRow label={t('SettingsPage.system.database.connectionPool')} value={t('SettingsPage.system.database.connectionPoolValue')} />
          <InfoRow label={t('SettingsPage.system.database.schemas')} value="18" />
          <InfoRow label="TimescaleDB / LogDB" value={t('SettingsPage.system.database.enabled')} />
        </InfoCard>

        {/* Cache & Queue */}
        <InfoCard title={t('SettingsPage.system.cacheQueue.title')} icon={<Layers className="h-4 w-4 text-primary" />} isLoading={infraLoading}>
          <InfoRow
            label="Redis"
            value={
              <span className="flex items-center gap-2">
                <StatusDot status={redisComp?.status ?? 'unhealthy'} />
                {redisComp?.status === 'healthy' ? t('SettingsPage.system.status.connected') : redisComp?.status ?? t('SettingsPage.system.status.unknown')}
                {infraHealth?.platform?.redis_version && (
                  <span className="text-xs text-muted-foreground">v{infraHealth.platform.redis_version}</span>
                )}
              </span>
            }
          />
          <InfoRow
            label={t('SettingsPage.system.cacheQueue.celeryWorkers')}
            value={
              <span className="flex items-center gap-2">
                <StatusDot status={celeryComp?.status ?? 'unhealthy'} />
                {celeryComp?.details?.workers != null
                  ? t('SettingsPage.system.cacheQueue.workersActive', { workers: celeryComp.details.workers as number })
                  : celeryComp?.status === 'degraded'
                    ? t('SettingsPage.system.cacheQueue.noWorkers')
                    : t('SettingsPage.system.status.unknown')}
              </span>
            }
          />
          <InfoRow label={t('SettingsPage.system.cacheQueue.celeryBeat')} value={celeryComp?.status === 'healthy' ? t('SettingsPage.system.cacheQueue.running') : t('SettingsPage.system.status.unknown')} />
        </InfoCard>

        {/* Runtime */}
        <InfoCard title={t('SettingsPage.system.runtime.title')} icon={<Activity className="h-4 w-4 text-primary" />} isLoading={infraLoading}>
          <InfoRow
            label={t('SettingsPage.system.runtime.uptime')}
            icon={<Clock className="h-3.5 w-3.5" />}
            value={infraHealth?.uptime_seconds ? formatUptime(infraHealth.uptime_seconds) : '--'}
          />
          <InfoRow label={t('SettingsPage.system.runtime.apiRoutes')} value="1,215+" />
          <InfoRow label={t('SettingsPage.system.runtime.modulesLoaded')} icon={<Cpu className="h-3.5 w-3.5" />} value="9" />
          <InfoRow label={t('SettingsPage.system.runtime.adapters')} value="11" />
        </InfoCard>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Content renderer · maps tab id to the correct component
// ---------------------------------------------------------------------------
function SettingsContent({ tab }: { tab: string }) {
  const { t } = useTranslation('settings');

  switch (tab) {
    case 'general':
      return (
        <Card>
          <CardHeader>
            <CardTitle>{t('SettingsPage.content.general.title')}</CardTitle>
            <CardDescription>{t('generalPage.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <GeneralSettingsTab />
          </CardContent>
        </Card>
      );

    case 'appearance':
      return (
        <Card>
          <CardHeader>
            <CardTitle>{t('SettingsPage.content.appearance.title')}</CardTitle>
            <CardDescription>{t('SettingsPage.content.appearance.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <AppearanceSettingsTab />
          </CardContent>
        </Card>
      );

    case 'access':
      return (
        <Card>
          <CardHeader>
            <CardTitle>{t('SettingsPage.content.access.title', 'Read-only / Write access')}</CardTitle>
            <CardDescription>
              {t('SettingsPage.content.access.description', 'Switch the platform between safe monitor-only (read-only) and full management (read-write).')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AccessSettingsTab />
          </CardContent>
        </Card>
      );

    case 'sso':
      return <SSOSettingsPage embedded />;

    case 'api-keys':
      return <APIKeysTab />;

    case 'oauth2-apps':
      return <OAuth2AppsTab />;

    case 'ai':
      return (
        <Card>
          <CardHeader>
            <CardTitle>{t('SettingsPage.content.ai.title')}</CardTitle>
            <CardDescription>
              {t('SettingsPage.content.ai.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AISettingsPage embedded />
          </CardContent>
        </Card>
      );

    case 'notifications':
      return (
        <Card>
          <CardHeader>
            <CardTitle>{t('SettingsPage.content.notifications.title')}</CardTitle>
            <CardDescription>
              {t('SettingsPage.content.notifications.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NotificationsSettingsTab />
          </CardContent>
        </Card>
      );

    // Plugins moved to top-level /plugins route

    case 'modules':
      return (
        <Card>
          <CardHeader>
            <CardTitle>{t('SettingsPage.content.modules.title')}</CardTitle>
            <CardDescription>
              {t('SettingsPage.content.modules.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ModulesSettingsTab />
          </CardContent>
        </Card>
      );

    case 'system':
      return <SystemSettingsTab />;

    case 'about':
      return <AboutSettingsTab />;

    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Main Settings Page
// ---------------------------------------------------------------------------
export function SettingsPage() {
  const { t } = useTranslation('settings');
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();

  const currentTab = tab && VALID_TABS.includes(tab) ? tab : 'general';
  // i18next's TFunction supports every call form used inside buildSettingsSections
  // (t(key), t(key, 'default'), t(key, {opts})) but its overloaded type isn't
  // structurally assignable to the local TFunc alias — cast through unknown.
  const settingsSections = buildSettingsSections(t as unknown as TFunc);

  // Redirect bare /settings (and invalid tab values) to /settings/general,
  // but ONLY for the routes this page actually owns: bare `/settings` and
  // `/settings/<tab>`. Two distinct hazards make a naive guard misfire,
  // because <AnimatePresence mode="wait"> in MainLayout keeps this page
  // mounted through its exit animation while the router context has ALREADY
  // advanced to the next URL — so `useParams` here reads the NEXT route's
  // params (i.e. `tab === undefined`) and this effect re-runs against a URL
  // this page no longer controls:
  //   1. Navigating AWAY from settings entirely (e.g. /dashboard) — excluded
  //      by the `/settings` prefix check.
  //   2. Navigating DEEPER within settings to a foreign route that merely
  //      shares the prefix — specifically /settings/modules/:moduleId
  //      (rendered by ModuleDetailPage, NOT this page). `modules` is both a
  //      valid tab AND a literal route segment, so clicking a module row
  //      (/settings/modules → /settings/modules/:id) would otherwise see
  //      `tab === undefined` and bounce the user back to /settings/general.
  //      Excluded by the segment-count check: this page only owns 1- or
  //      2-segment settings paths.
  useEffect(() => {
    const segments = window.location.pathname.split('/').filter(Boolean);
    if (segments[0] !== 'settings' || segments.length > 2) return;
    if (!tab || !VALID_TABS.includes(tab)) {
      navigate('/settings/general', { replace: true });
    }
  }, [tab, navigate]);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Settings}
        title={t('title')}
        subtitle={t('subtitle')}
      />

      <div className="flex flex-col lg:flex-row gap-6">
        {/* ---- Sidebar (desktop: fixed left column, mobile: horizontal scroll) ---- */}
        <aside className="shrink-0 lg:w-60">
          {/* Mobile: horizontal scrollable nav */}
          <nav className="flex lg:hidden gap-1 overflow-x-auto pb-2 -mx-1 px-1">
            {settingsSections.flatMap((section) =>
              section.items.map((item) => (
                <button
                  key={item.id}
                  onClick={() => navigate(`/settings/${item.id}`, { replace: true })}
                  className={cn(
                    'flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors',
                    currentTab === item.id
                      ? 'bg-accent text-accent-foreground font-medium'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  <item.icon className="h-4 w-4 shrink-0" />
                  {item.label}
                </button>
              ))
            )}
          </nav>

          {/* Desktop: categorized sidebar */}
          <div className="hidden lg:block space-y-6">
            {settingsSections.map((section) => (
              <div key={section.category}>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 px-3">
                  {section.category}
                </h4>
                <nav className="space-y-1">
                  {section.items.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => navigate(`/settings/${item.id}`, { replace: true })}
                      className={cn(
                        'w-full flex items-center gap-3 px-3 py-2 text-sm rounded-md transition-colors',
                        currentTab === item.id
                          ? 'bg-accent text-accent-foreground font-medium'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                      )}
                    >
                      <item.icon className="h-4 w-4 shrink-0" />
                      {item.label}
                    </button>
                  ))}
                </nav>
              </div>
            ))}
          </div>
        </aside>

        {/* ---- Content area ---- */}
        <main className="flex-1 min-w-0">
          <SettingsContent tab={currentTab} />
        </main>
      </div>
    </div>
  );
}

export default SettingsPage;
