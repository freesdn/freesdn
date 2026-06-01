// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Notification Settings
 * =================================================
 *
 * Full notification center settings page with sections:
 *   1. General Preferences  (master toggle, per-channel enables, custom email)
 *   2. Severity Thresholds  (min severity per channel)
 *   3. Quiet Hours          (schedule, timezone, exceptions)
 *   4. Category Subscriptions (per-category × per-channel matrix)
 *   5. Digest Settings       (batching frequency & time)
 *   6. Delivery Providers    (summary card linking to full Provider Management page)
 *
 * Located at /settings/notifications
 */

import { useState, useMemo, useCallback, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  Bell,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Clock,
  Globe,
  Hash,
  Layers,
  Loader2,
  Mail,
  MessageCircle,
  MessageSquare,
  RefreshCw,
  Save,
  Smartphone,
  XCircle,
  Zap,
  AlertTriangle,
} from 'lucide-react';

import {
  notificationApi,
  type NotificationPreference,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITIES = ['info', 'warning', 'error', 'critical'] as const;

const CATEGORIES = [
  { id: 'system', labelKey: 'categories.system.label', descKey: 'categories.system.desc' },
  { id: 'security', labelKey: 'categories.security.label', descKey: 'categories.security.desc' },
  { id: 'device', labelKey: 'categories.device.label', descKey: 'categories.device.desc' },
  { id: 'network', labelKey: 'categories.network.label', descKey: 'categories.network.desc' },
  { id: 'alert', labelKey: 'categories.alert.label', descKey: 'categories.alert.desc' },
  { id: 'user', labelKey: 'categories.user.label', descKey: 'categories.user.desc' },
] as const;

const CHANNELS = [
  { id: 'email', labelKey: 'channels.email', icon: Mail },
  { id: 'slack', labelKey: 'channels.slack', icon: Hash },
  { id: 'in_app', labelKey: 'channels.in_app', icon: Bell },
] as const;

const TIMEZONES = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Asia/Tokyo',
  'Asia/Shanghai',
  'Asia/Kolkata',
  'Australia/Sydney',
];

const DIGEST_FREQUENCIES = [
  { value: 'realtime', labelKey: 'digest.frequencies.realtime' },
  { value: 'hourly', labelKey: 'digest.frequencies.hourly' },
  { value: 'daily', labelKey: 'digest.frequencies.daily' },
  { value: 'weekly', labelKey: 'digest.frequencies.weekly' },
] as const;

// ─── Icon & Color maps ──────────────────────────────────────────────────────

const CHANNEL_ICONS: Record<string, React.ElementType> = {
  mail: Mail,
  hash: Hash,
  'message-square': MessageSquare,
  globe: Globe,
  smartphone: Smartphone,
  'message-circle': MessageCircle,
};

function ChannelIcon({ icon, className }: { icon?: string; className?: string }) {
  const Icon = (icon && CHANNEL_ICONS[icon]) || Bell;
  return <Icon className={className} />;
}

// ─── Types ───────────────────────────────────────────────────────────────────

// ─── Collapsible Section ─────────────────────────────────────────────────────

function SettingsSection({
  title,
  description,
  icon: Icon,
  defaultOpen = true,
  badge,
  children,
}: {
  title: string;
  description: string;
  icon: React.ElementType;
  defaultOpen?: boolean;
  badge?: React.ReactNode;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <Card>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center w-full gap-3 p-5 text-left hover:bg-muted/30 transition-colors rounded-t-lg"
      >
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
          <Icon className="h-5 w-5" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-sm">{title}</h3>
            {badge}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
        </div>
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
        )}
      </button>
      {open && (
        <CardContent noOffset className="pt-0 pb-5 px-5 border-t">
          <div className="pt-4">{children}</div>
        </CardContent>
      )}
    </Card>
  );
}

// ─── Setting Row ─────────────────────────────────────────────────────────────

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
        <Label className="text-sm font-medium">{label}</Label>
        {description && <p className="text-xs text-muted-foreground">{description}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 1: General Preferences
// ═════════════════════════════════════════════════════════════════════════════

function GeneralPreferencesSection({
  prefs,
  onChange,
}: {
  prefs: NotificationPreference;
  onChange: (patch: Partial<NotificationPreference>) => void;
}) {
  const { t } = useTranslation('settings');
  return (
    <SettingsSection
      title={t('NotificationsSettingsTab.general.title')}
      description={t('NotificationsSettingsTab.general.description')}
      icon={Bell}
    >
      <div className="space-y-4">
        <SettingRow
          label={t('NotificationsSettingsTab.general.enable.label')}
          description={t('NotificationsSettingsTab.general.enable.description')}
        >
          <Switch
            checked={prefs.notifications_enabled}
            onCheckedChange={(v) => onChange({ notifications_enabled: v })}
          />
        </SettingRow>

        <div className={cn('space-y-3 transition-opacity', !prefs.notifications_enabled && 'opacity-40 pointer-events-none')}>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('NotificationsSettingsTab.general.channelToggles')}</p>

          <SettingRow label={t('NotificationsSettingsTab.general.email.label')} description={t('NotificationsSettingsTab.general.email.description')}>
            <Switch
              checked={prefs.email_enabled}
              onCheckedChange={(v) => onChange({ email_enabled: v })}
            />
          </SettingRow>

          <SettingRow label={t('NotificationsSettingsTab.general.slack.label')} description={t('NotificationsSettingsTab.general.slack.description')}>
            <Switch
              checked={prefs.slack_enabled}
              onCheckedChange={(v) => onChange({ slack_enabled: v })}
            />
          </SettingRow>

          <SettingRow label={t('NotificationsSettingsTab.general.inApp.label')} description={t('NotificationsSettingsTab.general.inApp.description')}>
            <Switch
              checked={prefs.in_app_enabled}
              onCheckedChange={(v) => onChange({ in_app_enabled: v })}
            />
          </SettingRow>

          <div className="rounded-lg border p-4 space-y-2">
            <Label className="text-sm font-medium">{t('NotificationsSettingsTab.general.emailOverride.label')}</Label>
            <p className="text-xs text-muted-foreground">
              {t('NotificationsSettingsTab.general.emailOverride.description')}
            </p>
            <Input
              value={prefs.notification_email || ''}
              onChange={(e) => onChange({ notification_email: e.target.value || undefined })}
              placeholder={t('NotificationsSettingsTab.general.emailOverride.placeholder')}
              type="email"
              className="max-w-sm"
            />
          </div>
        </div>
      </div>
    </SettingsSection>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 2: Severity Thresholds
// ═════════════════════════════════════════════════════════════════════════════

function SeverityThresholdsSection({
  prefs,
  onChange,
}: {
  prefs: NotificationPreference;
  onChange: (patch: Partial<NotificationPreference>) => void;
}) {
  const { t } = useTranslation('settings');
  return (
    <SettingsSection
      title={t('NotificationsSettingsTab.severity.title')}
      description={t('NotificationsSettingsTab.severity.description')}
      icon={AlertTriangle}
      defaultOpen={false}
    >
      <div className="space-y-4">
        {CHANNELS.map((ch) => {
          const key = `min_${ch.id}_severity` as keyof NotificationPreference;
          const current = (prefs[key] as string) || 'info';
          const channelLabel = t(`NotificationsSettingsTab.${ch.labelKey}`);
          return (
            <div key={ch.id} className="flex items-center justify-between gap-4 rounded-lg border p-4">
              <div className="flex items-center gap-3">
                <ch.icon className="h-4 w-4 text-muted-foreground" />
                <div>
                  <Label className="text-sm font-medium">{channelLabel}</Label>
                  <p className="text-xs text-muted-foreground">
                    {t('NotificationsSettingsTab.severity.minForChannel', { channel: channelLabel.toLowerCase() })}
                  </p>
                </div>
              </div>
              <Select value={current} onValueChange={(v) => onChange({ [key]: v })}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s} className="capitalize">
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          );
        })}
        <p className="text-xs text-muted-foreground">
          {t('NotificationsSettingsTab.severity.example.before')}<strong>{t('NotificationsSettingsTab.severity.example.error')}</strong>{t('NotificationsSettingsTab.severity.example.middle')}<strong>{t('NotificationsSettingsTab.severity.example.critical')}</strong>{t('NotificationsSettingsTab.severity.example.after')}
        </p>
      </div>
    </SettingsSection>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 3: Quiet Hours
// ═════════════════════════════════════════════════════════════════════════════

function QuietHoursSection({
  prefs,
  onChange,
}: {
  prefs: NotificationPreference;
  onChange: (patch: Partial<NotificationPreference>) => void;
}) {
  const { t } = useTranslation('settings');
  const hours = Array.from({ length: 24 }, (_, i) => {
    const h = i.toString().padStart(2, '0');
    return { value: `${h}:00`, label: `${h}:00` };
  });

  return (
    <SettingsSection
      title={t('NotificationsSettingsTab.quietHours.title')}
      description={t('NotificationsSettingsTab.quietHours.description')}
      icon={Clock}
      defaultOpen={false}
      badge={
        prefs.quiet_hours_enabled ? (
          <Badge variant="secondary" className="text-[10px]">{t('NotificationsSettingsTab.quietHours.active')}</Badge>
        ) : null
      }
    >
      <div className="space-y-4">
        <SettingRow
          label={t('NotificationsSettingsTab.quietHours.enable.label')}
          description={t('NotificationsSettingsTab.quietHours.enable.description')}
        >
          <Switch
            checked={prefs.quiet_hours_enabled}
            onCheckedChange={(v) => onChange({ quiet_hours_enabled: v })}
          />
        </SettingRow>

        <div className={cn('space-y-4 transition-opacity', !prefs.quiet_hours_enabled && 'opacity-40 pointer-events-none')}>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationsSettingsTab.quietHours.startTime')}</Label>
              <Select
                value={prefs.quiet_hours_start || '22:00'}
                onValueChange={(v) => onChange({ quiet_hours_start: v })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {hours.map((h) => (
                    <SelectItem key={h.value} value={h.value}>{h.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationsSettingsTab.quietHours.endTime')}</Label>
              <Select
                value={prefs.quiet_hours_end || '07:00'}
                onValueChange={(v) => onChange({ quiet_hours_end: v })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {hours.map((h) => (
                    <SelectItem key={h.value} value={h.value}>{h.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-xs">{t('NotificationsSettingsTab.quietHours.timezone')}</Label>
              <Select
                value={prefs.quiet_hours_timezone || 'UTC'}
                onValueChange={(v) => onChange({ quiet_hours_timezone: v })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {TIMEZONES.map((tz) => (
                    <SelectItem key={tz} value={tz}>{tz.replace(/_/g, ' ')}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="rounded-lg border p-4 space-y-3">
            <Label className="text-sm font-medium">{t('NotificationsSettingsTab.quietHours.bypass.label')}</Label>
            <p className="text-xs text-muted-foreground">
              {t('NotificationsSettingsTab.quietHours.bypass.description')}
            </p>
            <div className="flex flex-wrap gap-3">
              {CATEGORIES.map((cat) => {
                const active = (prefs.quiet_hours_exceptions || []).includes(cat.id);
                return (
                  <label
                    key={cat.id}
                    className={cn(
                      'flex items-center gap-2 rounded-md border px-3 py-2 text-sm cursor-pointer transition-colors',
                      active ? 'border-primary bg-primary/5' : 'border-muted hover:border-muted-foreground/30',
                    )}
                  >
                    <Checkbox
                      checked={active}
                      onCheckedChange={(checked) => {
                        const current = prefs.quiet_hours_exceptions || [];
                        const next = checked
                          ? [...current, cat.id]
                          : current.filter((c) => c !== cat.id);
                        onChange({ quiet_hours_exceptions: next });
                      }}
                    />
                    {t(`NotificationsSettingsTab.${cat.labelKey}`)}
                  </label>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </SettingsSection>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 4: Category Subscriptions
// ═════════════════════════════════════════════════════════════════════════════

function CategorySubscriptionsSection({
  prefs,
  onChange,
}: {
  prefs: NotificationPreference;
  onChange: (patch: Partial<NotificationPreference>) => void;
}) {
  const { t } = useTranslation('settings');
  const subs = prefs.subscriptions || {};

  const toggleSub = (catId: string, channelId: string, value: boolean) => {
    const current = subs[catId] || { email: true, slack: true, in_app: true };
    onChange({
      subscriptions: {
        ...subs,
        [catId]: { ...current, [channelId]: value },
      },
    });
  };

  return (
    <SettingsSection
      title={t('NotificationsSettingsTab.subscriptions.title')}
      description={t('NotificationsSettingsTab.subscriptions.description')}
      icon={Layers}
      defaultOpen={false}
    >
      <div className="rounded-lg border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/30">
                <th className="text-left px-4 py-3 font-medium text-muted-foreground">{t('NotificationsSettingsTab.subscriptions.categoryHeader')}</th>
                {CHANNELS.map((ch) => (
                  <th key={ch.id} className="text-center px-4 py-3 font-medium text-muted-foreground w-24">
                    <div className="flex items-center justify-center gap-1.5">
                      <ch.icon className="h-3.5 w-3.5" />
                      {t(`NotificationsSettingsTab.${ch.labelKey}`)}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {CATEGORIES.map((cat, idx) => {
                const catSubs = subs[cat.id] || { email: true, slack: true, in_app: true };
                return (
                  <tr key={cat.id} className={cn('border-b last:border-0', idx % 2 && 'bg-muted/10')}>
                    <td className="px-4 py-3">
                      <div>
                        <span className="font-medium">{t(`NotificationsSettingsTab.${cat.labelKey}`)}</span>
                        <p className="text-xs text-muted-foreground">{t(`NotificationsSettingsTab.${cat.descKey}`)}</p>
                      </div>
                    </td>
                    {CHANNELS.map((ch) => (
                      <td key={ch.id} className="text-center px-4 py-3">
                        <Checkbox
                          checked={catSubs[ch.id as keyof typeof catSubs] ?? true}
                          onCheckedChange={(v) => toggleSub(cat.id, ch.id, !!v)}
                        />
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </SettingsSection>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 5: Digest Settings
// ═════════════════════════════════════════════════════════════════════════════

function DigestSettingsSection({
  prefs,
  onChange,
}: {
  prefs: NotificationPreference;
  onChange: (patch: Partial<NotificationPreference>) => void;
}) {
  const { t } = useTranslation('settings');
  return (
    <SettingsSection
      title={t('NotificationsSettingsTab.digest.title')}
      description={t('NotificationsSettingsTab.digest.description')}
      icon={Mail}
      defaultOpen={false}
      badge={
        prefs.digest_enabled ? (
          <Badge variant="secondary" className="text-[10px]">
            {prefs.digest_frequency || 'daily'}
          </Badge>
        ) : null
      }
    >
      <div className="space-y-4">
        <SettingRow
          label={t('NotificationsSettingsTab.digest.enable.label')}
          description={t('NotificationsSettingsTab.digest.enable.description')}
        >
          <Switch
            checked={prefs.digest_enabled}
            onCheckedChange={(v) => onChange({ digest_enabled: v })}
          />
        </SettingRow>

        <div className={cn('grid grid-cols-1 sm:grid-cols-2 gap-4 transition-opacity', !prefs.digest_enabled && 'opacity-40 pointer-events-none')}>
          <div className="space-y-2">
            <Label className="text-xs">{t('NotificationsSettingsTab.digest.frequency')}</Label>
            <Select
              value={prefs.digest_frequency || 'daily'}
              onValueChange={(v) => onChange({ digest_frequency: v })}
            >
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {DIGEST_FREQUENCIES.map((f) => (
                  <SelectItem key={f.value} value={f.value}>{t(`NotificationsSettingsTab.${f.labelKey}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label className="text-xs">{t('NotificationsSettingsTab.digest.deliveryTime')}</Label>
            <Input
              type="time"
              value={prefs.digest_time || '09:00'}
              onChange={(e) => onChange({ digest_time: e.target.value })}
              className="max-w-[160px]"
            />
            <p className="text-xs text-muted-foreground">
              {t('NotificationsSettingsTab.digest.deliveryTimeHint')}
            </p>
          </div>
        </div>
      </div>
    </SettingsSection>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 6: Delivery Providers (Summary + Link to full page)
// ═════════════════════════════════════════════════════════════════════════════

function ProvidersSection() {
  const { t } = useTranslation('settings');
  const { data: providers = [], isLoading } = useQuery({
    queryKey: ['notification-providers'],
    queryFn: () => notificationApi.getProviders().then((r) => r.data),
    staleTime: 30_000,
  });

  const channelStats = useMemo(() => {
    const map = new Map<string, { total: number; enabled: number; verified: number }>();
    for (const p of providers) {
      const s = map.get(p.channel) || { total: 0, enabled: 0, verified: 0 };
      s.total++;
      if (p.is_enabled) s.enabled++;
      if (p.is_verified) s.verified++;
      map.set(p.channel, s);
    }
    return Array.from(map.entries());
  }, [providers]);

  const errors = providers.filter((p) => p.last_error && p.is_enabled).length;

  return (
    <SettingsSection
      title={t('NotificationsSettingsTab.providers.title')}
      description={t('NotificationsSettingsTab.providers.description')}
      icon={Zap}
      badge={
        <Badge variant="secondary" className="text-[10px]">
          {t('NotificationsSettingsTab.providers.configuredCount', { count: providers.length })}
        </Badge>
      }
    >
      <div className="space-y-4">
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : providers.length === 0 ? (
          <EmptyState
            variant="compact"
            icon={Zap}
            title={t('NotificationsSettingsTab.providers.empty.title')}
            description={t('NotificationsSettingsTab.providers.empty.description')}
          />
        ) : (
          <>
            {/* Channel summary cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              {channelStats.map(([ch, stats]) => (
                <div key={ch} className="flex items-center gap-2 rounded-lg border p-3">
                  <ChannelIcon icon={
                    ch === 'email' ? 'mail' : ch === 'slack' ? 'hash' : ch === 'teams' ? 'message-square' : ch === 'webhook' ? 'globe' : ch === 'sms' ? 'smartphone' : 'message-circle'
                  } className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <p className="text-xs font-medium capitalize">{ch}</p>
                    <p className="text-[10px] text-muted-foreground">
                      {stats.enabled}/{stats.total} · {t('NotificationsSettingsTab.providers.verifiedCount', { count: stats.verified })}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {errors > 0 && (
              <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
                <AlertTriangle className="h-4 w-4 text-destructive shrink-0" />
                <span className="text-destructive text-xs">
                  {errors === 1
                    ? t('NotificationsSettingsTab.providers.errors.one', { count: errors })
                    : t('NotificationsSettingsTab.providers.errors.other', { count: errors })}
                </span>
              </div>
            )}
          </>
        )}

        {/* Link to full providers page */}
        <Link
          to="/notification-providers"
          className="flex items-center justify-between gap-3 rounded-lg border border-primary/20 bg-primary/5 p-4 hover:bg-primary/10 transition-colors group"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Zap className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm font-medium">{t('NotificationsSettingsTab.providers.manage.title')}</p>
              <p className="text-xs text-muted-foreground">
                {t('NotificationsSettingsTab.providers.manage.description')}
              </p>
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
        </Link>
      </div>
    </SettingsSection>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Main Tab Component
// ═════════════════════════════════════════════════════════════════════════════

const DEFAULT_PREFS: NotificationPreference = {
  id: '',
  user_id: '',
  notifications_enabled: true,
  email_enabled: true,
  slack_enabled: true,
  in_app_enabled: true,
  notification_email: undefined,
  min_email_severity: 'info',
  min_slack_severity: 'info',
  min_in_app_severity: 'info',
  subscriptions: {},
  quiet_hours_enabled: false,
  quiet_hours_start: '22:00',
  quiet_hours_end: '07:00',
  quiet_hours_timezone: 'UTC',
  quiet_hours_exceptions: ['security'],
  digest_enabled: false,
  digest_frequency: 'daily',
  digest_time: '09:00',
  created_at: '',
  updated_at: '',
};

// Parse an "HH:MM" string into an integer hour (0-23). The backend
// PUT /notifications/preferences expects quiet_hours_start/end as ints,
// not the "HH:MM" strings the UI keeps in local state.
function parseHour(value: string | undefined): number | null {
  if (!value) return null;
  const hour = parseInt(value.split(':')[0], 10);
  if (Number.isNaN(hour) || hour < 0 || hour > 23) return null;
  return hour;
}

// Translate the FE preference shape into the backend
// NotificationPreferencesUpdate contract:
//   { enabled_channels: string[], quiet_hours_start/end: int|null,
//     category_settings: dict }
// The whole-object PUT previously sent booleans + "HH:MM" strings +
// `subscriptions`, which 422'd on every save.
function buildPreferencesPayload(prefs: NotificationPreference): Record<string, unknown> {
  const enabled_channels: string[] = [];
  if (prefs.notifications_enabled) {
    if (prefs.email_enabled) enabled_channels.push('email');
    if (prefs.slack_enabled) enabled_channels.push('slack');
    if (prefs.in_app_enabled) enabled_channels.push('in_app');
  }

  const quietHoursOn = prefs.quiet_hours_enabled;
  return {
    enabled_channels,
    quiet_hours_start: quietHoursOn ? parseHour(prefs.quiet_hours_start) : null,
    quiet_hours_end: quietHoursOn ? parseHour(prefs.quiet_hours_end) : null,
    category_settings: prefs.subscriptions ?? {},
  };
}

// Translate the backend GET /notifications/preferences response
//   { enabled_channels: string[], quiet_hours: {start,end}|null,
//     category_settings: dict }
// into the FE preference shape. The backend response does NOT match
// NotificationPreference, so a naive spread left every toggle stuck on its
// default and the saved server state never showed in the UI.
function mapServerToLocal(server: unknown): Partial<NotificationPreference> {
  if (!server || typeof server !== 'object') return {};
  const s = server as Record<string, unknown>;

  // If the response already looks like the FE shape (e.g. the DEFAULT_PREFS
  // fallback from the failed-fetch catch), pass it through untouched.
  if (!('enabled_channels' in s) && !('quiet_hours' in s) && !('category_settings' in s)) {
    return s as Partial<NotificationPreference>;
  }

  const out: Partial<NotificationPreference> = {};

  if (Array.isArray(s.enabled_channels)) {
    const channels = s.enabled_channels as string[];
    out.email_enabled = channels.includes('email');
    out.slack_enabled = channels.includes('slack');
    out.in_app_enabled = channels.includes('in_app');
    out.notifications_enabled = channels.length > 0;
  }

  const qh = s.quiet_hours as { start?: number; end?: number } | null | undefined;
  if (qh && typeof qh === 'object') {
    out.quiet_hours_enabled = true;
    if (typeof qh.start === 'number') out.quiet_hours_start = `${String(qh.start).padStart(2, '0')}:00`;
    if (typeof qh.end === 'number') out.quiet_hours_end = `${String(qh.end).padStart(2, '0')}:00`;
  } else {
    out.quiet_hours_enabled = false;
  }

  if (s.category_settings && typeof s.category_settings === 'object') {
    out.subscriptions = s.category_settings as NotificationPreference['subscriptions'];
  }

  return out;
}

export function NotificationsSettingsTab() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [localPrefs, setLocalPrefs] = useState<NotificationPreference>(DEFAULT_PREFS);
  const [isSaving, setIsSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'success' | 'error'>('idle');

  // Fetch preferences
  const { data: serverPrefs, isLoading: loadingPrefs, isError } = useQuery({
    queryKey: ['notification-preferences'],
    queryFn: async () => {
      try {
        const resp = await notificationApi.getPreferences();
        return resp.data;
      } catch {
        return DEFAULT_PREFS;
      }
    },
    staleTime: 60_000,
  });

  // Sync server prefs → local state
  useEffect(() => {
    if (serverPrefs) {
      setLocalPrefs({ ...DEFAULT_PREFS, ...mapServerToLocal(serverPrefs) });
    }
  }, [serverPrefs]);

  const handlePrefChange = useCallback((patch: Partial<NotificationPreference>) => {
    setLocalPrefs((prev) => ({ ...prev, ...patch }));
    setSaveStatus('idle');
  }, []);

  const handleSavePreferences = async () => {
    setIsSaving(true);
    setSaveStatus('idle');
    try {
      await notificationApi.updatePreferences(
        buildPreferencesPayload(localPrefs) as Partial<NotificationPreference>,
      );
      queryClient.invalidateQueries({ queryKey: ['notification-preferences'] });
      setSaveStatus('success');
      setTimeout(() => setSaveStatus('idle'), 3000);
    } catch {
      setSaveStatus('error');
    } finally {
      setIsSaving(false);
    }
  };

  if (loadingPrefs) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('NotificationsSettingsTab.loadError')}</span>
          </CardContent>
        </Card>
      )}

      {/* Section 1: General Preferences */}
      <GeneralPreferencesSection prefs={localPrefs} onChange={handlePrefChange} />

      {/* Section 2: Severity Thresholds */}
      <SeverityThresholdsSection prefs={localPrefs} onChange={handlePrefChange} />

      {/* Section 3: Quiet Hours */}
      <QuietHoursSection prefs={localPrefs} onChange={handlePrefChange} />

      {/* Section 4: Category Subscriptions */}
      <CategorySubscriptionsSection prefs={localPrefs} onChange={handlePrefChange} />

      {/* Section 5: Digest Settings */}
      <DigestSettingsSection prefs={localPrefs} onChange={handlePrefChange} />

      {/* Save Preferences Bar */}
      <div className="flex items-center justify-between gap-3 rounded-lg border bg-muted/30 p-4">
        <div className="flex items-center gap-2 text-sm">
          {saveStatus === 'success' && (
            <>
              <CheckCircle className="h-4 w-4 text-emerald-500" />
              <span className="text-emerald-600 dark:text-emerald-400">{t('NotificationsSettingsTab.save.success')}</span>
            </>
          )}
          {saveStatus === 'error' && (
            <>
              <XCircle className="h-4 w-4 text-destructive" />
              <span className="text-destructive">{t('NotificationsSettingsTab.save.error')}</span>
            </>
          )}
          {saveStatus === 'idle' && (
            <span className="text-muted-foreground">{t('NotificationsSettingsTab.save.idle')}</span>
          )}
        </div>
        <Button onClick={handleSavePreferences} disabled={isSaving} size="sm">
          {isSaving ? (
            <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-2 h-4 w-4" />
          )}
          {t('NotificationsSettingsTab.save.button')}
        </Button>
      </div>

      {/* Section 6: Delivery Providers */}
      <ProvidersSection />
    </div>
  );
}

export default NotificationsSettingsTab;
